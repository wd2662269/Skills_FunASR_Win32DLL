/*
 * ws_client.c - Raw Winsock2 WebSocket client
 *
 * Implements RFC 6455 minimum viable:
 *   - TCP connect
 *   - HTTP/1.1 Upgrade handshake
 *   - Frame send (text/binary) with client masking
 *   - Frame recv (text/binary/close)
 *
 * IOCP coroutine data path covers connect + upgrade + frame send/recv.
 */

#include "ws_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <mswsock.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")

#ifdef FUNASR_USE_X64_ASM
void ws_mask_xor_copy_x64(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32);
void ws_mask_xor_inplace_x64(uint8_t* buf, uint64_t len, uint32_t mask32);
#endif

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif

static THREAD_LOCAL uint8_t* g_tls_masked_buf = NULL;
static THREAD_LOCAL uint32_t g_tls_masked_cap = 0;

/* ---- URL parser ---- */
static int parse_ws_url(const char* url, char* host, uint16_t* port, char* path)
{
    /* ws://host:port/path */
    const char* p = url;
    if (strncmp(p, "ws://", 5) == 0) p += 5;
    else return -1; /* wss:// not implemented yet */

    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        size_t host_len = (size_t)(colon - p);
        if (host_len == 0 || host_len >= 256) return -1;
        memcpy(host, p, host_len);
        host[host_len] = '\0';
        *port = (uint16_t)atoi(colon + 1);
    } else {
        *port = 80;
        size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
        if (hlen == 0 || hlen >= 256) return -1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
    }

    if (slash) {
        size_t plen = strlen(slash);
        if (plen >= 256) return -1;
        memcpy(path, slash, plen + 1);
    } else {
        path[0] = '/';
        path[1] = '\0';
    }
    return 0;
}

/* ---- Generate random mask key ---- */
static void gen_mask_key(uint8_t key[4])
{
    /* TODO(东哥): RtlGenRandom / rdrand intrinsic */
    uint32_t r = (uint32_t)time(NULL) ^ (uint32_t)GetTickCount();
    memcpy(key, &r, 4);
}

/* ---- Base64 encode (for Sec-WebSocket-Key) ---- */
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_encode(const uint8_t* in, int len, char* out)
{
    int i, j = 0;
    for (i = 0; i < len - 2; i += 3) {
        out[j++] = b64[(in[i] >> 2) & 0x3F];
        out[j++] = b64[((in[i] & 0x3) << 4) | ((in[i+1] >> 4) & 0xF)];
        out[j++] = b64[((in[i+1] & 0xF) << 2) | ((in[i+2] >> 6) & 0x3)];
        out[j++] = b64[in[i+2] & 0x3F];
    }
    if (i < len) {
        out[j++] = b64[(in[i] >> 2) & 0x3F];
        if (i == len - 1) {
            out[j++] = b64[((in[i] & 0x3) << 4)];
            out[j++] = '=';
        } else {
            out[j++] = b64[((in[i] & 0x3) << 4) | ((in[i+1] >> 4) & 0xF)];
            out[j++] = b64[((in[i+1] & 0xF) << 2)];
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    return j;
}

static int send_all(SOCKET s, const uint8_t* buf, uint32_t len)
{
    uint32_t sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)(buf + sent), (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (uint32_t)n;
    }
    return 0;
}

static int wsasend_all(SOCKET s, WSABUF* bufs, DWORD buf_count)
{
    DWORD idx = 0;
    while (idx < buf_count) {
        DWORD sent = 0;
        int rc = WSASend(s, &bufs[idx], buf_count - idx, &sent, 0, NULL, NULL);
        if (rc == SOCKET_ERROR || sent == 0) return -1;

        DWORD remain = sent;
        while (remain > 0 && idx < buf_count) {
            if (remain >= bufs[idx].len) {
                remain -= bufs[idx].len;
                idx++;
            } else {
                bufs[idx].buf += remain;
                bufs[idx].len -= remain;
                remain = 0;
            }
        }
    }
    return 0;
}

static int wsasend_all_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                            WSABUF* bufs, DWORD buf_count)
{
    DWORD idx = 0;
    while (idx < buf_count) {
        DWORD sent = 0;
        if (funasr_coro_await_wsasend(task, ws->sock, &bufs[idx], buf_count - idx,
                                      0, &sent) < 0) {
            return -1;
        }
        if (sent == 0) return -1;

        DWORD remain = sent;
        while (remain > 0 && idx < buf_count) {
            if (remain >= bufs[idx].len) {
                remain -= bufs[idx].len;
                idx++;
            } else {
                bufs[idx].buf += remain;
                bufs[idx].len -= remain;
                remain = 0;
            }
        }
    }
    return 0;
}

static int ws_recv_http_upgrade_blocking(SOCKET sock)
{
    char resp[2048];
    int total = 0;
    while (total < (int)sizeof(resp) - 1) {
        int n = recv(sock, resp + total, (int)sizeof(resp) - 1 - total, 0);
        if (n <= 0) return -1;
        total += n;
        resp[total] = '\0';
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (!strstr(resp, " 101 ")) return -1;
    return 0;
}

static int ws_recv_http_upgrade_iocp(ws_conn_t* ws, funasr_coro_task_t* task, DWORD timeout_ms)
{
    char resp[2048];
    int total = 0;

    while (total < (int)sizeof(resp) - 1) {
        WSABUF buf;
        DWORD flags = 0;
        DWORD recvd = 0;

        buf.buf = resp + total;
        buf.len = (ULONG)((int)sizeof(resp) - 1 - total);
        if (funasr_coro_await_wsarecv_timeout(task, ws->sock, &buf, 1, &flags, timeout_ms, &recvd) < 0)
            return -1;
        if (recvd == 0) return -1;

        total += (int)recvd;
        resp[total] = '\0';
        if (strstr(resp, "\r\n\r\n")) break;
    }

    if (!strstr(resp, " 101 ")) return -1;
    return 0;
}

static int ws_send_upgrade_request_blocking(ws_conn_t* ws)
{
    uint8_t nonce[16];
    char key_b64[32];
    char req[1024];
    int reqlen;

    gen_mask_key(nonce);
    gen_mask_key(nonce + 4);
    gen_mask_key(nonce + 8);
    gen_mask_key(nonce + 12);
    base64_encode(nonce, 16, key_b64);

    reqlen = _snprintf_s(req, sizeof(req), _TRUNCATE,
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        ws->path, ws->host, ws->port, key_b64);
    if (reqlen < 0) return -1;

    if (send_all(ws->sock, (const uint8_t*)req, (uint32_t)reqlen) < 0) return -1;
    return ws_recv_http_upgrade_blocking(ws->sock);
}

static int ws_send_upgrade_request_iocp(ws_conn_t* ws, funasr_coro_task_t* task, DWORD timeout_ms)
{
    uint8_t nonce[16];
    char key_b64[32];
    char req[1024];
    int reqlen;
    WSABUF buf;

    gen_mask_key(nonce);
    gen_mask_key(nonce + 4);
    gen_mask_key(nonce + 8);
    gen_mask_key(nonce + 12);
    base64_encode(nonce, 16, key_b64);

    reqlen = _snprintf_s(req, sizeof(req), _TRUNCATE,
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        ws->path, ws->host, ws->port, key_b64);
    if (reqlen < 0) return -1;

    buf.buf = req;
    buf.len = (ULONG)reqlen;
    while (buf.len > 0) {
        DWORD sent = 0;
        if (funasr_coro_await_wsasend_timeout(task, ws->sock, &buf, 1, 0, timeout_ms, &sent) < 0)
            return -1;
        if (sent == 0) return -1;
        buf.buf += sent;
        buf.len -= sent;
    }

    return ws_recv_http_upgrade_iocp(ws, task, timeout_ms);
}

static int ws_get_connectex_fn(SOCKET sock, LPFN_CONNECTEX* fn_out)
{
    GUID guid = WSAID_CONNECTEX;
    DWORD bytes = 0;
    if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 fn_out, sizeof(*fn_out),
                 &bytes, NULL, NULL) != 0) {
        return -1;
    }
    return 0;
}

/* ---- Connect + Upgrade ---- */
int ws_connect(ws_conn_t* ws, const char* url)
{
    memset(ws, 0, sizeof(*ws));
    ws->sock = INVALID_SOCKET;

    if (parse_ws_url(url, ws->host, &ws->port, ws->path) < 0)
        return -1;

    /* Resolve + connect */
    struct addrinfo hints = {0}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    if (_snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", ws->port) < 0)
        return -1;

    if (getaddrinfo(ws->host, port_str, &hints, &res) != 0)
        return -1;

    ws->sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ws->sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(ws->sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(ws->sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    {
        BOOL keepalive = TRUE;
        int nodelay = 1;
        setsockopt(ws->sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
        setsockopt(ws->sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    }

    if (ws_send_upgrade_request_blocking(ws) < 0) {
        closesocket(ws->sock);
        return -1;
    }

    ws->connected = 1;
    return 0;
}

int ws_connect_iocp(ws_conn_t* ws, funasr_coro_task_t* task, const char* url)
{
    funasr_coro_sched_t* sched = NULL;
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct sockaddr_in local_addr;
    LPFN_CONNECTEX connect_ex = NULL;
    funasr_coro_io_op_t op;
    char port_str[8];
    int rc = -1;
    DWORD timeout_ms = 0;

    if (!ws || !task || !url) return -1;

    memset(ws, 0, sizeof(*ws));
    ws->sock = INVALID_SOCKET;
    sched = funasr_coro_task_sched(task);
    if (!sched) return -1;
    timeout_ms = sched->default_io_timeout_ms;

    if (parse_ws_url(url, ws->host, &ws->port, ws->path) < 0) return -1;
    if (_snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", ws->port) < 0) return -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(ws->host, port_str, &hints, &res) != 0) return -1;

    ws->sock = WSASocketW(res->ai_family, res->ai_socktype, res->ai_protocol,
                          NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ws->sock == INVALID_SOCKET) goto done;

    if (funasr_coro_bind_socket(sched, ws->sock) < 0) goto done;
    if (ws_get_connectex_fn(ws->sock, &connect_ex) < 0) goto done;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = 0;
    if (bind(ws->sock, (const struct sockaddr*)&local_addr, sizeof(local_addr)) != 0) goto done;

    memset(&op, 0, sizeof(op));
    if (!connect_ex(ws->sock, res->ai_addr, (int)res->ai_addrlen, NULL, 0, NULL, &op.overlapped)) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) goto done;
        if (funasr_coro_await_handle_op(task, (HANDLE)ws->sock, &op, timeout_ms) < 0) goto done;
    }

    {
        BOOL keepalive = TRUE;
        int nodelay = 1;
        setsockopt(ws->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        setsockopt(ws->sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
        setsockopt(ws->sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    }

    if (ws_send_upgrade_request_iocp(ws, task, timeout_ms) < 0) goto done;

    ws->connected = 1;
    rc = 0;

done:
    if (res) freeaddrinfo(res);
    if (rc < 0) {
        if (ws->sock != INVALID_SOCKET) {
            closesocket(ws->sock);
            ws->sock = INVALID_SOCKET;
        }
        ws->connected = 0;
    }
    return rc;
}

/* ---- Send frame ---- */
static int ws_send_frame(ws_conn_t* ws, uint8_t opcode,
                         const uint8_t* payload, uint32_t len)
{
    if (!ws->connected) return -1;

    /* Header: FIN + opcode */
    uint8_t header[14];
    int hlen = 0;
    header[hlen++] = 0x80 | opcode; /* FIN=1 */

    /* Payload length + MASK bit (client must mask) */
    if (len < 126) {
        header[hlen++] = 0x80 | (uint8_t)len;
    } else if (len < 65536) {
        header[hlen++] = 0x80 | 126;
        header[hlen++] = (uint8_t)(len >> 8);
        header[hlen++] = (uint8_t)(len & 0xFF);
    } else {
        header[hlen++] = 0x80 | 127;
        /* 8-byte extended length */
        memset(&header[hlen], 0, 4); hlen += 4;
        header[hlen++] = (uint8_t)(len >> 24);
        header[hlen++] = (uint8_t)(len >> 16);
        header[hlen++] = (uint8_t)(len >> 8);
        header[hlen++] = (uint8_t)(len);
    }

    /* Mask key */
    uint8_t mask[4];
    gen_mask_key(mask);
    memcpy(&header[hlen], mask, 4);
    hlen += 4;

    /* Send masked payload
     * TODO(东哥): true zero-copy still needs kernel/network stack integration.
     */
    if (len > 0) {
        if (g_tls_masked_cap < len) {
            uint32_t new_cap = g_tls_masked_cap ? g_tls_masked_cap : 4096;
            while (new_cap < len) {
                if (new_cap > 0x7FFFFFFFu / 2u) {
                    new_cap = len;
                    break;
                }
                new_cap *= 2;
            }
            uint8_t* new_buf = (uint8_t*)realloc(g_tls_masked_buf, new_cap);
            if (!new_buf) return -1;
            g_tls_masked_buf = new_buf;
            g_tls_masked_cap = new_cap;
        }
        uint32_t mask32 = 0;
        memcpy(&mask32, mask, sizeof(mask32));
#ifdef FUNASR_USE_X64_ASM
        ws_mask_xor_copy_x64(g_tls_masked_buf, payload, len, mask32);
#else
        for (uint32_t i = 0; i < len; i++)
            g_tls_masked_buf[i] = payload[i] ^ mask[i & 3];
#endif
        WSABUF bufs[2];
        bufs[0].buf = (CHAR*)header;
        bufs[0].len = (ULONG)hlen;
        bufs[1].buf = (CHAR*)g_tls_masked_buf;
        bufs[1].len = len;
        if (wsasend_all(ws->sock, bufs, 2) < 0) return -1;
    } else {
        WSABUF b;
        b.buf = (CHAR*)header;
        b.len = (ULONG)hlen;
        if (wsasend_all(ws->sock, &b, 1) < 0) return -1;
    }
    return 0;
}

static int ws_send_frame_iocp(ws_conn_t* ws, funasr_coro_task_t* task, uint8_t opcode,
                              const uint8_t* payload, uint32_t len)
{
    if (!ws->connected || !task) return -1;

    uint8_t header[14];
    int hlen = 0;
    header[hlen++] = 0x80 | opcode;

    if (len < 126) {
        header[hlen++] = 0x80 | (uint8_t)len;
    } else if (len < 65536) {
        header[hlen++] = 0x80 | 126;
        header[hlen++] = (uint8_t)(len >> 8);
        header[hlen++] = (uint8_t)(len & 0xFF);
    } else {
        header[hlen++] = 0x80 | 127;
        memset(&header[hlen], 0, 4);
        hlen += 4;
        header[hlen++] = (uint8_t)(len >> 24);
        header[hlen++] = (uint8_t)(len >> 16);
        header[hlen++] = (uint8_t)(len >> 8);
        header[hlen++] = (uint8_t)(len);
    }

    uint8_t mask[4];
    gen_mask_key(mask);
    memcpy(&header[hlen], mask, 4);
    hlen += 4;

    if (len > 0) {
        if (g_tls_masked_cap < len) {
            uint32_t new_cap = g_tls_masked_cap ? g_tls_masked_cap : 4096;
            while (new_cap < len) {
                if (new_cap > 0x7FFFFFFFu / 2u) {
                    new_cap = len;
                    break;
                }
                new_cap *= 2;
            }
            uint8_t* new_buf = (uint8_t*)realloc(g_tls_masked_buf, new_cap);
            if (!new_buf) return -1;
            g_tls_masked_buf = new_buf;
            g_tls_masked_cap = new_cap;
        }

        uint32_t mask32 = 0;
        memcpy(&mask32, mask, sizeof(mask32));
#ifdef FUNASR_USE_X64_ASM
        ws_mask_xor_copy_x64(g_tls_masked_buf, payload, len, mask32);
#else
        for (uint32_t i = 0; i < len; i++)
            g_tls_masked_buf[i] = payload[i] ^ mask[i & 3];
#endif

        WSABUF bufs[2];
        bufs[0].buf = (CHAR*)header;
        bufs[0].len = (ULONG)hlen;
        bufs[1].buf = (CHAR*)g_tls_masked_buf;
        bufs[1].len = len;
        if (wsasend_all_iocp(ws, task, bufs, 2) < 0) return -1;
    } else {
        WSABUF b;
        b.buf = (CHAR*)header;
        b.len = (ULONG)hlen;
        if (wsasend_all_iocp(ws, task, &b, 1) < 0) return -1;
    }

    return 0;
}

int ws_send_text(ws_conn_t* ws, const char* text, uint32_t len)
{
    return ws_send_frame(ws, 0x01, (const uint8_t*)text, len);
}

int ws_send_binary(ws_conn_t* ws, const uint8_t* data, uint32_t len)
{
    return ws_send_frame(ws, 0x02, data, len);
}

int ws_send_text_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                      const char* text, uint32_t len)
{
    return ws_send_frame_iocp(ws, task, 0x01, (const uint8_t*)text, len);
}

int ws_send_binary_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                        const uint8_t* data, uint32_t len)
{
    return ws_send_frame_iocp(ws, task, 0x02, data, len);
}

/* ---- Receive frame ---- */
static int recv_exact(SOCKET s, uint8_t* buf, int need)
{
    int got = 0;
    while (got < need) {
        int n = recv(s, (char*)(buf + got), need - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

static int recv_exact_iocp(ws_conn_t* ws, funasr_coro_task_t* task, uint8_t* buf, int need)
{
    int got = 0;
    while (got < need) {
        WSABUF wbuf;
        DWORD flags = 0;
        DWORD recvd = 0;

        wbuf.buf = (CHAR*)(buf + got);
        wbuf.len = (ULONG)(need - got);

        if (funasr_coro_await_wsarecv(task, ws->sock, &wbuf, 1, &flags, &recvd) < 0)
            return -1;
        if (recvd == 0) return -1;

        got += (int)recvd;
    }
    return 0;
}

int ws_recv(ws_conn_t* ws, uint8_t* out_buf, uint32_t buf_size,
            uint32_t* out_len, uint8_t* out_opcode)
{
    if (!ws->connected) return -1;

    uint8_t h[2];
    if (recv_exact(ws->sock, h, 2) < 0) return -1;

    *out_opcode = h[0] & 0x0F;
    int masked  = (h[1] >> 7) & 1;
    uint64_t plen = h[1] & 0x7F;

    if (plen == 126) {
        uint8_t ext[2];
        if (recv_exact(ws->sock, ext, 2) < 0) return -1;
        plen = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8];
        if (recv_exact(ws->sock, ext, 8) < 0) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++)
            plen = (plen << 8) | ext[i];
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (recv_exact(ws->sock, mask, 4) < 0) return -1;
    }

    if (plen > buf_size) return -1; /* overflow */

    *out_len = (uint32_t)plen;
    if (plen > 0) {
        if (recv_exact(ws->sock, out_buf, (int)plen) < 0) return -1;
        if (masked) {
            uint32_t mask32 = 0;
            memcpy(&mask32, mask, sizeof(mask32));
#ifdef FUNASR_USE_X64_ASM
            ws_mask_xor_inplace_x64(out_buf, plen, mask32);
#else
            for (uint32_t i = 0; i < (uint32_t)plen; i++)
                out_buf[i] ^= mask[i & 3];
#endif
        }
    }
    return 0;
}

int ws_recv_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                 uint8_t* out_buf, uint32_t buf_size,
                 uint32_t* out_len, uint8_t* out_opcode)
{
    if (!ws->connected || !task) return -1;

    uint8_t h[2];
    if (recv_exact_iocp(ws, task, h, 2) < 0) return -1;

    *out_opcode = h[0] & 0x0F;
    int masked = (h[1] >> 7) & 1;
    uint64_t plen = h[1] & 0x7F;

    if (plen == 126) {
        uint8_t ext[2];
        if (recv_exact_iocp(ws, task, ext, 2) < 0) return -1;
        plen = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8];
        if (recv_exact_iocp(ws, task, ext, 8) < 0) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++)
            plen = (plen << 8) | ext[i];
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (recv_exact_iocp(ws, task, mask, 4) < 0) return -1;
    }

    if (plen > buf_size) return -1;

    *out_len = (uint32_t)plen;
    if (plen > 0) {
        if (recv_exact_iocp(ws, task, out_buf, (int)plen) < 0) return -1;
        if (masked) {
            uint32_t mask32 = 0;
            memcpy(&mask32, mask, sizeof(mask32));
#ifdef FUNASR_USE_X64_ASM
            ws_mask_xor_inplace_x64(out_buf, plen, mask32);
#else
            for (uint32_t i = 0; i < (uint32_t)plen; i++)
                out_buf[i] ^= mask[i & 3];
#endif
        }
    }

    return 0;
}

int ws_bind_iocp(ws_conn_t* ws, funasr_coro_sched_t* sched)
{
    if (!ws || !sched || !ws->connected || ws->sock == INVALID_SOCKET) return -1;
    return funasr_coro_bind_socket(sched, ws->sock);
}

/* ---- Close ---- */
void ws_close(ws_conn_t* ws)
{
    if (ws->connected) {
        /* Send close frame */
        ws_send_frame(ws, 0x08, NULL, 0);
        ws->connected = 0;
    }
    if (ws->sock != INVALID_SOCKET) {
        shutdown(ws->sock, SD_BOTH);
        closesocket(ws->sock);
        ws->sock = INVALID_SOCKET;
    }
}

int ws_is_alive(ws_conn_t* ws)
{
    if (!ws || !ws->connected || ws->sock == INVALID_SOCKET) return 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(ws->sock, &rfds);

    TIMEVAL tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    int sret = select(0, &rfds, NULL, NULL, &tv);
    if (sret == SOCKET_ERROR) return 0;
    if (sret == 0) return 1; /* no event yet, treat as alive */

    if (FD_ISSET(ws->sock, &rfds)) {
        char b;
        int n = recv(ws->sock, &b, 1, MSG_PEEK);
        if (n > 0) return 1;
        if (n == 0) return 0; /* orderly close */
        return WSAGetLastError() == WSAEWOULDBLOCK;
    }

    return 1;
}
