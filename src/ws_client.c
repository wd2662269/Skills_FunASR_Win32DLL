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
#include <mswsock.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "Bcrypt.lib")

#ifdef FUNASR_USE_X64_ASM
void ws_mask_xor_copy_x64(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32);
void ws_mask_xor_inplace_x64(uint8_t* buf, uint64_t len, uint32_t mask32);
void ws_mask_xor_copy_avx2_x64(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32);
void ws_mask_xor_inplace_avx2_x64(uint8_t* buf, uint64_t len, uint32_t mask32);
#endif

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif

static THREAD_LOCAL uint8_t* g_tls_masked_buf = NULL;
static THREAD_LOCAL uint32_t g_tls_masked_cap = 0;
static THREAD_LOCAL uint8_t g_tls_rng_cache[256];
static THREAD_LOCAL uint32_t g_tls_rng_cache_pos = 256;

#define WS_IOCP_RX_INIT_CAP (64u * 1024u)
#define WS_IOCP_RX_PREFETCH (16u * 1024u)
#define WS_DNS_CACHE_SIZE 32
#define WS_DNS_CACHE_TTL_MS 60000
#define WS_DNS_RESOLVE_TIMEOUT_MS 3000

typedef struct {
    int valid;
    ULONGLONG expire_ms;
    char host[256];
    char port[8];
    struct sockaddr_in addr;
} ws_dns_cache_entry_t;

static ws_dns_cache_entry_t g_dns_cache[WS_DNS_CACHE_SIZE];
static SRWLOCK g_dns_cache_lock = SRWLOCK_INIT;
static volatile LONG g_dns_cache_rr = 0;

typedef void (*ws_mask_copy_fn_t)(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32);
typedef void (*ws_mask_inplace_fn_t)(uint8_t* buf, uint64_t len, uint32_t mask32);

static void ws_mask_xor_copy_c(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32)
{
    uint64_t i = 0;
    uint64_t mask64 = ((uint64_t)mask32 << 32) | (uint64_t)mask32;
    uint8_t mask[4];
    memcpy(mask, &mask32, sizeof(mask));

    for (; i + sizeof(uint64_t) <= len; i += sizeof(uint64_t)) {
        uint64_t v;
        memcpy(&v, src + i, sizeof(v));
        v ^= mask64;
        memcpy(dst + i, &v, sizeof(v));
    }

    if (i + sizeof(uint32_t) <= len) {
        uint32_t v32;
        memcpy(&v32, src + i, sizeof(v32));
        v32 ^= mask32;
        memcpy(dst + i, &v32, sizeof(v32));
        i += sizeof(uint32_t);
    }

    for (; i < len; i++) {
        dst[i] = src[i] ^ mask[i & 3];
    }
}

static void ws_mask_xor_inplace_c(uint8_t* buf, uint64_t len, uint32_t mask32)
{
    uint64_t i = 0;
    uint64_t mask64 = ((uint64_t)mask32 << 32) | (uint64_t)mask32;
    uint8_t mask[4];
    memcpy(mask, &mask32, sizeof(mask));

    for (; i + sizeof(uint64_t) <= len; i += sizeof(uint64_t)) {
        uint64_t v;
        memcpy(&v, buf + i, sizeof(v));
        v ^= mask64;
        memcpy(buf + i, &v, sizeof(v));
    }

    if (i + sizeof(uint32_t) <= len) {
        uint32_t v32;
        memcpy(&v32, buf + i, sizeof(v32));
        v32 ^= mask32;
        memcpy(buf + i, &v32, sizeof(v32));
        i += sizeof(uint32_t);
    }

    for (; i < len; i++) {
        buf[i] ^= mask[i & 3];
    }
}

static ws_mask_copy_fn_t g_ws_mask_copy_fn = ws_mask_xor_copy_c;
static ws_mask_inplace_fn_t g_ws_mask_inplace_fn = ws_mask_xor_inplace_c;
static volatile LONG g_ws_mask_dispatch_ready = 0;

static int ws_secure_random_fill(uint8_t* out, size_t len)
{
    NTSTATUS status;
    if (!out || len == 0 || len > 0xFFFFFFFFu) return -1;

    /* RFC 6455 masking/nonces must be unpredictable: CSPRNG only. */
    status = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status >= 0) return 0;
    return -1;
}

static int ws_random_bytes(uint8_t* out, size_t len)
{
    if (!out || len == 0) return -1;

    while (len > 0) {
        size_t avail;
        size_t take;
        if (g_tls_rng_cache_pos >= sizeof(g_tls_rng_cache)) {
            if (ws_secure_random_fill(g_tls_rng_cache, sizeof(g_tls_rng_cache)) < 0) {
                return -1;
            }
            g_tls_rng_cache_pos = 0;
        }

        avail = sizeof(g_tls_rng_cache) - g_tls_rng_cache_pos;
        take = (len < avail) ? len : avail;
        memcpy(out, g_tls_rng_cache + g_tls_rng_cache_pos, take);
        out += take;
        len -= take;
        g_tls_rng_cache_pos += (uint32_t)take;
    }
    return 0;
}

#ifdef FUNASR_USE_X64_ASM
static int ws_cpu_has_avx2(void)
{
#if defined(_MSC_VER)
    int info[4] = {0};
    __cpuid(info, 1);
    if ((info[2] & (1 << 27)) == 0) return 0; /* OSXSAVE */
    if ((info[2] & (1 << 28)) == 0) return 0; /* AVX */

    {
        unsigned __int64 xcr0 = _xgetbv(0);
        if ((xcr0 & 0x6) != 0x6) return 0; /* XMM + YMM state */
    }

    __cpuidex(info, 7, 0);
    return (info[1] & (1 << 5)) != 0; /* AVX2 */
#else
    return 0;
#endif
}
#endif

static void ws_mask_dispatch_init_once(void)
{
    if (InterlockedCompareExchange(&g_ws_mask_dispatch_ready, 1, 0) != 0) return;

#ifdef FUNASR_USE_X64_ASM
    if (ws_cpu_has_avx2()) {
        g_ws_mask_copy_fn = ws_mask_xor_copy_avx2_x64;
        g_ws_mask_inplace_fn = ws_mask_xor_inplace_avx2_x64;
    } else {
        g_ws_mask_copy_fn = ws_mask_xor_copy_x64;
        g_ws_mask_inplace_fn = ws_mask_xor_inplace_x64;
    }
#else
    g_ws_mask_copy_fn = ws_mask_xor_copy_c;
    g_ws_mask_inplace_fn = ws_mask_xor_inplace_c;
#endif
}

static int ws_rx_ensure_space(ws_conn_t* ws, uint32_t need_free)
{
    if (!ws) return -1;

    if (ws->rx_cap >= ws->rx_end + need_free) return 0;

    if (ws->rx_start > 0 && ws->rx_end > ws->rx_start) {
        uint32_t live = ws->rx_end - ws->rx_start;
        memmove(ws->rx_buf, ws->rx_buf + ws->rx_start, live);
        ws->rx_start = 0;
        ws->rx_end = live;
        if (ws->rx_cap >= ws->rx_end + need_free) return 0;
    } else if (ws->rx_start == ws->rx_end) {
        ws->rx_start = 0;
        ws->rx_end = 0;
    }

    uint32_t new_cap = ws->rx_cap ? ws->rx_cap : WS_IOCP_RX_INIT_CAP;
    while (new_cap < ws->rx_end + need_free) {
        if (new_cap > 0x7FFFFFFFu / 2u) {
            new_cap = ws->rx_end + need_free;
            break;
        }
        new_cap *= 2u;
    }

    uint8_t* new_buf = (uint8_t*)realloc(ws->rx_buf, new_cap);
    if (!new_buf) return -1;
    ws->rx_buf = new_buf;
    ws->rx_cap = new_cap;
    return 0;
}

static void ws_rx_reset(ws_conn_t* ws)
{
    if (!ws) return;
    ws->rx_start = 0;
    ws->rx_end = 0;
}

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
static int gen_mask_key(uint8_t key[4])
{
    return ws_random_bytes(key, 4);
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

    if (ws_random_bytes(nonce, sizeof(nonce)) < 0) return -1;
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

    if (ws_random_bytes(nonce, sizeof(nonce)) < 0) return -1;
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

static int ws_dns_cache_lookup(const char* host, const char* port, struct sockaddr_in* out_addr)
{
    if (!host || !port || !out_addr) return 0;
    ULONGLONG now = GetTickCount64();
    int found = 0;

    AcquireSRWLockShared(&g_dns_cache_lock);
    for (int i = 0; i < WS_DNS_CACHE_SIZE; i++) {
        if (!g_dns_cache[i].valid) continue;
        if (g_dns_cache[i].expire_ms < now) continue;
        if (strcmp(g_dns_cache[i].host, host) == 0 &&
            strcmp(g_dns_cache[i].port, port) == 0) {
            *out_addr = g_dns_cache[i].addr;
            found = 1;
            break;
        }
    }
    ReleaseSRWLockShared(&g_dns_cache_lock);
    return found;
}

static void ws_dns_cache_store(const char* host, const char* port, const struct sockaddr_in* addr)
{
    if (!host || !port || !addr) return;
    int slot = -1;
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    for (int i = 0; i < WS_DNS_CACHE_SIZE; i++) {
        if (g_dns_cache[i].valid &&
            strcmp(g_dns_cache[i].host, host) == 0 &&
            strcmp(g_dns_cache[i].port, port) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < WS_DNS_CACHE_SIZE; i++) {
            if (!g_dns_cache[i].valid || g_dns_cache[i].expire_ms < now) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        slot = (int)(InterlockedIncrement(&g_dns_cache_rr) % WS_DNS_CACHE_SIZE);
    }

    g_dns_cache[slot].valid = 1;
    g_dns_cache[slot].expire_ms = now + WS_DNS_CACHE_TTL_MS;
    strncpy_s(g_dns_cache[slot].host, sizeof(g_dns_cache[slot].host), host, _TRUNCATE);
    strncpy_s(g_dns_cache[slot].port, sizeof(g_dns_cache[slot].port), port, _TRUNCATE);
    g_dns_cache[slot].addr = *addr;
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

typedef struct {
    funasr_coro_io_op_t op;
    HANDLE iocp;
    struct addrinfo hints;
    int gai_err;
    DWORD timeout_ms;
    int has_addr;
    struct sockaddr_in addr4;
    char host[256];
    char port[8];
} ws_dns_job_t;

static int ws_dns_pick_ipv4_from_addrinfo(const struct addrinfo* res, struct sockaddr_in* out_addr)
{
    const struct addrinfo* it = res;
    if (!out_addr) return -1;

    while (it) {
        if (it->ai_family == AF_INET &&
            it->ai_addr &&
            it->ai_addrlen >= sizeof(struct sockaddr_in)) {
            memcpy(out_addr, it->ai_addr, sizeof(struct sockaddr_in));
            return 0;
        }
        it = it->ai_next;
    }
    return -1;
}

#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
static int ws_dns_pick_ipv4_from_addrinfoex(const ADDRINFOEXW* res, struct sockaddr_in* out_addr)
{
    const ADDRINFOEXW* it = res;
    if (!out_addr) return -1;

    while (it) {
        if (it->ai_family == AF_INET &&
            it->ai_addr &&
            it->ai_addrlen >= sizeof(struct sockaddr_in)) {
            memcpy(out_addr, it->ai_addr, sizeof(struct sockaddr_in));
            return 0;
        }
        it = it->ai_next;
    }
    return -1;
}
#endif

static DWORD WINAPI ws_dns_worker(LPVOID param)
{
    ws_dns_job_t* job = (ws_dns_job_t*)param;
    if (!job) return 0;
    job->gai_err = WSANO_RECOVERY;
    job->has_addr = 0;
    memset(&job->addr4, 0, sizeof(job->addr4));

#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
    {
        ADDRINFOEXW hints_ex;
        PADDRINFOEXW res_ex = NULL;
        OVERLAPPED ov;
        HANDLE query_handle = NULL;
        int rc = 0;
        DWORD wait_ms = job->timeout_ms ? job->timeout_ms : WS_DNS_RESOLVE_TIMEOUT_MS;
        wchar_t host_w[256];
        wchar_t port_w[8];

        memset(&hints_ex, 0, sizeof(hints_ex));
        hints_ex.ai_flags = job->hints.ai_flags;
        hints_ex.ai_family = job->hints.ai_family;
        hints_ex.ai_socktype = job->hints.ai_socktype;
        hints_ex.ai_protocol = job->hints.ai_protocol;

        memset(&ov, 0, sizeof(ov));
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) {
            rc = WSA_NOT_ENOUGH_MEMORY;
        } else if (MultiByteToWideChar(CP_UTF8, 0, job->host, -1, host_w, (int)(sizeof(host_w) / sizeof(host_w[0]))) <= 0 ||
                   MultiByteToWideChar(CP_UTF8, 0, job->port, -1, port_w, (int)(sizeof(port_w) / sizeof(port_w[0]))) <= 0) {
            rc = WSAEINVAL;
        } else {
            rc = GetAddrInfoExW(host_w, port_w, NS_DNS, NULL, &hints_ex, &res_ex,
                                NULL, &ov, NULL, &query_handle);
            if (rc == WSA_IO_PENDING) {
                DWORD wait_rc = WaitForSingleObject(ov.hEvent, wait_ms);
                if (wait_rc == WAIT_OBJECT_0) {
                    rc = GetAddrInfoExOverlappedResult(&ov);
                } else if (wait_rc == WAIT_TIMEOUT) {
                    if (query_handle) {
                        GetAddrInfoExCancel(&query_handle);
                    }
                    WaitForSingleObject(ov.hEvent, INFINITE);
                    rc = WSAETIMEDOUT;
                } else {
                    rc = WSAEFAULT;
                }
            }
        }

        if (rc == 0 && res_ex) {
            if (ws_dns_pick_ipv4_from_addrinfoex(res_ex, &job->addr4) == 0) {
                job->has_addr = 1;
            } else {
                rc = WSAHOST_NOT_FOUND;
            }
        }
        if (res_ex) {
            FreeAddrInfoExW(res_ex);
        }
        if (ov.hEvent) {
            CloseHandle(ov.hEvent);
        }
        job->gai_err = rc;
    }
#else
    {
        struct addrinfo* res = NULL;
        int rc = getaddrinfo(job->host, job->port, &job->hints, &res);
        if (rc == 0 && res) {
            if (ws_dns_pick_ipv4_from_addrinfo(res, &job->addr4) == 0) {
                job->has_addr = 1;
            } else {
                rc = WSAHOST_NOT_FOUND;
            }
        }
        if (res) freeaddrinfo(res);
        job->gai_err = rc;
    }
#endif

    PostQueuedCompletionStatus(job->iocp, 0, 0, &job->op.overlapped);
    return 0;
}

static int ws_resolve_iocp(funasr_coro_task_t* task,
                           const char* host,
                           const char* port,
                           const struct addrinfo* hints,
                           struct sockaddr_storage* out_addr,
                           int* out_addr_len)
{
    ws_dns_job_t* job = NULL;
    funasr_coro_sched_t* sched = NULL;
    struct sockaddr_in addr4;
    int port_num = 0;

    if (!task || !host || !port || !hints || !out_addr || !out_addr_len) return -1;
    memset(out_addr, 0, sizeof(*out_addr));
    *out_addr_len = 0;

    port_num = atoi(port);
    if (port_num <= 0 || port_num > 65535) return -1;

    /* Fast path for literal IPv4 without any DNS call. */
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons((uint16_t)port_num);
    if (InetPtonA(AF_INET, host, &addr4.sin_addr) == 1) {
        memcpy(out_addr, &addr4, sizeof(addr4));
        *out_addr_len = (int)sizeof(addr4);
        return 0;
    }

    if (ws_dns_cache_lookup(host, port, &addr4)) {
        memcpy(out_addr, &addr4, sizeof(addr4));
        *out_addr_len = (int)sizeof(addr4);
        return 0;
    }

    sched = funasr_coro_task_sched(task);
    if (!sched || !sched->iocp) return -1;

    job = (ws_dns_job_t*)calloc(1, sizeof(*job));
    if (!job) return -1;

    if (strncpy_s(job->host, sizeof(job->host), host, _TRUNCATE) != 0 ||
        strncpy_s(job->port, sizeof(job->port), port, _TRUNCATE) != 0) {
        free(job);
        return -1;
    }
    memcpy(&job->hints, hints, sizeof(*hints));
    job->iocp = sched->iocp;
    job->timeout_ms = sched->default_io_timeout_ms;

    if (!QueueUserWorkItem(ws_dns_worker, job, WT_EXECUTEDEFAULT)) {
        task->last_error = ERROR_NOT_ENOUGH_MEMORY;
        free(job);
        return -1;
    }

    if (funasr_coro_await_handle_op(task, NULL, &job->op, INFINITE) < 0) {
        task->last_error = ERROR_GEN_FAILURE;
        free(job);
        return -1;
    }

    if (job->gai_err != 0 || !job->has_addr) {
        task->last_error = (job->gai_err == WSAETIMEDOUT) ? WAIT_TIMEOUT : ERROR_HOST_UNREACHABLE;
        free(job);
        return -1;
    }

    addr4 = job->addr4;
    memcpy(out_addr, &addr4, sizeof(addr4));
    *out_addr_len = (int)sizeof(addr4);
    ws_dns_cache_store(host, port, &addr4);

    free(job);
    return 0;
}

/* ---- Connect + Upgrade ---- */
int ws_connect(ws_conn_t* ws, const char* url)
{
    memset(ws, 0, sizeof(*ws));
    ws->sock = INVALID_SOCKET;
    ws_mask_dispatch_init_once();

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
        int sndbuf = 1 << 20;
        int rcvbuf = 1 << 20;
        setsockopt(ws->sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
        setsockopt(ws->sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
        setsockopt(ws->sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
        setsockopt(ws->sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    }

    if (ws_send_upgrade_request_blocking(ws) < 0) {
        closesocket(ws->sock);
        return -1;
    }

    ws->connected = 1;
    ws_rx_reset(ws);
    return 0;
}

int ws_connect_iocp(ws_conn_t* ws, funasr_coro_task_t* task, const char* url)
{
    funasr_coro_sched_t* sched = NULL;
    struct addrinfo hints;
    struct sockaddr_in local_addr;
    struct sockaddr_storage remote_addr;
    int remote_addr_len = 0;
    LPFN_CONNECTEX connect_ex = NULL;
    funasr_coro_io_op_t op;
    char port_str[8];
    int rc = -1;
    DWORD timeout_ms = 0;

    if (!ws || !task || !url) return -1;

    memset(ws, 0, sizeof(*ws));
    ws->sock = INVALID_SOCKET;
    ws_mask_dispatch_init_once();
    sched = funasr_coro_task_sched(task);
    if (!sched) return -1;
    timeout_ms = sched->default_io_timeout_ms;

    if (parse_ws_url(url, ws->host, &ws->port, ws->path) < 0) return -1;
    if (_snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", ws->port) < 0) return -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (ws_resolve_iocp(task, ws->host, port_str, &hints, &remote_addr, &remote_addr_len) < 0)
        return -1;

    ws->sock = WSASocketW(((struct sockaddr*)&remote_addr)->sa_family, SOCK_STREAM, IPPROTO_TCP,
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
    if (!connect_ex(ws->sock, (const struct sockaddr*)&remote_addr, remote_addr_len,
                    NULL, 0, NULL, &op.overlapped)) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) goto done;
        if (funasr_coro_await_handle_op(task, (HANDLE)ws->sock, &op, timeout_ms) < 0) goto done;
    }

    {
        BOOL keepalive = TRUE;
        int nodelay = 1;
        int sndbuf = 1 << 20;
        int rcvbuf = 1 << 20;
        setsockopt(ws->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        setsockopt(ws->sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
        setsockopt(ws->sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
        setsockopt(ws->sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
        setsockopt(ws->sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    }

    if (ws_send_upgrade_request_iocp(ws, task, timeout_ms) < 0) goto done;

    ws->connected = 1;
    ws_rx_reset(ws);
    rc = 0;

done:
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
    ws_mask_dispatch_init_once();

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
    if (gen_mask_key(mask) < 0) return -1;
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
        g_ws_mask_copy_fn(g_tls_masked_buf, payload, len, mask32);
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
    ws_mask_dispatch_init_once();

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
    if (gen_mask_key(mask) < 0) return -1;
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
        g_ws_mask_copy_fn(g_tls_masked_buf, payload, len, mask32);

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
        uint32_t avail = ws->rx_end - ws->rx_start;
        if (avail == 0) {
            WSABUF wbuf;
            DWORD flags = 0;
            DWORD recvd = 0;
            uint32_t want = WS_IOCP_RX_PREFETCH;

            if ((uint32_t)(need - got) > want) want = (uint32_t)(need - got);
            if (ws_rx_ensure_space(ws, want) < 0) return -1;

            wbuf.buf = (CHAR*)(ws->rx_buf + ws->rx_end);
            wbuf.len = (ULONG)(ws->rx_cap - ws->rx_end);
            if (funasr_coro_await_wsarecv(task, ws->sock, &wbuf, 1, &flags, &recvd) < 0)
                return -1;
            if (recvd == 0) return -1;

            ws->rx_end += recvd;
            avail = ws->rx_end - ws->rx_start;
        }

        uint32_t take = (uint32_t)(need - got);
        if (take > avail) take = avail;
        memcpy(buf + got, ws->rx_buf + ws->rx_start, take);
        ws->rx_start += take;
        got += (int)take;
        if (ws->rx_start == ws->rx_end) ws_rx_reset(ws);
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
            ws_mask_dispatch_init_once();
            g_ws_mask_inplace_fn(out_buf, plen, mask32);
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
            ws_mask_dispatch_init_once();
            g_ws_mask_inplace_fn(out_buf, plen, mask32);
        }
    }

    return 0;
}

int ws_bind_iocp(ws_conn_t* ws, funasr_coro_sched_t* sched)
{
    if (!ws || !sched || !ws->connected || ws->sock == INVALID_SOCKET) return -1;
    if (ws_rx_ensure_space(ws, WS_IOCP_RX_PREFETCH) < 0) return -1;
    ws_rx_reset(ws);
    return funasr_coro_bind_socket(sched, ws->sock);
}

void ws_abort(ws_conn_t* ws)
{
    if (!ws) return;
    ws->connected = 0;
    if (ws->sock != INVALID_SOCKET) {
        shutdown(ws->sock, SD_BOTH);
        closesocket(ws->sock);
        ws->sock = INVALID_SOCKET;
    }
    free(ws->rx_buf);
    ws->rx_buf = NULL;
    ws->rx_cap = 0;
    ws->rx_start = 0;
    ws->rx_end = 0;
}

/* ---- Close ---- */
void ws_close(ws_conn_t* ws)
{
    if (!ws) return;
    if (ws->connected) {
        /* Best-effort close handshake. */
        ws_send_frame(ws, 0x08, NULL, 0);
    }
    ws_abort(ws);
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

void ws_tls_cleanup(void)
{
    if (g_tls_masked_buf) {
        free(g_tls_masked_buf);
        g_tls_masked_buf = NULL;
    }
    g_tls_masked_cap = 0;
    SecureZeroMemory(g_tls_rng_cache, sizeof(g_tls_rng_cache));
    g_tls_rng_cache_pos = (uint32_t)sizeof(g_tls_rng_cache);
}
