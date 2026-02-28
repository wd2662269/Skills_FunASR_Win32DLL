/*
 * ws_client.h - Minimal WebSocket client (raw Winsock2)
 *
 * No high-level libs. Raw TCP + HTTP upgrade + RFC 6455 framing.
 * 东哥后续可替换为 IOCP / scatter-gather / zero-copy 版本。
 */

#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "iocp_coro.h"

typedef struct {
    SOCKET      sock;
    char        host[256];
    char        path[256];
    uint16_t    port;
    int         connected;
} ws_conn_t;

/*
 * Parse "ws://host:port/path" and connect + HTTP upgrade.
 * Returns 0 on success (ws->connected = 1), -1 on failure.
 */
int ws_connect(ws_conn_t* ws, const char* url);

/*
 * Async connect + HTTP upgrade through IOCP coroutine.
 * Socket will be associated with task scheduler's IOCP.
 */
int ws_connect_iocp(ws_conn_t* ws, funasr_coro_task_t* task, const char* url);

/*
 * Send a text frame (opcode 0x1).
 */
int ws_send_text(ws_conn_t* ws, const char* text, uint32_t len);

/*
 * Send a binary frame (opcode 0x2).
 */
int ws_send_binary(ws_conn_t* ws, const uint8_t* data, uint32_t len);

/*
 * Receive one complete message.
 *   out_buf   : caller-allocated buffer
 *   buf_size  : buffer capacity
 *   out_len   : actual bytes received
 *   out_opcode: 0x1=text, 0x2=binary, 0x8=close
 * Returns 0 on success, -1 on error/close.
 */
int ws_recv(ws_conn_t* ws, uint8_t* out_buf, uint32_t buf_size,
            uint32_t* out_len, uint8_t* out_opcode);

/*
 * Bind connected socket to coroutine scheduler's IOCP.
 * Must be called once before ws_send_*_iocp / ws_recv_iocp.
 */
int ws_bind_iocp(ws_conn_t* ws, funasr_coro_sched_t* sched);

/*
 * IOCP + coroutine versions of send/recv.
 */
int ws_send_text_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                      const char* text, uint32_t len);
int ws_send_binary_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                        const uint8_t* data, uint32_t len);
int ws_recv_iocp(ws_conn_t* ws, funasr_coro_task_t* task,
                 uint8_t* out_buf, uint32_t buf_size,
                 uint32_t* out_len, uint8_t* out_opcode);

/*
 * Close WebSocket gracefully + close socket.
 */
void ws_close(ws_conn_t* ws);

/*
 * Lightweight liveness check for pooled socket.
 * Returns 1 if usable, 0 if dead/broken.
 */
int ws_is_alive(ws_conn_t* ws);

#endif /* WS_CLIENT_H */
