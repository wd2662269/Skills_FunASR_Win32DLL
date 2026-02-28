/*
 * funasr_dll.c - FunASR PCM-to-Text via raw WebSocket
 *
 * Direct port of pcm_transcribe.js to C.
 * Flow: connect -> send config JSON -> send PCM chunks -> recv text -> done
 *
 * TODO(东哥):
 *   - Promote IOCP path from fallback-enabled to only path after soak tests
 *   - Connection pool (reuse WS connections)
 *   - Zero-copy scatter-gather for PCM chunks
 *   - ASM-optimized XOR masking (AVX2/SSE2)
 *   - ntdll direct syscalls for memory alloc
 */

#include "funasr_dll.h"
#include "ws_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define SAMPLE_RATE   16000
#define CHUNK_BYTES   9600   /* 300ms of s16le mono @ 16kHz */
#define RECV_BUF_SIZE (1024 * 1024)  /* 1MB for accumulated text */
#define MAX_TEXT_SIZE (256 * 1024)
#define WS_POOL_SIZE  64
#define WS_URL_MAX    256
#define WS_IDLE_TIMEOUT_MS 60000
#define WS_IO_TIMEOUT_MS 30000

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif

static volatile LONG g_initialized = 0;
static volatile LONG g_active_sessions = 0;
static SRWLOCK g_wsa_lock = SRWLOCK_INIT;
static SRWLOCK g_pool_lock = SRWLOCK_INIT;
static THREAD_LOCAL uint8_t* g_tls_recv_buf = NULL;
static THREAD_LOCAL uint32_t g_tls_recv_cap = 0;

typedef struct {
    ws_conn_t conn;
    char url[WS_URL_MAX];
    HANDLE bound_iocp;
    int mode;
    int occupied;
    int in_use;
    ULONGLONG last_used_ms;
} ws_pool_entry_t;

static ws_pool_entry_t g_ws_pool[WS_POOL_SIZE];
static THREAD_LOCAL funasr_coro_sched_t g_tls_iocp_sched;
static THREAD_LOCAL int g_tls_iocp_sched_ready = 0;

enum {
    WS_MODE_BLOCKING = 0,
    WS_MODE_IOCP = 1
};

static uint8_t* tls_get_recv_buf(uint32_t need)
{
    if (g_tls_recv_cap < need) {
        uint32_t new_cap = g_tls_recv_cap ? g_tls_recv_cap : 4096;
        while (new_cap < need) {
            if (new_cap > 0x7FFFFFFFu / 2u) {
                new_cap = need;
                break;
            }
            new_cap *= 2;
        }
        uint8_t* new_buf = (uint8_t*)realloc(g_tls_recv_buf, new_cap);
        if (!new_buf) return NULL;
        g_tls_recv_buf = new_buf;
        g_tls_recv_cap = new_cap;
    }
    return g_tls_recv_buf;
}

static void ws_pool_reset_entry(ws_pool_entry_t* entry)
{
    if (!entry) return;
    ws_close(&entry->conn);
    entry->occupied = 0;
    entry->in_use = 0;
    entry->url[0] = '\0';
    entry->last_used_ms = 0;
    entry->bound_iocp = NULL;
    entry->mode = WS_MODE_BLOCKING;
    memset(&entry->conn, 0, sizeof(entry->conn));
    entry->conn.sock = INVALID_SOCKET;
}

static void ws_pool_close_all_locked(void)
{
    for (int i = 0; i < WS_POOL_SIZE; i++) {
        ws_pool_reset_entry(&g_ws_pool[i]);
    }
}

static int ws_pool_acquire_blocking(const char* ws_url, ws_pool_entry_t** out_entry)
{
    if (!ws_url || !out_entry) return -1;
    size_t url_len = strlen(ws_url);
    if (url_len == 0 || url_len >= WS_URL_MAX) return -1;

    ws_pool_entry_t* entry = NULL;
    ULONGLONG now_ms = GetTickCount64();

    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < WS_POOL_SIZE; i++) {
        if (!g_ws_pool[i].occupied || g_ws_pool[i].in_use) continue;
        if (g_ws_pool[i].last_used_ms > 0 &&
            now_ms - g_ws_pool[i].last_used_ms > WS_IDLE_TIMEOUT_MS) {
            ws_pool_reset_entry(&g_ws_pool[i]);
        }
    }

    for (int i = 0; i < WS_POOL_SIZE; i++) {
        if (g_ws_pool[i].occupied && g_ws_pool[i].mode == WS_MODE_BLOCKING &&
            !g_ws_pool[i].in_use &&
            strcmp(g_ws_pool[i].url, ws_url) == 0) {
            entry = &g_ws_pool[i];
            entry->in_use = 1;
            break;
        }
    }

    if (!entry) {
        for (int i = 0; i < WS_POOL_SIZE; i++) {
            if (!g_ws_pool[i].occupied) {
                entry = &g_ws_pool[i];
                memset(entry, 0, sizeof(*entry));
                entry->conn.sock = INVALID_SOCKET;
                memcpy(entry->url, ws_url, url_len + 1);
                entry->mode = WS_MODE_BLOCKING;
                entry->occupied = 1;
                entry->in_use = 1;
                entry->last_used_ms = now_ms;
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_pool_lock);

    if (!entry) return -1;

    if (entry->conn.connected && !ws_is_alive(&entry->conn)) {
        ws_pool_reset_entry(entry);
        AcquireSRWLockExclusive(&g_pool_lock);
        entry->conn.sock = INVALID_SOCKET;
        memcpy(entry->url, ws_url, url_len + 1);
        entry->mode = WS_MODE_BLOCKING;
        entry->occupied = 1;
        entry->in_use = 1;
        entry->last_used_ms = now_ms;
        ReleaseSRWLockExclusive(&g_pool_lock);
    }

    if (!entry->conn.connected) {
        if (ws_connect(&entry->conn, ws_url) < 0) {
            AcquireSRWLockExclusive(&g_pool_lock);
            ws_pool_reset_entry(entry);
            ReleaseSRWLockExclusive(&g_pool_lock);
            return -1;
        }
    }

    *out_entry = entry;
    return 0;
}

static int ws_pool_acquire_iocp(const char* ws_url,
                                HANDLE iocp_handle,
                                ws_pool_entry_t** out_entry,
                                int* out_need_connect)
{
    if (!ws_url || !iocp_handle || !out_entry || !out_need_connect) return -1;
    size_t url_len = strlen(ws_url);
    if (url_len == 0 || url_len >= WS_URL_MAX) return -1;

    ws_pool_entry_t* entry = NULL;
    ULONGLONG now_ms = GetTickCount64();

    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < WS_POOL_SIZE; i++) {
        if (!g_ws_pool[i].occupied || g_ws_pool[i].in_use) continue;
        if (g_ws_pool[i].last_used_ms > 0 &&
            now_ms - g_ws_pool[i].last_used_ms > WS_IDLE_TIMEOUT_MS) {
            ws_pool_reset_entry(&g_ws_pool[i]);
        }
    }

    for (int i = 0; i < WS_POOL_SIZE; i++) {
        if (g_ws_pool[i].occupied &&
            g_ws_pool[i].mode == WS_MODE_IOCP &&
            !g_ws_pool[i].in_use &&
            g_ws_pool[i].bound_iocp == iocp_handle &&
            strcmp(g_ws_pool[i].url, ws_url) == 0) {
            entry = &g_ws_pool[i];
            entry->in_use = 1;
            break;
        }
    }

    if (!entry) {
        for (int i = 0; i < WS_POOL_SIZE; i++) {
            if (!g_ws_pool[i].occupied) {
                entry = &g_ws_pool[i];
                memset(entry, 0, sizeof(*entry));
                entry->conn.sock = INVALID_SOCKET;
                memcpy(entry->url, ws_url, url_len + 1);
                entry->bound_iocp = iocp_handle;
                entry->mode = WS_MODE_IOCP;
                entry->occupied = 1;
                entry->in_use = 1;
                entry->last_used_ms = now_ms;
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_pool_lock);

    if (!entry) return -1;

    if (entry->conn.connected && !ws_is_alive(&entry->conn)) {
        AcquireSRWLockExclusive(&g_pool_lock);
        ws_pool_reset_entry(entry);
        entry->conn.sock = INVALID_SOCKET;
        memcpy(entry->url, ws_url, url_len + 1);
        entry->bound_iocp = iocp_handle;
        entry->mode = WS_MODE_IOCP;
        entry->occupied = 1;
        entry->in_use = 1;
        entry->last_used_ms = now_ms;
        ReleaseSRWLockExclusive(&g_pool_lock);
    }

    *out_need_connect = !entry->conn.connected;
    *out_entry = entry;
    return 0;
}

static void ws_pool_release(ws_pool_entry_t* entry, int keep_alive)
{
    if (!entry) return;

    AcquireSRWLockExclusive(&g_pool_lock);
    if (!keep_alive) {
        ws_pool_reset_entry(entry);
    } else {
        entry->last_used_ms = GetTickCount64();
        entry->in_use = 0;
    }
    entry->in_use = 0;
    ReleaseSRWLockExclusive(&g_pool_lock);
}

#ifdef FUNASR_EXPORTS
/* ---- DllMain (DLL build only) ---- */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule; (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        if (g_initialized) {
            AcquireSRWLockExclusive(&g_pool_lock);
            ws_pool_close_all_locked();
            ReleaseSRWLockExclusive(&g_pool_lock);
            WSACleanup();
            g_initialized = 0;
        }
        break;
    }
    return TRUE;
}
#endif

/* ---- Public API ---- */

FUNASR_API int funasr_init(void)
{
    AcquireSRWLockExclusive(&g_wsa_lock);
    if (!g_initialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            ReleaseSRWLockExclusive(&g_wsa_lock);
            return -1;
        }
        g_initialized = 1;
    }
    ReleaseSRWLockExclusive(&g_wsa_lock);
    return 0;
}

static funasr_coro_sched_t* tls_get_iocp_sched(void)
{
    if (!g_tls_iocp_sched_ready) {
        if (funasr_coro_sched_init(&g_tls_iocp_sched) < 0) {
            return NULL;
        }
        funasr_coro_sched_set_default_timeout(&g_tls_iocp_sched, WS_IO_TIMEOUT_MS);
        g_tls_iocp_sched_ready = 1;
    }
    return &g_tls_iocp_sched;
}

FUNASR_API void funasr_cleanup(void)
{
    AcquireSRWLockExclusive(&g_wsa_lock);
    if (g_initialized && g_active_sessions == 0) {
        AcquireSRWLockExclusive(&g_pool_lock);
        ws_pool_close_all_locked();
        ReleaseSRWLockExclusive(&g_pool_lock);
        g_initialized = 0;
        WSACleanup();
        if (g_tls_iocp_sched_ready) {
            funasr_coro_sched_destroy(&g_tls_iocp_sched);
            g_tls_iocp_sched_ready = 0;
        }
    }
    ReleaseSRWLockExclusive(&g_wsa_lock);
}

FUNASR_API void funasr_free(const char* ptr)
{
    if (ptr) free((void*)ptr);
}

/*
 * Build the initial config JSON (matches FunASR protocol):
 * {"mode":"offline","chunk_size":[5,10,5],"wav_name":"pcm",
 *  "is_speaking":true,"wav_format":"pcm","audio_fs":16000}
 */
static int build_config_json(char* buf, int size)
{
    return snprintf(buf, size,
        "{\"mode\":\"offline\",\"chunk_size\":[5,10,5],"
        "\"wav_name\":\"pcm\",\"is_speaking\":true,"
        "\"wav_format\":\"pcm\",\"audio_fs\":%d}", SAMPLE_RATE);
}

/*
 * Parse FunASR response JSON for "text" field.
 * Minimal JSON parser — just find "text":"..." 
 *
 * TODO(东哥): Replace with proper zero-alloc JSON scanner
 */
static int extract_text(const char* json, char* out, int out_size)
{
    const char* key = "\"text\":\"";
    const char* p = strstr(json, key);
    if (!p) return 0;
    p += strlen(key);

    int i = 0;
    while (*p && *p != '"' && i < out_size - 1) {
        if (*p == '\\' && *(p+1)) {
            p++; /* skip escape */
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i;
}

/*
 * Check if response explicitly contains "is_final": true.
 */
static int is_final_true(const char* json)
{
    const char* p = strstr(json, "\"is_final\"");
    if (!p) return 0;

    p = strchr(p, ':');
    if (!p) return 0;
    p++;

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;

    return strncmp(p, "true", 4) == 0;
}

typedef struct {
    const uint8_t* pcm_data;
    uint32_t pcm_len;
    const char* ws_url;
    ws_pool_entry_t* pool_entry;
    char* result;
    int result_len;
    int got_final;
    int keep_alive;
    int used_pool;
    int status;
} funasr_pcm_iocp_job_t;

static void funasr_pcm_iocp_entry(funasr_coro_task_t* task, void* arg)
{
    funasr_pcm_iocp_job_t* job = (funasr_pcm_iocp_job_t*)arg;
    funasr_coro_sched_t* sched = NULL;
    ws_conn_t* ws = NULL;
    uint8_t* recv_buf = NULL;
    char config[512];
    const char* eos = "{\"is_speaking\":false}";
    int need_connect = 0;

    if (!task || !job) {
        if (task) funasr_coro_task_finish(task, -1);
        return;
    }

    sched = funasr_coro_task_sched(task);
    if (!sched) {
        funasr_coro_task_finish(task, -1);
        return;
    }

    job->status = -1;
    job->used_pool = 0;
    job->keep_alive = 0;

    if (ws_pool_acquire_iocp(job->ws_url, sched->iocp, &job->pool_entry, &need_connect) < 0)
        goto done;
    job->used_pool = 1;
    ws = &job->pool_entry->conn;

    if (need_connect) {
        if (ws_connect_iocp(ws, task, job->ws_url) < 0) goto done;
    }

    int clen = build_config_json(config, sizeof(config));
    if (clen <= 0) goto done;
    if (ws_send_text_iocp(ws, task, config, (uint32_t)clen) < 0) goto done;

    uint32_t offset = 0;
    while (offset < job->pcm_len) {
        uint32_t chunk = job->pcm_len - offset;
        if (chunk > CHUNK_BYTES) chunk = CHUNK_BYTES;
        if (ws_send_binary_iocp(ws, task, job->pcm_data + offset, chunk) < 0)
            goto done;
        offset += chunk;
    }

    if (ws_send_text_iocp(ws, task, eos, (uint32_t)strlen(eos)) < 0) goto done;

    job->result = (char*)calloc(MAX_TEXT_SIZE, 1);
    if (!job->result) goto done;

    recv_buf = tls_get_recv_buf(RECV_BUF_SIZE);
    if (!recv_buf) goto done;

    for (;;) {
        uint32_t msg_len = 0;
        uint8_t opcode = 0;
        if (ws_recv_iocp(ws, task, recv_buf, RECV_BUF_SIZE - 1, &msg_len, &opcode) < 0)
            goto done;

        if (opcode == 0x08) goto done;
        if (opcode != 0x01 || msg_len == 0) continue;

        recv_buf[msg_len] = '\0';
        int remaining = MAX_TEXT_SIZE - job->result_len;
        int tlen = extract_text((char*)recv_buf, job->result + job->result_len, remaining);
        if (tlen > 0) job->result_len += tlen;
        if (is_final_true((char*)recv_buf)) {
            job->got_final = 1;
            break;
        }
    }

    if (job->result_len > 0 && job->got_final) {
        job->result[job->result_len] = '\0';
        job->keep_alive = 1;
        job->status = 0;
    }

done:
    if (job->status != 0) {
        free(job->result);
        job->result = NULL;
    }
    if (job->used_pool) {
        ws_pool_release(job->pool_entry, job->keep_alive);
    }
    funasr_coro_task_finish(task, job->status);
}

static const char* funasr_pcm_try_iocp_coro(const uint8_t* pcm_data, uint32_t pcm_len,
                                             const char* ws_url)
{
    funasr_coro_sched_t* sched = NULL;
    funasr_coro_task_t task;
    funasr_pcm_iocp_job_t job;

    memset(&job, 0, sizeof(job));
    job.pcm_data = pcm_data;
    job.pcm_len = pcm_len;
    job.ws_url = ws_url;

    sched = tls_get_iocp_sched();
    if (!sched) return NULL;

    if (funasr_coro_sched_spawn(sched, &task, funasr_pcm_iocp_entry, &job, 1u << 20) < 0) {
        return NULL;
    }

    if (funasr_coro_sched_run(sched) < 0) {
        free(job.result);
        return NULL;
    }

    if (task.result_code < 0 || !job.result) {
        free(job.result);
        return NULL;
    }

    return job.result;
}

FUNASR_API const char* funasr_pcm(const uint8_t* pcm_data, uint32_t pcm_len,
                                   const char* ws_url)
{
    const char* final_result = NULL;
    ws_pool_entry_t* pool_entry = NULL;
    ws_conn_t direct_ws;
    ws_conn_t* ws = NULL;
    int keep_alive = 0;
    int got_final = 0;
    int use_direct = 0;
    char* result = NULL;
    uint8_t* recv_buf = NULL;
    int result_len = 0;

    if (!pcm_data || pcm_len == 0 || !ws_url) return NULL;

    AcquireSRWLockShared(&g_wsa_lock);
    if (!g_initialized) {
        ReleaseSRWLockShared(&g_wsa_lock);
        if (funasr_init() < 0) return NULL;
        AcquireSRWLockShared(&g_wsa_lock);
    }
    InterlockedIncrement(&g_active_sessions);
    ReleaseSRWLockShared(&g_wsa_lock);

    final_result = funasr_pcm_try_iocp_coro(pcm_data, pcm_len, ws_url);
    if (final_result) {
        InterlockedDecrement(&g_active_sessions);
        return final_result;
    }

    if (ws_pool_acquire_blocking(ws_url, &pool_entry) == 0) {
        ws = &pool_entry->conn;
    } else {
        memset(&direct_ws, 0, sizeof(direct_ws));
        direct_ws.sock = INVALID_SOCKET;
        if (ws_connect(&direct_ws, ws_url) < 0) {
            InterlockedDecrement(&g_active_sessions);
            return NULL;
        }
        ws = &direct_ws;
        use_direct = 1;
    }

    /* 1. Send config JSON */
    char config[512];
    int clen = build_config_json(config, sizeof(config));
    if (ws_send_text(ws, config, (uint32_t)clen) < 0) goto done;

    /* 2. Send PCM data in chunks */
    uint32_t offset = 0;
    while (offset < pcm_len) {
        uint32_t chunk = pcm_len - offset;
        if (chunk > CHUNK_BYTES) chunk = CHUNK_BYTES;
        if (ws_send_binary(ws, pcm_data + offset, chunk) < 0) goto done;
        offset += chunk;
        /* No Sleep — blast it out.
         * TODO(东哥): If server can't keep up, add pacing via IOCP */
    }

    /* 3. Send end-of-speech marker */
    const char* eos = "{\"is_speaking\":false}";
    if (ws_send_text(ws, eos, (uint32_t)strlen(eos)) < 0) goto done;

    /* 4. Receive transcription results */
    result = (char*)calloc(MAX_TEXT_SIZE, 1);
    if (!result) goto done;

    recv_buf = tls_get_recv_buf(RECV_BUF_SIZE);
    if (!recv_buf) goto done;

    /* Set receive timeout (30 seconds) */
    DWORD timeout = 30000;
    setsockopt(ws->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    for (;;) {
        uint32_t msg_len = 0;
        uint8_t opcode = 0;
        if (ws_recv(ws, recv_buf, RECV_BUF_SIZE - 1, &msg_len, &opcode) < 0)
            goto done;

        if (opcode == 0x08) goto done; /* close frame */

        if (opcode == 0x01 && msg_len > 0) { /* text frame */
            recv_buf[msg_len] = '\0';
            int remaining = MAX_TEXT_SIZE - result_len;
            int tlen = extract_text((char*)recv_buf, result + result_len, remaining);
            if (tlen > 0) result_len += tlen;
            if (is_final_true((char*)recv_buf)) {
                got_final = 1;
                break;
            }
        }
    }
    result[result_len] = '\0';    
    if (result_len > 0 && got_final) {
        keep_alive = 1;
        final_result = result;
        result = NULL;
    }

done:
    free(result);
    if (use_direct) {
        ws_close(&direct_ws);
    } else {
        ws_pool_release(pool_entry, keep_alive);
    }
    InterlockedDecrement(&g_active_sessions);
    return final_result;
}

FUNASR_API const char* funasr_pcm_file(const char* pcm_path, const char* ws_url)
{
    if (!pcm_path || !ws_url) return NULL;

    /* Read entire PCM file
     * TODO(东哥): NtCreateFile + NtReadFile + memory-mapped I/O
     */
    HANDLE hFile = CreateFileA(pcm_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        CloseHandle(hFile);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(file_size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read_bytes;
    if (!ReadFile(hFile, buf, file_size, &read_bytes, NULL) || read_bytes != file_size) {
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);

    const char* result = funasr_pcm(buf, file_size, ws_url);
    free(buf);
    return result;
}
