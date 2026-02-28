/*
 * funasr_dll.c - FunASR PCM-to-Text via raw WebSocket
 *
 * Direct port of pcm_transcribe.js to C.
 * Flow: connect -> send config JSON -> send PCM chunks -> recv text -> done
 *
 * TODO(东哥):
 *   - IOCP-only main path + sharded connection pool are enabled
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
#define WS_POOL_SHARDS 8
#define WS_POOL_SHARD_SIZE (WS_POOL_SIZE / WS_POOL_SHARDS)
#define WS_URL_MAX    256
#define WS_IDLE_TIMEOUT_MS 60000
#define WS_IO_TIMEOUT_MS 30000
#define WS_POOL_ACQUIRE_BACKPRESSURE_MS 1000
#define WS_POOL_ACQUIRE_WAIT_SLICE_MS 50
#define WS_CONN_MAX_INFLIGHT 1
#define WS_AUTO_WARM_IDLE_MIN 2
#define WS_AUTO_WARM_COOLDOWN_MS 3000
#define WS_AUTO_WARM_SLOTS 64
#define WS_AUTO_WARM_MAX_INFLIGHT 2
#define FUNASR_MAX_CONCURRENT_SESSIONS 256
#define FUNASR_SHARED_IOCP_WORKERS_MIN 4
#define FUNASR_SHARED_IOCP_WORKERS_DEFAULT 4
#define FUNASR_SHARED_IOCP_WORKERS_MAX 8
#define FUNASR_SHARED_PUMP_WAIT_MS 10
#define WS_WORKER_REBALANCE_DELTA 1
#define WS_AUTO_WARM_IDLE_SPARE 1

_Static_assert((WS_POOL_SIZE % WS_POOL_SHARDS) == 0, "WS_POOL_SIZE must be divisible by WS_POOL_SHARDS");

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL _Thread_local
#endif

static volatile LONG g_initialized = 0;
static volatile LONG g_active_sessions = 0;
static volatile LONG g_auto_warm_inflight = 0;
static SRWLOCK g_wsa_lock = SRWLOCK_INIT;
static SRWLOCK g_pool_shard_locks[WS_POOL_SHARDS];
static INIT_ONCE g_pool_lock_init_once = INIT_ONCE_STATIC_INIT;
static HANDLE g_pool_wait_event = NULL;
static HANDLE g_shared_workers_init_event = NULL;
static THREAD_LOCAL uint8_t* g_tls_recv_buf = NULL;
static THREAD_LOCAL uint32_t g_tls_recv_cap = 0;
static THREAD_LOCAL DWORD g_tls_last_error = 0;

static volatile LONG64 g_metric_total_requests = 0;
static volatile LONG64 g_metric_total_success = 0;
static volatile LONG64 g_metric_total_fail = 0;
static volatile LONG64 g_metric_total_timeout = 0;
static volatile LONG64 g_metric_pool_reuse_hits = 0;
static volatile LONG64 g_metric_pool_new_connects = 0;

static volatile LONG64 g_prof_calls = 0;
static volatile LONG64 g_prof_us_total = 0;
static volatile LONG64 g_prof_us_pool_acquire = 0;
static volatile LONG64 g_prof_us_connect = 0;
static volatile LONG64 g_prof_us_send_config = 0;
static volatile LONG64 g_prof_us_send_audio = 0;
static volatile LONG64 g_prof_us_send_eos = 0;
static volatile LONG64 g_prof_us_recv_frame = 0;
static volatile LONG64 g_prof_us_json_parse = 0;

static LARGE_INTEGER g_qpc_freq;
static volatile LONG g_qpc_ready = 0;

typedef struct {
    int used;
    char url[WS_URL_MAX];
    ULONGLONG next_allowed_ms;
} ws_auto_warm_slot_t;

typedef struct {
    char url[WS_URL_MAX];
    uint32_t target_idle;
} ws_auto_warm_job_t;

typedef struct {
    ws_conn_t conn;
    char url[WS_URL_MAX];
    HANDLE bound_iocp;
    int mode;
    int occupied;
    int in_flight;
    ULONGLONG last_used_ms;
} ws_pool_entry_t;

typedef struct funasr_shared_req funasr_shared_req_t;
typedef struct funasr_shared_task_ctx funasr_shared_task_ctx_t;

typedef struct {
    HANDLE thread;
    HANDLE queue_event;
    SRWLOCK queue_lock;
    funasr_shared_req_t* queue_head;
    funasr_shared_req_t* queue_tail;
    funasr_shared_task_ctx_t* active_ctx_head;
    funasr_coro_sched_t sched;
    volatile LONG stop;
    volatile LONG ready;
    volatile LONG queued_reqs;
    volatile LONG inflight_reqs;
} funasr_shared_worker_t;

static ws_pool_entry_t g_ws_pool[WS_POOL_SIZE];
static ws_auto_warm_slot_t g_auto_warm_slots[WS_AUTO_WARM_SLOTS];
static SRWLOCK g_auto_warm_lock = SRWLOCK_INIT;
static THREAD_LOCAL funasr_coro_sched_t g_tls_iocp_sched;
static THREAD_LOCAL int g_tls_iocp_sched_ready = 0;
static funasr_shared_worker_t g_shared_workers[FUNASR_SHARED_IOCP_WORKERS_MAX];
static volatile LONG g_shared_worker_count = FUNASR_SHARED_IOCP_WORKERS_DEFAULT;
static volatile LONG g_shared_workers_ready = 0;
static volatile LONG g_shared_workers_initing = 0;

static int funasr_shared_workers_init(void);
static void funasr_shared_workers_shutdown(void);

static LONG atomic_read_long(const volatile LONG* v)
{
    return InterlockedCompareExchange((volatile LONG*)v, 0, 0);
}

static void ws_pool_notify_waiters(void)
{
    if (g_pool_wait_event) {
        SetEvent(g_pool_wait_event);
    }
}

static LONG funasr_detect_shared_worker_count(void)
{
    DWORD cpus = 0;
    LONG n = FUNASR_SHARED_IOCP_WORKERS_DEFAULT;

#if defined(ALL_PROCESSOR_GROUPS)
    cpus = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#endif
    if (cpus == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        cpus = si.dwNumberOfProcessors;
    }
    if (cpus > 0) {
        n = (LONG)(cpus / 2);
        if (n < FUNASR_SHARED_IOCP_WORKERS_MIN) n = FUNASR_SHARED_IOCP_WORKERS_MIN;
        if (n > FUNASR_SHARED_IOCP_WORKERS_MAX) n = FUNASR_SHARED_IOCP_WORKERS_MAX;
    }
    if (n <= 0) n = FUNASR_SHARED_IOCP_WORKERS_DEFAULT;
    return n;
}

enum {
    WS_MODE_IOCP = 1
};

#ifdef FUNASR_USE_X64_ASM
const char* funasr_find_text_key_x64(const char* buf, uint64_t len);
const char* funasr_find_is_final_key_x64(const char* buf, uint64_t len);
#endif

static uint64_t qpc_now_ticks(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (uint64_t)t.QuadPart;
}

static uint64_t qpc_us_since(uint64_t begin_ticks)
{
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    uint64_t delta = (uint64_t)(end.QuadPart - (LONGLONG)begin_ticks);
    if (g_qpc_freq.QuadPart == 0) return 0;
    return (delta * 1000000ull) / (uint64_t)g_qpc_freq.QuadPart;
}

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

static BOOL CALLBACK ws_pool_init_once_cb(PINIT_ONCE init_once, PVOID param, PVOID* context)
{
    (void)init_once;
    (void)param;
    (void)context;
    for (int i = 0; i < WS_POOL_SHARDS; i++) {
        InitializeSRWLock(&g_pool_shard_locks[i]);
    }
    return TRUE;
}

static void ws_pool_init_shard_locks_once(void)
{
    InitOnceExecuteOnce(&g_pool_lock_init_once, ws_pool_init_once_cb, NULL, NULL);
}

static uint32_t hash_url_fnv1a(const char* s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (uint8_t)(*s++);
        h *= 16777619u;
    }
    return h;
}

static int ws_pool_shard_index(const char* ws_url)
{
    return (int)(hash_url_fnv1a(ws_url) % WS_POOL_SHARDS);
}

static int ws_pool_entry_shard(const ws_pool_entry_t* entry)
{
    int idx = (int)(entry - g_ws_pool);
    return idx / WS_POOL_SHARD_SIZE;
}

static int ws_pool_shard_begin(int shard_idx)
{
    return shard_idx * WS_POOL_SHARD_SIZE;
}

static int ws_pool_shard_end(int shard_idx)
{
    return ws_pool_shard_begin(shard_idx) + WS_POOL_SHARD_SIZE;
}

typedef struct {
    ws_conn_t conn;
} ws_async_abort_job_t;

static int ws_pool_entry_is_idle_expired(const ws_pool_entry_t* entry, ULONGLONG now_ms)
{
    if (!entry || !entry->occupied) return 0;
    if (entry->in_flight != 0) return 0;
    if (entry->last_used_ms == 0) return 0;
    return (now_ms - entry->last_used_ms) > WS_IDLE_TIMEOUT_MS;
}

static int ws_pool_detach_entry_locked(ws_pool_entry_t* entry, ws_conn_t* out_conn)
{
    int had_conn = 0;
    if (!entry) return 0;

    had_conn = (entry->conn.sock != INVALID_SOCKET) || (entry->conn.rx_buf != NULL) || (entry->conn.connected != 0);
    if (out_conn) {
        if (had_conn) {
            *out_conn = entry->conn;
        } else {
            memset(out_conn, 0, sizeof(*out_conn));
            out_conn->sock = INVALID_SOCKET;
        }
    }

    entry->occupied = 0;
    entry->in_flight = 0;
    entry->url[0] = '\0';
    entry->last_used_ms = 0;
    entry->bound_iocp = NULL;
    entry->mode = 0;
    memset(&entry->conn, 0, sizeof(entry->conn));
    entry->conn.sock = INVALID_SOCKET;
    return had_conn;
}

static DWORD WINAPI ws_pool_async_abort_worker(LPVOID param)
{
    ws_async_abort_job_t* job = (ws_async_abort_job_t*)param;
    if (job) {
        ws_abort(&job->conn);
        free(job);
    }
    return 0;
}

static void ws_pool_abort_conn_async(const ws_conn_t* conn)
{
    ws_async_abort_job_t* job = NULL;
    if (!conn) return;
    if (conn->sock == INVALID_SOCKET && !conn->rx_buf && !conn->connected) return;

    job = (ws_async_abort_job_t*)calloc(1, sizeof(*job));
    if (!job) {
        ws_conn_t sync_conn = *conn;
        ws_abort(&sync_conn);
        return;
    }
    job->conn = *conn;
    if (!QueueUserWorkItem(ws_pool_async_abort_worker, job, WT_EXECUTEDEFAULT)) {
        ws_abort(&job->conn);
        free(job);
    }
}

static void ws_pool_reset_entry(ws_pool_entry_t* entry)
{
    ws_conn_t conn;
    int had_conn = 0;

    if (!entry) return;
    memset(&conn, 0, sizeof(conn));
    conn.sock = INVALID_SOCKET;
    had_conn = ws_pool_detach_entry_locked(entry, &conn);
    if (had_conn) {
        ws_abort(&conn);
    }
    ws_pool_notify_waiters();
}

static void ws_pool_close_all(void)
{
    for (int shard = 0; shard < WS_POOL_SHARDS; shard++) {
        AcquireSRWLockExclusive(&g_pool_shard_locks[shard]);
        for (int i = ws_pool_shard_begin(shard); i < ws_pool_shard_end(shard); i++) {
            ws_pool_reset_entry(&g_ws_pool[i]);
        }
        ReleaseSRWLockExclusive(&g_pool_shard_locks[shard]);
    }
}

static int ws_pool_acquire_iocp(const char* ws_url,
                                HANDLE iocp_handle,
                                ws_pool_entry_t** out_entry,
                                int* out_need_connect,
                                DWORD wait_timeout_ms,
                                int prefer_new_slot)
{
    if (!ws_url || !iocp_handle || !out_entry || !out_need_connect) return -1;
    size_t url_len = strlen(ws_url);
    if (url_len == 0 || url_len >= WS_URL_MAX) return -1;

    ws_pool_entry_t* entry = NULL;
    int primary_shard = ws_pool_shard_index(ws_url);
    ULONGLONG deadline = wait_timeout_ms ? (GetTickCount64() + wait_timeout_ms) : 0;

    for (;;) {
        ULONGLONG now_ms = GetTickCount64();

        if (!prefer_new_slot) {
            /* Pass 1: try reuse from primary shard first. */
            for (int step = 0; step < WS_POOL_SHARDS && !entry; step++) {
                int shard = (primary_shard + step) % WS_POOL_SHARDS;
                SRWLOCK* shard_lock = &g_pool_shard_locks[shard];
                int begin = ws_pool_shard_begin(shard);
                int end = ws_pool_shard_end(shard);
                ws_conn_t stale_conns[WS_POOL_SHARD_SIZE];
                int stale_count = 0;
                int freed_any = 0;

                AcquireSRWLockExclusive(shard_lock);
                for (int i = begin; i < end; i++) {
                    ws_pool_entry_t* cur = &g_ws_pool[i];
                    if (ws_pool_entry_is_idle_expired(cur, now_ms)) {
                        if (stale_count < WS_POOL_SHARD_SIZE &&
                            ws_pool_detach_entry_locked(cur, &stale_conns[stale_count])) {
                            stale_count++;
                        }
                        freed_any = 1;
                        continue;
                    }

                    if (!cur->occupied || cur->in_flight >= WS_CONN_MAX_INFLIGHT) continue;

                    if (cur->mode == WS_MODE_IOCP &&
                        cur->bound_iocp == iocp_handle &&
                        strcmp(cur->url, ws_url) == 0) {
                        entry = cur;
                        entry->in_flight++;
                        InterlockedIncrement64(&g_metric_pool_reuse_hits);
                        break;
                    }
                }
                ReleaseSRWLockExclusive(shard_lock);

                if (freed_any) ws_pool_notify_waiters();
                for (int i = 0; i < stale_count; i++) {
                    ws_pool_abort_conn_async(&stale_conns[i]);
                }
            }
        }

        /* Pass 2: allocate free slot across all shards to avoid hot-shard capacity caps. */
        for (int step = 0; step < WS_POOL_SHARDS && !entry; step++) {
            int shard = (primary_shard + step) % WS_POOL_SHARDS;
            SRWLOCK* shard_lock = &g_pool_shard_locks[shard];
            int begin = ws_pool_shard_begin(shard);
            int end = ws_pool_shard_end(shard);
            ws_conn_t stale_conns[WS_POOL_SHARD_SIZE];
            int stale_count = 0;
            int freed_any = 0;

            AcquireSRWLockExclusive(shard_lock);
            for (int i = begin; i < end; i++) {
                ws_pool_entry_t* cur = &g_ws_pool[i];
                if (ws_pool_entry_is_idle_expired(cur, now_ms)) {
                    if (stale_count < WS_POOL_SHARD_SIZE &&
                        ws_pool_detach_entry_locked(cur, &stale_conns[stale_count])) {
                        stale_count++;
                    }
                    freed_any = 1;
                }

                if (!g_ws_pool[i].occupied) {
                    entry = &g_ws_pool[i];
                    memset(entry, 0, sizeof(*entry));
                    entry->conn.sock = INVALID_SOCKET;
                    memcpy(entry->url, ws_url, url_len + 1);
                    entry->bound_iocp = iocp_handle;
                    entry->mode = WS_MODE_IOCP;
                    entry->occupied = 1;
                    entry->in_flight = 1;
                    entry->last_used_ms = now_ms;
                    InterlockedIncrement64(&g_metric_pool_new_connects);
                    break;
                }
            }
            ReleaseSRWLockExclusive(shard_lock);

            if (freed_any) ws_pool_notify_waiters();
            for (int i = 0; i < stale_count; i++) {
                ws_pool_abort_conn_async(&stale_conns[i]);
            }
        }

        if (entry) break;
        if (deadline && GetTickCount64() >= deadline) return -1;
        {
            DWORD wait_ms = WS_POOL_ACQUIRE_WAIT_SLICE_MS;
            if (deadline) {
                ULONGLONG now = GetTickCount64();
                ULONGLONG remain = (deadline > now) ? (deadline - now) : 0;
                if (remain == 0) return -1;
                if (remain < wait_ms) wait_ms = (DWORD)remain;
            }
            if (g_pool_wait_event) {
                WaitForSingleObject(g_pool_wait_event, wait_ms);
            } else {
                Sleep(wait_ms);
            }
        }
    }

    if (!entry) return -1;

    if (entry->conn.connected && !ws_is_alive(&entry->conn)) {
        ws_conn_t stale_conn;
        int had_conn = 0;
        int shard = ws_pool_entry_shard(entry);
        SRWLOCK* shard_lock = &g_pool_shard_locks[shard];
        ULONGLONG now_ms = GetTickCount64();
        memset(&stale_conn, 0, sizeof(stale_conn));
        stale_conn.sock = INVALID_SOCKET;
        AcquireSRWLockExclusive(shard_lock);
        had_conn = ws_pool_detach_entry_locked(entry, &stale_conn);
        entry->conn.sock = INVALID_SOCKET;
        memcpy(entry->url, ws_url, url_len + 1);
        entry->bound_iocp = iocp_handle;
        entry->mode = WS_MODE_IOCP;
        entry->occupied = 1;
        entry->in_flight = 1;
        entry->last_used_ms = now_ms;
        ReleaseSRWLockExclusive(shard_lock);
        if (had_conn) {
            ws_pool_abort_conn_async(&stale_conn);
        }
    }

    *out_need_connect = !entry->conn.connected;
    *out_entry = entry;
    return 0;
}

static int ws_pool_count_idle_iocp(const char* ws_url, HANDLE iocp_handle)
{
    if (!ws_url || !iocp_handle) return 0;
    int count = 0;

    for (int shard = 0; shard < WS_POOL_SHARDS; shard++) {
        AcquireSRWLockShared(&g_pool_shard_locks[shard]);
        for (int i = ws_pool_shard_begin(shard); i < ws_pool_shard_end(shard); i++) {
            ws_pool_entry_t* e = &g_ws_pool[i];
            if (!e->occupied || e->mode != WS_MODE_IOCP) continue;
            if (e->bound_iocp != iocp_handle) continue;
            if (e->in_flight != 0) continue;
            if (!e->conn.connected) continue;
            if (strcmp(e->url, ws_url) != 0) continue;
            count++;
        }
        ReleaseSRWLockShared(&g_pool_shard_locks[shard]);
    }
    return count;
}

static int ws_auto_warm_should_fire(const char* ws_url)
{
    if (!ws_url || !ws_url[0]) return 0;

    ULONGLONG now = GetTickCount64();
    uint32_t h = hash_url_fnv1a(ws_url);
    int base = (int)(h % WS_AUTO_WARM_SLOTS);
    int empty = -1;
    int fire = 0;

    AcquireSRWLockExclusive(&g_auto_warm_lock);
    for (int i = 0; i < WS_AUTO_WARM_SLOTS; i++) {
        int idx = (base + i) % WS_AUTO_WARM_SLOTS;
        ws_auto_warm_slot_t* s = &g_auto_warm_slots[idx];
        if (!s->used) {
            if (empty < 0) empty = idx;
            continue;
        }
        if (strcmp(s->url, ws_url) == 0) {
            if (now >= s->next_allowed_ms) {
                s->next_allowed_ms = now + WS_AUTO_WARM_COOLDOWN_MS;
                fire = 1;
            }
            ReleaseSRWLockExclusive(&g_auto_warm_lock);
            return fire;
        }
    }

    if (empty < 0) empty = base;
    g_auto_warm_slots[empty].used = 1;
    strncpy_s(g_auto_warm_slots[empty].url, sizeof(g_auto_warm_slots[empty].url), ws_url, _TRUNCATE);
    g_auto_warm_slots[empty].next_allowed_ms = now + WS_AUTO_WARM_COOLDOWN_MS;
    fire = 1;
    ReleaseSRWLockExclusive(&g_auto_warm_lock);
    return fire;
}

static uint32_t ws_auto_warm_target_idle_dynamic(void)
{
    LONG active = atomic_read_long(&g_active_sessions);
    LONG worker_count = atomic_read_long(&g_shared_worker_count);
    LONG per_worker = 0;
    LONG target = 0;
    LONG max_idle = 0;

    if (active < 0) active = 0;
    if (worker_count <= 0) worker_count = FUNASR_SHARED_IOCP_WORKERS_DEFAULT;
    per_worker = (active + worker_count - 1) / worker_count;
    target = per_worker + WS_AUTO_WARM_IDLE_SPARE;
    max_idle = WS_POOL_SIZE / worker_count;
    if (max_idle < WS_AUTO_WARM_IDLE_MIN) max_idle = WS_AUTO_WARM_IDLE_MIN;
    if (target < WS_AUTO_WARM_IDLE_MIN) target = WS_AUTO_WARM_IDLE_MIN;
    if (target > max_idle) target = max_idle;
    return (uint32_t)target;
}

static DWORD WINAPI ws_auto_warm_worker(LPVOID param)
{
    ws_auto_warm_job_t* job = (ws_auto_warm_job_t*)param;
    if (job) {
        funasr_warmup(job->url, job->target_idle);
        free(job);
    }
    InterlockedDecrement(&g_auto_warm_inflight);
    return 0;
}

static void ws_maybe_auto_warm_async(const char* ws_url)
{
    ws_auto_warm_job_t* job = NULL;
    LONG inflight = 0;

    if (!ws_url || !ws_url[0]) return;
    if (g_active_sessions > (FUNASR_MAX_CONCURRENT_SESSIONS / 4)) return;
    inflight = InterlockedCompareExchange(&g_auto_warm_inflight, 0, 0);
    if (inflight >= WS_AUTO_WARM_MAX_INFLIGHT) return;
    if (!ws_auto_warm_should_fire(ws_url)) return;

    job = (ws_auto_warm_job_t*)calloc(1, sizeof(*job));
    if (!job) return;
    strncpy_s(job->url, sizeof(job->url), ws_url, _TRUNCATE);
    job->target_idle = ws_auto_warm_target_idle_dynamic();

    inflight = InterlockedIncrement(&g_auto_warm_inflight);
    if (inflight > WS_AUTO_WARM_MAX_INFLIGHT) {
        InterlockedDecrement(&g_auto_warm_inflight);
        free(job);
        return;
    }

    if (!QueueUserWorkItem(ws_auto_warm_worker, job, WT_EXECUTEDEFAULT)) {
        InterlockedDecrement(&g_auto_warm_inflight);
        free(job);
    }
}

static void ws_pool_release(ws_pool_entry_t* entry, int keep_alive)
{
    if (!entry) return;
    SRWLOCK* shard_lock = &g_pool_shard_locks[ws_pool_entry_shard(entry)];

    AcquireSRWLockExclusive(shard_lock);
    if (entry->in_flight > 0) entry->in_flight--;
    if (!keep_alive || !entry->conn.connected) {
        ws_pool_reset_entry(entry);
    } else {
        entry->last_used_ms = GetTickCount64();
        /* Drop any stale buffered bytes before next request reuse. */
        entry->conn.rx_start = 0;
        entry->conn.rx_end = 0;
    }
    ReleaseSRWLockExclusive(shard_lock);
    ws_pool_notify_waiters();
}

static void funasr_tls_cleanup_buffers(void)
{
    if (g_tls_recv_buf) {
        free(g_tls_recv_buf);
        g_tls_recv_buf = NULL;
    }
    g_tls_recv_cap = 0;
    g_tls_last_error = 0;
    ws_tls_cleanup();
}

#ifdef FUNASR_EXPORTS
/* ---- DllMain (DLL build only) ---- */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule; (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        funasr_tls_cleanup_buffers();
        break;
    case DLL_PROCESS_DETACH:
        funasr_tls_cleanup_buffers();
        if (g_initialized) {
            funasr_shared_workers_shutdown();
            ws_pool_close_all();
            if (g_shared_workers_init_event) {
                CloseHandle(g_shared_workers_init_event);
                g_shared_workers_init_event = NULL;
            }
            if (g_pool_wait_event) {
                CloseHandle(g_pool_wait_event);
                g_pool_wait_event = NULL;
            }
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
        if (InterlockedCompareExchange(&g_qpc_ready, 1, 0) == 0) {
            QueryPerformanceFrequency(&g_qpc_freq);
        }
        if (!g_pool_wait_event) {
            g_pool_wait_event = CreateEventW(NULL, FALSE, FALSE, NULL);
            if (!g_pool_wait_event) {
                WSACleanup();
                ReleaseSRWLockExclusive(&g_wsa_lock);
                return -1;
            }
        }
        if (!g_shared_workers_init_event) {
            g_shared_workers_init_event = CreateEventW(NULL, TRUE, TRUE, NULL);
            if (!g_shared_workers_init_event) {
                CloseHandle(g_pool_wait_event);
                g_pool_wait_event = NULL;
                WSACleanup();
                ReleaseSRWLockExclusive(&g_wsa_lock);
                return -1;
            }
        }
        ws_pool_init_shard_locks_once();
        /* Shared worker schedulers enable cross-thread IOCP pool reuse. */
        if (funasr_shared_workers_init() < 0) {
            CloseHandle(g_shared_workers_init_event);
            g_shared_workers_init_event = NULL;
            CloseHandle(g_pool_wait_event);
            g_pool_wait_event = NULL;
            WSACleanup();
            ReleaseSRWLockExclusive(&g_wsa_lock);
            return -1;
        }
        g_initialized = 1;
    }
    ReleaseSRWLockExclusive(&g_wsa_lock);
    return 0;
}

static int try_acquire_session_quota(void)
{
    for (;;) {
        LONG cur = g_active_sessions;
        if (cur >= FUNASR_MAX_CONCURRENT_SESSIONS) {
            return -1;
        }
        if (InterlockedCompareExchange(&g_active_sessions, cur + 1, cur) == cur) {
            return 0;
        }
    }
}

static void release_session_quota(void)
{
    InterlockedDecrement(&g_active_sessions);
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
        funasr_shared_workers_shutdown();
        ws_pool_close_all();
        if (g_shared_workers_init_event) {
            CloseHandle(g_shared_workers_init_event);
            g_shared_workers_init_event = NULL;
        }
        if (g_pool_wait_event) {
            CloseHandle(g_pool_wait_event);
            g_pool_wait_event = NULL;
        }
        g_initialized = 0;
        WSACleanup();
    }
    ReleaseSRWLockExclusive(&g_wsa_lock);

    if (g_tls_iocp_sched_ready) {
        funasr_coro_sched_destroy(&g_tls_iocp_sched);
        g_tls_iocp_sched_ready = 0;
    }
    funasr_tls_cleanup_buffers();
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

static const char* find_literal(const char* buf, uint32_t len, const char* pat, uint32_t pat_len)
{
    const char* cur = NULL;
    const char* end = NULL;
    if (!buf || !pat || pat_len == 0 || len < pat_len) return NULL;

    cur = buf;
    end = buf + (len - pat_len + 1);
    while (cur < end) {
        const char* hit = (const char*)memchr(cur, (unsigned char)pat[0], (size_t)(end - cur));
        if (!hit) return NULL;
        if (memcmp(hit, pat, pat_len) == 0) {
            return hit;
        }
        cur = hit + 1;
    }
    return NULL;
}

static int json_hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int json_parse_u16(const char* p, const char* end, uint16_t* out_code)
{
    uint16_t v = 0;
    for (int n = 0; n < 4; n++) {
        int h;
        if (!p || !out_code || (p + n) >= end) return -1;
        h = json_hex_value(p[n]);
        if (h < 0) return -1;
        v = (uint16_t)((v << 4) | (uint16_t)h);
    }
    *out_code = v;
    return 0;
}

static int utf8_append_codepoint(uint32_t cp, char* out, int out_size, int* io_idx)
{
    int i;
    if (!out || !io_idx || out_size <= 0) return -1;

    i = *io_idx;
    if (cp <= 0x7Fu) {
        if (i + 1 >= out_size) return -1;
        out[i++] = (char)cp;
    } else if (cp <= 0x7FFu) {
        if (i + 2 >= out_size) return -1;
        out[i++] = (char)(0xC0u | (cp >> 6));
        out[i++] = (char)(0x80u | (cp & 0x3Fu));
    } else if (cp <= 0xFFFFu) {
        if (i + 3 >= out_size) return -1;
        out[i++] = (char)(0xE0u | (cp >> 12));
        out[i++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[i++] = (char)(0x80u | (cp & 0x3Fu));
    } else if (cp <= 0x10FFFFu) {
        if (i + 4 >= out_size) return -1;
        out[i++] = (char)(0xF0u | (cp >> 18));
        out[i++] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        out[i++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[i++] = (char)(0x80u | (cp & 0x3Fu));
    } else {
        return -1;
    }

    *io_idx = i;
    return 0;
}

/*
 * Parse FunASR response JSON for "text" field.
 * Minimal JSON parser — just find "text":"..." 
 *
 * TODO(东哥): Replace with proper zero-alloc JSON scanner
 */
static int extract_text(const char* json, uint32_t json_len, char* out, int out_size)
{
    const char* p = NULL;
    const char* end = json + json_len;
#ifdef FUNASR_USE_X64_ASM
    p = funasr_find_text_key_x64(json, json_len);
#else
    p = find_literal(json, json_len, "\"text\":\"", 8);
    if (p) p += 8;
#endif
    if (!p || p >= end) return 0;

    int i = 0;
    while (p < end && *p != '"' && i < out_size - 1) {
        if (*p != '\\') {
            out[i++] = *p++;
            continue;
        }

        p++;
        if (p >= end) break;

        switch (*p) {
        case '"': out[i++] = '"'; p++; break;
        case '\\': out[i++] = '\\'; p++; break;
        case '/': out[i++] = '/'; p++; break;
        case 'b': out[i++] = '\b'; p++; break;
        case 'f': out[i++] = '\f'; p++; break;
        case 'n': out[i++] = '\n'; p++; break;
        case 'r': out[i++] = '\r'; p++; break;
        case 't': out[i++] = '\t'; p++; break;
        case 'u': {
            uint16_t u1 = 0;
            uint32_t cp = 0xFFFDu;
            p++;
            if (json_parse_u16(p, end, &u1) < 0) goto done;
            p += 4;
            cp = (uint32_t)u1;

            if (u1 >= 0xD800u && u1 <= 0xDBFFu) {
                if ((end - p) >= 6 && p[0] == '\\' && p[1] == 'u') {
                    uint16_t u2 = 0;
                    if (json_parse_u16(p + 2, end, &u2) == 0 &&
                        u2 >= 0xDC00u && u2 <= 0xDFFFu) {
                        cp = 0x10000u + ((((uint32_t)u1 - 0xD800u) << 10) | ((uint32_t)u2 - 0xDC00u));
                        p += 6;
                    }
                }
            } else if (u1 >= 0xDC00u && u1 <= 0xDFFFu) {
                cp = 0xFFFDu;
            }

            if (utf8_append_codepoint(cp, out, out_size, &i) < 0) goto done;
            break;
        }
        default:
            out[i++] = *p++;
            break;
        }
    }
done:
    out[i] = '\0';
    return i;
}

/*
 * Check if response explicitly contains "is_final": true.
 */
static int is_final_true(const char* json, uint32_t json_len)
{
    const char* p = NULL;
    const char* end = json + json_len;
#ifdef FUNASR_USE_X64_ASM
    p = funasr_find_is_final_key_x64(json, json_len);
#else
    p = find_literal(json, json_len, "\"is_final\"", 10);
    if (p) p += 10;
#endif
    if (!p || p >= end) return 0;

    while (p < end && *p != ':') p++;
    if (p >= end) return 0;
    p++;

    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        p++;

    if ((end - p) < 4) return 0;
    return strncmp(p, "true", 4) == 0;
}

typedef struct funasr_pcm_iocp_job funasr_pcm_iocp_job_t;
typedef struct funasr_warmup_job funasr_warmup_job_t;
typedef void (*funasr_pcm_iocp_done_fn)(funasr_pcm_iocp_job_t* job, void* user);
typedef void (*funasr_warmup_done_fn)(funasr_warmup_job_t* job, void* user);

struct funasr_pcm_iocp_job {
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
    DWORD last_error;
    funasr_pcm_iocp_done_fn on_done;
    void* on_done_user;
};

struct funasr_warmup_job {
    const char* ws_url;
    uint32_t target_idle;
    int warmed_new;
    int status;
    DWORD last_error;
    funasr_warmup_done_fn on_done;
    void* on_done_user;
};

enum {
    FUNASR_SHARED_REQ_PCM = 1,
    FUNASR_SHARED_REQ_WARMUP = 2
};

struct funasr_shared_req {
    funasr_shared_req_t* next;
    int type;
    HANDLE done_event;
    int status;
    DWORD last_error;
    union {
        struct {
            const uint8_t* pcm_data;
            uint32_t pcm_len;
            const char* ws_url;
            const char* result;
        } pcm;
        struct {
            const char* ws_url;
            uint32_t target_idle;
            int warmed_new;
        } warmup;
    } u;
};

struct funasr_shared_task_ctx {
    funasr_shared_task_ctx_t* next;
    funasr_shared_worker_t* worker;
    funasr_shared_req_t* req;
    int completed;
    int type;
    funasr_coro_task_t task;
    union {
        funasr_pcm_iocp_job_t pcm;
        funasr_warmup_job_t warmup;
    } job;
};

static void funasr_pcm_iocp_entry(funasr_coro_task_t* task, void* arg)
{
    funasr_pcm_iocp_job_t* job = (funasr_pcm_iocp_job_t*)arg;
    funasr_coro_sched_t* sched = NULL;
    ws_conn_t* ws = NULL;
    uint8_t* recv_buf = NULL;
    char config[512];
    const char* eos = "{\"is_speaking\":false}";
    int need_connect = 0;
    uint64_t t_req = 0;
    uint64_t us_pool_acquire = 0;
    uint64_t us_connect = 0;
    uint64_t us_send_config = 0;
    uint64_t us_send_audio = 0;
    uint64_t us_send_eos = 0;
    uint64_t us_recv_frame = 0;
    uint64_t us_json_parse = 0;
    uint64_t t_phase = 0;

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
    t_req = qpc_now_ticks();

    t_phase = qpc_now_ticks();
    if (ws_pool_acquire_iocp(job->ws_url, sched->iocp, &job->pool_entry, &need_connect,
                             WS_POOL_ACQUIRE_BACKPRESSURE_MS, 0) < 0) {
        job->last_error = WAIT_TIMEOUT;
        goto done;
    }
    us_pool_acquire += qpc_us_since(t_phase);
    job->used_pool = 1;
    ws = &job->pool_entry->conn;

    if (need_connect) {
        t_phase = qpc_now_ticks();
        if (ws_connect_iocp(ws, task, job->ws_url) < 0) goto done;
        us_connect += qpc_us_since(t_phase);
    }

    int clen = build_config_json(config, sizeof(config));
    if (clen <= 0) goto done;
    t_phase = qpc_now_ticks();
    if (ws_send_text_iocp(ws, task, config, (uint32_t)clen) < 0) goto done;
    us_send_config += qpc_us_since(t_phase);

    uint32_t offset = 0;
    t_phase = qpc_now_ticks();
    while (offset < job->pcm_len) {
        uint32_t chunk = job->pcm_len - offset;
        if (chunk > CHUNK_BYTES) chunk = CHUNK_BYTES;
        if (ws_send_binary_iocp(ws, task, job->pcm_data + offset, chunk) < 0)
            goto done;
        offset += chunk;
    }
    us_send_audio += qpc_us_since(t_phase);

    t_phase = qpc_now_ticks();
    if (ws_send_text_iocp(ws, task, eos, (uint32_t)strlen(eos)) < 0) goto done;
    us_send_eos += qpc_us_since(t_phase);

    job->result = (char*)calloc(MAX_TEXT_SIZE, 1);
    if (!job->result) goto done;

    recv_buf = tls_get_recv_buf(RECV_BUF_SIZE);
    if (!recv_buf) goto done;

    for (;;) {
        uint32_t msg_len = 0;
        uint8_t opcode = 0;
        t_phase = qpc_now_ticks();
        if (ws_recv_iocp(ws, task, recv_buf, RECV_BUF_SIZE - 1, &msg_len, &opcode) < 0)
            goto done;
        us_recv_frame += qpc_us_since(t_phase);

        if (opcode == 0x08) goto done;
        if (opcode != 0x01 || msg_len == 0) continue;

        t_phase = qpc_now_ticks();
        int remaining = MAX_TEXT_SIZE - job->result_len;
        int tlen = extract_text((char*)recv_buf, msg_len, job->result + job->result_len, remaining);
        if (tlen > 0) job->result_len += tlen;
        if (is_final_true((char*)recv_buf, msg_len)) {
            job->got_final = 1;
            us_json_parse += qpc_us_since(t_phase);
            break;
        }
        us_json_parse += qpc_us_since(t_phase);
    }

    if (job->result_len > 0 && job->got_final) {
        job->result[job->result_len] = '\0';
        job->keep_alive = 1;
        job->status = 0;
        job->last_error = 0;
    }

done:
    InterlockedIncrement64(&g_prof_calls);
    InterlockedExchangeAdd64(&g_prof_us_total, (LONG64)qpc_us_since(t_req));
    InterlockedExchangeAdd64(&g_prof_us_pool_acquire, (LONG64)us_pool_acquire);
    InterlockedExchangeAdd64(&g_prof_us_connect, (LONG64)us_connect);
    InterlockedExchangeAdd64(&g_prof_us_send_config, (LONG64)us_send_config);
    InterlockedExchangeAdd64(&g_prof_us_send_audio, (LONG64)us_send_audio);
    InterlockedExchangeAdd64(&g_prof_us_send_eos, (LONG64)us_send_eos);
    InterlockedExchangeAdd64(&g_prof_us_recv_frame, (LONG64)us_recv_frame);
    InterlockedExchangeAdd64(&g_prof_us_json_parse, (LONG64)us_json_parse);

    if (job->status != 0 && job->last_error == 0) {
        job->last_error = funasr_coro_task_last_error(task);
        if (job->last_error == 0) job->last_error = ERROR_GEN_FAILURE;
    }
    if (job->status != 0) {
        free(job->result);
        job->result = NULL;
    }
    if (job->used_pool) {
        ws_pool_release(job->pool_entry, job->keep_alive);
    }
    if (job->on_done) {
        job->on_done(job, job->on_done_user);
    }
    funasr_coro_task_finish(task, job->status);
}

static void funasr_warmup_iocp_entry(funasr_coro_task_t* task, void* arg)
{
    funasr_warmup_job_t* job = (funasr_warmup_job_t*)arg;
    funasr_coro_sched_t* sched = NULL;

    if (!task || !job || !job->ws_url || job->target_idle == 0) {
        if (task) funasr_coro_task_finish(task, -1);
        return;
    }

    sched = funasr_coro_task_sched(task);
    if (!sched) {
        funasr_coro_task_finish(task, -1);
        return;
    }

    job->warmed_new = 0;
    job->status = 0;
    job->last_error = 0;

    for (;;) {
        ws_pool_entry_t* entry = NULL;
        int need_connect = 0;
        int idle = ws_pool_count_idle_iocp(job->ws_url, sched->iocp);
        if (idle >= (int)job->target_idle) break;

        if (ws_pool_acquire_iocp(job->ws_url, sched->iocp, &entry, &need_connect, 50, 1) < 0) {
            break; /* best effort */
        }

        if (need_connect) {
            if (ws_connect_iocp(&entry->conn, task, job->ws_url) < 0) {
                ws_pool_release(entry, 0);
                job->status = -1;
                job->last_error = funasr_coro_task_last_error(task);
                if (job->last_error == 0) job->last_error = ERROR_GEN_FAILURE;
                break;
            }
            job->warmed_new++;
        }
        ws_pool_release(entry, 1);
    }

    if (job->on_done) {
        job->on_done(job, job->on_done_user);
    }
    funasr_coro_task_finish(task, job->status);
}

static int funasr_shared_worker_pick(const char* ws_url)
{
    LONG worker_count = atomic_read_long(&g_shared_worker_count);
    int base = 0;
    int best = -1;
    LONG best_load = LONG_MAX;
    LONG base_load = LONG_MAX;

    if (worker_count <= 0) worker_count = FUNASR_SHARED_IOCP_WORKERS_DEFAULT;
    if (ws_url && ws_url[0]) {
        base = (int)(hash_url_fnv1a(ws_url) % (uint32_t)worker_count);
    }

    for (int step = 0; step < worker_count; step++) {
        int idx = (base + step) % worker_count;
        funasr_shared_worker_t* worker = &g_shared_workers[idx];
        LONG load = 0;

        if (atomic_read_long(&worker->ready) != 1 || !worker->queue_event) continue;
        load = atomic_read_long(&worker->queued_reqs) + atomic_read_long(&worker->inflight_reqs);
        if (idx == base) base_load = load;
        if (load < best_load) {
            best_load = load;
            best = idx;
            if (load == 0) break;
        }
    }

    if (best < 0) return base;
    if (base_load != LONG_MAX && base_load <= best_load + WS_WORKER_REBALANCE_DELTA) {
        return base;
    }
    return best;
}

static void funasr_shared_req_complete_error(funasr_shared_req_t* req, DWORD err)
{
    if (!req) return;
    req->status = -1;
    req->last_error = err ? err : ERROR_GEN_FAILURE;
    SetEvent(req->done_event);
}

static void funasr_shared_pcm_done(funasr_pcm_iocp_job_t* job, void* user)
{
    funasr_shared_task_ctx_t* ctx = (funasr_shared_task_ctx_t*)user;
    if (!ctx || !ctx->req || !job) return;

    ctx->req->status = job->status;
    ctx->req->last_error = job->last_error ? job->last_error : (job->status == 0 ? 0 : ERROR_GEN_FAILURE);
    ctx->req->u.pcm.result = job->result;
    ctx->completed = 1;
    if (ctx->worker) InterlockedDecrement(&ctx->worker->inflight_reqs);
    SetEvent(ctx->req->done_event);
}

static void funasr_shared_warmup_done(funasr_warmup_job_t* job, void* user)
{
    funasr_shared_task_ctx_t* ctx = (funasr_shared_task_ctx_t*)user;
    if (!ctx || !ctx->req || !job) return;

    ctx->req->status = job->status;
    ctx->req->last_error = job->last_error ? job->last_error : (job->status == 0 ? 0 : ERROR_GEN_FAILURE);
    ctx->req->u.warmup.warmed_new = job->warmed_new;
    ctx->completed = 1;
    if (ctx->worker) InterlockedDecrement(&ctx->worker->inflight_reqs);
    SetEvent(ctx->req->done_event);
}

static void funasr_shared_worker_enqueue(funasr_shared_worker_t* worker, funasr_shared_req_t* req)
{
    if (!worker || !req) return;
    InterlockedIncrement(&worker->queued_reqs);
    req->next = NULL;
    AcquireSRWLockExclusive(&worker->queue_lock);
    if (worker->queue_tail) {
        worker->queue_tail->next = req;
    } else {
        worker->queue_head = req;
    }
    worker->queue_tail = req;
    SetEvent(worker->queue_event);
    ReleaseSRWLockExclusive(&worker->queue_lock);
}

static funasr_shared_req_t* funasr_shared_worker_pop_all(funasr_shared_worker_t* worker)
{
    funasr_shared_req_t* head = NULL;
    if (!worker) return NULL;

    AcquireSRWLockExclusive(&worker->queue_lock);
    head = worker->queue_head;
    worker->queue_head = NULL;
    worker->queue_tail = NULL;
    ResetEvent(worker->queue_event);
    ReleaseSRWLockExclusive(&worker->queue_lock);
    return head;
}

static void funasr_shared_worker_reap(funasr_shared_worker_t* worker)
{
    funasr_shared_task_ctx_t** p = NULL;
    if (!worker) return;

    p = &worker->active_ctx_head;
    while (*p) {
        funasr_shared_task_ctx_t* ctx = *p;
        if (ctx->completed && ctx->task.done) {
            *p = ctx->next;
            free(ctx);
            continue;
        }
        p = &ctx->next;
    }
}

static int funasr_shared_worker_spawn_req(funasr_shared_worker_t* worker, funasr_shared_req_t* req)
{
    funasr_shared_task_ctx_t* ctx = NULL;
    int rc = -1;

    if (!worker || !req) return -1;
    ctx = (funasr_shared_task_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        funasr_shared_req_complete_error(req, ERROR_OUTOFMEMORY);
        return -1;
    }
    ctx->worker = worker;
    ctx->req = req;
    ctx->type = req->type;
    InterlockedIncrement(&worker->inflight_reqs);

    if (req->type == FUNASR_SHARED_REQ_PCM) {
        ctx->job.pcm.pcm_data = req->u.pcm.pcm_data;
        ctx->job.pcm.pcm_len = req->u.pcm.pcm_len;
        ctx->job.pcm.ws_url = req->u.pcm.ws_url;
        ctx->job.pcm.on_done = funasr_shared_pcm_done;
        ctx->job.pcm.on_done_user = ctx;
        rc = funasr_coro_sched_spawn(&worker->sched, &ctx->task, funasr_pcm_iocp_entry, &ctx->job.pcm, 1u << 20);
    } else if (req->type == FUNASR_SHARED_REQ_WARMUP) {
        ctx->job.warmup.ws_url = req->u.warmup.ws_url;
        ctx->job.warmup.target_idle = req->u.warmup.target_idle;
        ctx->job.warmup.on_done = funasr_shared_warmup_done;
        ctx->job.warmup.on_done_user = ctx;
        rc = funasr_coro_sched_spawn(&worker->sched, &ctx->task, funasr_warmup_iocp_entry, &ctx->job.warmup, 1u << 18);
    }

    if (rc < 0) {
        InterlockedDecrement(&worker->inflight_reqs);
        free(ctx);
        funasr_shared_req_complete_error(req, ERROR_OUTOFMEMORY);
        return -1;
    }

    ctx->next = worker->active_ctx_head;
    worker->active_ctx_head = ctx;
    return 0;
}

static DWORD WINAPI funasr_shared_worker_main(LPVOID param)
{
    funasr_shared_worker_t* worker = (funasr_shared_worker_t*)param;
    if (!worker) return 0;

    if (funasr_coro_sched_init(&worker->sched) < 0) {
        InterlockedExchange(&worker->ready, -1);
        return 0;
    }
    funasr_coro_sched_set_default_timeout(&worker->sched, WS_IO_TIMEOUT_MS);
    InterlockedExchange(&worker->ready, 1);

    for (;;) {
        funasr_shared_req_t* batch = NULL;

        batch = funasr_shared_worker_pop_all(worker);
        while (batch) {
            funasr_shared_req_t* req = batch;
            batch = batch->next;
            req->next = NULL;
            InterlockedDecrement(&worker->queued_reqs);
            funasr_shared_worker_spawn_req(worker, req);
        }

        if (worker->sched.active_tasks > 0) {
            if (funasr_coro_sched_pump(&worker->sched, FUNASR_SHARED_PUMP_WAIT_MS) < 0) {
                Sleep(1);
            }
            funasr_shared_worker_reap(worker);
            continue;
        }

        if (worker->stop) break;
        WaitForSingleObject(worker->queue_event, FUNASR_SHARED_PUMP_WAIT_MS);
    }

    {
        funasr_shared_req_t* batch = funasr_shared_worker_pop_all(worker);
        while (batch) {
            funasr_shared_req_t* req = batch;
            batch = batch->next;
            req->next = NULL;
            InterlockedDecrement(&worker->queued_reqs);
            funasr_shared_req_complete_error(req, ERROR_OPERATION_ABORTED);
        }
    }

    while (worker->sched.active_tasks > 0) {
        if (funasr_coro_sched_pump(&worker->sched, FUNASR_SHARED_PUMP_WAIT_MS) < 0) break;
        funasr_shared_worker_reap(worker);
    }

    {
        funasr_shared_task_ctx_t* ctx = worker->active_ctx_head;
        while (ctx) {
            funasr_shared_task_ctx_t* next = ctx->next;
            if (!ctx->completed && ctx->req) {
                if (ctx->worker) InterlockedDecrement(&ctx->worker->inflight_reqs);
                funasr_shared_req_complete_error(ctx->req, ERROR_OPERATION_ABORTED);
            }
            free(ctx);
            ctx = next;
        }
        worker->active_ctx_head = NULL;
    }

    funasr_coro_sched_destroy(&worker->sched);
    InterlockedExchange(&worker->ready, 0);
    return 0;
}

static void funasr_shared_workers_notify_init_done(void)
{
    HANDLE evt = g_shared_workers_init_event;
    if (evt) {
        SetEvent(evt);
    }
}

static int funasr_shared_workers_wait_init_done(void)
{
    HANDLE evt = g_shared_workers_init_event;
    if (evt) {
        WaitForSingleObject(evt, INFINITE);
    } else {
        while (InterlockedCompareExchange(&g_shared_workers_initing, 0, 0) != 0) {
            SwitchToThread();
        }
    }
    return InterlockedCompareExchange(&g_shared_workers_ready, 0, 0) ? 0 : -1;
}

static void funasr_shared_workers_shutdown(void)
{
    for (int i = 0; i < FUNASR_SHARED_IOCP_WORKERS_MAX; i++) {
        funasr_shared_worker_t* worker = &g_shared_workers[i];
        if (worker->thread || worker->queue_event) {
            InterlockedExchange(&worker->stop, 1);
            if (worker->queue_event) SetEvent(worker->queue_event);
        }
    }

    for (int i = 0; i < FUNASR_SHARED_IOCP_WORKERS_MAX; i++) {
        funasr_shared_worker_t* worker = &g_shared_workers[i];
        if (worker->thread) {
            WaitForSingleObject(worker->thread, 5000);
            CloseHandle(worker->thread);
            worker->thread = NULL;
        }
        if (worker->queue_event) {
            CloseHandle(worker->queue_event);
            worker->queue_event = NULL;
        }
        worker->queue_head = NULL;
        worker->queue_tail = NULL;
        worker->active_ctx_head = NULL;
        InterlockedExchange(&worker->queued_reqs, 0);
        InterlockedExchange(&worker->inflight_reqs, 0);
        InterlockedExchange(&worker->ready, 0);
    }
    InterlockedExchange(&g_shared_workers_ready, 0);
    InterlockedExchange(&g_shared_workers_initing, 0);
    InterlockedExchange(&g_shared_worker_count, FUNASR_SHARED_IOCP_WORKERS_DEFAULT);
    funasr_shared_workers_notify_init_done();
}

static int funasr_shared_workers_init(void)
{
    LONG worker_count = 0;
    int rc = -1;

    if (InterlockedCompareExchange(&g_shared_workers_ready, 0, 0)) return 0;
    if (InterlockedCompareExchange(&g_shared_workers_initing, 1, 0) != 0) {
        return funasr_shared_workers_wait_init_done();
    }
    if (g_shared_workers_init_event) ResetEvent(g_shared_workers_init_event);

    worker_count = funasr_detect_shared_worker_count();
    if (worker_count < FUNASR_SHARED_IOCP_WORKERS_MIN) worker_count = FUNASR_SHARED_IOCP_WORKERS_MIN;
    if (worker_count > FUNASR_SHARED_IOCP_WORKERS_MAX) worker_count = FUNASR_SHARED_IOCP_WORKERS_MAX;
    InterlockedExchange(&g_shared_worker_count, worker_count);

    for (int i = 0; i < worker_count; i++) {
        funasr_shared_worker_t* worker = &g_shared_workers[i];
        memset(worker, 0, sizeof(*worker));
        InitializeSRWLock(&worker->queue_lock);
        worker->queue_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!worker->queue_event) {
            goto fail;
        }
        worker->thread = CreateThread(NULL, 0, funasr_shared_worker_main, worker, 0, NULL);
        if (!worker->thread) {
            goto fail;
        }
    }

    for (int i = 0; i < worker_count; i++) {
        funasr_shared_worker_t* worker = &g_shared_workers[i];
        int spin = 0;
        while (InterlockedCompareExchange(&worker->ready, 0, 0) == 0 && spin < 5000) {
            Sleep(1);
            spin++;
        }
        if (InterlockedCompareExchange(&worker->ready, 0, 0) != 1) {
            goto fail;
        }
    }

    InterlockedExchange(&g_shared_workers_ready, 1);
    rc = 0;
    goto done;

fail:
    funasr_shared_workers_shutdown();
    rc = -1;

done:
    InterlockedExchange(&g_shared_workers_initing, 0);
    funasr_shared_workers_notify_init_done();
    return rc;
}

static const char* funasr_pcm_try_iocp_coro_shared(const uint8_t* pcm_data, uint32_t pcm_len,
                                                    const char* ws_url,
                                                    DWORD* out_error)
{
    int idx = 0;
    funasr_shared_worker_t* worker = NULL;
    funasr_shared_req_t req;

    if (!InterlockedCompareExchange(&g_shared_workers_ready, 0, 0)) {
        if (out_error) *out_error = ERROR_NOT_READY;
        return NULL;
    }

    idx = funasr_shared_worker_pick(ws_url);
    worker = &g_shared_workers[idx];
    if (InterlockedCompareExchange(&worker->ready, 0, 0) != 1 || !worker->queue_event) {
        if (out_error) *out_error = ERROR_NOT_READY;
        return NULL;
    }

    memset(&req, 0, sizeof(req));
    req.type = FUNASR_SHARED_REQ_PCM;
    req.done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!req.done_event) {
        if (out_error) *out_error = ERROR_OUTOFMEMORY;
        return NULL;
    }
    req.u.pcm.pcm_data = pcm_data;
    req.u.pcm.pcm_len = pcm_len;
    req.u.pcm.ws_url = ws_url;

    funasr_shared_worker_enqueue(worker, &req);
    WaitForSingleObject(req.done_event, INFINITE);
    CloseHandle(req.done_event);

    if (req.status < 0 || !req.u.pcm.result) {
        if (out_error) *out_error = req.last_error ? req.last_error : ERROR_GEN_FAILURE;
        return NULL;
    }

    if (out_error) *out_error = 0;
    return req.u.pcm.result;
}

static int funasr_warmup_iocp_shared(const char* ws_url, uint32_t target_idle)
{
    int idx = 0;
    funasr_shared_worker_t* worker = NULL;
    funasr_shared_req_t req;

    if (!InterlockedCompareExchange(&g_shared_workers_ready, 0, 0)) return -1;
    idx = funasr_shared_worker_pick(ws_url);
    worker = &g_shared_workers[idx];
    if (InterlockedCompareExchange(&worker->ready, 0, 0) != 1 || !worker->queue_event) return -1;

    memset(&req, 0, sizeof(req));
    req.type = FUNASR_SHARED_REQ_WARMUP;
    req.done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!req.done_event) return -1;
    req.u.warmup.ws_url = ws_url;
    req.u.warmup.target_idle = target_idle;

    funasr_shared_worker_enqueue(worker, &req);
    WaitForSingleObject(req.done_event, INFINITE);
    CloseHandle(req.done_event);

    if (req.status < 0) return -1;
    return req.u.warmup.warmed_new;
}

static const char* funasr_pcm_try_iocp_coro_local(const uint8_t* pcm_data, uint32_t pcm_len,
                                                   const char* ws_url,
                                                   DWORD* out_error)
{
    funasr_coro_sched_t* sched = NULL;
    funasr_coro_task_t task;
    funasr_pcm_iocp_job_t job;

    memset(&job, 0, sizeof(job));
    job.pcm_data = pcm_data;
    job.pcm_len = pcm_len;
    job.ws_url = ws_url;

    sched = tls_get_iocp_sched();
    if (!sched) {
        if (out_error) *out_error = ERROR_NOT_READY;
        return NULL;
    }

    if (funasr_coro_sched_spawn(sched, &task, funasr_pcm_iocp_entry, &job, 1u << 20) < 0) {
        if (out_error) *out_error = ERROR_OUTOFMEMORY;
        return NULL;
    }

    if (funasr_coro_sched_run(sched) < 0) {
        free(job.result);
        if (out_error) *out_error = ERROR_GEN_FAILURE;
        return NULL;
    }

    if (task.result_code < 0 || !job.result) {
        free(job.result);
        if (out_error) *out_error = job.last_error ? job.last_error : ERROR_GEN_FAILURE;
        return NULL;
    }

    if (out_error) *out_error = 0;
    return job.result;
}

FUNASR_API const char* funasr_pcm(const uint8_t* pcm_data, uint32_t pcm_len,
                                   const char* ws_url)
{
    const char* final_result = NULL;
    DWORD err = 0;

    if (!pcm_data || pcm_len == 0 || !ws_url) return NULL;

    for (;;) {
        AcquireSRWLockShared(&g_wsa_lock);
        if (g_initialized) {
            g_tls_last_error = 0;
            InterlockedIncrement64(&g_metric_total_requests);
            if (try_acquire_session_quota() < 0) {
                ReleaseSRWLockShared(&g_wsa_lock);
                g_tls_last_error = ERROR_TOO_MANY_SESS;
                InterlockedIncrement64(&g_metric_total_fail);
                return NULL;
            }
            ReleaseSRWLockShared(&g_wsa_lock);
            break;
        }
        ReleaseSRWLockShared(&g_wsa_lock);
        if (funasr_init() < 0) return NULL;
    }

    if (InterlockedCompareExchange(&g_shared_workers_ready, 0, 0)) {
        final_result = funasr_pcm_try_iocp_coro_shared(pcm_data, pcm_len, ws_url, &err);
    } else {
        final_result = funasr_pcm_try_iocp_coro_local(pcm_data, pcm_len, ws_url, &err);
    }
    release_session_quota();
    g_tls_last_error = err;
    if (final_result) {
        InterlockedIncrement64(&g_metric_total_success);
        ws_maybe_auto_warm_async(ws_url);
    } else {
        InterlockedIncrement64(&g_metric_total_fail);
        if (err == WAIT_TIMEOUT) InterlockedIncrement64(&g_metric_total_timeout);
    }
    return final_result;
}

FUNASR_API int funasr_warmup(const char* ws_url, uint32_t target_idle)
{
    funasr_coro_sched_t* sched = NULL;
    funasr_coro_task_t task;
    funasr_warmup_job_t job;

    if (!ws_url || target_idle == 0) return 0;

    AcquireSRWLockShared(&g_wsa_lock);
    if (!g_initialized) {
        ReleaseSRWLockShared(&g_wsa_lock);
        if (funasr_init() < 0) return -1;
        AcquireSRWLockShared(&g_wsa_lock);
    }
    ReleaseSRWLockShared(&g_wsa_lock);

    if (InterlockedCompareExchange(&g_shared_workers_ready, 0, 0)) {
        return funasr_warmup_iocp_shared(ws_url, target_idle);
    }

    sched = tls_get_iocp_sched();
    if (!sched) return -1;

    memset(&job, 0, sizeof(job));
    job.ws_url = ws_url;
    job.target_idle = target_idle;

    if (funasr_coro_sched_spawn(sched, &task, funasr_warmup_iocp_entry, &job, 1u << 18) < 0)
        return -1;
    if (funasr_coro_sched_run(sched) < 0) return -1;
    if (task.result_code < 0) return -1;
    return job.warmed_new;
}

FUNASR_API const char* funasr_pcm_file(const char* pcm_path, const char* ws_url)
{
    if (!pcm_path || !ws_url) return NULL;

    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    void* view = NULL;
    LARGE_INTEGER file_size_li;

    hFile = CreateFileA(pcm_path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    if (!GetFileSizeEx(hFile, &file_size_li) ||
        file_size_li.QuadPart <= 0 ||
        file_size_li.QuadPart > 0xFFFFFFFFLL) {
        CloseHandle(hFile);
        return NULL;
    }

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap) {
        view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (view) {
            const char* result = funasr_pcm((const uint8_t*)view, (uint32_t)file_size_li.QuadPart, ws_url);
            UnmapViewOfFile(view);
            CloseHandle(hMap);
            CloseHandle(hFile);
            return result;
        }
        CloseHandle(hMap);
        hMap = NULL;
    }

    /* Fallback path if mapping is unavailable in current environment. */
    {
        uint32_t file_size = (uint32_t)file_size_li.QuadPart;
        uint8_t* buf = (uint8_t*)malloc(file_size);
        DWORD read_bytes = 0;
        const char* result = NULL;

        if (!buf) {
            CloseHandle(hFile);
            return NULL;
        }
        if (!ReadFile(hFile, buf, file_size, &read_bytes, NULL) || read_bytes != file_size) {
            free(buf);
            CloseHandle(hFile);
            return NULL;
        }
        CloseHandle(hFile);

        result = funasr_pcm(buf, file_size, ws_url);
        free(buf);
        return result;
    }
}

FUNASR_API uint32_t funasr_last_error(void)
{
    return g_tls_last_error;
}

FUNASR_API void funasr_get_metrics(funasr_metrics_t* out_metrics)
{
    if (!out_metrics) return;
    out_metrics->total_requests = (uint64_t)g_metric_total_requests;
    out_metrics->total_success = (uint64_t)g_metric_total_success;
    out_metrics->total_fail = (uint64_t)g_metric_total_fail;
    out_metrics->total_timeout = (uint64_t)g_metric_total_timeout;
    out_metrics->pool_reuse_hits = (uint64_t)g_metric_pool_reuse_hits;
    out_metrics->pool_new_connects = (uint64_t)g_metric_pool_new_connects;
}

FUNASR_API void funasr_get_profile(funasr_profile_t* out_profile)
{
    if (!out_profile) return;
    out_profile->calls = (uint64_t)g_prof_calls;
    out_profile->us_total = (uint64_t)g_prof_us_total;
    out_profile->us_pool_acquire = (uint64_t)g_prof_us_pool_acquire;
    out_profile->us_connect = (uint64_t)g_prof_us_connect;
    out_profile->us_send_config = (uint64_t)g_prof_us_send_config;
    out_profile->us_send_audio = (uint64_t)g_prof_us_send_audio;
    out_profile->us_send_eos = (uint64_t)g_prof_us_send_eos;
    out_profile->us_recv_frame = (uint64_t)g_prof_us_recv_frame;
    out_profile->us_json_parse = (uint64_t)g_prof_us_json_parse;
}
