/*
 * test_main.c - Standalone test for funasr.dll
 *
 * Usage:
 *   funasr_test.exe <pcm_file> [ws://host:port] [concurrency] [rounds]
 *
 * Example (32 concurrent x 10 waves):
 *   funasr_test.exe a.pcm ws://192.168.31.192:10090 32 10
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "funasr_dll.h"

#define MAX_CONCURRENCY 64

/* From current known-good sample result. */
static const char* k_expected_text =
    "请输入您的分机号，美团来电。哎，您好您好，刚才您在我们这里点了一份外卖。"
    "嗯，是这样的，我们会第三方配送，请您说一下手机号呃，189 嗯8998 嗯1795 嗯，"
    "哎好的好的，嗯，感谢您的支持，祝您生活愉快，再见。";

static int looks_like_expected(const char* text)
{
    if (!text) return 0;
    return strstr(text, "189") != NULL &&
           strstr(text, "1795") != NULL;
}

typedef struct {
    int thread_id;
    int round_id;
    int sample_index;
    int print_ok;
    const char* pcm_path;
    const char* ws_url;
    LONG* ok_count;
    LONG* fail_count;
    LONG* timeout_count;
    LONG* match_count;
    ULONGLONG* total_ms;
    DWORD* errors;
    ULONGLONG* latencies_ms;
    CRITICAL_SECTION* print_lock;
} worker_arg_t;

static int cmp_u64(const void* a, const void* b)
{
    ULONGLONG va = *(const ULONGLONG*)a;
    ULONGLONG vb = *(const ULONGLONG*)b;
    return (va > vb) - (va < vb);
}

static double percentile_ms(ULONGLONG* arr, int n, double p)
{
    if (!arr || n <= 0) return 0.0;
    qsort(arr, (size_t)n, sizeof(arr[0]), cmp_u64);
    int idx = (int)((p / 100.0) * (double)(n - 1));
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return (double)arr[idx];
}

static DWORD WINAPI worker_proc(LPVOID param)
{
    worker_arg_t* a = (worker_arg_t*)param;
    ULONGLONG t0 = GetTickCount64();
    const char* text = funasr_pcm_file(a->pcm_path, a->ws_url);
    DWORD err = funasr_last_error();
    ULONGLONG dt = GetTickCount64() - t0;
    InterlockedExchangeAdd64((volatile LONG64*)a->total_ms, (LONG64)dt);
    a->latencies_ms[a->sample_index] = dt;
    a->errors[a->sample_index] = err;

    if (!text) {
        InterlockedIncrement(a->fail_count);
        if (err == WAIT_TIMEOUT) InterlockedIncrement(a->timeout_count);
        EnterCriticalSection(a->print_lock);
        printf("[R%02d T%02d] FAIL (%llums, err=%lu)\n",
               a->round_id + 1, a->thread_id, dt, (unsigned long)err);
        LeaveCriticalSection(a->print_lock);
        return 0;
    }

    InterlockedIncrement(a->ok_count);
    if (strcmp(text, k_expected_text) == 0 || looks_like_expected(text)) {
        InterlockedIncrement(a->match_count);
    }

    if (a->print_ok) {
        EnterCriticalSection(a->print_lock);
        printf("[R%02d T%02d] OK (%llums)\n", a->round_id + 1, a->thread_id, dt);
        LeaveCriticalSection(a->print_lock);
    }

    funasr_free(text);
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcm_file> [ws://host:port] [concurrency] [rounds]\n", argv[0]);
        return 1;
    }

    const char* pcm_path = argv[1];
    const char* ws_url = argc > 2 ? argv[2] : "ws://192.168.31.192:10090";
    int concurrency = argc > 3 ? atoi(argv[3]) : 1;
    int rounds = argc > 4 ? atoi(argv[4]) : (concurrency > 1 ? 10 : 1);
    if (concurrency < 1) concurrency = 1;
    if (concurrency > MAX_CONCURRENCY) concurrency = MAX_CONCURRENCY;
    if (rounds < 1) rounds = 1;

    printf("FunASR DLL test\n");
    printf("  PCM: %s\n", pcm_path);
    printf("  URL: %s\n", ws_url);
    printf("  Concurrency: %d\n", concurrency);
    printf("  Rounds: %d\n", rounds);

    if (funasr_init() < 0) {
        fprintf(stderr, "funasr_init failed\n");
        return 1;
    }

    if (concurrency == 1 && rounds == 1) {
        const char* text = funasr_pcm_file(pcm_path, ws_url);
        if (text) {
            printf("Result: %s\n", text);
            funasr_free(text);
            funasr_cleanup();
            return 0;
        }
        fprintf(stderr, "Transcription failed\n");
        funasr_cleanup();
        return 1;
    }

    HANDLE threads[MAX_CONCURRENCY];
    worker_arg_t args[MAX_CONCURRENCY];
    LONG ok_count = 0;
    LONG fail_count = 0;
    LONG timeout_count = 0;
    LONG match_count = 0;
    LONG started_count = 0;
    ULONGLONG total_ms = 0;
    ULONGLONG* latencies_ms = NULL;
    DWORD* errors = NULL;
    CRITICAL_SECTION print_lock;
    funasr_metrics_t m0 = {0}, m1 = {0};
    funasr_profile_t p0 = {0}, p1 = {0};
    int total_samples = concurrency * rounds;
    int print_ok = (rounds == 1 && concurrency <= 8) ? 1 : 0;
    int run_failed = 0;

    latencies_ms = (ULONGLONG*)calloc((size_t)total_samples, sizeof(*latencies_ms));
    errors = (DWORD*)calloc((size_t)total_samples, sizeof(*errors));
    if (!latencies_ms || !errors) {
        fprintf(stderr, "Allocation failed for %d samples\n", total_samples);
        free(latencies_ms);
        free(errors);
        funasr_cleanup();
        return 1;
    }

    InitializeCriticalSection(&print_lock);
    funasr_get_metrics(&m0);
    funasr_get_profile(&p0);

    ULONGLONG t0 = GetTickCount64();
    for (int r = 0; r < rounds; r++) {
        ULONGLONG wave_t0 = GetTickCount64();
        int launched = 0;
        for (int i = 0; i < concurrency; i++) {
            int sample_index = r * concurrency + i;
            args[i].thread_id = i;
            args[i].round_id = r;
            args[i].sample_index = sample_index;
            args[i].print_ok = print_ok;
            args[i].pcm_path = pcm_path;
            args[i].ws_url = ws_url;
            args[i].ok_count = &ok_count;
            args[i].fail_count = &fail_count;
            args[i].timeout_count = &timeout_count;
            args[i].match_count = &match_count;
            args[i].total_ms = &total_ms;
            args[i].errors = errors;
            args[i].latencies_ms = latencies_ms;
            args[i].print_lock = &print_lock;
            threads[i] = CreateThread(NULL, 0, worker_proc, &args[i], 0, NULL);
            if (!threads[i]) {
                fprintf(stderr, "CreateThread failed at round %d thread %d\n", r + 1, i);
                run_failed = 1;
                break;
            }
            launched++;
        }

        if (launched > 0) {
            WaitForMultipleObjects((DWORD)launched, threads, TRUE, INFINITE);
            for (int i = 0; i < launched; i++) {
                if (threads[i]) CloseHandle(threads[i]);
            }
            started_count += launched;
        }

        printf("[Wave %d/%d] done in %llums, launched=%d, ok=%ld, fail=%ld\n",
               r + 1, rounds, GetTickCount64() - wave_t0, launched, ok_count, fail_count);

        if (run_failed) {
            break;
        }
    }
    ULONGLONG wall_ms = GetTickCount64() - t0;
    funasr_get_metrics(&m1);
    funasr_get_profile(&p1);
    DeleteCriticalSection(&print_lock);

    uint64_t dm_total = m1.total_requests - m0.total_requests;
    uint64_t dm_timeout = m1.total_timeout - m0.total_timeout;
    uint64_t dm_reuse = m1.pool_reuse_hits - m0.pool_reuse_hits;
    uint64_t dm_new = m1.pool_new_connects - m0.pool_new_connects;
    uint64_t dp_calls = p1.calls - p0.calls;
    uint64_t dp_us_total = p1.us_total - p0.us_total;
    uint64_t dp_us_pool = p1.us_pool_acquire - p0.us_pool_acquire;
    uint64_t dp_us_connect = p1.us_connect - p0.us_connect;
    uint64_t dp_us_send_cfg = p1.us_send_config - p0.us_send_config;
    uint64_t dp_us_send_audio = p1.us_send_audio - p0.us_send_audio;
    uint64_t dp_us_send_eos = p1.us_send_eos - p0.us_send_eos;
    uint64_t dp_us_recv = p1.us_recv_frame - p0.us_recv_frame;
    uint64_t dp_us_json = p1.us_json_parse - p0.us_json_parse;
    double reuse_rate = (dm_reuse + dm_new) ? (100.0 * (double)dm_reuse / (double)(dm_reuse + dm_new)) : 0.0;
    double fail_rate = started_count > 0 ? (100.0 * (double)fail_count / (double)started_count) : 0.0;
    double timeout_rate = started_count > 0 ? (100.0 * (double)timeout_count / (double)started_count) : 0.0;
    double qps = wall_ms > 0 ? (1000.0 * (double)ok_count / (double)wall_ms) : 0.0;
    double p95 = percentile_ms(latencies_ms, started_count, 95.0);
    double p99 = percentile_ms(latencies_ms, started_count, 99.0);

    printf("\n=== Summary ===\n");
    printf("Total: %ld (%d rounds x %d concurrency)\n", started_count, rounds, concurrency);
    printf("OK: %ld\n", ok_count);
    printf("FAIL: %ld\n", fail_count);
    printf("Timeout: %ld\n", timeout_count);
    printf("ExpectedTextMatch: %ld\n", match_count);
    printf("WallTime: %llums\n", wall_ms);
    printf("QPS: %.2f\n", qps);
    printf("P95: %.2fms\n", p95);
    printf("P99: %.2fms\n", p99);
    printf("FailRate: %.2f%%\n", fail_rate);
    printf("TimeoutRate: %.2f%%\n", timeout_rate);
    printf("PoolReuseRate: %.2f%% (reuse=%llu, new=%llu)\n",
           reuse_rate, (unsigned long long)dm_reuse, (unsigned long long)dm_new);
    printf("RequestsByDLL: %llu\n", (unsigned long long)dm_total);
    if (dp_calls > 0) {
        printf("ProfileCalls: %llu\n", (unsigned long long)dp_calls);
        printf("ProfileAvgTotal: %.2fus\n", (double)dp_us_total / (double)dp_calls);
        printf("ProfileAvgPool: %.2fus\n", (double)dp_us_pool / (double)dp_calls);
        printf("ProfileAvgConnect: %.2fus\n", (double)dp_us_connect / (double)dp_calls);
        printf("ProfileAvgSendCfg: %.2fus\n", (double)dp_us_send_cfg / (double)dp_calls);
        printf("ProfileAvgSendAudio: %.2fus\n", (double)dp_us_send_audio / (double)dp_calls);
        printf("ProfileAvgSendEOS: %.2fus\n", (double)dp_us_send_eos / (double)dp_calls);
        printf("ProfileAvgRecv: %.2fus\n", (double)dp_us_recv / (double)dp_calls);
        printf("ProfileAvgJSON: %.2fus\n", (double)dp_us_json / (double)dp_calls);
    }
    if (started_count > 0) {
        printf("AvgPerReq(Wall): %.2fms\n", (double)wall_ms / (double)started_count);
        printf("AvgPerReq(Thread): %.2fms\n", (double)total_ms / (double)started_count);
    }

    free(latencies_ms);
    free(errors);
    funasr_cleanup();
    return (run_failed || fail_count != 0) ? 1 : 0;
}
