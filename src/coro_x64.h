#ifndef CORO_X64_H
#define CORO_X64_H

#include <stdint.h>

typedef struct funasr_ctx_x64 {
    uint64_t rsp;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
} funasr_ctx_x64_t;

#ifdef __cplusplus
extern "C" {
#endif

void funasr_ctx_switch_x64(funasr_ctx_x64_t* from, const funasr_ctx_x64_t* to);

#ifdef __cplusplus
}
#endif

#endif /* CORO_X64_H */
