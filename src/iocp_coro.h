#ifndef IOCP_CORO_H
#define IOCP_CORO_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stddef.h>
#include <stdint.h>

typedef struct funasr_coro_task funasr_coro_task_t;
typedef struct funasr_coro_sched funasr_coro_sched_t;
typedef void (*funasr_coro_entry_fn)(funasr_coro_task_t* task, void* arg);

typedef struct funasr_coro_io_op {
    OVERLAPPED overlapped;
    funasr_coro_task_t* task;
    struct funasr_coro_io_op* next_pending;
    HANDLE io_handle;
    ULONGLONG deadline_ms;
    DWORD bytes_transferred;
    DWORD error_code;
    int completed;
    int cancelled;
} funasr_coro_io_op_t;

struct funasr_coro_task {
    funasr_coro_sched_t* sched;
    void* fiber;
    void* user_data;
    funasr_coro_entry_fn entry;
    int done;
    int result_code;
    int waiting_io;
    DWORD last_error;
    funasr_coro_task_t* next_ready;
};

struct funasr_coro_sched {
    HANDLE iocp;
    void* main_fiber;
    int owns_main_fiber;
    funasr_coro_task_t* ready_head;
    funasr_coro_task_t* ready_tail;
    funasr_coro_task_t* current_task;
    funasr_coro_io_op_t* pending_head;
    DWORD default_io_timeout_ms;
    int active_tasks;
};

int funasr_coro_sched_init(funasr_coro_sched_t* sched);
void funasr_coro_sched_destroy(funasr_coro_sched_t* sched);

int funasr_coro_sched_spawn(funasr_coro_sched_t* sched,
                            funasr_coro_task_t* task,
                            funasr_coro_entry_fn entry,
                            void* arg,
                            size_t stack_size);

int funasr_coro_sched_run(funasr_coro_sched_t* sched);
int funasr_coro_sched_pump(funasr_coro_sched_t* sched, DWORD wait_cap_ms);
void funasr_coro_sched_set_default_timeout(funasr_coro_sched_t* sched, DWORD timeout_ms);

void funasr_coro_task_finish(funasr_coro_task_t* task, int result_code);
funasr_coro_sched_t* funasr_coro_task_sched(funasr_coro_task_t* task);
DWORD funasr_coro_task_last_error(const funasr_coro_task_t* task);

int funasr_coro_bind_socket(funasr_coro_sched_t* sched, SOCKET sock);

int funasr_coro_await_handle_op(funasr_coro_task_t* task,
                                HANDLE io_handle,
                                funasr_coro_io_op_t* op,
                                DWORD timeout_ms);

int funasr_coro_await_wsasend(funasr_coro_task_t* task,
                              SOCKET sock,
                              WSABUF* bufs,
                              DWORD buf_count,
                              DWORD flags,
                              DWORD* bytes_sent);

int funasr_coro_await_wsarecv(funasr_coro_task_t* task,
                              SOCKET sock,
                              WSABUF* bufs,
                              DWORD buf_count,
                              DWORD* flags,
                              DWORD* bytes_recv);

int funasr_coro_await_wsasend_timeout(funasr_coro_task_t* task,
                                      SOCKET sock,
                                      WSABUF* bufs,
                                      DWORD buf_count,
                                      DWORD flags,
                                      DWORD timeout_ms,
                                      DWORD* bytes_sent);

int funasr_coro_await_wsarecv_timeout(funasr_coro_task_t* task,
                                      SOCKET sock,
                                      WSABUF* bufs,
                                      DWORD buf_count,
                                      DWORD* flags,
                                      DWORD timeout_ms,
                                      DWORD* bytes_recv);

#endif /* IOCP_CORO_H */
