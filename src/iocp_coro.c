#include "iocp_coro.h"
#include <string.h>

#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#endif

#ifndef FILE_SKIP_SET_EVENT_ON_HANDLE
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

#define FUNASR_DEFAULT_IO_TIMEOUT_MS 30000

static ULONGLONG now_ms(void)
{
    return GetTickCount64();
}

static void funasr_coro_enqueue_ready(funasr_coro_sched_t* sched, funasr_coro_task_t* task)
{
    task->next_ready = NULL;
    if (!sched->ready_tail) {
        sched->ready_head = task;
        sched->ready_tail = task;
        return;
    }
    sched->ready_tail->next_ready = task;
    sched->ready_tail = task;
}

static funasr_coro_task_t* funasr_coro_dequeue_ready(funasr_coro_sched_t* sched)
{
    funasr_coro_task_t* task = sched->ready_head;
    if (!task) return NULL;

    sched->ready_head = task->next_ready;
    if (!sched->ready_head) sched->ready_tail = NULL;
    task->next_ready = NULL;
    return task;
}

static void funasr_coro_pending_add(funasr_coro_sched_t* sched, funasr_coro_io_op_t* op)
{
    op->next_pending = sched->pending_head;
    sched->pending_head = op;
}

static void funasr_coro_pending_remove(funasr_coro_sched_t* sched, funasr_coro_io_op_t* op)
{
    funasr_coro_io_op_t** p = &sched->pending_head;
    while (*p) {
        if (*p == op) {
            *p = op->next_pending;
            op->next_pending = NULL;
            return;
        }
        p = &(*p)->next_pending;
    }
}

static DWORD funasr_coro_next_wait_timeout(funasr_coro_sched_t* sched)
{
    ULONGLONG now = now_ms();
    DWORD min_wait = INFINITE;
    funasr_coro_io_op_t* op = sched->pending_head;

    while (op) {
        if (!op->completed && op->deadline_ms > 0) {
            if (op->deadline_ms <= now) return 0;
            ULONGLONG delta = op->deadline_ms - now;
            if (delta < min_wait) min_wait = (DWORD)delta;
        }
        op = op->next_pending;
    }
    return min_wait;
}

static void funasr_coro_cancel_timed_out_ops(funasr_coro_sched_t* sched)
{
    ULONGLONG now = now_ms();
    funasr_coro_io_op_t* op = sched->pending_head;

    while (op) {
        if (!op->completed && !op->cancelled && op->deadline_ms > 0 && op->deadline_ms <= now) {
            op->cancelled = 1;
            CancelIoEx(op->io_handle, &op->overlapped);
        }
        op = op->next_pending;
    }
}

static VOID CALLBACK funasr_coro_entry_trampoline(void* arg)
{
    funasr_coro_task_t* task = (funasr_coro_task_t*)arg;
    if (task && task->entry) {
        task->entry(task, task->user_data);
    }

    if (task && !task->done) {
        funasr_coro_task_finish(task, task->result_code);
    }
}

int funasr_coro_sched_init(funasr_coro_sched_t* sched)
{
    if (!sched) return -1;

    memset(sched, 0, sizeof(*sched));
    sched->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (!sched->iocp) return -1;

    sched->default_io_timeout_ms = FUNASR_DEFAULT_IO_TIMEOUT_MS;

    if (IsThreadAFiber()) {
        sched->main_fiber = GetCurrentFiber();
    } else {
        sched->main_fiber = ConvertThreadToFiber(NULL);
        if (!sched->main_fiber) {
            CloseHandle(sched->iocp);
            memset(sched, 0, sizeof(*sched));
            return -1;
        }
        sched->owns_main_fiber = 1;
    }

    return 0;
}

void funasr_coro_sched_destroy(funasr_coro_sched_t* sched)
{
    if (!sched) return;

    while (sched->ready_head) {
        funasr_coro_task_t* task = funasr_coro_dequeue_ready(sched);
        if (task && task->fiber) {
            DeleteFiber(task->fiber);
            task->fiber = NULL;
        }
    }

    if (sched->iocp) {
        CloseHandle(sched->iocp);
        sched->iocp = NULL;
    }

    if (sched->owns_main_fiber) {
        ConvertFiberToThread();
    }

    memset(sched, 0, sizeof(*sched));
}

int funasr_coro_sched_spawn(funasr_coro_sched_t* sched,
                            funasr_coro_task_t* task,
                            funasr_coro_entry_fn entry,
                            void* arg,
                            size_t stack_size)
{
    if (!sched || !task || !entry) return -1;

    memset(task, 0, sizeof(*task));
    task->sched = sched;
    task->entry = entry;
    task->user_data = arg;
    task->result_code = 0;
    task->fiber = CreateFiberEx(0, stack_size ? stack_size : (1u << 20), 0,
                                funasr_coro_entry_trampoline, task);
    if (!task->fiber) return -1;

    sched->active_tasks++;
    funasr_coro_enqueue_ready(sched, task);
    return 0;
}

void funasr_coro_sched_set_default_timeout(funasr_coro_sched_t* sched, DWORD timeout_ms)
{
    if (!sched) return;
    sched->default_io_timeout_ms = timeout_ms;
}

int funasr_coro_sched_run(funasr_coro_sched_t* sched)
{
    if (!sched || !sched->iocp || !sched->main_fiber) return -1;

    while (sched->active_tasks > 0) {
        funasr_coro_task_t* task = funasr_coro_dequeue_ready(sched);
        if (task) {
            sched->current_task = task;
            SwitchToFiber(task->fiber);
            sched->current_task = NULL;

            if (task->done) {
                if (task->fiber) {
                    DeleteFiber(task->fiber);
                    task->fiber = NULL;
                }
                sched->active_tasks--;
                continue;
            }

            if (!task->waiting_io) {
                funasr_coro_enqueue_ready(sched, task);
            }
            continue;
        }

        DWORD wait_ms = funasr_coro_next_wait_timeout(sched);
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* overlapped = NULL;
        BOOL ok = GetQueuedCompletionStatus(sched->iocp, &bytes, &key, &overlapped, wait_ms);
        if (overlapped) {
            funasr_coro_io_op_t* op = CONTAINING_RECORD(overlapped, funasr_coro_io_op_t, overlapped);
            op->bytes_transferred = bytes;
            op->error_code = ok ? 0 : GetLastError();
            op->completed = 1;
            funasr_coro_pending_remove(sched, op);

            if (op->task) {
                op->task->waiting_io = 0;
                funasr_coro_enqueue_ready(sched, op->task);
            }
        } else if (!ok) {
            DWORD err = GetLastError();
            if (err != WAIT_TIMEOUT) return -1;
        }

        funasr_coro_cancel_timed_out_ops(sched);
    }

    return 0;
}

void funasr_coro_task_finish(funasr_coro_task_t* task, int result_code)
{
    if (!task || !task->sched || !task->sched->main_fiber) return;

    task->result_code = result_code;
    task->done = 1;
    task->waiting_io = 0;
    SwitchToFiber(task->sched->main_fiber);
}

funasr_coro_sched_t* funasr_coro_task_sched(funasr_coro_task_t* task)
{
    return task ? task->sched : NULL;
}

DWORD funasr_coro_task_last_error(const funasr_coro_task_t* task)
{
    return task ? task->last_error : 0;
}

int funasr_coro_bind_socket(funasr_coro_sched_t* sched, SOCKET sock)
{
    if (!sched || sched->iocp == NULL || sock == INVALID_SOCKET) return -1;

    HANDLE h = CreateIoCompletionPort((HANDLE)sock, sched->iocp, 0, 0);
    if (h != sched->iocp) return -1;

    if (!SetFileCompletionNotificationModes((HANDLE)sock,
            FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        return -1;
    }

    return 0;
}

int funasr_coro_await_handle_op(funasr_coro_task_t* task,
                                HANDLE io_handle,
                                funasr_coro_io_op_t* op,
                                DWORD timeout_ms)
{
    if (!task || !task->sched || !task->sched->main_fiber || !op) return -1;

    if (timeout_ms == 0) timeout_ms = task->sched->default_io_timeout_ms;

    op->task = task;
    op->io_handle = io_handle;
    op->deadline_ms = timeout_ms ? (now_ms() + timeout_ms) : 0;
    funasr_coro_pending_add(task->sched, op);

    task->waiting_io = 1;
    while (!op->completed) {
        SwitchToFiber(task->sched->main_fiber);
    }

    funasr_coro_pending_remove(task->sched, op);

    if (op->error_code != 0) {
        if (op->cancelled && op->error_code == ERROR_OPERATION_ABORTED) {
            task->last_error = WAIT_TIMEOUT;
        } else {
            task->last_error = op->error_code;
        }
        return -1;
    }

    return 0;
}

int funasr_coro_await_wsasend_timeout(funasr_coro_task_t* task,
                                      SOCKET sock,
                                      WSABUF* bufs,
                                      DWORD buf_count,
                                      DWORD flags,
                                      DWORD timeout_ms,
                                      DWORD* bytes_sent)
{
    if (!task || !bufs || buf_count == 0 || sock == INVALID_SOCKET) return -1;

    funasr_coro_io_op_t op;
    DWORD sent = 0;

    memset(&op, 0, sizeof(op));
    int rc = WSASend(sock, bufs, buf_count, &sent, flags, &op.overlapped, NULL);
    if (rc == 0) {
        if (bytes_sent) *bytes_sent = sent;
        return 0;
    }

    int wsa_err = WSAGetLastError();
    if (wsa_err != WSA_IO_PENDING) {
        task->last_error = (DWORD)wsa_err;
        return -1;
    }

    if (funasr_coro_await_handle_op(task, (HANDLE)sock, &op, timeout_ms) < 0) return -1;
    if (bytes_sent) *bytes_sent = op.bytes_transferred;
    return 0;
}

int funasr_coro_await_wsarecv_timeout(funasr_coro_task_t* task,
                                      SOCKET sock,
                                      WSABUF* bufs,
                                      DWORD buf_count,
                                      DWORD* flags,
                                      DWORD timeout_ms,
                                      DWORD* bytes_recv)
{
    if (!task || !bufs || buf_count == 0 || sock == INVALID_SOCKET) return -1;

    funasr_coro_io_op_t op;
    DWORD recvd = 0;
    DWORD local_flags = flags ? *flags : 0;

    memset(&op, 0, sizeof(op));
    int rc = WSARecv(sock, bufs, buf_count, &recvd, &local_flags, &op.overlapped, NULL);
    if (rc == 0) {
        if (flags) *flags = local_flags;
        if (bytes_recv) *bytes_recv = recvd;
        return 0;
    }

    int wsa_err = WSAGetLastError();
    if (wsa_err != WSA_IO_PENDING) {
        task->last_error = (DWORD)wsa_err;
        return -1;
    }

    if (funasr_coro_await_handle_op(task, (HANDLE)sock, &op, timeout_ms) < 0) return -1;
    if (flags) *flags = local_flags;
    if (bytes_recv) *bytes_recv = op.bytes_transferred;
    return 0;
}

int funasr_coro_await_wsasend(funasr_coro_task_t* task,
                              SOCKET sock,
                              WSABUF* bufs,
                              DWORD buf_count,
                              DWORD flags,
                              DWORD* bytes_sent)
{
    return funasr_coro_await_wsasend_timeout(task, sock, bufs, buf_count, flags, 0, bytes_sent);
}

int funasr_coro_await_wsarecv(funasr_coro_task_t* task,
                              SOCKET sock,
                              WSABUF* bufs,
                              DWORD buf_count,
                              DWORD* flags,
                              DWORD* bytes_recv)
{
    return funasr_coro_await_wsarecv_timeout(task, sock, bufs, buf_count, flags, 0, bytes_recv);
}
