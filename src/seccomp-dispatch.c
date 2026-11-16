/* SPDX-License-Identifier: MIT */

/* Syscall dispatch engine for the seccomp supervisor.
 *
 * Each intercepted syscall notification is dispatched to a handler that either
 * forwards it through LKL (RETURN) or lets host kernel handle it (CONTINUE).
 * This is the beating heart of kbox: every file open, read, write, stat, and
 * directory operation the tracee makes gets routed through here.
 *
 * Single-threaded dispatch contract
 * ----------------------------------
 * All notification processing runs on a single thread (supervisor loop in
 * seccomp mode, SIGSYS handler in trap/rewrite mode). The following state is
 * protected only by this single-threaded invariant:
 *
 *   dispatch_scratch[]     Static I/O buffer (this file).
 *   kbox_fd_table entries  FD table (fd-table.c).
 *   Path scratch buffers   Translation/literal caches (path.c).
 *   shadow_sockets[]       SLIRP socket array (net-slirp.c).
 *   saved_guest_segv/bus   Fault handler saved actions (procmem.c).
 *   fault_armed            Thread-local; single-threaded guest means
 *                          only one thread ever arms it.
 *
 * If parallel dispatch or multi-threaded guest support is introduced,
 * every item above needs locking or per-thread allocation.
 */

#include <errno.h>
#include <fcntl.h>
/* seccomp types via seccomp.h -> seccomp-defs.h */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* pidfd_getfd is used to obtain a supervisor copy of a tracee FD that shares
 * the same file description (needed for emulating dup on host-passthrough FDs).
 * Available since Linux 5.6; kbox requires 5.13+ for seccomp USER_NOTIF.
 */
#ifndef __NR_pidfd_open
#if defined(__x86_64__)
#define __NR_pidfd_open 434
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_pidfd_open 434
#endif
#endif
#ifndef __NR_pidfd_getfd
#if defined(__x86_64__)
#define __NR_pidfd_getfd 438
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_pidfd_getfd 438
#endif
#endif
#ifndef __NR_faccessat2
#if defined(__x86_64__)
#define __NR_faccessat2 439
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_faccessat2 439
#endif
#endif
#ifndef __NR_statx
#if defined(__x86_64__)
#define __NR_statx 332
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_statx 291
#endif
#endif

#include "dispatch-internal.h"
#include "fd-table.h"
#include "kbox/elf.h"
#include "kbox/identity.h"
#include "kbox/path.h"
#include "lkl-wrap.h"
#include "loader-launch.h"
#include "net.h"
#include "procmem.h"
#include "rewrite.h"
#include "seccomp.h"
#include "shadow-fd.h"
#include "syscall-nr.h"
#include "syscall-trap-signal.h"
#include "syscall-trap.h"

/* Per-thread scratch buffer for I/O dispatch. Each supervisor thread is
 * non-reentrant: only one syscall is dispatched per thread at a time. Using TLS
 * avoids heap allocation from the SIGSYS handler in trap / rewrite mode, where
 * the guest may hold glibc heap locks, while supporting concurrent daemon
 * container threads.
 */
__thread uint8_t dispatch_scratch[KBOX_IO_CHUNK_LEN];

static int request_blocks_reserved_sigsys(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t set_ptr;
    size_t sigset_size;
    unsigned char mask[16];
    size_t read_len;
    int rc;

    if (!req)
        return 0;
    set_ptr = kbox_syscall_request_arg(req, 1);
    sigset_size = (size_t) kbox_syscall_request_arg(req, 3);
    if (set_ptr == 0 || sigset_size == 0)
        return 0;

    read_len = sigset_size;
    if (read_len > sizeof(mask))
        read_len = sizeof(mask);
    memset(mask, 0, sizeof(mask));

    rc = guest_mem_read(ctx, kbox_syscall_request_pid(req), set_ptr, mask,
                        read_len);
    if (rc < 0)
        return rc;

    return kbox_syscall_trap_sigset_blocks_reserved(mask, read_len) ? 1 : 0;
}

static struct kbox_dispatch emulate_trap_rt_sigprocmask(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long how = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t set_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t old_ptr = kbox_syscall_request_arg(req, 2);
    size_t sigset_size = (size_t) kbox_syscall_request_arg(req, 3);
    unsigned char current[sizeof(sigset_t)];
    unsigned char next[sizeof(sigset_t)];
    unsigned char pending[sizeof(sigset_t)];
    unsigned char set_mask[sizeof(sigset_t)];
    size_t mask_len;

    memset(current, 0, sizeof(current));
    memset(next, 0, sizeof(next));

    if (sigset_size == 0 || sigset_size > sizeof(current))
        return kbox_dispatch_errno(EINVAL);
    mask_len = sigset_size;

    /* In TRAP mode the signal mask lives in the ucontext delivered by kernel;
     * modifying it there takes effect when the handler returns.
     * In REWRITE mode there is no ucontext; the rewrite dispatch runs as normal
     * function call, so fall back to sigprocmask(2) directly.
     */
    if (kbox_syscall_trap_get_sigmask(current, sizeof(current)) < 0) {
        sigset_t tmp;
        if (sigprocmask(SIG_SETMASK, NULL, &tmp) < 0)
            return kbox_dispatch_errno(EIO);
        memcpy(current, &tmp, sizeof(current));
    }

    memset(set_mask, 0, sizeof(set_mask));
    memcpy(next, current, sizeof(next));

    if (set_ptr != 0) {
        int rc = guest_mem_read(ctx, kbox_syscall_request_pid(req), set_ptr,
                                set_mask, mask_len);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    if (old_ptr != 0) {
        /* Strip SIGSYS from the reported mask -- the guest must not
         * observe kbox's reserved signal in its signal state.
         */
        unsigned char visible[sizeof(sigset_t)];

        memcpy(visible, current, sizeof(visible));
        kbox_syscall_trap_sigset_strip_reserved(visible, sizeof(visible));
        int rc = guest_mem_write(ctx, kbox_syscall_request_pid(req), old_ptr,
                                 visible, mask_len);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    if (set_ptr != 0) {
        switch (how) {
        case SIG_BLOCK:
            for (size_t i = 0; i < mask_len; i++)
                next[i] |= set_mask[i];
            break;
        case SIG_UNBLOCK:
            for (size_t i = 0; i < mask_len; i++)
                next[i] &= (unsigned char) ~set_mask[i];
            break;
        case SIG_SETMASK:
            memcpy(next, set_mask, mask_len);
            break;
        default:
            return kbox_dispatch_errno(EINVAL);
        }
    }

    if (kbox_syscall_trap_set_sigmask(next, sizeof(next)) < 0) {
        sigset_t apply;
        memcpy(&apply, next, sizeof(next));
        if (sigprocmask(SIG_SETMASK, &apply, NULL) < 0)
            return kbox_dispatch_errno(EIO);
    }

    if (kbox_syscall_trap_get_pending(pending, sizeof(pending)) == 0) {
        for (size_t i = 0; i < sizeof(pending); i++)
            pending[i] &= next[i];
        (void) kbox_syscall_trap_set_pending(pending, sizeof(pending));
    }

    return kbox_dispatch_value(0);
}

static int trap_sigmask_contains_signal(int signo)
{
    sigset_t current;

    if (signo <= 0)
        return 0;
    if (kbox_syscall_trap_get_sigmask(&current, sizeof(current)) < 0)
        return 0;
    return sigismember(&current, signo) == 1;
}

static struct kbox_dispatch emulate_trap_rt_sigpending(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    uint64_t set_ptr = kbox_syscall_request_arg(req, 0);
    size_t sigset_size = (size_t) kbox_syscall_request_arg(req, 1);
    unsigned char pending[sizeof(sigset_t)];
    int rc;

    if (set_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    if (sigset_size == 0 || sigset_size > sizeof(pending))
        return kbox_dispatch_errno(EINVAL);
    if (kbox_syscall_trap_get_pending(pending, sizeof(pending)) < 0)
        return kbox_dispatch_errno(EIO);

    /* Strip SIGSYS from pending set -- the guest must not observe
     * kbox's reserved signal as pending.
     */
    kbox_syscall_trap_sigset_strip_reserved(pending, sizeof(pending));

    rc = guest_mem_write(ctx, kbox_syscall_request_pid(req), set_ptr, pending,
                         sigset_size);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    return kbox_dispatch_value(0);
}

struct kbox_fd_inject_ops {
    int (*addfd)(const struct kbox_supervisor_ctx *ctx,
                 uint64_t cookie,
                 int srcfd,
                 uint32_t newfd_flags);
    int (*addfd_at)(const struct kbox_supervisor_ctx *ctx,
                    uint64_t cookie,
                    int srcfd,
                    int target_fd,
                    uint32_t newfd_flags);
};

static int seccomp_request_addfd(const struct kbox_supervisor_ctx *ctx,
                                 uint64_t cookie,
                                 int srcfd,
                                 uint32_t newfd_flags)
{
    return kbox_notify_addfd(ctx->listener_fd, cookie, srcfd, newfd_flags);
}

static int seccomp_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                    uint64_t cookie,
                                    int srcfd,
                                    int target_fd,
                                    uint32_t newfd_flags)
{
    return kbox_notify_addfd_at(ctx->listener_fd, cookie, srcfd, target_fd,
                                newfd_flags);
}

static const struct kbox_fd_inject_ops seccomp_fd_inject_ops = {
    .addfd = seccomp_request_addfd,
    .addfd_at = seccomp_request_addfd_at,
};

static int local_request_addfd(const struct kbox_supervisor_ctx *ctx,
                               uint64_t cookie,
                               int srcfd,
                               uint32_t newfd_flags)
{
    int ret;

    (void) ctx;
    (void) cookie;
#ifdef F_DUPFD_CLOEXEC
    if (newfd_flags & O_CLOEXEC) {
        ret = (int) kbox_syscall_trap_host_syscall6(SYS_fcntl, (uint64_t) srcfd,
                                                    (uint64_t) F_DUPFD_CLOEXEC,
                                                    0, 0, 0, 0);
        return ret >= 0 ? ret : -(int) -ret;
    }
#endif
    ret = (int) kbox_syscall_trap_host_syscall6(SYS_fcntl, (uint64_t) srcfd,
                                                (uint64_t) F_DUPFD, 0, 0, 0, 0);
    return ret >= 0 ? ret : -(int) -ret;
}

static int local_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                  uint64_t cookie,
                                  int srcfd,
                                  int target_fd,
                                  uint32_t newfd_flags)
{
    (void) ctx;
    (void) cookie;
#ifdef __linux__
    {
        int ret = (int) kbox_syscall_trap_host_syscall6(
            SYS_dup3, (uint64_t) srcfd, (uint64_t) target_fd,
            (uint64_t) ((newfd_flags & O_CLOEXEC) ? O_CLOEXEC : 0), 0, 0, 0);
        return ret >= 0 ? ret : -(int) -ret;
    }
#else
    (void) srcfd;
    (void) target_fd;
    (void) newfd_flags;
    return -ENOSYS;
#endif
}

static const struct kbox_fd_inject_ops local_fd_inject_ops = {
    .addfd = local_request_addfd,
    .addfd_at = local_request_addfd_at,
};

int request_addfd(const struct kbox_supervisor_ctx *ctx,
                  const struct kbox_syscall_request *req,
                  int srcfd,
                  uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd(ctx, kbox_syscall_request_cookie(req),
                                     srcfd, newfd_flags);
}

int request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                     const struct kbox_syscall_request *req,
                     int srcfd,
                     int target_fd,
                     uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd_at || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd_at(ctx, kbox_syscall_request_cookie(req),
                                        srcfd, target_fd, newfd_flags);
}

static unsigned ctx_lkl_fd_ref_count(const struct kbox_supervisor_ctx *ctx,
                                     long lkl_fd)
{
    if (!ctx || lkl_fd < 0)
        return 0;
    unsigned total = 0;
    if (ctx->proc_fds && ctx->proc_fd_count > 0) {
        for (size_t i = 0; i < ctx->proc_fd_count; i++) {
            if (ctx->proc_fds[i].table)
                total +=
                    kbox_fd_table_lkl_ref_count(ctx->proc_fds[i].table, lkl_fd);
        }
    } else if (ctx->fd_table) {
        total += kbox_fd_table_lkl_ref_count(ctx->fd_table, lkl_fd);
    }
    if (ctx->pending_forks) {
        for (size_t i = 0; i < ctx->pending_fork_count; i++) {
            if (ctx->pending_forks[i].table)
                total += kbox_fd_table_lkl_ref_count(
                    ctx->pending_forks[i].table, lkl_fd);
        }
    }
    return total;
}

static long ctx_close_lkl_if_unreferenced(struct kbox_supervisor_ctx *ctx,
                                          long lkl_fd,
                                          int maybe_net_socket)
{
    if (lkl_fd < 0)
        return 0;
    if (ctx_lkl_fd_ref_count(ctx, lkl_fd) != 0)
        return 0;
    if (maybe_net_socket)
        kbox_net_deregister_socket((int) lkl_fd);
    return lkl_close_and_invalidate(ctx, lkl_fd);
}

static int read_proc_tgid_ppid(pid_t pid,
                               pid_t *tgid_out,
                               pid_t *ppid_out,
                               char *state_out)
{
    char path[64];
    char buf[1024];
    int fd;
    ssize_t n;
    pid_t tgid = -1;
    pid_t ppid = -1;
    char state = '\0';

    snprintf(path, sizeof(path), "/proc/%d/status", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -ENOENT;
    buf[n] = '\0';

    for (char *p = buf; *p;) {
        if (strncmp(p, "State:", 6) == 0) {
            char *q = p + 6;
            while (*q == ' ' || *q == '\t')
                q++;
            state = *q;
        } else if (strncmp(p, "Tgid:", 5) == 0) {
            tgid = (pid_t) strtol(p + 5, NULL, 10);
        } else if (strncmp(p, "PPid:", 5) == 0) {
            ppid = (pid_t) strtol(p + 5, NULL, 10);
        }
        if (state && tgid > 0 && ppid >= 0)
            break;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    if (tgid <= 0)
        return -ENOENT;
    if (tgid_out)
        *tgid_out = tgid;
    if (ppid_out)
        *ppid_out = ppid;
    if (state_out)
        *state_out = state;
    return 0;
}

static struct kbox_proc_fd_entry *find_proc_fd_entry(
    struct kbox_supervisor_ctx *ctx,
    pid_t tgid)
{
    if (!ctx || !ctx->proc_fds)
        return NULL;
    for (size_t i = 0; i < ctx->proc_fd_count; i++) {
        if (ctx->proc_fds[i].tgid == tgid)
            return &ctx->proc_fds[i];
    }
    return NULL;
}

static void set_active_host_cwd(struct kbox_supervisor_ctx *ctx,
                                const char *cwd)
{
    if (!ctx)
        return;
    if (!cwd || cwd[0] == '\0') {
        ctx->host_cwd[0] = '\0';
        if (ctx->active_proc)
            ctx->active_proc->host_cwd[0] = '\0';
        return;
    }
    snprintf(ctx->host_cwd, sizeof(ctx->host_cwd), "%s", cwd);
    if (ctx->active_proc)
        snprintf(ctx->active_proc->host_cwd, sizeof(ctx->active_proc->host_cwd),
                 "%s", cwd);
}

static void sync_ctx_host_cwd(struct kbox_supervisor_ctx *ctx,
                              struct kbox_proc_fd_entry *e)
{
    const char *src = e ? e->host_cwd : "";
    if (strcmp(ctx->host_cwd, src) != 0)
        invalidate_translated_path_cache(ctx);
    if (src[0] == '\0')
        ctx->host_cwd[0] = '\0';
    else
        snprintf(ctx->host_cwd, sizeof(ctx->host_cwd), "%s", src);
    ctx->active_proc = e;
}

static void release_table_entries_close_lkl(struct kbox_supervisor_ctx *ctx,
                                            struct kbox_fd_table *t)
{
    if (!t)
        return;

    struct {
        struct kbox_fd_entry *arr;
        long count;
        long base;
    } ranges[3] = {
        {t->low_fds, KBOX_LOW_FD_MAX, 0},
        {t->mid_fds, KBOX_MID_FD_MAX, KBOX_LOW_FD_MAX},
        {t->entries, KBOX_FD_TABLE_MAX, KBOX_FD_BASE},
    };
    for (int r = 0; r < 3; r++) {
        for (long j = 0; j < ranges[r].count; j++) {
            long lkl = ranges[r].arr[j].lkl_fd;
            if (lkl == -1)
                continue;
            kbox_fd_table_remove(t, ranges[r].base + j);
            if (lkl >= 0)
                ctx_close_lkl_if_unreferenced(ctx, lkl, 1);
        }
    }
}

static void dup_table_supervisor_fds(struct kbox_fd_table *t)
{
    struct {
        struct kbox_fd_entry *arr;
        long count;
    } ranges[3] = {
        {t->low_fds, KBOX_LOW_FD_MAX},
        {t->mid_fds, KBOX_MID_FD_MAX},
        {t->entries, KBOX_FD_TABLE_MAX},
    };
    for (int r = 0; r < 3; r++) {
        for (long j = 0; j < ranges[r].count; j++) {
            struct kbox_fd_entry *e = &ranges[r].arr[j];
            if (e->lkl_fd == -1)
                continue;
            if (e->shadow_sp >= 0) {
                int dup_sp = fcntl(e->shadow_sp, F_DUPFD_CLOEXEC, 3);
                e->shadow_sp = dup_sp >= 0 ? dup_sp : -1;
            } else if (e->host_fd >= 0) {
                int dup_h = fcntl((int) e->host_fd, F_DUPFD_CLOEXEC, 3);
                e->host_fd = dup_h >= 0 ? dup_h : -1;
            }
            if (e->host_sv_fd >= 0) {
                int dup_sv = fcntl(e->host_sv_fd, F_DUPFD_CLOEXEC, 3);
                e->host_sv_fd = dup_sv >= 0 ? dup_sv : -1;
            }
        }
    }
}

static void reap_dead_proc_fds(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->proc_fds)
        return;

    for (size_t i = 0; i < ctx->proc_fd_count;) {
        if (!ctx->proc_fds[i].owned) {
            i++;
            continue;
        }
        pid_t tgid = ctx->proc_fds[i].tgid;
        char state = '\0';
        int rc = read_proc_tgid_ppid(tgid, NULL, NULL, &state);
        int alive = (rc == 0 && state != 'Z' && state != 'X');
        if (!alive && kill(tgid, 0) == 0 && rc == 0 && state != 'Z' &&
            state != 'X')
            alive = 1;
        if (alive) {
            i++;
            continue;
        }

        struct kbox_fd_table *dead_tab = ctx->proc_fds[i].table;
        if (ctx->fd_table == dead_tab)
            ctx->fd_table = ctx->root_fd_table;
        ctx->active_proc = NULL;
        ctx->proc_fds[i] = ctx->proc_fds[ctx->proc_fd_count - 1];
        ctx->proc_fd_count--;

        for (size_t c = 0; c < KBOX_PID_TGID_CACHE_MAX; c++) {
            if (ctx->pid_tgid_cache[c].tgid == tgid) {
                ctx->pid_tgid_cache[c].pid = 0;
                ctx->pid_tgid_cache[c].tgid = 0;
            }
        }
        release_table_entries_close_lkl(ctx, dead_tab);
        free(dead_tab);
    }
}

static void release_pending_fork_slot(struct kbox_supervisor_ctx *ctx,
                                      size_t idx)
{
    if (!ctx || !ctx->pending_forks || idx >= ctx->pending_fork_count)
        return;

    struct kbox_fd_table *snap = ctx->pending_forks[idx].table;
    for (size_t i = idx; i + 1 < ctx->pending_fork_count; i++)
        ctx->pending_forks[i] = ctx->pending_forks[i + 1];
    ctx->pending_fork_count--;
    memset(&ctx->pending_forks[ctx->pending_fork_count], 0,
           sizeof(ctx->pending_forks[0]));

    if (snap) {
        release_table_entries_close_lkl(ctx, snap);
        free(snap);
    }
}

static void reap_dead_pending_forks(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->pending_forks)
        return;

    for (size_t i = 0; i < ctx->pending_fork_count;) {
        char state = '\0';
        int rc = read_proc_tgid_ppid(ctx->pending_forks[i].parent_tgid, NULL,
                                     NULL, &state);
        if (rc < 0 || state == 'Z' || state == 'X') {
            release_pending_fork_slot(ctx, i);
            continue;
        }
        i++;
    }
}

/* Snapshot the parent's FD table when clone/clone3/fork/vfork creates a child
 * with a private file descriptor table (!(flags & (CLONE_THREAD|CLONE_FILES))).
 * This closes the race where the parent closes an inherited FD before the
 * child makes its first seccomp-trapped syscall.
 */
void kbox_dispatch_snapshot_fork(struct kbox_supervisor_ctx *ctx,
                                 pid_t caller_pid)
{
    if (!ctx || !ctx->fd_table || caller_pid <= 0)
        return;

    pid_t parent_tgid = 0;
    const char *cwd = ctx->host_cwd;
    if (ctx->active_proc && ctx->active_proc->tgid > 0) {
        parent_tgid = ctx->active_proc->tgid;
        cwd = ctx->active_proc->host_cwd;
    } else if (read_proc_tgid_ppid(caller_pid, &parent_tgid, NULL, NULL) < 0 ||
               parent_tgid <= 0) {
        return;
    }

    if (!ctx->pending_forks) {
        ctx->pending_forks =
            calloc(KBOX_PENDING_FORKS_MAX, sizeof(*ctx->pending_forks));
        if (!ctx->pending_forks)
            return;
    }

    if (ctx->pending_fork_count >= KBOX_PENDING_FORKS_MAX)
        reap_dead_pending_forks(ctx);
    if (ctx->pending_fork_count >= KBOX_PENDING_FORKS_MAX)
        release_pending_fork_slot(ctx, 0);

    struct kbox_fd_table *snap_tab = calloc(1, sizeof(*snap_tab));
    if (!snap_tab)
        return;
    memcpy(snap_tab, ctx->fd_table, sizeof(*snap_tab));
    dup_table_supervisor_fds(snap_tab);

    struct kbox_pending_fork *pf =
        &ctx->pending_forks[ctx->pending_fork_count++];
    pf->parent_tgid = parent_tgid;
    pf->table = snap_tab;
    snprintf(pf->host_cwd, sizeof(pf->host_cwd), "%s", cwd ? cwd : "/");
}

static int take_pending_fork_table(struct kbox_supervisor_ctx *ctx,
                                   pid_t parent_tgid,
                                   struct kbox_fd_table **out_tab,
                                   char *out_cwd,
                                   size_t cwd_len)
{
    if (!ctx || !ctx->pending_forks || parent_tgid <= 0)
        return 0;

    for (size_t i = 0; i < ctx->pending_fork_count; i++) {
        if (ctx->pending_forks[i].parent_tgid != parent_tgid)
            continue;
        *out_tab = ctx->pending_forks[i].table;
        snprintf(out_cwd, cwd_len, "%s", ctx->pending_forks[i].host_cwd);
        for (size_t j = i; j + 1 < ctx->pending_fork_count; j++)
            ctx->pending_forks[j] = ctx->pending_forks[j + 1];
        ctx->pending_fork_count--;
        memset(&ctx->pending_forks[ctx->pending_fork_count], 0,
               sizeof(ctx->pending_forks[0]));
        return 1;
    }
    return 0;
}

static void select_proc_fd_table(struct kbox_supervisor_ctx *ctx, pid_t pid)
{
    if (!ctx || !ctx->fd_table || ctx->child_pid <= 0 || pid <= 0)
        return;

    if (!ctx->proc_fds) {
        ctx->root_fd_table = ctx->fd_table;
        ctx->proc_fds = calloc(KBOX_PROC_FD_TABLES_MAX, sizeof(*ctx->proc_fds));
        if (!ctx->proc_fds)
            return;
        ctx->proc_fds[0].tgid = ctx->child_pid;
        ctx->proc_fds[0].owned = 0;
        ctx->proc_fds[0].table = ctx->root_fd_table;
        snprintf(ctx->proc_fds[0].host_cwd, sizeof(ctx->proc_fds[0].host_cwd),
                 "%s", ctx->host_cwd);
        ctx->proc_fd_count = 1;
        ctx->active_proc = &ctx->proc_fds[0];
    }

    size_t slot = (size_t) pid % KBOX_PID_TGID_CACHE_MAX;
    pid_t tgid = 0;
    pid_t ppid = -1;
    if (ctx->pid_tgid_cache[slot].pid == pid &&
        ctx->pid_tgid_cache[slot].tgid > 0) {
        tgid = ctx->pid_tgid_cache[slot].tgid;
    } else {
        if (read_proc_tgid_ppid(pid, &tgid, &ppid, NULL) < 0)
            return;
        ctx->pid_tgid_cache[slot].pid = pid;
        ctx->pid_tgid_cache[slot].tgid = tgid;
    }

    struct kbox_proc_fd_entry *existing = find_proc_fd_entry(ctx, tgid);
    if (existing) {
        ctx->fd_table = existing->table;
        sync_ctx_host_cwd(ctx, existing);
        return;
    }

    if (ppid < 0 && read_proc_tgid_ppid(pid, &tgid, &ppid, NULL) < 0)
        return;

    if (ctx->proc_fd_count >= KBOX_PROC_FD_TABLES_MAX - 1 ||
        ctx->proc_fd_count >= 16)
        reap_dead_proc_fds(ctx);
    if (ctx->pending_fork_count >= 16)
        reap_dead_pending_forks(ctx);
    if (ctx->proc_fd_count >= KBOX_PROC_FD_TABLES_MAX) {
        ctx->fd_table = ctx->root_fd_table;
        sync_ctx_host_cwd(ctx, &ctx->proc_fds[0]);
        return;
    }

    struct kbox_proc_fd_entry *parent_entry = NULL;
    struct kbox_fd_table *child_tab = NULL;
    char child_cwd[KBOX_MAX_PATH];
    child_cwd[0] = '\0';

    pid_t walk = ppid;
    for (int hop = 0; hop < 4 && walk > 1 && !parent_entry; hop++) {
        pid_t w_tgid = 0;
        pid_t w_ppid = -1;
        if (read_proc_tgid_ppid(walk, &w_tgid, &w_ppid, NULL) < 0)
            break;
        if (take_pending_fork_table(ctx, w_tgid, &child_tab, child_cwd,
                                    sizeof(child_cwd)))
            break;
        parent_entry = find_proc_fd_entry(ctx, w_tgid);
        walk = w_ppid;
    }

    if (!child_tab) {
        if (!parent_entry)
            parent_entry = &ctx->proc_fds[0];
        struct kbox_fd_table *parent_tab =
            parent_entry->table ? parent_entry->table : ctx->root_fd_table;

        child_tab = calloc(1, sizeof(*child_tab));
        if (!child_tab) {
            ctx->fd_table = ctx->root_fd_table;
            sync_ctx_host_cwd(ctx, &ctx->proc_fds[0]);
            return;
        }
        memcpy(child_tab, parent_tab, sizeof(*child_tab));
        dup_table_supervisor_fds(child_tab);
        snprintf(child_cwd, sizeof(child_cwd), "%s", parent_entry->host_cwd);
    }

    struct kbox_proc_fd_entry *ce = &ctx->proc_fds[ctx->proc_fd_count];
    ce->tgid = tgid;
    ce->owned = 1;
    ce->table = child_tab;
    snprintf(ce->host_cwd, sizeof(ce->host_cwd), "%s", child_cwd);
    ctx->proc_fd_count++;
    ctx->fd_table = child_tab;
    sync_ctx_host_cwd(ctx, ce);
}

void kbox_dispatch_cleanup_proc_fds(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->pending_forks) {
        while (ctx->pending_fork_count > 0)
            release_pending_fork_slot(ctx, ctx->pending_fork_count - 1);
        free(ctx->pending_forks);
        ctx->pending_forks = NULL;
    }
    if (ctx->root_fd_table)
        ctx->fd_table = ctx->root_fd_table;
    if (ctx->proc_fds) {
        for (size_t i = 0; i < ctx->proc_fd_count; i++) {
            if (ctx->proc_fds[i].owned && ctx->proc_fds[i].table) {
                release_table_entries_close_lkl(ctx, ctx->proc_fds[i].table);
                free(ctx->proc_fds[i].table);
                ctx->proc_fds[i].table = NULL;
            }
        }
        free(ctx->proc_fds);
        ctx->proc_fds = NULL;
        ctx->proc_fd_count = 0;
    }
    if (ctx->fd_table)
        release_table_entries_close_lkl(ctx, ctx->fd_table);
}

void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req)
{
    if (!ctx || !req)
        return;

    ctx->active_guest_mem = req->guest_mem;
    if (!ctx->active_guest_mem.ops) {
        ctx->active_guest_mem.ops = &kbox_process_vm_guest_mem_ops;
        ctx->active_guest_mem.opaque = (uintptr_t) req->pid;
    }
    ctx->guest_mem_ops = ctx->active_guest_mem.ops;
    if (!ctx->fd_inject_ops) {
        if (req->source == KBOX_SYSCALL_SOURCE_TRAP ||
            req->source == KBOX_SYSCALL_SOURCE_REWRITE) {
            ctx->fd_inject_ops = &local_fd_inject_ops;
        } else {
            ctx->fd_inject_ops = &seccomp_fd_inject_ops;
        }
    }
    if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
        select_proc_fd_table(ctx, req->pid);
}

int guest_mem_read(const struct kbox_supervisor_ctx *ctx,
                   pid_t pid,
                   uint64_t remote_addr,
                   void *out,
                   size_t len)
{
    (void) pid;
    return kbox_guest_mem_read(&ctx->active_guest_mem, remote_addr, out, len);
}

int guest_mem_write(const struct kbox_supervisor_ctx *ctx,
                    pid_t pid,
                    uint64_t remote_addr,
                    const void *in,
                    size_t len)
{
    (void) pid;
    return kbox_guest_mem_write(&ctx->active_guest_mem, remote_addr, in, len);
}

int guest_mem_write_force(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          const void *in,
                          size_t len)
{
    (void) pid;
    return kbox_guest_mem_write_force(&ctx->active_guest_mem, remote_addr, in,
                                      len);
}

int guest_mem_read_string(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          char *buf,
                          size_t max_len)
{
    (void) pid;
    return kbox_guest_mem_read_string(&ctx->active_guest_mem, remote_addr, buf,
                                      max_len);
}

int guest_mem_read_open_how(const struct kbox_supervisor_ctx *ctx,
                            pid_t pid,
                            uint64_t remote_addr,
                            uint64_t size,
                            struct kbox_open_how *out)
{
    (void) pid;

    return kbox_guest_mem_read_open_how(&ctx->active_guest_mem, remote_addr,
                                        size, out);
}

/* Stat ABI conversion. */

/* Convert LKL's generic-arch stat layout to the host's struct stat.
 *
 * LKL always fills stat buffers using the asm-generic layout regardless of the
 * host architecture. On x86_64 the two layouts differ:
 *   generic: st_mode (u32) at offset 16, st_nlink (u32) at offset 20
 *   x86_64:  st_nlink (u64) at offset 16, st_mode (u32) at offset 24
 *
 * On aarch64 the kernel uses the generic layout, but C library's struct stat
 * may still have different padding, so convert explicitly on all arch.
 */
void kbox_lkl_stat_to_host(const struct kbox_lkl_stat *src, struct stat *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->st_dev = (dev_t) src->st_dev;
    dst->st_ino = (ino_t) src->st_ino;
    dst->st_mode = (mode_t) src->st_mode;
    dst->st_nlink = (nlink_t) src->st_nlink;
    dst->st_uid = (uid_t) src->st_uid;
    dst->st_gid = (gid_t) src->st_gid;
    dst->st_rdev = (dev_t) src->st_rdev;
    dst->st_size = (off_t) src->st_size;
    dst->st_blksize = (blksize_t) src->st_blksize;
    dst->st_blocks = (blkcnt_t) src->st_blocks;
    dst->st_atim.tv_sec = (time_t) src->st_atime_sec;
    dst->st_atim.tv_nsec = (long) src->st_atime_nsec;
    dst->st_mtim.tv_sec = (time_t) src->st_mtime_sec;
    dst->st_mtim.tv_nsec = (long) src->st_mtime_nsec;
    dst->st_ctim.tv_sec = (time_t) src->st_ctime_sec;
    dst->st_ctim.tv_nsec = (long) src->st_ctime_nsec;
}

/* Dispatch result constructors. */

struct kbox_dispatch kbox_dispatch_continue(void)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_CONTINUE,
        .val = 0,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_errno(int err)
{
    if (err <= 0)
        err = EIO;
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = 0,
        .error = err,
    };
}

struct kbox_dispatch kbox_dispatch_value(int64_t val)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = val,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_from_lkl(long ret)
{
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    return kbox_dispatch_value((int64_t) ret);
}

/* Path and FD helper functions. */

/* Check if the original guest path at a given arg index starts with '/'.
 * Used to gate virtual-path CONTINUE on originally-absolute paths: relative
 * paths like "./proc" normalize to "/proc" but should go through LKL, while
 * absolute "/proc/self/status" should CONTINUE to the host kernel.
 */
static bool guest_path_is_absolute(const struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_syscall_request *req,
                                   size_t arg_idx)
{
    uint8_t first = 0;
    if (guest_mem_read(ctx, kbox_syscall_request_pid(req),
                       kbox_syscall_request_arg(req, arg_idx), &first, 1) == 0)
        return first == '/';
    return false;
}

static bool should_continue_virtual_path(const struct kbox_supervisor_ctx *ctx,
                                         const struct kbox_syscall_request *req,
                                         size_t path_idx,
                                         const char *translated)
{
    /* fd magic links belong to the host: the descriptors a guest process sees
     * are kbox-injected host fds (exec memfds, pipes, sockets), which a guest
     * procfs knows nothing about, while execve through /proc/self/fd/N is how
     * kbox hands executables to the kernel. */
    {
        const char *tail = NULL;
        if (!strncmp(translated, "/proc/self/fd", 13))
            tail = translated + 13;
        else if (!strncmp(translated, "/proc/thread-self/fd", 20))
            tail = translated + 20;
        else if (!strncmp(translated, "/proc/", 6) && translated[6] >= '0' &&
                 translated[6] <= '9') {
            const char *p2 = translated + 6;
            while (*p2 >= '0' && *p2 <= '9')
                p2++;
            if (!strncmp(p2, "/fd", 3))
                tail = p2 + 3;
        }
        if (tail && (tail[0] == '\0' || tail[0] == '/'))
            return true;
    }

    /* A container with its own procfs resolves /proc inside LKL; continuing
     * it would read the host's, and the magic links there are blocked. */
    if (ctx->private_proc && !strncmp(translated, "/proc", 5) &&
        (translated[5] == '\0' || translated[5] == '/'))
        return false;
    return kbox_is_lkl_virtual_path(translated) &&
           guest_path_is_absolute(ctx, req, path_idx);
}

/* Resolve dirfd for *at() syscalls.
 *
 * If the path is absolute, AT_FDCWD is fine regardless of dirfd. If dirfd is
 * AT_FDCWD, pass it through. Otherwise look up the virtual FD in the table to
 * get the LKL fd.  Returns -1 if the fd is not in the table (caller should
 * CONTINUE).
 */
long resolve_open_dirfd(const char *path,
                        long dirfd,
                        const struct kbox_fd_table *table)
{
    if (path[0] == '/')
        return AT_FDCWD_LINUX;
    if (dirfd == AT_FDCWD_LINUX)
        return AT_FDCWD_LINUX;
    return kbox_fd_table_get_lkl(table, dirfd);
}

int read_guest_string(const struct kbox_supervisor_ctx *ctx,
                      pid_t pid,
                      uint64_t addr,
                      char *buf,
                      size_t size)
{
    return guest_mem_read_string(ctx, pid, addr, buf, size);
}

static struct kbox_translated_path_cache_entry *find_translated_path_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *guest_path)
{
    size_t i;

    if (!ctx || !guest_path)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        struct kbox_translated_path_cache_entry *entry =
            &ctx->translated_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            strcmp(entry->guest_path, guest_path) == 0) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_translated_path_cache_entry *reserve_translated_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        if (!ctx->translated_path_cache[i].valid)
            return &ctx->translated_path_cache[i];
    }
    return &ctx->translated_path_cache[0];
}

static struct kbox_literal_path_cache_entry *find_literal_path_cache(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    uint64_t guest_addr)
{
    size_t i;

    if (!ctx || guest_addr == 0)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        struct kbox_literal_path_cache_entry *entry =
            &ctx->literal_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            entry->pid == pid && entry->guest_addr == guest_addr) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_literal_path_cache_entry *reserve_literal_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        if (!ctx->literal_path_cache[i].valid)
            return &ctx->literal_path_cache[i];
    }
    return &ctx->literal_path_cache[0];
}

int guest_addr_is_writable(pid_t pid, uint64_t addr)
{
    char maps_path[64];
    FILE *fp;
    char line[256];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return 1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3)
            continue;
        if (addr < start || addr >= end)
            continue;
        fclose(fp);
        return strchr(perms, 'w') != NULL;
    }

    fclose(fp);
    return 1;
}

struct guest_file_backing_interval {
    uint64_t file_start;
    uint64_t file_end;
    unsigned long long inode;
    char dev[32];
};

int guest_range_has_shared_file_write_mapping(pid_t pid,
                                              uint64_t addr,
                                              uint64_t len)
{
    char maps_path[64];
    FILE *fp;
    char line[512];
    uint64_t end_addr;
    struct guest_file_backing_interval *targets = NULL;
    size_t target_count = 0;
    size_t target_cap = 0;
    int rc = 0;

    if (len == 0)
        return 0;
    if (__builtin_add_overflow(addr, len, &end_addr))
        end_addr = UINT64_MAX;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, inode;
        unsigned long long offset;
        char perms[8];
        char dev[32];
        uint64_t overlap_start;
        uint64_t overlap_end;
        struct guest_file_backing_interval *new_targets;

        if (sscanf(line, "%llx-%llx %7s %llx %31s %llu", &start, &end, perms,
                   &offset, dev, &inode) != 6)
            continue;
        if (inode == 0)
            continue;
        if (end <= addr || start >= end_addr)
            continue;
        if (strchr(perms, 's') == NULL)
            continue;
        overlap_start = addr > start ? addr : (uint64_t) start;
        overlap_end = end_addr < end ? end_addr : (uint64_t) end;
        if (overlap_start >= overlap_end)
            continue;
        if (target_count == target_cap) {
            size_t new_cap = target_cap == 0 ? 4 : target_cap * 2;

            new_targets = realloc(targets, new_cap * sizeof(*targets));
            if (!new_targets) {
                rc = -1;
                goto out;
            }
            targets = new_targets;
            target_cap = new_cap;
        }
        if (__builtin_add_overflow((uint64_t) offset,
                                   overlap_start - (uint64_t) start,
                                   &targets[target_count].file_start)) {
            rc = -1;
            goto out;
        }
        if (__builtin_add_overflow(targets[target_count].file_start,
                                   overlap_end - overlap_start,
                                   &targets[target_count].file_end)) {
            rc = -1;
            goto out;
        }
        targets[target_count].inode = inode;
        memcpy(targets[target_count].dev, dev,
               sizeof(targets[target_count].dev));
        targets[target_count].dev[sizeof(targets[target_count].dev) - 1] = '\0';
        target_count++;
    }

    fclose(fp);
    fp = NULL;

    if (target_count == 0)
        goto out;

    fp = fopen(maps_path, "re");
    if (!fp) {
        rc = -1;
        goto out;
    }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, inode;
        unsigned long long offset;
        char perms[8];
        char dev[32];
        uint64_t map_file_start;
        uint64_t map_file_end;
        size_t i;

        if (sscanf(line, "%llx-%llx %7s %llx %31s %llu", &start, &end, perms,
                   &offset, dev, &inode) != 6)
            continue;
        if (inode == 0)
            continue;
        if (strchr(perms, 's') == NULL || strchr(perms, 'w') == NULL)
            continue;
        map_file_start = (uint64_t) offset;
        if (__builtin_add_overflow(map_file_start,
                                   (uint64_t) end - (uint64_t) start,
                                   &map_file_end)) {
            rc = -1;
            goto out;
        }
        for (i = 0; i < target_count; i++) {
            if (targets[i].inode != inode)
                continue;
            if (strcmp(targets[i].dev, dev) != 0)
                continue;
            if (map_file_end <= targets[i].file_start ||
                map_file_start >= targets[i].file_end) {
                continue;
            }
            rc = 1;
            goto out;
        }
    }

out:
    if (fp)
        fclose(fp);
    free(targets);
    return rc;
}

void invalidate_translated_path_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    ctx->path_translation_generation++;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++)
        ctx->translated_path_cache[i].valid = 0;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++)
        ctx->literal_path_cache[i].valid = 0;
}

int translate_guest_path(const struct kbox_supervisor_ctx *ctx,
                         pid_t pid,
                         uint64_t addr,
                         const char *host_root,
                         char *translated,
                         size_t size)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    char pathbuf[KBOX_MAX_PATH];
    struct kbox_literal_path_cache_entry *literal_entry;
    struct kbox_translated_path_cache_entry *entry;

    literal_entry = find_literal_path_cache(mutable_ctx, pid, addr);
    if (literal_entry) {
        size_t len = strlen(literal_entry->translated);

        if (len >= size)
            return -ENAMETOOLONG;
        memcpy(translated, literal_entry->translated, len + 1);
        return 0;
    }

    int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return rc;

    entry = find_translated_path_cache(mutable_ctx, pathbuf);
    if (entry) {
        if (strlen(entry->translated) >= size)
            return -ENAMETOOLONG;
        memcpy(translated, entry->translated, strlen(entry->translated) + 1);
        return 0;
    }

    rc = kbox_translate_path_for_lkl(pid, pathbuf, host_root, translated, size);
    if (rc < 0)
        return rc;

    entry = reserve_translated_path_cache(mutable_ctx);
    if (entry) {
        entry->valid = 1;
        entry->generation = mutable_ctx->path_translation_generation;
        strncpy(entry->guest_path, pathbuf, sizeof(entry->guest_path) - 1);
        entry->guest_path[sizeof(entry->guest_path) - 1] = '\0';
        strncpy(entry->translated, translated, sizeof(entry->translated) - 1);
        entry->translated[sizeof(entry->translated) - 1] = '\0';
    }

    if (!guest_addr_is_writable(pid, addr)) {
        literal_entry = reserve_literal_path_cache(mutable_ctx);
        if (literal_entry) {
            literal_entry->valid = 1;
            literal_entry->generation =
                mutable_ctx->path_translation_generation;
            literal_entry->pid = pid;
            literal_entry->guest_addr = addr;
            strncpy(literal_entry->translated, translated,
                    sizeof(literal_entry->translated) - 1);
            literal_entry->translated[sizeof(literal_entry->translated) - 1] =
                '\0';
        }
    }
    return 0;
}

int translate_request_path(const struct kbox_syscall_request *req,
                           const struct kbox_supervisor_ctx *ctx,
                           size_t path_idx,
                           const char *host_root,
                           char *translated,
                           size_t size)
{
    return translate_guest_path(ctx, kbox_syscall_request_pid(req),
                                kbox_syscall_request_arg(req, path_idx),
                                host_root, translated, size);
}

static int read_tracee_fd_link(pid_t pid, long fd, char *out, size_t out_size)
{
    char link_path[64];
    ssize_t n;

    if (pid <= 0 || fd < 0 || !out || out_size == 0)
        return -1;
    snprintf(link_path, sizeof(link_path), /* format-ok */
             "/proc/%d/fd/%ld", (int) pid, fd);
    n = readlink(link_path, out, out_size - 1);
    if (n < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

static bool host_dirfd_targets_proc(pid_t pid, long fd)
{
    char target[KBOX_MAX_PATH];

    if (pid <= 0 || read_tracee_fd_link(pid, fd, target, sizeof(target)) < 0)
        return false;

    if (strcmp(target, "/proc") == 0)
        return true;
    return strncmp(target, "/proc/", 6) == 0;
}

static bool path_has_prefix_dir(const char *path,
                                const char *prefix,
                                size_t prefix_len)
{
    if (prefix_len == 1 && prefix[0] == '/')
        return path[0] == '/';
    if (strncmp(path, prefix, prefix_len) != 0)
        return false;
    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

static int resolve_host_fd_guest_bind(const struct kbox_supervisor_ctx *ctx,
                                      pid_t pid,
                                      long fd,
                                      char *guest_out,
                                      size_t guest_out_size,
                                      int *ro_out)
{
    char target[KBOX_MAX_PATH];
    const struct kbox_host_bind *best = NULL;
    size_t best_hlen = 0;

    if (!ctx || ctx->host_bind_count == 0 || fd < 0)
        return 0;
    if (read_tracee_fd_link(pid, fd, target, sizeof(target)) < 0)
        return 0;

    for (size_t i = 0; i < ctx->host_bind_count; i++) {
        const struct kbox_host_bind *b = &ctx->host_binds[i];
        size_t hlen = strlen(b->host_path);
        if (path_has_prefix_dir(target, b->host_path, hlen) &&
            hlen >= best_hlen) {
            best = b;
            best_hlen = hlen;
        }
    }
    if (!best)
        return 0;

    if (ro_out)
        *ro_out = best->readonly;
    if (guest_out && guest_out_size > 0) {
        const char *tail = (best_hlen == 1 && best->host_path[0] == '/')
                               ? target
                               : target + best_hlen;
        int wn;
        if (tail[0] == '\0')
            wn = snprintf(guest_out, guest_out_size, "%s", best->guest_path);
        else if (best->guest_len == 1 && best->guest_path[0] == '/')
            wn = snprintf(guest_out, guest_out_size, "%s", tail);
        else
            wn = snprintf(guest_out, guest_out_size, "%s%s", best->guest_path,
                          tail);
        if (wn < 0 || (size_t) wn >= guest_out_size)
            return -ENAMETOOLONG;
    }
    return 1;
}

static int resolve_guest_cwd(const struct kbox_supervisor_ctx *ctx,
                             char *cwd_out,
                             size_t cwd_size)
{
    if (!ctx || !cwd_out || cwd_size == 0)
        return -EINVAL;
    if (ctx->host_cwd[0] != '\0') {
        int n = snprintf(cwd_out, cwd_size, "%s", ctx->host_cwd);
        return (n < 0 || (size_t) n >= cwd_size) ? -ENAMETOOLONG : 0;
    }
    long ret = kbox_lkl_getcwd(ctx->sysnrs, cwd_out, (long) cwd_size);
    if (ret < 0)
        return (int) ret;
    return 0;
}

int kbox_parse_host_volume(const char *spec, struct kbox_host_bind *out)
{
    char raw_host[KBOX_MAX_PATH];
    char raw_dst[KBOX_MAX_PATH];
    char resolved_host[KBOX_MAX_PATH];
    const char *c1;
    const char *c2;
    size_t hlen, dlen;

    if (!spec || !out || spec[0] == '\0')
        return -1;
    memset(out, 0, sizeof(*out));

    /* "nfs://<name>[/subdir]:<dest>[:ro]" — the scheme name is hard-coded and
     * is not a host path, so the first colon cannot be the separator. The
     * reference part is kept verbatim and resolved by the daemon against the
     * "mounts:" section of the config.
     */
    if (strncmp(spec, "nfs://", 6) == 0) {
        const char *sep = strchr(spec + 6, ':');
        if (!sep || sep == spec + 6)
            return -1;
        hlen = (size_t) (sep - spec);
        if (hlen >= sizeof(raw_host))
            return -1;
        memcpy(raw_host, spec, hlen);
        raw_host[hlen] = '\0';

        c1 = sep; /* destination starts here, parsed by the common path below */
        out->is_nfs = 1;
        snprintf(out->host_path, sizeof(out->host_path), "%s", raw_host);
    } else {
        c1 = strchr(spec, ':');
        if (!c1 || c1 == spec)
            return -1;
        hlen = (size_t) (c1 - spec);
        if (hlen >= sizeof(raw_host))
            return -1;
        memcpy(raw_host, spec, hlen);
        raw_host[hlen] = '\0';
    }

    const char *dst_start = c1 + 1;
    c2 = strchr(dst_start, ':');
    dlen = c2 ? (size_t) (c2 - dst_start) : strlen(dst_start);
    if (dlen == 0 || dlen >= sizeof(raw_dst) || dst_start[0] != '/')
        return -1;
    memcpy(raw_dst, dst_start, dlen);
    raw_dst[dlen] = '\0';

    if (kbox_normalize_join("/", raw_dst, out->guest_path,
                            sizeof(out->guest_path)) < 0)
        return -1;

    if (out->is_nfs) {
        out->guest_len = strlen(out->guest_path);
        goto parse_mode;
    }

    if (realpath(raw_host, resolved_host) != NULL) {
        snprintf(out->host_path, sizeof(out->host_path), "%s", resolved_host);
    } else if (raw_host[0] == '/') {
        if (kbox_normalize_join("/", raw_host, out->host_path,
                                sizeof(out->host_path)) < 0)
            return -1;
    } else {
        char cwd[KBOX_MAX_PATH];
        if (!getcwd(cwd, sizeof(cwd)))
            return -1;
        if (kbox_normalize_join(cwd, raw_host, out->host_path,
                                sizeof(out->host_path)) < 0)
            return -1;
    }

    size_t host_len = strlen(out->host_path);
    while (host_len > 1 && out->host_path[host_len - 1] == '/') {
        out->host_path[--host_len] = '\0';
    }
    out->guest_len = strlen(out->guest_path);

parse_mode:
    if (c2 && c2[1] != '\0') {
        const char *p = c2 + 1;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t tok_len = comma ? (size_t) (comma - p) : strlen(p);
            if (tok_len == 2 && strncmp(p, "ro", 2) == 0)
                out->readonly = 1;
            else if (tok_len == 2 && strncmp(p, "rw", 2) == 0)
                out->readonly = 0;
            if (!comma)
                break;
            p = comma + 1;
        }
    }
    return 0;
}

static int resolve_host_bind_canonical(const struct kbox_supervisor_ctx *ctx,
                                       long raw_dirfd,
                                       const char *guest_path,
                                       char *norm_out,
                                       size_t norm_size,
                                       char *host_out,
                                       size_t host_out_size,
                                       int *ro_out)
{
    char norm_buf[KBOX_MAX_PATH];
    const struct kbox_host_bind *best = NULL;

    if (!norm_out) {
        norm_out = norm_buf;
        norm_size = sizeof(norm_buf);
    }
    if (!ctx || !guest_path || guest_path[0] == '\0')
        return 0;

    if (guest_path[0] == '/') {
        if (kbox_normalize_join("/", guest_path, norm_out, norm_size) < 0)
            return -ENAMETOOLONG;
    } else if (raw_dirfd == AT_FDCWD_LINUX) {
        char cwd[KBOX_MAX_PATH];
        int crc = resolve_guest_cwd(ctx, cwd, sizeof(cwd));
        if (crc < 0)
            return 0;
        if (kbox_normalize_join(cwd, guest_path, norm_out, norm_size) < 0)
            return -ENAMETOOLONG;
    } else {
        return 0;
    }

    if (ctx->host_bind_count == 0)
        return 0;

    for (size_t i = 0; i < ctx->host_bind_count; i++) {
        const struct kbox_host_bind *b = &ctx->host_binds[i];
        /* NFS volumes are real mounts inside the guest kernel, not paths to
         * redirect at dispatch time. */
        if (b->is_nfs)
            continue;
        if (path_has_prefix_dir(norm_out, b->guest_path, b->guest_len)) {
            if (!best || b->guest_len >= best->guest_len)
                best = b;
        }
    }
    if (!best)
        return 0;

    const char *tail = (best->guest_len == 1 && best->guest_path[0] == '/')
                           ? norm_out
                           : norm_out + best->guest_len;
    int wn;
    if (tail[0] == '\0')
        wn = snprintf(host_out, host_out_size, "%s", best->host_path);
    else if (strcmp(best->host_path, "/") == 0)
        wn = snprintf(host_out, host_out_size, "%s", tail);
    else
        wn = snprintf(host_out, host_out_size, "%s%s", best->host_path, tail);
    if (wn < 0 || (size_t) wn >= host_out_size)
        return -ENAMETOOLONG;

    if (ro_out)
        *ro_out = best->readonly;
    return 1;
}

static void lkl_mkdir_p_best_effort(const struct kbox_sysnrs *sysnrs,
                                    const char *path)
{
    char buf[KBOX_MAX_PATH];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof(buf))
        return;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            kbox_lkl_mkdir(sysnrs, buf, 0755);
            *p = '/';
        }
    }
    kbox_lkl_mkdir(sysnrs, buf, 0755);
}

int kbox_ensure_lkl_bind_stubs(const struct kbox_sysnrs *sysnrs,
                               const struct kbox_host_bind *binds,
                               size_t count)
{
    if (!sysnrs || !binds)
        return 0;
    for (size_t i = 0; i < count; i++) {
        const struct kbox_host_bind *b = &binds[i];
        struct stat st;
        int is_dir = 1;

        /* NFS volumes are bind-mounted by the daemon, not stubbed here. */
        if (b->is_nfs)
            continue;
        if (stat(b->host_path, &st) == 0 && !S_ISDIR(st.st_mode))
            is_dir = 0;
        if (is_dir) {
            lkl_mkdir_p_best_effort(sysnrs, b->guest_path);
        } else {
            const char *slash = strrchr(b->guest_path, '/');
            if (slash && slash > b->guest_path) {
                char parent[KBOX_MAX_PATH];
                size_t plen = (size_t) (slash - b->guest_path);
                if (plen < sizeof(parent)) {
                    memcpy(parent, b->guest_path, plen);
                    parent[plen] = '\0';
                    lkl_mkdir_p_best_effort(sysnrs, parent);
                }
            }
            long fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, b->guest_path,
                                      O_CREAT | O_WRONLY, 0644);
            if (fd >= 0)
                kbox_lkl_close(sysnrs, fd);
        }
    }
    return 0;
}

int kbox_resolve_host_bind_at(const struct kbox_supervisor_ctx *ctx,
                              long raw_dirfd,
                              const char *guest_path,
                              char *host_out,
                              size_t host_out_size,
                              int *ro_out)
{
    return resolve_host_bind_canonical(ctx, raw_dirfd, guest_path, NULL, 0,
                                       host_out, host_out_size, ro_out);
}

int open_host_dirfd_for_dispatch(pid_t pid,
                                 long raw_dirfd,
                                 long lkl_dirfd,
                                 int *sv_dirfd_out,
                                 int *close_out)
{
    if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND ||
        lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO) {
        *sv_dirfd_out = AT_FDCWD;
        *close_out = 0;
        return 0;
    }
    int fd = dup_tracee_fd(pid, (int) raw_dirfd);
    if (fd < 0)
        return fd;
    *sv_dirfd_out = fd;
    *close_out = 1;
    return 0;
}

int host_bind_is_readonly(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          long raw_dirfd,
                          long lkl_dirfd)
{
    int ro = 0;

    if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO)
        return 1;
    if (lkl_dirfd == -1 && raw_dirfd >= 0) {
        if (resolve_host_fd_guest_bind(ctx, pid, raw_dirfd, NULL, 0, &ro) > 0)
            return ro;
    }
    return 0;
}

static int translate_request_path_or_bind(
    const struct kbox_syscall_request *req,
    const struct kbox_supervisor_ctx *ctx,
    size_t path_idx,
    char *translated,
    size_t size,
    long *lkl_dirfd_out)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr = kbox_syscall_request_arg(req, path_idx);

    if (ctx->host_bind_count > 0 || ctx->host_cwd[0] != '\0') {
        char pathbuf[KBOX_MAX_PATH];
        char norm[KBOX_MAX_PATH];
        int ro = 0;
        int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        int brc =
            resolve_host_bind_canonical(ctx, AT_FDCWD_LINUX, pathbuf, norm,
                                        sizeof(norm), translated, size, &ro);
        if (brc < 0)
            return brc;
        if (brc > 0) {
            *lkl_dirfd_out =
                ro ? KBOX_LKL_DIRFD_HOST_BIND_RO : KBOX_LKL_DIRFD_HOST_BIND;
            return 0;
        }
        if (ctx->host_cwd[0] != '\0' && pathbuf[0] != '/') {
            int n = snprintf(translated, size, "%s", norm);
            if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
            *lkl_dirfd_out = AT_FDCWD_LINUX;
            return 0;
        }
    }

    *lkl_dirfd_out = AT_FDCWD_LINUX;
    return translate_request_path(req, ctx, path_idx, ctx->host_root,
                                  translated, size);
}

int translate_request_at_path(const struct kbox_syscall_request *req,
                              struct kbox_supervisor_ctx *ctx,
                              size_t dirfd_idx,
                              size_t path_idx,
                              char *translated,
                              size_t size,
                              long *lkl_dirfd)
{
    long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, dirfd_idx));

    /* If dirfd is not AT_FDCWD and not tracked in our FD table, this is a
     * host-kernel FD (e.g., from a CONTINUE'd openat on /proc or /sys).
     * For relative or empty paths the host kernel must resolve them against
     * that dirfd, so signal CONTINUE by setting *lkl_dirfd = -1.
     *
     * Reject unsafe relative lookups instead of translating them through LKL:
     * translating "../../etc/passwd" against the guest cwd would silently
     * change syscall semantics, and continuing it against the host dirfd could
     * escape the virtual namespace.
     *
     * For absolute paths dirfd is irrelevant and normal translation proceeds.
     */
    if (raw_dirfd != AT_FDCWD_LINUX && raw_dirfd >= 0 &&
        kbox_fd_table_get_lkl(ctx->fd_table, raw_dirfd) < 0) {
        char pathbuf[KBOX_MAX_PATH];
        pid_t req_pid = kbox_syscall_request_pid(req);
        bool proc_dirfd = host_dirfd_targets_proc(req_pid, raw_dirfd);
        int rc = read_guest_string(ctx, req_pid,
                                   kbox_syscall_request_arg(req, path_idx),
                                   pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        if (pathbuf[0] != '/') {
            if (kbox_relative_path_has_dotdot(pathbuf) ||
                (proc_dirfd && kbox_relative_proc_escape_path(pathbuf))) {
                return -EPERM;
            }
            *lkl_dirfd = -1;
            int n = snprintf(translated, size, "%s", pathbuf);
            if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
            return 0;
        }
        /* Absolute path: dirfd is ignored, so normal translation is safe. */
    }

    if (ctx->host_bind_count > 0 || ctx->host_cwd[0] != '\0') {
        char pathbuf[KBOX_MAX_PATH];
        char norm[KBOX_MAX_PATH];
        int ro = 0;
        int rc = read_guest_string(ctx, kbox_syscall_request_pid(req),
                                   kbox_syscall_request_arg(req, path_idx),
                                   pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        int brc = resolve_host_bind_canonical(
            ctx, raw_dirfd, pathbuf, norm, sizeof(norm), translated, size, &ro);
        if (brc < 0)
            return brc;
        if (brc > 0) {
            *lkl_dirfd =
                ro ? KBOX_LKL_DIRFD_HOST_BIND_RO : KBOX_LKL_DIRFD_HOST_BIND;
            return 0;
        }
        if (ctx->host_cwd[0] != '\0' && raw_dirfd == AT_FDCWD_LINUX &&
            pathbuf[0] != '/') {
            int n = snprintf(translated, size, "%s", norm);
            if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
            *lkl_dirfd = AT_FDCWD_LINUX;
            return 0;
        }
    }

    int rc = translate_request_path(req, ctx, path_idx, ctx->host_root,
                                    translated, size);
    if (rc < 0)
        return rc;

    *lkl_dirfd = resolve_open_dirfd(translated, raw_dirfd, ctx->fd_table);
    return 0;
}

int should_continue_for_dirfd(long lkl_dirfd)
{
    if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND ||
        lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO)
        return 1;
    return lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX;
}

int child_fd_is_open(const struct kbox_supervisor_ctx *ctx, long fd)
{
    char link_path[64];
    char target[1];

    if (!ctx || ctx->child_pid <= 0 || fd < 0)
        return 0;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%ld",
             (int) ctx->child_pid, fd);
    if (readlink(link_path, target, sizeof(target)) >= 0)
        return 1;
    return errno != ENOENT;
}

long allocate_passthrough_hostonly_fd(struct kbox_supervisor_ctx *ctx)
{
    long base_fd = KBOX_FD_HOSTONLY_BASE;
    long end_fd = KBOX_FD_BASE + KBOX_FD_TABLE_MAX;
    long start_fd;
    long fd;

    if (!ctx || !ctx->fd_table)
        return -1;

    start_fd = ctx->fd_table->next_hostonly_fd;
    if (start_fd < base_fd || start_fd >= end_fd)
        start_fd = base_fd;

    for (fd = start_fd; fd < end_fd; fd++) {
        if (!child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_hostonly_fd = fd + 1;
            return fd;
        }
    }
    for (fd = base_fd; fd < start_fd; fd++) {
        if (!child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_hostonly_fd = fd + 1;
            return fd;
        }
    }

    return -1;
}

long next_hostonly_fd_hint(const struct kbox_supervisor_ctx *ctx)
{
    long fd;
    long end_fd = KBOX_FD_BASE + KBOX_FD_TABLE_MAX;

    if (!ctx || !ctx->fd_table)
        return -1;

    fd = ctx->fd_table->next_hostonly_fd;
    if (fd < KBOX_FD_HOSTONLY_BASE || fd >= end_fd)
        fd = KBOX_FD_HOSTONLY_BASE;
    return fd;
}

static long allocate_shadow_fd_from(struct kbox_supervisor_ctx *ctx,
                                    long min_fd)
{
    long base_fd = KBOX_FD_FAST_BASE;
    long end_fd = KBOX_FD_HOSTONLY_BASE;
    long start_fd;
    long fd;

    if (!ctx || !ctx->fd_table || min_fd >= end_fd)
        return -1;
    if (min_fd < base_fd)
        min_fd = base_fd;

    start_fd = ctx->fd_table->next_fast_fd;
    if (start_fd < min_fd || start_fd >= end_fd)
        start_fd = min_fd;

    for (fd = start_fd; fd < end_fd; fd++) {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

        if (entry && entry->lkl_fd == -1 && !child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_fast_fd = fd + 1;
            return fd;
        }
    }
    for (fd = min_fd; fd < start_fd; fd++) {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

        if (entry && entry->lkl_fd == -1 && !child_fd_is_open(ctx, fd)) {
            ctx->fd_table->next_fast_fd = fd + 1;
            return fd;
        }
    }

    return -1;
}

static long allocate_writable_shadow_fd(struct kbox_supervisor_ctx *ctx)
{
    return allocate_shadow_fd_from(ctx, KBOX_FD_FAST_BASE);
}

int ensure_proc_self_fd_dir(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx)
        return -1;
    if (ctx->proc_self_fd_dirfd >= 0)
        return ctx->proc_self_fd_dirfd;

    ctx->proc_self_fd_dirfd =
        open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return ctx->proc_self_fd_dirfd;
}

int ensure_proc_mem_fd(struct kbox_supervisor_ctx *ctx)
{
    char path[64];

    if (!ctx || ctx->child_pid <= 0)
        return -1;
    if (ctx->proc_mem_fd >= 0)
        return ctx->proc_mem_fd;

    snprintf(path, sizeof(path), "/proc/%d/mem", (int) ctx->child_pid);
    ctx->proc_mem_fd = open(path, O_RDWR | O_CLOEXEC);
    return ctx->proc_mem_fd;
}

int guest_mem_write_small_metadata(const struct kbox_supervisor_ctx *ctx,
                                   pid_t pid,
                                   uint64_t remote_addr,
                                   const void *in,
                                   size_t len)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    ssize_t n;
    int fd;

    if (!ctx || !in)
        return -EFAULT;
    if (len == 0)
        return 0;
    if (remote_addr == 0)
        return -EFAULT;
    if (pid != ctx->child_pid ||
        ctx->active_guest_mem.ops != &kbox_process_vm_guest_mem_ops)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    fd = ensure_proc_mem_fd(mutable_ctx);
    if (fd < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);
    if ((size_t) n != len)
        return -EIO;
    return 0;
}

/* Build the host-side path for a guest-relative (translated) path.
 * Only valid when host_root is set (host-directory rootfs mode): translated is
 * relative to host_root (stripped by kbox_translate_path_for_lkl). When
 * host_root is NULL (image / daemon LKL-rootfs modes), there is no host rootfs
 * directory and files must be served from LKL, never the supervisor's own `/`.
 */
static int build_host_open_path(const struct kbox_supervisor_ctx *ctx,
                                const char *translated,
                                char *out,
                                size_t out_size)
{
    int n;

    if (!ctx || !ctx->host_root)
        return -1;

    /* translated is absolute (starts with '/'), skip the leading '/' when
     * joining to avoid double-slash.
     */
    const char *tail = translated;
    if (*tail == '/')
        tail++;
    n = snprintf(out, out_size, "%s/%s", ctx->host_root, tail);
    return (n >= 0 && (size_t) n < out_size) ? 0 : -1;
}

int reopen_cached_shadow_fd(struct kbox_supervisor_ctx *ctx,
                            const struct kbox_path_shadow_cache_entry *entry)
{
    char fd_name[32];
    int dirfd;
    int fd;

    if (!entry)
        return -1;
    if (entry->path[0] != '\0') {
        char host_path[KBOX_MAX_PATH];
        if (build_host_open_path(ctx, entry->path, host_path,
                                 sizeof(host_path)) == 0) {
            fd = open(host_path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0)
                return fd;
        }
    }
    fd = entry->memfd;
    if (fd < 0)
        return -1;
    dirfd = ensure_proc_self_fd_dir(ctx);
    if (dirfd < 0)
        return -1;
    snprintf(fd_name, sizeof(fd_name), "%d", fd);
    return openat(dirfd, fd_name, O_RDONLY | O_CLOEXEC);
}

static int find_writeback_sp_in_range(const struct kbox_supervisor_ctx *ctx,
                                      const struct kbox_fd_entry *entries,
                                      long count,
                                      long target_lkl_fd,
                                      const struct kbox_lkl_stat *target_st)
{
    for (long i = 0; i < count; i++) {
        const struct kbox_fd_entry *cand = &entries[i];
        struct kbox_lkl_stat cand_st;

        if (cand->lkl_fd < 0 || !cand->shadow_writeback || cand->shadow_sp < 0)
            continue;
        if (cand->lkl_fd == target_lkl_fd)
            return cand->shadow_sp;
        memset(&cand_st, 0, sizeof(cand_st));
        if (kbox_lkl_fstat(ctx->sysnrs, cand->lkl_fd, &cand_st) == 0 &&
            cand_st.st_dev == target_st->st_dev &&
            cand_st.st_ino == target_st->st_ino) {
            return cand->shadow_sp;
        }
    }
    return -1;
}

int kbox_find_active_writeback_shadow_sp(struct kbox_supervisor_ctx *ctx,
                                         long lkl_fd)
{
    struct kbox_lkl_stat target_st;
    int sp;

    if (!ctx || !ctx->fd_table || ctx->active_writeback_shadows == 0 ||
        lkl_fd < 0)
        return -1;

    memset(&target_st, 0, sizeof(target_st));
    if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &target_st) < 0)
        return -1;

    sp = find_writeback_sp_in_range(ctx, ctx->fd_table->entries,
                                    KBOX_FD_TABLE_MAX, lkl_fd, &target_st);
    if (sp >= 0)
        return sp;
    sp = find_writeback_sp_in_range(ctx, ctx->fd_table->low_fds,
                                    KBOX_LOW_FD_MAX, lkl_fd, &target_st);
    if (sp >= 0)
        return sp;
    return find_writeback_sp_in_range(ctx, ctx->fd_table->mid_fds,
                                      KBOX_MID_FD_MAX, lkl_fd, &target_st);
}

int kbox_reopen_writeback_shadow_ro(struct kbox_supervisor_ctx *ctx,
                                    long lkl_fd,
                                    int *out_memfd)
{
    int sp = kbox_find_active_writeback_shadow_sp(ctx, lkl_fd);
    int dirfd;
    char fd_name[32];
    int ro_fd;

    if (sp < 0 || !out_memfd)
        return 0;

    dirfd = ensure_proc_self_fd_dir(ctx);
    if (dirfd < 0)
        return 0;

    snprintf(fd_name, sizeof(fd_name), "%d", sp);
    ro_fd = openat(dirfd, fd_name, O_RDONLY | O_CLOEXEC);
    if (ro_fd < 0)
        return 0;

    *out_memfd = ro_fd;
    return 1;
}

/* Promote a read-only regular LKL FD to a host-visible shadow at the same guest
 * FD number on first eligible read-only access. This avoids paying memfd copy
 * cost at open time while still letting later read/lseek/fstat/mmap operations
 * run on a real host FD.
 *
 * Returns:
 *   1  shadow is available (same-fd injected for seccomp, local-only for
 *      trap/rewrite)
 *   0  shadow promotion not applicable
 *  -1  promotion attempted but failed
 */
int ensure_same_fd_shadow(struct kbox_supervisor_ctx *ctx,
                          const struct kbox_syscall_request *req,
                          long fd,
                          long lkl_fd)
{
    struct kbox_fd_entry *entry;
    long flags;
    int memfd;

    off_t cur_off;

    if (!ctx || !req || !ctx->fd_table || fd < 0 || lkl_fd < 0)
        return 0;

    entry = fd_table_entry(ctx->fd_table, fd);
    if (!entry)
        return 0;
    if (entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ||
        entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
        return 1;
    }
    if (entry->host_fd >= 0)
        return 0;

    flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY)
        return 0;

    if (!kbox_reopen_writeback_shadow_ro(ctx, lkl_fd, &memfd)) {
        memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
        if (memfd < 0)
            return -1;
        kbox_shadow_seal(memfd);
    }

    cur_off = (off_t) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, 0, SEEK_CUR);
    if (cur_off >= 0 && lseek(memfd, cur_off, SEEK_SET) < 0) {
        close(memfd);
        return -1;
    }

    /* Keep lazy read shadows local to the supervisor in all modes.
     * Injecting them at the guest FD number lets read(2)/lseek(2) CONTINUE,
     * but it reintroduces a close/open reuse race under concurrent seccomp
     * notifications. The local-shadow handlers already cover read/lseek/fstat
     * safely, so prefer them over same-fd injection here.
     */
    entry->host_fd = KBOX_FD_LOCAL_ONLY_SHADOW;
    entry->shadow_sp = memfd;
    entry->shadow_writeback = 0;

    if (ctx->verbose) {
        fprintf(stderr, "kbox: lazy shadow promote fd=%ld lkl_fd=%ld mode=%s\n",
                fd, lkl_fd,
                entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ? "same-fd"
                                                              : "local-only");
    }
    return 1;
}

static struct kbox_dispatch forward_local_shadow_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd,
    int is_pread)
{
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count;
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;
    pid_t pid = kbox_syscall_request_pid(req);

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        ssize_t nr;

        if (chunk_len > count - total)
            chunk_len = count - total;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            long pread_off;
            if (__builtin_add_overflow(offset, (long) total, &pread_off)) {
                if (total == 0)
                    return kbox_dispatch_errno(EOVERFLOW);
                break;
            }
            nr = pread(entry->shadow_sp, scratch, chunk_len, (off_t) pread_off);
        } else {
            nr = read(entry->shadow_sp, scratch, chunk_len);
        }
        if (nr < 0) {
            if (total == 0)
                return kbox_dispatch_errno(errno);
            break;
        }
        if (nr == 0)
            break;
        uint64_t remote;
        if (__builtin_add_overflow(remote_buf, (uint64_t) total, &remote)) {
            if (total == 0)
                return kbox_dispatch_errno(EFAULT);
            break;
        }
        if (guest_mem_write(ctx, pid, remote, scratch, (size_t) nr) < 0) {
            return kbox_dispatch_errno(EFAULT);
        }
        total += (size_t) nr;
        if ((size_t) nr < chunk_len)
            break;
    }

    if (!is_pread) {
        off_t cur_off = lseek(entry->shadow_sp, 0, SEEK_CUR);
        if (cur_off >= 0)
            (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) cur_off,
                                  SEEK_SET);
    }

    return kbox_dispatch_value((int64_t) total);
}

static struct kbox_dispatch forward_local_shadow_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd)
{
    long off;
    long whence;
    off_t ret;

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();

    off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    ret = lseek(entry->shadow_sp, (off_t) off, (int) whence);
    if (ret < 0)
        return kbox_dispatch_errno(errno);

    (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) ret, SEEK_SET);
    return kbox_dispatch_value((int64_t) ret);
}

/* statx struct field offsets (standard on x86_64 and aarch64). */
#define STATX_MODE_OFFSET 0x20
#define STATX_UID_OFFSET 0x48
#define STATX_GID_OFFSET 0x4c
#define STATX_BUF_SIZE 0x100

static struct kbox_dispatch finish_open_dispatch(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long lkl_fd,
    long flags,
    const char *translated)
{
    struct kbox_dispatch shadow_dispatch;

    if (req && try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                               &shadow_dispatch)) {
        return shadow_dispatch;
    }

    if (req && try_writeback_shadow_open(ctx, req, lkl_fd, flags, translated,
                                         &shadow_dispatch)) {
        return shadow_dispatch;
    }

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd,
                                    kbox_is_tty_like_path(translated));
    if (vfd < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(EMFILE);
    }
    fprintf(stderr, "kboxdbg: open %s -> vfd=%ld lkl=%ld\n",
            translated ? translated : "?", vfd, lkl_fd);
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
    return kbox_dispatch_value((int64_t) vfd);
}

void normalize_host_stat_if_needed(struct kbox_supervisor_ctx *ctx,
                                   const char *path,
                                   struct stat *host_stat)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    host_stat->st_mode = (host_stat->st_mode & S_IFMT) | (n_mode & ~S_IFMT);
    host_stat->st_uid = n_uid;
    host_stat->st_gid = n_gid;
}

void normalize_statx_if_needed(struct kbox_supervisor_ctx *ctx,
                               const char *path,
                               uint8_t *statx_buf)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    uint16_t mode_le = (uint16_t) n_mode;
    memcpy(&statx_buf[STATX_MODE_OFFSET], &mode_le, 2);
    memcpy(&statx_buf[STATX_UID_OFFSET], &n_uid, 4);
    memcpy(&statx_buf[STATX_GID_OFFSET], &n_gid, 4);
}

void invalidate_path_shadow_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        if (ctx->path_shadow_cache[i].valid &&
            ctx->path_shadow_cache[i].memfd >= 0) {
            close(ctx->path_shadow_cache[i].memfd);
        }
        memset(&ctx->path_shadow_cache[i], 0,
               sizeof(ctx->path_shadow_cache[i]));
        ctx->path_shadow_cache[i].memfd = -1;
    }
    invalidate_translated_path_cache(ctx);
}

static struct kbox_path_shadow_cache_entry *find_path_shadow_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;

    if (!ctx || !translated)
        return NULL;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        struct kbox_path_shadow_cache_entry *entry = &ctx->path_shadow_cache[i];
        if (entry->valid && strcmp(entry->path, translated) == 0)
            return entry;
    }
    return NULL;
}

static struct kbox_path_shadow_cache_entry *reserve_path_shadow_cache_slot(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;
    struct kbox_path_shadow_cache_entry *entry;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return entry;

    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        entry = &ctx->path_shadow_cache[i];
        if (!entry->valid)
            return entry;
    }

    entry = &ctx->path_shadow_cache[0];
    if (entry->memfd >= 0)
        close(entry->memfd);
    memset(entry, 0, sizeof(*entry));
    entry->memfd = -1;
    return entry;
}

int ensure_path_shadow_cache(struct kbox_supervisor_ctx *ctx,
                             const char *translated)
{
    struct kbox_path_shadow_cache_entry *entry;
    struct stat host_stat;
    int host_fd;

    if (!ctx || !translated || translated[0] == '\0' ||
        ctx->active_writeback_shadows > 0 ||
        kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return 1;

    {
        char host_path[KBOX_MAX_PATH];
        if (build_host_open_path(ctx, translated, host_path,
                                 sizeof(host_path)) < 0)
            return 0;
        host_fd = open(host_path, O_RDONLY | O_CLOEXEC);
    }
    if (host_fd < 0)
        return 0;

    if (fstat(host_fd, &host_stat) < 0) {
        close(host_fd);
        return 0;
    }
    if (!S_ISREG(host_stat.st_mode)) {
        close(host_fd);
        return 0;
    }
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    entry = reserve_path_shadow_cache_slot(ctx, translated);
    if (!entry) {
        close(host_fd);
        return 0;
    }

    entry->valid = 1;
    entry->memfd = host_fd;
    strncpy(entry->path, translated, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';
    entry->host_stat = host_stat;
    return 1;
}

int try_cached_shadow_open_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req,
                                    long flags,
                                    const char *translated,
                                    struct kbox_dispatch *out)
{
    struct kbox_path_shadow_cache_entry *entry;
    int injected;
    int dup_fd;

    if (!ctx || !req || !translated || !out)
        return 0;
    if ((flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (flags & ~(O_RDONLY | O_CLOEXEC))
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry || entry->memfd < 0)
        return 0;

    dup_fd = reopen_cached_shadow_fd(ctx, entry);
    if (dup_fd < 0)
        return 0;

    /* Let the kernel pick a fresh host-visible FD. Reusing a fixed target FD
     * races with concurrent close(2): the supervisor removes its bookkeeping
     * before the kernel replays the close, so another thread can reuse that FD
     * number and have the older close tear down the new file.
     */
    injected =
        request_addfd(ctx, req, dup_fd, (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    close(dup_fd);
    if (injected < 0)
        return 0;

    *out = kbox_dispatch_value((int64_t) injected);
    return 1;
}

int try_cached_shadow_stat_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const char *translated,
                                    uint64_t remote_stat,
                                    pid_t pid)
{
    struct kbox_path_shadow_cache_entry *entry;

    if (!ctx || !translated || remote_stat == 0)
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry)
        return 0;

    return guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                          &entry->host_stat,
                                          sizeof(entry->host_stat)) == 0;
}

void note_shadow_writeback_open(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || entry->shadow_writeback)
        return;
    entry->shadow_writeback = 1;
    ctx->active_writeback_shadows++;
    invalidate_path_shadow_cache(ctx);
}

void note_shadow_writeback_close(struct kbox_supervisor_ctx *ctx,
                                 struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || !entry->shadow_writeback)
        return;
    entry->shadow_writeback = 0;
    if (ctx->active_writeback_shadows > 0)
        ctx->active_writeback_shadows--;
}

static void sync_cloexec_writebacks_in_range(struct kbox_supervisor_ctx *ctx,
                                             struct kbox_fd_entry *entries,
                                             long count)
{
    long i;

    if (!ctx || !entries)
        return;
    for (i = 0; i < count; i++) {
        struct kbox_fd_entry *entry = &entries[i];

        if (entry->lkl_fd != -1 && entry->cloexec) {
            if (entry->lkl_fd >= 0)
                invalidate_stat_cache_fd(ctx, entry->lkl_fd);
            if (entry->shadow_writeback) {
                (void) sync_shadow_writeback(ctx, entry);
                note_shadow_writeback_close(ctx, entry);
            }
        }
    }
}

static void close_cloexec_range(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_entry *entries,
                                long count,
                                long base_fd)
{
    for (long i = 0; i < count; i++) {
        struct kbox_fd_entry *entry = &entries[i];
        if (entry->lkl_fd == -1 || !entry->cloexec)
            continue;
        long lkl = entry->lkl_fd;
        if (lkl == KBOX_LKL_FD_SHADOW_ONLY) {
            kbox_fd_table_remove(ctx->fd_table, base_fd + i);
            continue;
        }
        kbox_fd_table_remove(ctx->fd_table, base_fd + i);
        if (lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, lkl, 1);
    }
}

void close_cloexec_with_writeback(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->fd_table)
        return;

    sync_cloexec_writebacks_in_range(ctx, ctx->fd_table->low_fds,
                                     KBOX_LOW_FD_MAX);
    sync_cloexec_writebacks_in_range(ctx, ctx->fd_table->mid_fds,
                                     KBOX_MID_FD_MAX);
    sync_cloexec_writebacks_in_range(ctx, ctx->fd_table->entries,
                                     KBOX_FD_TABLE_MAX);
    close_cloexec_range(ctx, ctx->fd_table->low_fds, KBOX_LOW_FD_MAX, 0);
    close_cloexec_range(ctx, ctx->fd_table->mid_fds, KBOX_MID_FD_MAX,
                        KBOX_LOW_FD_MAX);
    close_cloexec_range(ctx, ctx->fd_table->entries, KBOX_FD_TABLE_MAX,
                        KBOX_FD_BASE);
}

static long remove_fd_table_entry_with_writeback(
    struct kbox_supervisor_ctx *ctx,
    long fd)
{
    struct kbox_fd_entry *entry;

    if (!ctx || !ctx->fd_table)
        return -1;

    entry = fd_table_entry(ctx->fd_table, fd);
    if (entry && entry->shadow_writeback) {
        (void) sync_shadow_writeback(ctx, entry);
        note_shadow_writeback_close(ctx, entry);
    }
    return kbox_fd_table_remove(ctx->fd_table, fd);
}

int try_writeback_shadow_open(struct kbox_supervisor_ctx *ctx,
                              const struct kbox_syscall_request *req,
                              long lkl_fd,
                              long flags,
                              const char *translated,
                              struct kbox_dispatch *out)
{
    struct kbox_fd_entry *entry;
    int memfd;
    long target_fd;
    int injected;

    if (!ctx || !req || !out || lkl_fd < 0 || !translated)
        return 0;
    if ((flags & O_ACCMODE) == O_RDONLY)
        return 0;
    if (kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (memfd < 0)
        return 0;
    /* Do NOT seal: this shadow is for a writable FD; the tracee needs
     * write access.  Only read-only shadows (ensure_same_fd_shadow) are
     * sealed.
     */

    target_fd = allocate_writable_shadow_fd(ctx);
    if (target_fd < 0) {
        close(memfd);
        return 0;
    }

    /* Install only in the fast-shadow band.  Host-only FDs are allowed to
     * close directly in BPF, which would bypass writeback, and kernel-picked
     * ADDFD results can also exceed the fd-table range.  Unlike the old
     * preallocation approach, the fd-table entry is published only after
     * ADDFD_AT succeeds and after child_fd_is_open() has verified that no
     * pending close still owns this tracee fd number.
     */
    injected = request_addfd_at(ctx, req, memfd, (int) target_fd,
                                (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected < 0) {
        close(memfd);
        return 0;
    }

    /* SECCOMP_ADDFD_FLAG_SETFD guarantees injected == target_fd on success.
     * A mismatch means the kernel API contract broke; the tracee would hold
     * an untracked FD we cannot revoke.  Crash loudly instead of leaking.
     */
    if (injected != target_fd) {
        fprintf(stderr,
                "kbox: ADDFD_AT returned %d, expected %ld -- aborting\n",
                injected, target_fd);
        abort();
    }

    /* allocate_writable_shadow_fd validated target_fd is in-range and free.
     * insert_at must not fail here; if it does, the tracee holds a live FD
     * with no supervisor bookkeeping.
     */
    if (kbox_fd_table_insert_at(ctx->fd_table, injected, lkl_fd, 0) < 0) {
        fprintf(stderr,
                "kbox: fd_table_insert_at(%d) failed after ADDFD -- aborting\n",
                injected);
        abort();
    }

    entry = fd_table_entry(ctx->fd_table, injected);
    entry->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    entry->shadow_sp = memfd;
    note_shadow_writeback_open(ctx, entry);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: writable shadow promote fd=%d lkl_fd=%ld path=%s\n",
                injected, lkl_fd, translated);
    }
    *out = kbox_dispatch_value((int64_t) injected);
    return 1;
}

typedef long (*kbox_getdents_fn)(const struct kbox_sysnrs *sysnrs,
                                 long fd,
                                 void *buf,
                                 long count);

static struct kbox_dispatch forward_getdents_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    kbox_getdents_fn getdents_fn)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    uint64_t remote_dirp = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count, n;
    uint8_t *buf;
    long ret;
    int wrc;

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);

    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (remote_dirp == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count > KBOX_IO_CHUNK_LEN)
        count = KBOX_IO_CHUNK_LEN;

    buf = dispatch_scratch;

    ret = getdents_fn(ctx->sysnrs, lkl_fd, buf, (long) count);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    n = (size_t) ret;
    if (n > count)
        return kbox_dispatch_errno(EIO);

    wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_dirp, buf,
                          n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value((int64_t) n);
}

int dup_tracee_fd(pid_t pid, int tracee_fd);

/* Gate a CONTINUE syscall that takes an FD in arg0.  Deny if the FD is
 * untracked and in a blocked range; otherwise let the host kernel handle it.
 */
static struct kbox_dispatch forward_fd_gated_continue(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))
        return kbox_dispatch_errno(EBADF);
    return kbox_dispatch_continue();
}

/* Gate epoll_ctl: two FD args (epfd=arg0, fd=arg2). */
static struct kbox_dispatch forward_epoll_ctl_gated(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long epfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long lkl_ep = kbox_fd_table_get_lkl(ctx->fd_table, epfd);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    /* A descriptor the table does not know about is not kbox's to refuse: the
     * call is continued to the host anyway, and the host returns EBADF by
     * itself when the descriptor really is invalid. Answering EBADF here
     * aborted postgres backends -- they register the client socket they
     * inherited from the postmaster, and kbox had no entry for that number, so
     * the backend died before it could serve a single query.
     */
    if (fd_should_deny_io_ctx(ctx->fd_table, epfd, lkl_ep) ||
        fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)) {
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: epoll_ctl untracked epfd=%ld lkl_ep=%ld fd=%ld "
                    "lkl_fd=%ld -> continue\n",
                    epfd, lkl_ep, fd, lkl_fd);
    }
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: epoll_ctl ok epfd=%ld fd=%ld lkl_fd=%ld\n", epfd,
                fd, lkl_fd);
    return kbox_dispatch_continue();
}

/* Translate /proc/self and /proc/thread-self references to the tracee's
 * actual PID so the supervisor operates on the tracee's proc entries rather
 * than its own.
 */
static int is_decimal_fd_str(const char *s)
{
    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return 0;
    }
    return 1;
}

void translate_proc_self(const char *path,
                         pid_t pid,
                         char *sv_path,
                         size_t sv_path_len)
{
    if (strncmp(path, "/proc/thread-self/", 18) == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/task/%d/%s", (int) pid,
                 (int) pid, path + 18);
    else if (strcmp(path, "/proc/thread-self") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/task/%d", (int) pid,
                 (int) pid);
    else if (strncmp(path, "/proc/self/", 11) == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/%s", (int) pid, path + 11);
    else if (strcmp(path, "/proc/self") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d", (int) pid);
    else if (strncmp(path, "/dev/fd/", 8) == 0 && is_decimal_fd_str(path + 8))
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/%s", (int) pid, path + 8);
    else if (strcmp(path, "/dev/fd") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd", (int) pid);
    else if (strcmp(path, "/dev/stdin") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/0", (int) pid);
    else if (strcmp(path, "/dev/stdout") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/1", (int) pid);
    else if (strcmp(path, "/dev/stderr") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/2", (int) pid);
    else
        snprintf(sv_path, sv_path_len, "%s", path);
}

/* Emulate an open that would otherwise CONTINUE to the host kernel, tracking
 * the resulting FD as host-passthrough.  The supervisor opens the file in its
 * own namespace, injects the FD into the tracee via ADDFD, and records it in
 * the FD table.  For /proc/self paths, the supervisor translates to
 * /proc/{pid} so the opened file reflects the tracee, not the supervisor.
 *
 * supervisor_dirfd: AT_FDCWD for absolute paths, or a supervisor-owned copy
 *                   of the tracee's dirfd (caller must close after return).
 */
static struct kbox_dispatch emulate_host_open_tracked(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    int supervisor_dirfd,
    const char *path,
    int host_flags,
    mode_t mode)
{
    char sv_path[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    translate_proc_self(path, pid, sv_path, sizeof(sv_path));

    int host_fd =
        openat(supervisor_dirfd, sv_path, host_flags & ~O_CLOEXEC, mode);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t af = (host_flags & O_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, af);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (host_flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);
    return kbox_dispatch_value(tracee_fd);
}

static int host_open_flags_write(long host_flags)
{
    return (host_flags & O_ACCMODE) != O_RDONLY ||
           (host_flags & (O_CREAT | O_TRUNC | O_APPEND));
}

static struct kbox_dispatch emulate_host_at_open_tracked(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long raw_dirfd,
    long lkl_dirfd,
    const char *translated,
    long host_flags,
    mode_t mode)
{
    pid_t pid = kbox_syscall_request_pid(req);

    if (host_open_flags_write(host_flags) &&
        host_bind_is_readonly(ctx, pid, raw_dirfd, lkl_dirfd))
        return kbox_dispatch_errno(EROFS);

    int sv_dirfd = AT_FDCWD;
    int close_sv = 0;
    int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd, &sv_dirfd,
                                           &close_sv);
    if (drc < 0)
        return kbox_dispatch_errno(-drc);

    struct kbox_dispatch d = emulate_host_open_tracked(
        ctx, req, sv_dirfd, translated, (int) host_flags, mode);
    if (close_sv)
        close(sv_dirfd);
    return d;
}

/* forward_openat. */

static struct kbox_dispatch forward_openat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long host_flags_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = host_to_lkl_open_flags(host_flags_raw);
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        return emulate_host_at_open_tracked(ctx, req, raw_dirfd, lkl_dirfd,
                                            translated, host_flags_raw,
                                            (mode_t) mode);
    }

    if (should_continue_virtual_path(ctx, req, 1, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags_raw, (mode_t) mode);

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    long ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

/* forward_openat2. */

static struct kbox_dispatch forward_openat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    struct kbox_open_how how;
    rc = guest_mem_read_open_how(ctx, kbox_syscall_request_pid(req),
                                 kbox_syscall_request_arg(req, 2),
                                 kbox_syscall_request_arg(req, 3), &how);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    long host_flags2_raw = (long) how.flags;
    how.flags = (uint64_t) host_to_lkl_open_flags((long) how.flags);

    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        return emulate_host_at_open_tracked(ctx, req, raw_dirfd, lkl_dirfd,
                                            translated, host_flags2_raw,
                                            (mode_t) how.mode);
    }

    if (should_continue_virtual_path(ctx, req, 1, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags2_raw,
                                         (mode_t) how.mode);

    if (((long) how.flags & O_ACCMODE) == O_RDONLY) {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, (long) how.flags,
                                            translated, &cached_dispatch)) {
            return cached_dispatch;
        }
    }

    long ret = kbox_lkl_openat2(ctx->sysnrs, lkl_dirfd, translated, &how,
                                (long) sizeof(how));
    if (ret == -ENOSYS) {
        if (how.resolve != 0)
            return kbox_dispatch_errno(EOPNOTSUPP);
        ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated,
                              (long) how.flags, (long) how.mode);
    }
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if (((long) how.flags & O_ACCMODE) != O_RDONLY ||
        ((long) how.flags & O_TRUNC)) {
        invalidate_path_shadow_cache(ctx);
    }
    return finish_open_dispatch(ctx, req, ret, (long) how.flags, translated);
}

/* forward_open_legacy (x86_64 open(2), nr=2). */

static struct kbox_dispatch forward_open_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd = AT_FDCWD_LINUX;
    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long host_flags_legacy = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = host_to_lkl_open_flags(host_flags_legacy);
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (should_continue_for_dirfd(lkl_dirfd)) {
        return emulate_host_at_open_tracked(ctx, req, AT_FDCWD_LINUX, lkl_dirfd,
                                            translated, host_flags_legacy,
                                            (mode_t) mode);
    }

    if (should_continue_virtual_path(ctx, req, 0, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags_legacy,
                                         (mode_t) mode);

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    long ret =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

int sync_shadow_writeback(struct kbox_supervisor_ctx *ctx,
                          struct kbox_fd_entry *entry)
{
    struct stat st;
    uint8_t *buf = NULL;
    off_t off = 0;

    if (!ctx || !entry || !entry->shadow_writeback || entry->shadow_sp < 0 ||
        entry->lkl_fd < 0)
        return 0;

    if (fstat(entry->shadow_sp, &st) < 0)
        return -errno;
    if (kbox_lkl_ftruncate(ctx->sysnrs, entry->lkl_fd, (long) st.st_size) < 0)
        return -EIO;
    if (lseek(entry->shadow_sp, 0, SEEK_SET) < 0)
        return -errno;

    buf = dispatch_scratch;

    while (off < st.st_size) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        ssize_t rd;
        long wr;

        if ((off_t) chunk > st.st_size - off)
            chunk = (size_t) (st.st_size - off);
        rd = read(entry->shadow_sp, buf, chunk);
        if (rd < 0)
            return -errno;
        if (rd == 0)
            break;
        wr = kbox_lkl_pwrite64(ctx->sysnrs, entry->lkl_fd, buf, (long) rd,
                               (long) off);
        if (wr < 0)
            return (int) wr;
        off += rd;
    }

    return 0;
}

/* forward_close. */

static struct kbox_dispatch forward_close(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    int same_fd_shadow = entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW;
    if (fd <= 2)
        fprintf(stderr, "kboxdbg: close fd=%ld lkl=%ld pid=%u\n", fd, lkl_fd,
                kbox_syscall_request_pid(req));

    if (lkl_fd >= 0)
        invalidate_stat_cache_fd(ctx, lkl_fd);

    if (entry && entry->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Host-passthrough FDs (pipes, eventfds, stdio): the host kernel
         * tracks per-process FD lifecycle, so close via CONTINUE is correct.
         * Keep the FD table entry alive because the table is shared across
         * all supervised processes (parent + children after fork).  If the
         * child closes a pipe FD, the entry must remain so the parent (or
         * a sibling) that still holds the same FD number isn't denied.
         * Shadow socket entries (shadow_sp >= 0) hold supervisor resources
         * that must be released, so those are still removed.
         */
        if (entry->shadow_sp >= 0)
            kbox_fd_table_remove(ctx->fd_table, fd);
        return kbox_dispatch_continue();
    }

    if (lkl_fd >= 0) {
        if (same_fd_shadow) {
            if (entry && entry->shadow_writeback)
                (void) sync_shadow_writeback(ctx, entry);
            note_shadow_writeback_close(ctx, entry);
            kbox_fd_table_remove(ctx->fd_table, fd);
            ctx_close_lkl_if_unreferenced(ctx, lkl_fd, 0);
            return kbox_dispatch_continue();
        }

        kbox_fd_table_remove(ctx->fd_table, fd);
        long ret = ctx_close_lkl_if_unreferenced(ctx, lkl_fd, 0);
        if (ret < 0 && fd >= KBOX_FD_BASE)
            return kbox_dispatch_errno((int) (-ret));

        /* Low FD redirect (from dup2/dup3): the LKL side is closed above.
         * Do NOT continue to the host: a redirect onto 0/1/2 replaces the
         * host descriptor with a purely virtual one, and shells do close the
         * real stdio descriptor beforehand -- so there is nothing left at that
         * number and the host would answer EBADF for a close that the guest
         * has every right to expect to succeed. dash reports exactly that
         * ("cat: closing standard input: Bad file descriptor") and then
         * refuses to run, which is what broke postgres' bootstrap.
         */
        if (fd < KBOX_LOW_FD_MAX)
            return kbox_dispatch_value(0);

        return kbox_dispatch_value(0);
    }

    /* Not a virtual FD.  Check if this is a host FD that was injected
     * as shadow (the tracee closes it by the host number).  If so,
     * close the LKL side and let the host kernel close the host FD
     * via CONTINUE.
     */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0) {
        struct kbox_fd_entry *shadow_entry = fd_table_entry(ctx->fd_table, vfd);
        long lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);

        if (shadow_entry && shadow_entry->shadow_writeback)
            (void) sync_shadow_writeback(ctx, shadow_entry);
        note_shadow_writeback_close(ctx, shadow_entry);
        if (lkl >= 0)
            invalidate_stat_cache_fd(ctx, lkl);
        kbox_fd_table_remove(ctx->fd_table, vfd);

        if (lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, lkl, 1);
        return kbox_dispatch_continue();
    }

    return kbox_dispatch_continue();
}

/* forward_read_like (read and pread64). */

static struct kbox_dispatch forward_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_pread)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (fd <= 2)
        fprintf(stderr, "kboxdbg: read fd=%ld lkl=%ld n=%ld pid=%u\n", fd,
                lkl_fd, to_c_long_arg(kbox_syscall_request_arg(req, 2)),
                kbox_syscall_request_pid(req));
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
                return forward_local_shadow_read_like(req, ctx, entry, lkl_fd,
                                                      is_pread);
            }
            return kbox_dispatch_continue();
        }
    }

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        long ret;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            long pread_off;
            if (__builtin_add_overflow(offset, (long) total, &pread_off)) {
                if (total == 0)
                    return kbox_dispatch_errno(EOVERFLOW);
                break;
            }
            ret = kbox_lkl_pread64(ctx->sysnrs, lkl_fd, scratch,
                                   (long) chunk_len, pread_off);
        } else {
            ret = kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        }

        if (ret < 0) {
            if (total == 0)
                return kbox_dispatch_errno((int) (-ret));
            break;
        }

        size_t n = (size_t) ret;
        if (n == 0)
            break;

        uint64_t remote;
        if (__builtin_add_overflow(remote_buf, (uint64_t) total, &remote)) {
            if (total == 0)
                return kbox_dispatch_errno(EFAULT);
            break;
        }
        if (ctx->verbose) {
            fprintf(
                stderr,
                "kbox: %s fd=%ld lkl_fd=%ld remote=0x%llx chunk=%zu ret=%ld\n",
                is_pread ? "pread64" : "read", fd, lkl_fd,
                (unsigned long long) remote, chunk_len, ret);
        }
        int wrc = guest_mem_write(ctx, pid, remote, scratch, n);
        if (wrc < 0) {
            return kbox_dispatch_errno(-wrc);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    return kbox_dispatch_value((int64_t) total);
}

/* forward_write. */

static struct kbox_dispatch forward_write(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    invalidate_stat_cache_fd(ctx, lkl_fd);

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote;
        if (__builtin_add_overflow(remote_buf, (uint64_t) total, &remote)) {
            if (total == 0)
                return kbox_dispatch_errno(EFAULT);
            break;
        }
        int rrc = guest_mem_read(ctx, pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total == 0)
                return kbox_dispatch_errno(-rrc);
            break;
        }

        long ret =
            kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        if (ret < 0) {
            if (total == 0)
                return kbox_dispatch_errno((int) (-ret));
            break;
        }

        size_t n = (size_t) ret;

        /* Mirror to host stdout if this is a TTY fd.  The guest fd
         * is a virtual number (4096+) that does not exist on the
         * host side, so we write to stdout instead.
         */
        if (mirror_host && n > 0) {
            ssize_t written = write(STDOUT_FILENO, scratch, n);
            (void) written;
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value((int64_t) total);
}

/* forward_sendfile. */

/* Emulate sendfile(out_fd, in_fd, *offset, count).
 *
 * If both FDs are host-visible (shadow memfds, stdio, or other host FDs
 * not in the virtual table), let the host kernel handle it via CONTINUE.
 * Otherwise, emulate via LKL read + host/LKL write.
 *
 * busybox cat uses sendfile and some builds loop on ENOSYS instead of
 * falling back to read+write, so returning ENOSYS is not viable.
 */
static struct kbox_dispatch forward_sendfile(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long out_fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long in_fd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    uint64_t offset_ptr = kbox_syscall_request_arg(req, 2);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    long in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, in_fd);
    long out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, out_fd);

    /* Resolve shadow FDs: if in_fd is a host FD injected via ADDFD (shadow
     * memfd), find_by_host_fd locates the virtual entry that holds the LKL
     * FD for the same file.
     */
    if (in_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, in_fd);
        if (vfd >= 0)
            in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }
    if (out_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, out_fd);
        if (vfd >= 0)
            out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }

    if (ctx->verbose)
        fprintf(stderr,
                "kbox: sendfile in=%ld lkl=%ld out=%ld lkl=%ld deny_in=%d "
                "deny_out=%d\n",
                in_fd, in_lkl, out_fd, out_lkl,
                fd_should_deny_io_ctx(ctx->fd_table, in_fd, in_lkl),
                fd_should_deny_io_ctx(ctx->fd_table, out_fd, out_lkl));

    /* Both FDs have no LKL backing: the host kernel handles sendfile
     * if both are known host FDs. Deny if either is in a denied range.
     */
    if (in_lkl < 0 && out_lkl < 0) {
        if (fd_should_deny_io_ctx(ctx->fd_table, in_fd, in_lkl) ||
            fd_should_deny_io_ctx(ctx->fd_table, out_fd, out_lkl))
            return kbox_dispatch_errno(EBADF);
        return kbox_dispatch_continue();
    }

    if (in_lkl < 0 && fd_should_deny_io_ctx(ctx->fd_table, in_fd, in_lkl))
        return kbox_dispatch_errno(EBADF);
    if (out_lkl < 0 && fd_should_deny_io_ctx(ctx->fd_table, out_fd, out_lkl))
        return kbox_dispatch_errno(EBADF);

    /* Both descriptors live in LKL, and the emulation below moves the bytes
     * somewhere the caller cannot read back: cp reports the whole file copied
     * and leaves an empty destination, which is how every configure script in
     * an official image fails. Answer ENOSYS instead and let the caller fall
     * back to read/write, which land correctly.
     */
    if (in_lkl >= 0 && out_lkl >= 0)
        return kbox_dispatch_errno(ENOSYS);

    if (count_raw <= 0)
        return kbox_dispatch_value(0);
    size_t count = (size_t) count_raw;
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    /* Read optional offset from tracee memory. */
    pid_t pid = kbox_syscall_request_pid(req);
    off_t offset = 0;
    int has_offset = (offset_ptr != 0);
    if (has_offset) {
        int rc = guest_mem_read(ctx, pid, offset_ptr, &offset, sizeof(offset));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    int sv_in = -1;
    int sv_out = -1;
    int close_in = 0;
    int close_out = 0;
    if (in_lkl < 0) {
        sv_in = kbox_fd_table_get_host_sv_fd(ctx->fd_table, in_fd);
        if (sv_in < 0) {
            sv_in = dup_tracee_fd(pid, (int) in_fd);
            if (sv_in < 0)
                return kbox_dispatch_errno(-sv_in);
            close_in = 1;
        }
    }
    if (out_lkl < 0) {
        sv_out = kbox_fd_table_get_host_sv_fd(ctx->fd_table, out_fd);
        if (sv_out < 0) {
            sv_out = dup_tracee_fd(pid, (int) out_fd);
            if (sv_out < 0) {
                if (close_in)
                    close(sv_in);
                return kbox_dispatch_errno(-sv_out);
            }
            close_out = 1;
        }
    }

    uint8_t *scratch = dispatch_scratch;
    struct kbox_dispatch result = kbox_dispatch_value(0);
    size_t total = 0;

    while (total < count) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        if (chunk > count - total)
            chunk = count - total;

        /* Read from source (LKL fd or host tracee fd). */
        long nr;
        if (in_lkl >= 0) {
            if (has_offset) {
                long pread_off;
                if (__builtin_add_overflow(offset, (long) total, &pread_off)) {
                    if (total == 0) {
                        result = kbox_dispatch_errno(EOVERFLOW);
                        goto out_close;
                    }
                    break;
                }
                nr = kbox_lkl_pread64(ctx->sysnrs, in_lkl, scratch,
                                      (long) chunk, pread_off);
            } else {
                nr = kbox_lkl_read(ctx->sysnrs, in_lkl, scratch, (long) chunk);
            }
            if (nr < 0) {
                if (total == 0) {
                    result = kbox_dispatch_errno((int) (-nr));
                    goto out_close;
                }
                break;
            }
        } else {
            ssize_t hr;
            if (has_offset) {
                off_t pread_off;
                if (__builtin_add_overflow(offset, (off_t) total, &pread_off)) {
                    if (total == 0) {
                        result = kbox_dispatch_errno(EOVERFLOW);
                        goto out_close;
                    }
                    break;
                }
                hr = pread(sv_in, scratch, chunk, pread_off);
            } else {
                hr = read(sv_in, scratch, chunk);
            }
            if (hr < 0) {
                if (total == 0) {
                    result = kbox_dispatch_errno(errno);
                    goto out_close;
                }
                break;
            }
            nr = (long) hr;
        }
        if (nr == 0)
            break;

        size_t n = (size_t) nr;

        /* Write to destination (LKL fd or host tracee fd). */
        size_t written = 0;
        while (written < n) {
            if (out_lkl >= 0) {
                long wr =
                    kbox_lkl_write(ctx->sysnrs, out_lkl, scratch + written,
                                   (long) (n - written));
                if (wr <= 0) {
                    if (total + written == 0) {
                        result =
                            kbox_dispatch_errno(wr < 0 ? (int) (-wr) : EIO);
                        goto out_close;
                    }
                    total += written;
                    goto done;
                }
                written += (size_t) wr;
            } else {
                ssize_t wr = write(sv_out, scratch + written, n - written);
                if (wr <= 0) {
                    if (total + written == 0) {
                        result = kbox_dispatch_errno(wr < 0 ? errno : EIO);
                        goto out_close;
                    }
                    total += written;
                    goto done;
                }
                written += (size_t) wr;
            }
        }

        total += written;
        if (n < chunk)
            break;
    }

done:
    /* The write landed, but the name it landed under is cached: a reader that
     * opens the same path next gets the pre-write shadow and sees an empty
     * file. forward_write drops that cache after every write, and this path
     * has to do the same -- otherwise cp reports success, the destination
     * holds the bytes, and everything that reads it back finds nothing.
     */
    if (total > 0)
        invalidate_path_shadow_cache(ctx);

    /* Update offset in tracee memory if provided.  Best-effort: data has
     * already been transferred, so return the byte count even if the
     * offset writeback fails (avoids data duplication on retry).
     */
    if (has_offset && total > 0) {
        off_t new_off;
        if (!__builtin_add_overflow(offset, (off_t) total, &new_off))
            guest_mem_write(ctx, pid, offset_ptr, &new_off, sizeof(new_off));
    }

    result = kbox_dispatch_value((int64_t) total);

out_close:
    if (close_in && sv_in >= 0)
        close(sv_in);
    if (close_out && sv_out >= 0)
        close(sv_out);
    return result;
}

/* forward_lseek. */

static struct kbox_dispatch forward_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
                return forward_local_shadow_lseek(req, ctx, entry, lkl_fd);
            return kbox_dispatch_continue();
        }
    }

    long off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, off, whence);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: lseek fd=%ld lkl_fd=%ld off=%ld whence=%ld ret=%ld\n",
                fd, lkl_fd, off, whence, ret);
    }
    return kbox_dispatch_from_lkl(ret);
}

static int find_available_tracee_fd(const struct kbox_supervisor_ctx *ctx,
                                    pid_t pid,
                                    int minfd);
static void cleanup_replaced_fd_tracking(struct kbox_supervisor_ctx *ctx,
                                         long fd);
static struct kbox_dispatch dup_same_fd_shadow_to(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *orig,
    long newfd,
    int cloexec,
    int replace_existing);

/* forward_fcntl. */

static struct kbox_dispatch forward_fcntl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        long pt_cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
        if (pt_cmd == F_DUPFD || pt_cmd == F_DUPFD_CLOEXEC) {
            /* Emulate F_DUPFD on host-passthrough FD: get a supervisor copy
             * via pidfd_getfd (or /proc/<pid>/fd fallback), inject at the first
             * free tracee FD >= minfd, and track the result.
             */
            long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            uint32_t af = (pt_cmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
            int target_fd;

            if (minfd < 0)
                return kbox_dispatch_errno(EINVAL);
            target_fd = find_available_tracee_fd(
                ctx, kbox_syscall_request_pid(req), (int) minfd);
            if (target_fd < 0)
                return kbox_dispatch_errno(-target_fd);

            int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) fd);
            if (copy < 0) {
                if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO) {
                    track_host_passthrough_fd(ctx->fd_table, target_fd);
                    if (pt_cmd == F_DUPFD_CLOEXEC)
                        kbox_fd_table_set_cloexec(ctx->fd_table, target_fd, 1);
                    return kbox_dispatch_continue();
                }
                return kbox_dispatch_errno(-copy);
            }
            int tracee_new = request_addfd_at(ctx, req, copy, target_fd, af);
            close(copy);
            if (tracee_new < 0)
                return kbox_dispatch_errno(-tracee_new);
            track_host_passthrough_fd(ctx->fd_table, tracee_new);
            if (pt_cmd == F_DUPFD_CLOEXEC)
                kbox_fd_table_set_cloexec(ctx->fd_table, tracee_new, 1);
            return kbox_dispatch_value(tracee_new);
        }
        if (pt_cmd == F_SETFD) {
            long carg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                      (carg & FD_CLOEXEC) ? 1 : 0);
        }
        return kbox_dispatch_continue();
    }

    if (lkl_fd < 0) {
        /* Shadow socket: handle F_DUPFD* and F_SETFL. */
        long svfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (svfd >= 0) {
            long scmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            if (scmd == F_DUPFD || scmd == F_DUPFD_CLOEXEC) {
                long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                /* When minfd > 0, skip ADDFD (can't honor the minimum)
                 * and let CONTINUE handle it correctly.  The dup is
                 * untracked but no FD leaks.
                 */
                struct kbox_fd_entry *orig = NULL;
                if (minfd > 0)
                    goto fcntl_shadow_continue;
                orig = fd_table_entry(ctx->fd_table, svfd);
                if (orig && orig->shadow_sp >= 0) {
                    uint32_t af = (scmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
                    int nh = request_addfd(ctx, req, orig->shadow_sp, af);
                    if (nh >= 0) {
                        long nv = kbox_fd_table_insert(ctx->fd_table,
                                                       orig->lkl_fd, 0);
                        if (nv < 0)
                            return kbox_dispatch_errno(EMFILE);
                        kbox_fd_table_set_host_fd(ctx->fd_table, nv, nh);
                        /* Clear stale SHADOW_ONLY at the ADDFD-allocated FD
                         * so resolve_lkl_socket finds the shadow socket.
                         */
                        {
                            struct kbox_fd_entry *stale =
                                fd_table_entry(ctx->fd_table, nh);
                            if (stale && nh != nv &&
                                stale->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                                kbox_fd_table_remove(ctx->fd_table, nh);
                        }
                        int ns = dup(orig->shadow_sp);
                        if (ns >= 0) {
                            struct kbox_fd_entry *ne = NULL;
                            ne = fd_table_entry(ctx->fd_table, nv);
                            if (ne) {
                                ne->shadow_sp = ns;
                                if (scmd == F_DUPFD_CLOEXEC)
                                    ne->cloexec = 1;
                            } else {
                                close(ns);
                            }
                        }
                        return kbox_dispatch_value((int64_t) nh);
                    }
                }
            }
            if (scmd == F_SETFL) {
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                long slkl = kbox_fd_table_get_lkl(ctx->fd_table, svfd);
                if (slkl >= 0)
                    kbox_lkl_fcntl(ctx->sysnrs, slkl, F_SETFL, sarg);
            }
            if (scmd == F_SETFD) {
                /* Keep fd-table cloexec in sync with host kernel. */
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                kbox_fd_table_set_cloexec(ctx->fd_table, svfd,
                                          (sarg & FD_CLOEXEC) ? 1 : 0);
            }
            goto fcntl_shadow_continue;
        }
        /* The descriptor is not in the table, so kbox has no LKL socket to
         * apply a flag to. Continuing the call to the host is worse than
         * useless: the guest's number is not a host descriptor, so the caller
         * gets EBADF -- which is how postgres backends died right after
         * accepting a client, asking for nonblocking mode and treating the
         * refusal as fatal. Report the three flag commands as done; there is
         * nothing meaningful to apply them to.
         */
        {
            long lcmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            if (lcmd == F_SETFL || lcmd == F_GETFL || lcmd == F_SETFD) {
                long larg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: fcntl untracked fd=%ld cmd=%ld arg=%ld "
                            "answered locally\n",
                            fd, lcmd, larg);
                if (lcmd == F_GETFL)
                    return kbox_dispatch_value(O_RDWR);
                if (lcmd == F_SETFD)
                    kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                              (larg & FD_CLOEXEC) ? 1 : 0);
                return kbox_dispatch_value(0);
            }
        }
        if (!fd_should_deny_io(fd, lkl_fd))
            goto fcntl_shadow_continue;
        return kbox_dispatch_errno(EBADF);
    fcntl_shadow_continue:
        return kbox_dispatch_continue();
    }

    /* An FD that has both a virtual number and a host shadow (an accepted
     * socket is one) must answer here. Its virtual number is not a host
     * descriptor, so CONTINUE would run fcntl on a number the host does not
     * have and answer EBADF -- which is how every postgres backend died with
     * "could not set socket to nonblocking mode: Bad file descriptor" right
     * after accepting a client.
     */
    {
        long pt_cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
        long pt_arg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
        struct kbox_fd_entry *he = fd_table_entry(ctx->fd_table, fd);

        if (he && he->shadow_sp >= 0 &&
            (pt_cmd == F_SETFL || pt_cmd == F_GETFL || pt_cmd == F_SETFD)) {
            if (pt_cmd == F_SETFD) {
                kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                          (pt_arg & FD_CLOEXEC) ? 1 : 0);
                return kbox_dispatch_value(0);
            }
            if (pt_cmd == F_SETFL) {
                if (lkl_fd >= 0)
                    (void) kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_SETFL,
                                          host_to_lkl_open_flags(pt_arg));
                if (fcntl(he->shadow_sp, F_SETFL, (int) pt_arg) < 0)
                    return kbox_dispatch_errno(errno);
                return kbox_dispatch_value(0);
            }
            {
                long hr = fcntl(he->shadow_sp, F_GETFL);
                if (hr < 0)
                    return kbox_dispatch_errno(errno);
                return kbox_dispatch_value(lkl_to_host_open_flags(hr));
            }
        }
    }

    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long arg = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        if (arg < 0)
            return kbox_dispatch_errno(EINVAL);
        struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, fd);
        if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
            orig->shadow_sp >= 0) {
            long target_fd = allocate_shadow_fd_from(ctx, arg);
            if (target_fd < 0)
                return kbox_dispatch_errno(EMFILE);
            return dup_same_fd_shadow_to(req, ctx, orig, target_fd,
                                         cmd == F_DUPFD_CLOEXEC, 0);
        }

        long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));

        int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
        long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
        if (new_vfd < 0) {
            lkl_close_and_invalidate(ctx, ret);
            return kbox_dispatch_errno(EMFILE);
        }
        if (cmd == F_DUPFD_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, new_vfd, 1);
        return kbox_dispatch_value((int64_t) new_vfd);
    }

    if (cmd == F_SETFD) {
        kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                  (arg & FD_CLOEXEC) ? 1 : 0);
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }

    /* LKL's fcntl_setlk dereferences lock state it does not have for files this
     * sandbox backs on the host, and the resulting SIGSEGV takes the daemon --
     * and every container running in it -- down. Hit by Kafka's log-directory
     * lock. A single-writer sandbox has nobody to contend with, so report the
     * lock as taken rather than asking LKL to track it. F_GETLK has to fill a
     * struct flock the dispatcher cannot see through, so leave it to the guest
     * to treat as unsupported.
     */
    if (cmd == F_SETLK || cmd == F_SETLKW)
        return kbox_dispatch_value(0);
    if (cmd == F_GETLK || cmd == F_OFD_GETLK || cmd == F_OFD_SETLK ||
        cmd == F_OFD_SETLKW)
        return kbox_dispatch_errno(ENOSYS);

    /* F_SETFL: translate host open flags to LKL before forwarding. */
    if (cmd == F_SETFL)
        arg = host_to_lkl_open_flags(arg);

    long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);

    if (ret < 0 && ctx->verbose) {
        const struct kbox_fd_entry *fe = fd_table_entry(ctx->fd_table, fd);
        fprintf(stderr, "kbox: fcntl fd=%ld lkl=%ld cmd=%ld arg=%ld -> %ld", fd,
                lkl_fd, cmd, arg, ret);
        fprintf(stderr, " (host_fd=%ld shadow=%d)\n", fe ? fe->host_fd : -999L,
                fe ? fe->shadow_sp : -999);
    }

    /* F_GETFL: translate LKL open flags back to host before returning. */
    if (cmd == F_GETFL && ret >= 0)
        ret = lkl_to_host_open_flags(ret);

    return kbox_dispatch_from_lkl(ret);
}

static int read_tracee_fd_flags(pid_t pid, int tracee_fd, int *out_flags)
{
    char path[64];
    char buf[512];
    int n = snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", (int) pid,
                     tracee_fd);
    if (n < 0 || (size_t) n >= sizeof(path))
        return -ENAMETOOLONG;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    int saved_errno = errno;
    close(fd);
    if (nr < 0)
        return -saved_errno;
    buf[nr] = '\0';

    const char *p = strstr(buf, "flags:");
    if (!p)
        return -EINVAL;
    p += 6;
    while (*p == ' ' || *p == '\t')
        p++;
    char *end = NULL;
    unsigned long flags = strtoul(p, &end, 8);
    if (end == p)
        return -EINVAL;
    *out_flags = (int) flags;
    return 0;
}

static int open_tracee_proc_fd(pid_t pid, int tracee_fd)
{
    char path[64];
    int n =
        snprintf(path, sizeof(path), "/proc/%d/fd/%d", (int) pid, tracee_fd);
    if (n < 0 || (size_t) n >= sizeof(path))
        return -ENAMETOOLONG;

    int fd_flags = 0;
    int open_mode = O_RDONLY;
    if (read_tracee_fd_flags(pid, tracee_fd, &fd_flags) == 0) {
        if (fd_flags & O_PATH)
            open_mode = O_PATH;
        else
            open_mode = fd_flags & O_ACCMODE;
    }

    int copy = open(path, open_mode | O_CLOEXEC);
    if (copy >= 0)
        return copy;
    int saved_errno = errno;
    if (open_mode != O_RDONLY && open_mode != O_PATH) {
        copy = open(path, O_RDONLY | O_CLOEXEC);
        if (copy >= 0)
            return copy;
    }
    return -saved_errno;
}

static int open_tracee_pidfd(pid_t pid)
{
    int pidfd = (int) syscall(__NR_pidfd_open, (int) pid, (unsigned int) 0);
    if (pidfd >= 0)
        return pidfd;
    int saved_errno = errno;
    if (saved_errno == EPERM || saved_errno == ENOSYS || saved_errno == EACCES)
        return -saved_errno;
    /* pidfd_open(..., 0) fails (EINVAL/ENOENT/ESRCH) on non-leader thread TIDs;
     * resolve the thread-group leader TGID whose FD table the thread shares.
     */
    pid_t tgid = 0;
    if (read_proc_tgid_ppid(pid, &tgid, NULL, NULL) == 0 && tgid > 0 &&
        tgid != pid) {
        pidfd = (int) syscall(__NR_pidfd_open, (int) tgid, (unsigned int) 0);
        if (pidfd >= 0)
            return pidfd;
        return -errno;
    }
    return -saved_errno;
}

/* Obtain a supervisor-side copy of a tracee FD that shares the same file
 * description.  Uses pidfd_getfd (Linux 5.6+) which preserves the file
 * description identity (same position, flags, etc.) -- unlike
 * open(/proc/pid/fd/N) which creates a new description.  Falls back to
 * /proc/<pid>/fd/N when pidfd_getfd is blocked (EPERM/ENOSYS/EACCES), such as
 * under default container seccomp profiles.
 * Returns a supervisor FD on success, -errno on failure.
 */
int dup_tracee_fd(pid_t pid, int tracee_fd)
{
    int pidfd = open_tracee_pidfd(pid);
    if (pidfd >= 0) {
        int copy = (int) syscall(__NR_pidfd_getfd, pidfd,
                                 (unsigned int) tracee_fd, (unsigned int) 0);
        int saved_errno = errno;
        close(pidfd);
        if (copy >= 0)
            return copy;
        if (saved_errno != EPERM && saved_errno != ENOSYS &&
            saved_errno != EACCES)
            return -saved_errno;
    } else if (pidfd != -EPERM && pidfd != -ENOSYS && pidfd != -EACCES &&
               pidfd != -EINVAL) {
        return pidfd;
    }
    return open_tracee_proc_fd(pid, tracee_fd);
}

static int find_available_tracee_fd(const struct kbox_supervisor_ctx *ctx,
                                    pid_t pid,
                                    int minfd)
{
    const int limit = 65536;

    if (minfd < 0 || minfd >= limit)
        return -EINVAL;

    char proc_dir[64];
    snprintf(proc_dir, sizeof(proc_dir), "/proc/%d/fd", (int) pid);
    struct stat dir_st;
    if (stat(proc_dir, &dir_st) == 0) {
        for (int candidate = minfd; candidate < limit; candidate++) {
            if (ctx && ctx->fd_table &&
                kbox_fd_table_get_lkl(ctx->fd_table, candidate) != -1)
                continue;
            char fd_path[80];
            struct stat st;
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", (int) pid,
                     candidate);
            if (lstat(fd_path, &st) < 0 && errno == ENOENT)
                return candidate;
        }
        return -EMFILE;
    }

    int pidfd = open_tracee_pidfd(pid);
    if (pidfd < 0)
        return pidfd;

    for (int candidate = minfd; candidate < limit; candidate++) {
        if (ctx && ctx->fd_table &&
            kbox_fd_table_get_lkl(ctx->fd_table, candidate) != -1)
            continue;
        int probe = (int) syscall(__NR_pidfd_getfd, pidfd,
                                  (unsigned int) candidate, (unsigned int) 0);
        if (probe >= 0) {
            close(probe);
            continue;
        }
        if (errno == EBADF) {
            close(pidfd);
            return candidate;
        }
        int saved_errno = errno;
        close(pidfd);
        return -saved_errno;
    }

    close(pidfd);
    return -EMFILE;
}

static void cleanup_replaced_fd_tracking(struct kbox_supervisor_ctx *ctx,
                                         long fd)
{
    long stale_lkl;
    long shadow_vfd;

    if (!ctx || !ctx->fd_table)
        return;

    stale_lkl = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (stale_lkl >= 0) {
        remove_fd_table_entry_with_writeback(ctx, fd);
        ctx_close_lkl_if_unreferenced(ctx, stale_lkl, 0);
    } else if (stale_lkl == KBOX_LKL_FD_SHADOW_ONLY) {
        remove_fd_table_entry_with_writeback(ctx, fd);
    }

    shadow_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (shadow_vfd >= 0) {
        long shadow_lkl = kbox_fd_table_get_lkl(ctx->fd_table, shadow_vfd);
        remove_fd_table_entry_with_writeback(ctx, shadow_vfd);
        if (shadow_lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, shadow_lkl, 1);
    }
}

/* Duplicate a KBOX_FD_HOST_SAME_FD_SHADOW entry onto target_fd so both FDs
 * share the underlying memfd (preserving offset, writeback tracking, and LKL
 * FD ownership across dup/dup2/dup3/F_DUPFD).
 */
static struct kbox_dispatch dup_same_fd_shadow_to(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *orig,
    long newfd,
    int cloexec,
    int replace_existing)
{
    if (!orig || orig->lkl_fd < 0 || orig->shadow_sp < 0 ||
        !fd_table_entry(ctx->fd_table, newfd))
        return kbox_dispatch_errno(EBADF);

    long orig_lkl = orig->lkl_fd;
    int orig_wb = orig->shadow_writeback;
    int new_sp = fcntl(orig->shadow_sp, F_DUPFD_CLOEXEC, 3);
    if (new_sp < 0)
        return kbox_dispatch_errno(EMFILE);

    uint32_t af = cloexec ? O_CLOEXEC : 0;
    int injected = request_addfd_at(ctx, req, new_sp, (int) newfd, af);
    if (injected < 0) {
        close(new_sp);
        return kbox_dispatch_errno(-injected);
    }
    if (injected != newfd) {
        close(new_sp);
        return kbox_dispatch_errno(EIO);
    }

    if (replace_existing)
        cleanup_replaced_fd_tracking(ctx, newfd);

    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, orig_lkl, 0) < 0) {
        close(new_sp);
        return kbox_dispatch_errno(EMFILE);
    }

    struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, newfd);
    ne->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    ne->shadow_sp = new_sp;
    if (orig_wb)
        note_shadow_writeback_open(ctx, ne);
    if (cloexec)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);

    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup. */

static struct kbox_dispatch forward_dup(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Emulate dup on a host-passthrough FD (pipe, stdio, eventfd, etc.)
         * by obtaining a supervisor copy via pidfd_getfd, injecting it into
         * the tracee via ADDFD, and tracking the result.
         */
        int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) fd);
        if (copy < 0)
            return kbox_dispatch_errno(-copy);
        int tracee_fd = request_addfd(ctx, req, copy, 0);
        close(copy);
        if (tracee_fd < 0)
            return kbox_dispatch_errno(-tracee_fd);
        track_host_passthrough_fd(ctx->fd_table, tracee_fd);
        return kbox_dispatch_value(tracee_fd);
    }

    if (lkl_fd < 0) {
        /* Check for shadow socket (tracee holds host_fd from ADDFD). */
        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (orig_vfd < 0) {
            if (!fd_should_deny_io(fd, lkl_fd))
                return kbox_dispatch_continue();
            return kbox_dispatch_errno(EBADF);
        }

        /* Shadow socket dup: inject a new copy of the socketpair end into
         * the tracee and track the new host_fd.
         */
        struct kbox_fd_entry *orig = NULL;
        orig = fd_table_entry(ctx->fd_table, orig_vfd);
        if (!orig || orig->shadow_sp < 0)
            return kbox_dispatch_continue();

        long orig_lkl = orig->lkl_fd;
        int new_host = request_addfd(ctx, req, orig->shadow_sp, 0);
        if (new_host < 0)
            return kbox_dispatch_errno(-new_host);

        long new_vfd = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
        if (new_vfd < 0) {
            /* Can't track the FD; return error.  The tracee already has
             * the FD via ADDFD which we can't revoke, but returning
             * EMFILE tells the caller dup failed so it won't use it.
             */
            return kbox_dispatch_errno(EMFILE);
        }
        kbox_fd_table_set_host_fd(ctx->fd_table, new_vfd, new_host);
        {
            struct kbox_fd_entry *stale =
                fd_table_entry(ctx->fd_table, new_host);
            if (stale && new_host != new_vfd &&
                stale->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                kbox_fd_table_remove(ctx->fd_table, new_host);
        }

        /* Propagate shadow_sp so chained dups work. */
        int new_sp = dup(orig->shadow_sp);
        if (new_sp >= 0) {
            struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, new_vfd);
            if (ne)
                ne->shadow_sp = new_sp;
            else
                close(new_sp);
        }
        return kbox_dispatch_value((int64_t) new_host);
    }

    struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, fd);
    if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
        orig->shadow_sp >= 0) {
        long target_fd = allocate_shadow_fd_from(ctx, KBOX_FD_FAST_BASE);
        if (target_fd < 0)
            return kbox_dispatch_errno(EMFILE);
        return dup_same_fd_shadow_to(req, ctx, orig, target_fd, 0, 0);
    }

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_fd);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
    long new_vfd = kbox_fd_table_insert(ctx->fd_table, ret, mirror);
    if (new_vfd < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    return kbox_dispatch_value((int64_t) new_vfd);
}

static struct kbox_dispatch finish_shadow_dup_at(
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *orig,
    long newfd,
    int new_host,
    int cloexec)
{
    long orig_lkl = orig->lkl_fd;
    int orig_sp = orig->shadow_sp;

    /* Remove any stale mapping at newfd (virtual, shadow, or SHADOW_ONLY). */
    long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
    if (stale == KBOX_LKL_FD_SHADOW_ONLY) {
        kbox_fd_table_remove(ctx->fd_table, newfd);
    } else if (stale >= 0) {
        remove_fd_table_entry_with_writeback(ctx, newfd);
        ctx_close_lkl_if_unreferenced(ctx, stale, 0);
    } else {
        long sv = kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
        if (sv >= 0) {
            long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
            remove_fd_table_entry_with_writeback(ctx, sv);
            if (sl >= 0)
                ctx_close_lkl_if_unreferenced(ctx, sl, 1);
        }
    }

    long nv = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
    if (nv < 0)
        return kbox_dispatch_errno(EMFILE);
    kbox_fd_table_set_host_fd(ctx->fd_table, nv, new_host);

    int ns = dup(orig_sp);
    if (ns >= 0) {
        struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, nv);
        if (ne) {
            ne->shadow_sp = ns;
            if (cloexec)
                ne->cloexec = 1;
        } else {
            close(ns);
        }
    }
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup2. */

static struct kbox_dispatch forward_dup2(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);

    if (lkl_old == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Emulate dup2 on a host-passthrough FD. Use pidfd_getfd to get
         * a supervisor copy sharing the same file description, then inject
         * at the target FD via ADDFD_AT.  When blocked (container seccomp),
         * allow the kernel to perform dup2 natively via CONTINUE.
         */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);
        int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) oldfd);
        if (copy < 0) {
            if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO) {
                cleanup_replaced_fd_tracking(ctx, newfd);
                track_host_passthrough_fd(ctx->fd_table, newfd);
                return kbox_dispatch_continue();
            }
            return kbox_dispatch_errno(-copy);
        }
        int injected = request_addfd_at(ctx, req, copy, (int) newfd, 0);
        close(copy);
        if (injected < 0)
            return kbox_dispatch_errno(-injected);
        cleanup_replaced_fd_tracking(ctx, newfd);
        track_host_passthrough_fd(ctx->fd_table, newfd);
        return kbox_dispatch_value((int64_t) newfd);
    }

    if (lkl_old < 0) {
        /* Shadow socket dup2: dup2(fd, fd) must return fd unchanged. */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig =
                fd_table_entry(ctx->fd_table, orig_vfd);
            if (orig && orig->shadow_sp >= 0) {
                int new_host =
                    request_addfd_at(ctx, req, orig->shadow_sp, (int) newfd, 0);
                if (new_host >= 0)
                    return finish_shadow_dup_at(ctx, orig, newfd, new_host, 0);
            }
        }
        if (!fd_should_deny_io(oldfd, lkl_old)) {
            cleanup_replaced_fd_tracking(ctx, newfd);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    if (oldfd == newfd)
        return kbox_dispatch_value((int64_t) newfd);

    /* Redirect onto a low FD (0/1/2). Those descriptors are the guest's
     * stdio: the guest reads and closes them through the host, so the host has
     * to own whatever lands there. The file behind the source FD is only
     * reachable through a supervisor shadow -- kbox keeps read shadows local
     * and never injects them at the source number -- so a plain CONTINUE would
     * dup a host number that does not exist. Inject the shadow at the target
     * number and mark the entry as a same-fd shadow instead: reads then
     * continue to the host and see the file's bytes. Without this, postgres'
     * bootstrap read its own input as EBADF and died with "input in flex
     * scanner failed".
     */
    if (newfd < KBOX_LOW_FD_MAX) {
        struct kbox_fd_entry *src = fd_table_entry(ctx->fd_table, oldfd);
        int memfd = (src && src->shadow_sp >= 0) ? src->shadow_sp : -1;
        int own_memfd = 0;
        int writeback = src ? src->shadow_writeback : 0;
        long src_flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_old, F_GETFL, 0);

        /* Only for read-only sources. A writable redirect has to keep writing
         * into LKL -- redirecting ">" onto fd 1 through a memfd would swallow
         * every byte the guest writes and leave the file empty, which is what
         * made every script written inside a container run as a no-op. */
        if (src_flags >= 0 && (src_flags & O_ACCMODE) != O_RDONLY)
            memfd = -2;

        if (memfd != -2 && memfd < 0) {
            memfd = kbox_shadow_create(ctx->sysnrs, lkl_old);
            if (memfd < 0)
                return kbox_dispatch_errno(-memfd);
            kbox_shadow_seal(memfd);
            own_memfd = 1;
        }

        if (memfd != -2) {
            int injected = request_addfd_at(ctx, req, memfd, (int) newfd, 0);
            if (injected < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(-injected);
            }

            cleanup_replaced_fd_tracking(ctx, newfd);
            if (kbox_fd_table_insert_at(ctx->fd_table, newfd, lkl_old, 0) < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(EBADF);
            }
            struct kbox_fd_entry *dst = fd_table_entry(ctx->fd_table, newfd);
            if (dst) {
                dst->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
                dst->shadow_sp = own_memfd ? memfd : -1;
                dst->shadow_writeback = writeback;
            }
            return kbox_dispatch_value((int64_t) newfd);
        }
    }

    struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, oldfd);
    if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
        orig->shadow_sp >= 0)
        return dup_same_fd_shadow_to(req, ctx, orig, newfd, 0, 1);

    /* Dup first, then close the old mapping.  This preserves the old newfd
     * if the dup fails (e.g. EMFILE), matching dup2 atomicity semantics.
     */
    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = remove_fd_table_entry_with_writeback(ctx, newfd);
    if (existing >= 0)
        ctx_close_lkl_if_unreferenced(ctx, existing, 0);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup3. */

static struct kbox_dispatch forward_dup3(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* dup3 only accepts O_CLOEXEC; reject anything else per POSIX. */
    if (flags & ~((long) O_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);

    if (lkl_old == KBOX_LKL_FD_SHADOW_ONLY) {
        if (oldfd == newfd)
            return kbox_dispatch_errno(EINVAL);
        uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
        int copy = dup_tracee_fd(kbox_syscall_request_pid(req), (int) oldfd);
        if (copy < 0) {
            if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO) {
                cleanup_replaced_fd_tracking(ctx, newfd);
                track_host_passthrough_fd(ctx->fd_table, newfd);
                if (flags & O_CLOEXEC)
                    kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
                return kbox_dispatch_continue();
            }
            return kbox_dispatch_errno(-copy);
        }
        int injected = request_addfd_at(ctx, req, copy, (int) newfd, af);
        close(copy);
        if (injected < 0)
            return kbox_dispatch_errno(-injected);
        cleanup_replaced_fd_tracking(ctx, newfd);
        track_host_passthrough_fd(ctx->fd_table, newfd);
        if (flags & O_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
        return kbox_dispatch_value((int64_t) newfd);
    }

    if (lkl_old < 0) {
        /* Shadow socket dup3: dup3(fd, fd, ...) must return EINVAL. */
        if (oldfd == newfd) {
            if (kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd) >= 0)
                return kbox_dispatch_errno(EINVAL);
        }

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig =
                fd_table_entry(ctx->fd_table, orig_vfd);
            if (orig && orig->shadow_sp >= 0) {
                uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
                int new_host = request_addfd_at(ctx, req, orig->shadow_sp,
                                                (int) newfd, af);
                if (new_host >= 0)
                    return finish_shadow_dup_at(ctx, orig, newfd, new_host,
                                                (flags & O_CLOEXEC) != 0);
            }
        }
        if (!fd_should_deny_io(oldfd, lkl_old)) {
            cleanup_replaced_fd_tracking(ctx, newfd);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    if (oldfd == newfd)
        return kbox_dispatch_errno(EINVAL);

    /* Redirect onto a low FD (0/1/2). Those descriptors are the guest's
     * stdio: the guest reads and closes them through the host, so the host has
     * to own whatever lands there. The file behind the source FD is only
     * reachable through a supervisor shadow -- kbox keeps read shadows local
     * and never injects them at the source number -- so a plain CONTINUE would
     * dup a host number that does not exist. Inject the shadow at the target
     * number and mark the entry as a same-fd shadow instead: reads then
     * continue to the host and see the file's bytes. Without this, postgres'
     * bootstrap read its own input as EBADF and died with "input in flex
     * scanner failed".
     */
    if (newfd < KBOX_LOW_FD_MAX) {
        struct kbox_fd_entry *src = fd_table_entry(ctx->fd_table, oldfd);
        int memfd = (src && src->shadow_sp >= 0) ? src->shadow_sp : -1;
        int own_memfd = 0;
        int writeback = src ? src->shadow_writeback : 0;
        long src_flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_old, F_GETFL, 0);

        /* Only for read-only sources. A writable redirect has to keep writing
         * into LKL -- redirecting ">" onto fd 1 through a memfd would swallow
         * every byte the guest writes and leave the file empty, which is what
         * made every script written inside a container run as a no-op. */
        if (src_flags >= 0 && (src_flags & O_ACCMODE) != O_RDONLY)
            memfd = -2;

        if (memfd != -2 && memfd < 0) {
            memfd = kbox_shadow_create(ctx->sysnrs, lkl_old);
            if (memfd < 0)
                return kbox_dispatch_errno(-memfd);
            kbox_shadow_seal(memfd);
            own_memfd = 1;
        }

        if (memfd != -2) {
            int injected = request_addfd_at(ctx, req, memfd, (int) newfd, 0);
            if (injected < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(-injected);
            }

            cleanup_replaced_fd_tracking(ctx, newfd);
            if (kbox_fd_table_insert_at(ctx->fd_table, newfd, lkl_old, 0) < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(EBADF);
            }
            struct kbox_fd_entry *dst = fd_table_entry(ctx->fd_table, newfd);
            if (dst) {
                dst->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
                dst->shadow_sp = own_memfd ? memfd : -1;
                dst->shadow_writeback = writeback;
            }
            return kbox_dispatch_value((int64_t) newfd);
        }
    }

    struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, oldfd);
    if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
        orig->shadow_sp >= 0)
        return dup_same_fd_shadow_to(req, ctx, orig, newfd,
                                     (flags & O_CLOEXEC) != 0, 1);

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = remove_fd_table_entry_with_writeback(ctx, newfd);
    if (existing >= 0)
        ctx_close_lkl_if_unreferenced(ctx, existing, 0);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_fstat. */

static struct kbox_dispatch forward_fstat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    int wb_sp = -1;
    if (entry && entry->shadow_writeback && entry->shadow_sp >= 0)
        wb_sp = entry->shadow_sp;
    else if (ctx->active_writeback_shadows > 0)
        wb_sp = kbox_find_active_writeback_shadow_sp(ctx, lkl_fd);
    int skip_cache = (wb_sp >= 0) || (ctx->active_writeback_shadows > 0);

    /* Check the stat cache first to avoid an LKL round-trip.  Skip the static
     * LKL cache when any writeback shadow is active because writes/ftruncate
     * mutate the live memfd size before writeback.
     */
#if KBOX_STAT_CACHE_ENABLED
    if (!skip_cache) {
        for (int ci = 0; ci < KBOX_STAT_CACHE_MAX; ci++) {
            if (ctx->stat_cache[ci].lkl_fd == lkl_fd) {
                int wrc = guest_mem_write_small_metadata(
                    ctx, kbox_syscall_request_pid(req), remote_stat,
                    &ctx->stat_cache[ci].st, sizeof(ctx->stat_cache[ci].st));
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
                return kbox_dispatch_value(0);
            }
        }
    }
#endif

    /* Always source identity/permission metadata (st_dev, st_ino, st_mode,
     * st_uid, st_gid, st_nlink) from LKL rather than an anonymous shadow memfd
     * so writable shadows and read-only FDs to the same inode agree on
     * st_dev/st_ino (e.g. Chromium PlatformSharedMemoryRegion::Create).
     */
    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);

    if (wb_sp >= 0) {
        struct stat mem_stat;
        if (fstat(wb_sp, &mem_stat) == 0) {
            host_stat.st_size = mem_stat.st_size;
            host_stat.st_blocks = mem_stat.st_blocks;
        }
    }

    /* Insert into stat cache (overwrite oldest slot via round-robin). */
#if KBOX_STAT_CACHE_ENABLED
    if (!skip_cache) {
        static __thread unsigned stat_cache_rr;
        unsigned slot = stat_cache_rr % KBOX_STAT_CACHE_MAX;
        stat_cache_rr++;
        ctx->stat_cache[slot].lkl_fd = lkl_fd;
        ctx->stat_cache[slot].st = host_stat;
    }
#endif

    int wrc = guest_mem_write_small_metadata(ctx, kbox_syscall_request_pid(req),
                                             remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_newfstatat. */

static struct kbox_dispatch forward_newfstatat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 2);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    /* /proc is the container's own procfs, so /proc/self/exe names the memfd
     * the supervisor exec'd; following it fails and official entrypoints
     * (gosu, su-exec, tini) stat it before re-exec. Follow it to the guest
     * path the container was started with instead. lstat stays on the real
     * link, which is what `ls -l` wants. */
    if (!(flags & AT_SYMLINK_NOFOLLOW) &&
        strcmp(translated, "/proc/self/exe") == 0) {
        const char *exe =
            kbox_guest_exe_for(ctx, kbox_syscall_request_pid(req));
        if (exe[0])
            snprintf(translated, sizeof(translated), "%s", exe);
    }

    /* Host dirfd or virtual path: call host fstatat with a local path copy
     * to eliminate the TOCTOU window where a sibling thread could swap the
     * path between validation and the kernel re-read.
     */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
        }
        struct stat host_stat;
        int host_rc = fstatat(sv_dirfd, sv_path, &host_stat, (int) flags);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        normalize_host_stat_if_needed(ctx, translated, &host_stat);
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                                 &host_stat, sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat, pid)) {
        return kbox_dispatch_value(0);
    }

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));

    long ret;
    if (translated[0] == '\0' && (flags & AT_EMPTY_PATH))
        ret = kbox_lkl_fstat(ctx->sysnrs, lkl_dirfd, &kst);
    else
        ret = kbox_lkl_newfstatat(ctx->sysnrs, lkl_dirfd, translated, &kst,
                                  flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Guest-thread local fast-path.  Handles syscalls that never touch LKL and
 * can be resolved on the calling thread without a service-thread round-trip.
 * Returns 1 if handled (result in *out), 0 if the caller must use the service
 * thread.  Safe to call from the SIGSYS handler or rewrite trampoline context.
 *
 * Three tiers:
 *   1. Pure emulation: cached constant values (getpid, getppid, gettid).
 *   2. Always-CONTINUE: host kernel handles the syscall unmodified.
 *   3. Conditional emulation: e.g. arch_prctl(SET_FS) in trap/rewrite.
 *
 * LKL-touching syscalls (stat, openat, read on LKL FDs, etc.) are NOT
 * handled here; they MUST go through the service thread.
 */
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out)
{
    if (!h || !out)
        return 0;

    /* Tier 1: pure emulation. */
    if (nr == h->getpid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }
    if (nr == h->getppid) {
        *out = kbox_dispatch_value(0);
        return 1;
    }
    if (nr == h->gettid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }

    /* Tier 2: always-CONTINUE; host kernel handles these directly. */
    if (nr == h->brk || nr == h->futex || nr == h->rseq ||
        nr == h->set_tid_address || nr == h->set_robust_list ||
        nr == h->munmap || nr == h->mremap || nr == h->membarrier ||
        nr == h->madvise || nr == h->wait4 || nr == h->waitid ||
        nr == h->exit || nr == h->exit_group || nr == h->rt_sigreturn ||
        nr == h->rt_sigaltstack || nr == h->rt_sigsuspend ||
        nr == h->setitimer || nr == h->getitimer || nr == h->setpgid ||
        nr == h->getpgid || nr == h->getsid || nr == h->setsid ||
        nr == h->fork || nr == h->vfork || nr == h->sched_yield ||
        nr == h->sched_setparam || nr == h->sched_getparam ||
        nr == h->sched_setscheduler || nr == h->sched_getscheduler ||
        nr == h->sched_get_priority_max || nr == h->sched_get_priority_min ||
        nr == h->sched_setaffinity || nr == h->sched_getaffinity ||
        nr == h->getrlimit || nr == h->getrusage || nr == h->ppoll ||
        nr == h->pselect6 || nr == h->nanosleep || nr == h->clock_nanosleep ||
        nr == h->timer_create || nr == h->timer_gettime ||
        nr == h->timer_getoverrun || nr == h->timer_settime ||
        nr == h->timer_delete || nr == h->sysinfo) {
        *out = kbox_dispatch_continue();
        return 1;
    }

    return 0;
}

static struct kbox_dispatch dispatch_host_statfs(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    const char *host_path,
    uint64_t remote_buf)
{
    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    if (statfs(host_path, &sfs) < 0)
        return kbox_dispatch_errno(errno);
    int wrc = guest_mem_write(ctx, pid, remote_buf, &sfs, sizeof(sfs));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch dispatch_lkl_statfs_result(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    long ret,
    const struct statfs *sfs,
    uint64_t remote_buf)
{
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    int wrc = guest_mem_write(ctx, pid, remote_buf, sfs, sizeof(*sfs));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_statfs(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd = AT_FDCWD_LINUX;
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (should_continue_for_dirfd(lkl_dirfd))
        return dispatch_host_statfs(ctx, pid, translated, remote_buf);

    if (should_continue_virtual_path(ctx, req, 0, translated)) {
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        return dispatch_host_statfs(ctx, pid, sv_path, remote_buf);
    }

    char host_path[KBOX_MAX_PATH];
    if (build_host_open_path(ctx, translated, host_path, sizeof(host_path)) ==
        0)
        return dispatch_host_statfs(ctx, pid, host_path, remote_buf);

    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    long ret = kbox_lkl_statfs(ctx->sysnrs, translated, &sfs);
    return dispatch_lkl_statfs_result(ctx, pid, ret, &sfs, remote_buf);
}

static struct kbox_dispatch forward_fstatfs(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    long ret = kbox_lkl_fstatfs(ctx->sysnrs, lkl_fd, &sfs);
    return dispatch_lkl_statfs_result(ctx, pid, ret, &sfs, remote_buf);
}

/* forward_statx. */

static struct kbox_dispatch forward_statx(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 2));
    unsigned mask = (unsigned) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t remote_statx = kbox_syscall_request_arg(req, 4);
    if (remote_statx == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Host dirfd or virtual path: call host statx with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
        }
        uint8_t statx_buf[STATX_BUF_SIZE];
        memset(statx_buf, 0, sizeof(statx_buf));
        long host_rc = syscall(__NR_statx, sv_dirfd, sv_path, flags,
                               (unsigned int) mask, statx_buf);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        normalize_statx_if_needed(ctx, translated, statx_buf);
        int wrc = guest_mem_write(ctx, pid, remote_statx, statx_buf,
                                  sizeof(statx_buf));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    uint8_t statx_buf[STATX_BUF_SIZE];
    memset(statx_buf, 0, sizeof(statx_buf));

    long ret = kbox_lkl_statx(ctx->sysnrs, lkl_dirfd, translated, flags, mask,
                              statx_buf);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    normalize_statx_if_needed(ctx, translated, statx_buf);

    int wrc =
        guest_mem_write(ctx, pid, remote_statx, statx_buf, sizeof(statx_buf));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_faccessat / forward_faccessat2. */

static struct kbox_dispatch do_faccessat(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx,
                                         long flags)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* Host dirfd or virtual path: call host faccessat with local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
        }
        int host_rc = (int) syscall(__NR_faccessat2, sv_dirfd, sv_path,
                                    (int) mode, (int) flags);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        return kbox_dispatch_value(0);
    }

    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_faccessat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx, 0);
}

static struct kbox_dispatch forward_faccessat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx,
                        to_c_long_arg(kbox_syscall_request_arg(req, 3)));
}

/* forward_getdents64. */

static struct kbox_dispatch forward_getdents64(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents64);
}

/* forward_getdents (legacy). */

static struct kbox_dispatch forward_getdents(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents);
}

/* forward_chdir. */

static struct kbox_dispatch forward_chdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    if (ctx->host_bind_count > 0 || ctx->host_cwd[0] != '\0') {
        pid_t pid = kbox_syscall_request_pid(req);
        uint64_t addr = kbox_syscall_request_arg(req, 0);
        char pathbuf[KBOX_MAX_PATH];
        char norm[KBOX_MAX_PATH];
        int ro = 0;
        int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        int brc = resolve_host_bind_canonical(ctx, AT_FDCWD_LINUX, pathbuf,
                                              norm, sizeof(norm), translated,
                                              sizeof(translated), &ro);
        if (brc < 0)
            return kbox_dispatch_errno(-brc);
        if (brc > 0) {
            struct stat st;
            if (stat(translated, &st) < 0)
                return kbox_dispatch_errno(errno);
            if (!S_ISDIR(st.st_mode))
                return kbox_dispatch_errno(ENOTDIR);
            set_active_host_cwd(ctx, norm);
            invalidate_translated_path_cache(ctx);
            return kbox_dispatch_value(0);
        }
        if (ctx->host_cwd[0] != '\0' && pathbuf[0] != '/') {
            snprintf(translated, sizeof(translated), "%s", norm);
        } else {
            rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                        sizeof(translated));
            if (rc < 0)
                return kbox_dispatch_errno(-rc);
        }
    } else {
        int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                        sizeof(translated));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    long ret = kbox_lkl_chdir(ctx->sysnrs, translated);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    set_active_host_cwd(ctx, "");
    invalidate_translated_path_cache(ctx);
    return kbox_dispatch_value(0);
}

/* forward_fchdir. */

static struct kbox_dispatch forward_fchdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))) {
        char guest_cwd[KBOX_MAX_PATH];
        pid_t pid = kbox_syscall_request_pid(req);
        if (resolve_host_fd_guest_bind(ctx, pid, fd, guest_cwd,
                                       sizeof(guest_cwd), NULL) > 0)
            set_active_host_cwd(ctx, guest_cwd);
        else
            set_active_host_cwd(ctx, "");
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long ret = kbox_lkl_fchdir(ctx->sysnrs, lkl_fd);
    if (ret >= 0) {
        set_active_host_cwd(ctx, "");
        invalidate_translated_path_cache(ctx);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* forward_getcwd. */

static struct kbox_dispatch forward_getcwd(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);
    int64_t size_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (size_raw <= 0)
        return kbox_dispatch_errno(EINVAL);

    size_t size = (size_t) size_raw;
    if (size > KBOX_MAX_PATH)
        size = KBOX_MAX_PATH;

    if (ctx->host_cwd[0] != '\0') {
        size_t n = strlen(ctx->host_cwd) + 1;
        if (n > size)
            return kbox_dispatch_errno(ERANGE);
        int wrc = guest_mem_write(ctx, pid, remote_buf, ctx->host_cwd, n);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value((int64_t) n);
    }

    char out[KBOX_MAX_PATH];
    long ret = kbox_lkl_getcwd(ctx->sysnrs, out, (long) size);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    if (n == 0 || n > size)
        return kbox_dispatch_errno(EIO);

    int wrc = guest_mem_write(ctx, pid, remote_buf, out, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* Shared skeleton for simple *at() syscalls: translate path + resolve dirfd,
 * then delegate to a callback for the actual LKL call.
 */

typedef long (*at_path_invoke_fn)(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx,
                                  long lkl_dirfd,
                                  const char *translated);

static struct kbox_dispatch forward_at_path_call(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    at_path_invoke_fn invoke,
    at_path_invoke_fn host_invoke,
    int invalidate_on_success)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd: call the host syscall with a supervisor-owned copy of the
     * tracee's dirfd to avoid the TOCTOU re-read.
     */
    if (should_continue_for_dirfd(lkl_dirfd)) {
        if (!host_invoke)
            return kbox_dispatch_errno(ENOENT);
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        if (host_bind_is_readonly(ctx, pid, raw_dirfd, lkl_dirfd))
            return kbox_dispatch_errno(EROFS);
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                               &sv_dirfd, &close_sv);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        long ret = host_invoke(req, ctx, (long) sv_dirfd, translated);
        if (close_sv)
            close(sv_dirfd);
        if (invalidate_on_success && ret >= 0)
            invalidate_path_shadow_cache(ctx);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));
        return kbox_dispatch_value(ret);
    }

    long ret = invoke(req, ctx, lkl_dirfd, translated);
    if (invalidate_on_success && ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

static long invoke_mkdirat(const struct kbox_syscall_request *req,
                           struct kbox_supervisor_ctx *ctx,
                           long lkl_dirfd,
                           const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_mkdirat(ctx->sysnrs, lkl_dirfd, translated, mode);
}

static long host_invoke_mkdirat(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                long sv_dirfd,
                                const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (mkdirat((int) sv_dirfd, path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_mkdirat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_mkdirat, host_invoke_mkdirat,
                                1);
}

static long invoke_unlinkat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_unlinkat(ctx->sysnrs, lkl_dirfd, translated, flags);
}

static long host_invoke_unlinkat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (unlinkat((int) sv_dirfd, path, (int) flags) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_unlinkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_unlinkat, host_invoke_unlinkat,
                                1);
}

/* forward_renameat / forward_renameat2. */

static struct kbox_dispatch do_renameat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx,
                                        long flags)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    long olddirfd, newdirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, oldtrans,
                                       sizeof(oldtrans), &olddirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_at_path(req, ctx, 2, 3, newtrans, sizeof(newtrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd on either side: call host renameat2 with supervisor-owned
     * copies of the tracee's dirfds.
     */
    if (should_continue_for_dirfd(olddirfd) ||
        should_continue_for_dirfd(newdirfd)) {
        if (!should_continue_for_dirfd(olddirfd) ||
            !should_continue_for_dirfd(newdirfd))
            return kbox_dispatch_errno(EXDEV);
        long raw_old = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        long raw_new = to_dirfd_arg(kbox_syscall_request_arg(req, 2));
        if (host_bind_is_readonly(ctx, pid, raw_old, olddirfd) ||
            host_bind_is_readonly(ctx, pid, raw_new, newdirfd))
            return kbox_dispatch_errno(EROFS);
        int sv_old = AT_FDCWD;
        int sv_new = AT_FDCWD;
        int close_old = 0;
        int close_new = 0;
        int drc = open_host_dirfd_for_dispatch(pid, raw_old, olddirfd, &sv_old,
                                               &close_old);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        drc = open_host_dirfd_for_dispatch(pid, raw_new, newdirfd, &sv_new,
                                           &close_new);
        if (drc < 0) {
            if (close_old)
                close(sv_old);
            return kbox_dispatch_errno(-drc);
        }
        int host_rc = (int) syscall(__NR_renameat2, sv_old, oldtrans, sv_new,
                                    newtrans, (unsigned int) flags);
        int saved = errno;
        if (close_old)
            close(sv_old);
        if (close_new)
            close(sv_new);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_renameat2(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                                  newtrans, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_renameat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx, 0);
}

static struct kbox_dispatch forward_renameat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx,
                       to_c_long_arg(kbox_syscall_request_arg(req, 4)));
}

static long invoke_fchmodat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return kbox_lkl_fchmodat(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
}

static long host_invoke_fchmodat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (fchmodat((int) sv_dirfd, path, (mode_t) mode, 0) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_fchmodat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchmodat, host_invoke_fchmodat,
                                0);
}

static long invoke_fchownat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
    return kbox_lkl_fchownat(ctx->sysnrs, lkl_dirfd, translated, owner, group,
                             flags);
}

static long host_invoke_fchownat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
    if (fchownat((int) sv_dirfd, path, (uid_t) owner, (gid_t) group,
                 (int) flags) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_fchownat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchownat, host_invoke_fchownat,
                                0);
}

/* forward_mount. */

static struct kbox_dispatch forward_mount(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char srcbuf[KBOX_MAX_PATH];
    char tgtbuf[KBOX_MAX_PATH];
    char fsbuf[KBOX_MAX_PATH];
    char databuf[KBOX_MAX_PATH];
    int rc;

    const char *source = NULL;
    if (kbox_syscall_request_arg(req, 0) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                                   srcbuf, sizeof(srcbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        source = srcbuf;
    }

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                               tgtbuf, sizeof(tgtbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    const char *fstype = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 2),
                                   fsbuf, sizeof(fsbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        fstype = fsbuf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    const void *data = NULL;
    if (kbox_syscall_request_arg(req, 4) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 4),
                                   databuf, sizeof(databuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        data = databuf;
    }

    /* Translate paths through normalization and host-root confinement. */
    char translated_tgt[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, tgtbuf, ctx->host_root,
                                     translated_tgt, sizeof(translated_tgt));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Translate the source for bind mounts (MS_BIND uses a path, not a
     * device).  Non-bind sources (device names, "none") pass through
     * unmodified.
     */
    char translated_src[KBOX_MAX_PATH];
    const char *effective_src = source;
    if (source && (flags & 0x1000 /* MS_BIND */)) {
        rc =
            kbox_translate_path_for_lkl(pid, srcbuf, ctx->host_root,
                                        translated_src, sizeof(translated_src));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        effective_src = translated_src;
    }

    long ret = kbox_lkl_mount(ctx->sysnrs, effective_src, translated_tgt,
                              fstype, flags, data);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_umount2. */

static struct kbox_dispatch forward_umount2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_umount2(ctx->sysnrs, translated, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* Legacy x86_64 syscall forwarders (stat, lstat, access, etc.). */

static struct kbox_dispatch forward_stat_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int nofollow)
{
    char translated[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    long lkl_dirfd = AT_FDCWD_LINUX;
    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Host bind or virtual path: call host fstatat with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 0, translated)) {
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        int stat_flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;
        struct stat host_stat;
        if (fstatat(AT_FDCWD, sv_path, &host_stat, stat_flags) < 0)
            return kbox_dispatch_errno(errno);
        normalize_host_stat_if_needed(ctx, translated, &host_stat);
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                                 &host_stat, sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat, pid)) {
        return kbox_dispatch_value(0);
    }

    long flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_newfstatat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                   &kst, flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Shared skeleton for legacy (non-*at) path syscalls: translate a single
 * path from arg[0], then delegate to a callback for the LKL call.
 */

typedef long (*legacy_path_invoke_fn)(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *translated);

static long invoke_access_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated);

static struct kbox_dispatch forward_legacy_path_call(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    legacy_path_invoke_fn invoke,
    legacy_path_invoke_fn host_invoke)
{
    char translated[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    long lkl_dirfd = AT_FDCWD_LINUX;
    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host bind or virtual path: call host syscall with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 0, translated)) {
        if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO &&
            invoke != invoke_access_legacy)
            return kbox_dispatch_errno(EROFS);
        if (!host_invoke)
            return kbox_dispatch_errno(ENOENT);
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        long ret = host_invoke(req, ctx, sv_path);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));
        return kbox_dispatch_value(ret);
    }
    return kbox_dispatch_from_lkl(invoke(req, ctx, translated));
}

static long invoke_access_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_faccessat2(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode,
                               0);
}

static long host_invoke_access_legacy(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (faccessat(AT_FDCWD, path, (int) mode, 0) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_access_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_access_legacy,
                                    host_invoke_access_legacy);
}

static long invoke_mkdir_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_mkdir(ctx->sysnrs, translated, (int) mode);
}

static long host_invoke_mkdir_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (mkdir(path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_mkdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_mkdir_legacy,
                                    host_invoke_mkdir_legacy);
}

static long invoke_unlink_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated)
{
    (void) req;
    return kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated, 0);
}

static long host_invoke_unlink_legacy(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *path)
{
    (void) req;
    (void) ctx;
    if (unlink(path) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_unlink_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_unlink_legacy,
                                    host_invoke_unlink_legacy);
}

static long invoke_rmdir_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    (void) req;
    return kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                             AT_REMOVEDIR);
}

static long host_invoke_rmdir_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) req;
    (void) ctx;
    if (rmdir(path) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_rmdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_rmdir_legacy,
                                    host_invoke_rmdir_legacy);
}

static struct kbox_dispatch forward_rename_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, oldtrans,
                                    sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_path(req, ctx, 1, ctx->host_root, newtrans,
                                sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_renameat2(ctx->sysnrs, AT_FDCWD_LINUX, oldtrans,
                                  AT_FDCWD_LINUX, newtrans, 0);
    return kbox_dispatch_from_lkl(ret);
}

static long invoke_chmod_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_fchmodat(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
}

static long host_invoke_chmod_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (chmod(path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_chmod_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_chmod_legacy,
                                    host_invoke_chmod_legacy);
}

static long invoke_chown_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_fchownat(ctx->sysnrs, AT_FDCWD_LINUX, translated, owner,
                             group, 0);
}

static long host_invoke_chown_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long owner = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long group = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (chown(path, (uid_t) owner, (gid_t) group) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_chown_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_chown_legacy,
                                    host_invoke_chown_legacy);
}

/* Syscall dispatch tables.
 *
 * X-macros eliminate the repetitive if-chains for the two most common dispatch
 * patterns. Each _(field, handler) entry expands to
 *   if (nr == h->field) return handler(req, ctx);
 *
 * Complex cases (extra args, guards, inline logic) remain as explicit if-blocks
 * after the table expansions.
 */

/* DISPATCH_FORWARD: forwarded to a handler that takes (req, ctx). */
#define DISPATCH_FORWARD_TABLE(_)                                             \
    /* Legacy x86_64 syscalls. */                                             \
    _(access, forward_access_legacy)                                          \
    _(mkdir, forward_mkdir_legacy)                                            \
    _(rmdir, forward_rmdir_legacy)                                            \
    _(unlink, forward_unlink_legacy)                                          \
    _(rename, forward_rename_legacy)                                          \
    _(chmod, forward_chmod_legacy)                                            \
    _(chown, forward_chown_legacy)                                            \
    _(open, forward_open_legacy)                                              \
    /* File open/create. */                                                   \
    _(openat, forward_openat)                                                 \
    _(openat2, forward_openat2)                                               \
    /* Metadata. */                                                           \
    _(fstat, forward_fstat)                                                   \
    _(newfstatat, forward_newfstatat)                                         \
    _(statx, forward_statx)                                                   \
    _(faccessat2, forward_faccessat2)                                         \
    /* Directories. */                                                        \
    _(getdents64, forward_getdents64)                                         \
    _(getdents, forward_getdents)                                             \
    _(mkdirat, forward_mkdirat)                                               \
    _(unlinkat, forward_unlinkat)                                             \
    _(renameat2, forward_renameat2)                                           \
    _(fchmodat, forward_fchmodat)                                             \
    _(fchownat, forward_fchownat)                                             \
    /* Navigation. */                                                         \
    _(chdir, forward_chdir)                                                   \
    _(fchdir, forward_fchdir)                                                 \
    _(getcwd, forward_getcwd)                                                 \
    /* Mount. */                                                              \
    _(mount, forward_mount)                                                   \
    _(umount2, forward_umount2)                                               \
    /* FD operations. */                                                      \
    _(close, forward_close)                                                   \
    _(fcntl, forward_fcntl)                                                   \
    _(dup, forward_dup)                                                       \
    _(dup2, forward_dup2)                                                     \
    _(dup3, forward_dup3)                                                     \
    /* I/O. */                                                                \
    _(write, forward_write)                                                   \
    _(lseek, forward_lseek)                                                   \
    /* Networking. */                                                         \
    _(socket, forward_socket)                                                 \
    _(bind, forward_bind)                                                     \
    _(listen, forward_listen)                                                 \
    _(accept, forward_accept)                                                 \
    _(accept4, forward_accept4)                                               \
    _(connect, forward_connect)                                               \
    _(sendto, forward_sendto)                                                 \
    _(sendmmsg, forward_sendmmsg)                                             \
    _(recvfrom, forward_recvfrom)                                             \
    _(recvmsg, forward_recvmsg)                                               \
    _(getsockopt, forward_getsockopt)                                         \
    _(setsockopt, forward_setsockopt)                                         \
    _(getsockname, forward_getsockname)                                       \
    _(getpeername, forward_getpeername)                                       \
    _(shutdown, forward_shutdown)                                             \
    /* I/O extended. */                                                       \
    _(pwrite64, forward_pwrite64)                                             \
    _(pwritev, forward_pwritev)                                               \
    _(preadv, forward_preadv)                                                 \
    _(pwritev2, forward_pwritev2)                                             \
    _(preadv2, forward_preadv2)                                               \
    _(writev, forward_writev)                                                 \
    _(readv, forward_readv)                                                   \
    _(ftruncate, forward_ftruncate)                                           \
    _(fallocate, forward_fallocate)                                           \
    _(flock, forward_flock)                                                   \
    _(fchmod, forward_fchmod)                                                 \
    _(fadvise64, forward_fadvise64)                                           \
    _(fsync, forward_fsync)                                                   \
    _(fdatasync, forward_fdatasync)                                           \
    _(sync, forward_sync)                                                     \
    _(ioctl, forward_ioctl)                                                   \
    /* File operations. */                                                    \
    _(readlinkat, forward_readlinkat)                                         \
    _(pipe2, forward_pipe2)                                                   \
    _(socketpair, forward_socketpair)                                         \
    _(getxattr, forward_xattr_nodata)                                         \
    _(lgetxattr, forward_xattr_nodata)                                        \
    _(fgetxattr, forward_xattr_nodata)                                        \
    _(listxattr, forward_xattr_empty_list)                                    \
    _(llistxattr, forward_xattr_empty_list)                                   \
    _(flistxattr, forward_xattr_empty_list)                                   \
    _(symlinkat, forward_symlinkat)                                           \
    _(linkat, forward_linkat)                                                 \
    _(utimensat, forward_utimensat)                                           \
    _(sendfile, forward_sendfile)                                             \
    /* Time. */                                                               \
    _(clock_gettime, forward_clock_gettime)                                   \
    _(clock_getres, forward_clock_getres)                                     \
    _(gettimeofday, forward_gettimeofday)                                     \
    /* Process lifecycle. */                                                  \
    _(umask, forward_umask)                                                   \
    _(uname, forward_uname)                                                   \
    _(getrandom, forward_getrandom)                                           \
    _(syslog, forward_syslog)                                                 \
    _(prctl, forward_prctl)                                                   \
    _(capget, forward_capget)                                                 \
    _(capset, forward_capset)                                                 \
    /* Threading. */                                                          \
    _(clone3, forward_clone3)                                                 \
    /* FD-creating syscalls tracked as host-passthrough. */                   \
    _(eventfd2, forward_eventfd)                                              \
    _(timerfd_create, forward_timerfd_create)                                 \
    _(signalfd4, forward_signalfd4)                                           \
    _(epoll_create1, forward_epoll_create1)                                   \
    /* FD-consuming syscalls gated by deny check (were in CONTINUE table). */ \
    _(epoll_ctl, forward_epoll_ctl_gated)                                     \
    _(epoll_wait, forward_fd_gated_continue)                                  \
    _(epoll_pwait, forward_fd_gated_continue)                                 \
    _(timerfd_settime, forward_fd_gated_continue)                             \
    _(timerfd_gettime, forward_fd_gated_continue)                             \
    _(statfs, forward_statfs)                                                 \
    _(fstatfs, forward_fstatfs)

/* DISPATCH_CONTINUE: host kernel handles directly, no LKL involvement.
 * Only non-FD syscalls remain here; FD-based syscalls are in the handler
 * table so their FD arguments can be validated.
 */
/* clang-format off */
#define DISPATCH_CONTINUE_TABLE(_)                                             \
    _(setpgid) _(getpgid) _(getsid) _(setsid) _(brk) _(wait4) _(waitid)        \
    _(exit) _(exit_group) _(rt_sigreturn) _(rt_sigaltstack) _(rt_sigsuspend)  \
    _(setitimer)                                                               \
    _(getitimer) _(set_tid_address) _(set_robust_list) _(futex) _(rseq)        \
    _(membarrier) _(madvise) _(getrlimit) _(getrusage)                         \
    /* Scheduling. */                                                          \
    _(sched_yield) _(sched_setparam) _(sched_getparam) _(sched_setscheduler)   \
    _(sched_getscheduler) _(sched_get_priority_max) _(sched_get_priority_min)  \
    _(sched_setaffinity) _(sched_getaffinity)                                  \
    /* I/O multiplexing (non-FD-creating multiplexers only). */                \
    _(ppoll) _(pselect6) _(poll)                                               \
    /* Sleep. */                                                               \
    _(nanosleep) _(clock_nanosleep)                                            \
    /* POSIX per-process timers. */                                            \
    _(timer_create) _(timer_gettime) _(timer_getoverrun) _(timer_settime)      \
    _(timer_delete)                                                            \
    /* System info (path/FD statfs handled in DISPATCH_FORWARD_TABLE). */      \
    _(sysinfo) _(getcpu)
/* clang-format on */

static int is_guest_process_pid(struct kbox_supervisor_ctx *ctx,
                                pid_t caller_tid,
                                pid_t target)
{
    if (target == 1 || target == caller_tid ||
        (ctx && target == ctx->child_pid))
        return 1;
    if (!ctx || target <= 1 || ctx->child_pid <= 0)
        return 0;

    pid_t tgid = 0;
    pid_t ppid = -1;
    if (read_proc_tgid_ppid(target, &tgid, &ppid, NULL) < 0)
        return 0;
    if (tgid == ctx->child_pid || tgid == caller_tid ||
        (tgid > 0 && find_proc_fd_entry(ctx, tgid) != NULL))
        return 1;

    pid_t walk = ppid;
    for (int hop = 0; hop < 32 && walk > 1; hop++) {
        if (walk == ctx->child_pid || walk == caller_tid ||
            find_proc_fd_entry(ctx, walk) != NULL)
            return 1;
        pid_t next_ppid = -1;
        if (read_proc_tgid_ppid(walk, NULL, &next_ppid, NULL) < 0)
            break;
        if (next_ppid == walk)
            break;
        walk = next_ppid;
    }
    return 0;
}

struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h = ctx->host_nrs;
    int nr;

    if (!ctx || !req)
        return kbox_dispatch_errno(EINVAL);

    /* A vfork parent is suspended until its child execs, so its first syscall
     * afterwards is the moment the exec rewrite can be undone. Doing it here,
     * rather than from a watcher thread guessing when the exec landed, means
     * the bytes are never restored while the kernel has yet to read them. */
    for (size_t i = 0;
         i < sizeof(ctx->vfork_pending) / sizeof(ctx->vfork_pending[0]); i++) {
        struct kbox_vfork_pending *slot = &ctx->vfork_pending[i];
        if (!slot->saved)
            continue;
        if (slot->parent != (pid_t) kbox_syscall_request_pid(req))
            continue;
        struct iovec local = {.iov_base = slot->saved, .iov_len = slot->len};
        struct iovec remote = {.iov_base = (void *) (uintptr_t) slot->addr,
                               .iov_len = slot->len};
        (void) process_vm_writev(slot->parent, &local, 1, &remote, 1, 0);
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: exec: vfork parent %d restored on syscall nr=%d\n",
                    (int) slot->parent, (int) req->nr);
        free(slot->saved);
        slot->saved = NULL;
    }

    kbox_dispatch_prepare_request_ctx(ctx, req);
    nr = req->nr;

    if (ctx->verbose) {
        const char *name = syscall_name_from_nr(h, nr);
        fprintf(stderr, "%s syscall: pid=%u nr=%d (%s)\n",
                req->source == KBOX_SYSCALL_SOURCE_SECCOMP ? "seccomp notify"
                                                           : "in-process",
                kbox_syscall_request_pid(req), nr, name ? name : "unknown");
    }

    /* Table-driven dispatch: forward to handler. */

#define _(field, handler) \
    if (nr == h->field)   \
        return handler(req, ctx);
    DISPATCH_FORWARD_TABLE(_)
#undef _

    /* Table-driven dispatch: CONTINUE to host kernel. */

#define _(field)        \
    if (nr == h->field) \
        return kbox_dispatch_continue();
    DISPATCH_CONTINUE_TABLE(_)
#undef _

    /* Entries with extra arguments or guards. */

    if (nr == h->stat)
        return forward_stat_legacy(req, ctx, 0);
    if (nr == h->lstat)
        return forward_stat_legacy(req, ctx, 1);
    if (nr == h->read)
        return forward_read_like(req, ctx, 0);
    if (nr == h->pread64)
        return forward_read_like(req, ctx, 1);
    if (nr == h->faccessat && h->faccessat > 0)
        return forward_faccessat(req, ctx);
    if (nr == h->renameat && h->renameat > 0)
        return forward_renameat(req, ctx);
    if (nr == h->copy_file_range)
        return kbox_dispatch_errno(ENOSYS);
    /* msync had no dispatch entry at all, so the deny-unknown tail answered
     * ENOSYS. Kafka's KRaft log -- and anything else that fsyncs a mapping --
     * then failed with "Function not implemented (msync with parameter MS_SYNC
     * failed)" and shut the broker down. The mapping belongs to LKL, so LKL has
     * to be the one to write it back.
     */
    if (ctx->verbose && (nr == 26 || nr == 227))
        fprintf(stderr, "kbox: msync seen nr=%d table_msync=%d\n", nr,
                h->msync);

    if (nr == h->msync || ((h->msync <= 0) && (nr == 26 || nr == 227))) {
        /* The mapping lives in the tracee's own address space: file mappings
         * are served from host shadows, so the kernel that has to write the
         * pages back is the host one. Asking LKL about that address answers
         * EINVAL/ENOSYS because it never mapped it. */
        return kbox_dispatch_continue();
    }
    if (nr == h->execve || nr == h->execveat) {
        if (ctx->proc_fd_count > 1)
            reap_dead_proc_fds(ctx);
        return forward_execve(req, ctx, nr == h->execveat);
    }

    /* Process info: in seccomp-notify mode, return real host PIDs/TIDs so
     * /proc/self/task entries, PID files, and kernel si_pid on tgkill match
     * getpid()/gettid() (e.g. glibc nptl_setxid). Trap/rewrite modes keep
     * constant virtualization.
     */

    /* SysV IPC lives in the pod's IPC namespace and its segments are mapped
     * into the tracee's own address space, so the host kernel has to be the
     * one handling these. Left to the default they were refused with ENOSYS,
     * and postgres died in bootstrap: its shared memory is shmget(posix is
     * only chosen when sysv is unavailable, which is never on a real host).
     */
    if (nr == h->shmget || nr == h->shmat || nr == h->shmdt ||
        nr == h->shmctl || nr == h->semget || nr == h->semop ||
        nr == h->semctl || nr == h->semtimedop || nr == h->msgget ||
        nr == h->msgsnd || nr == h->msgrcv || nr == h->msgctl)
        return kbox_dispatch_continue();

    if (nr == h->getpid) {
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        return kbox_dispatch_value(1);
    }
    if (nr == h->getppid) {
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP &&
            kbox_syscall_request_pid(req) != ctx->child_pid)
            return kbox_dispatch_continue();
        return kbox_dispatch_value(0);
    }
    if (nr == h->gettid) {
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        return kbox_dispatch_value(1);
    }

    /* Identity: UID. */

    if (nr == h->getuid)
        return dispatch_get_uid(kbox_lkl_getuid, ctx);
    if (nr == h->geteuid)
        return dispatch_get_uid(kbox_lkl_geteuid, ctx);
    if (nr == h->getresuid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresuid_override(req, ctx, 0);
            if (ctx->override_uid != (uid_t) -1)
                return forward_getresuid_override(req, ctx, ctx->override_uid);
            return kbox_dispatch_continue();
        }
        return forward_getresuid(req, ctx);
    }

    /* Identity: GID. */

    if (nr == h->getgid)
        return dispatch_get_gid(kbox_lkl_getgid, ctx);
    if (nr == h->getegid)
        return dispatch_get_gid(kbox_lkl_getegid, ctx);
    if (nr == h->getresgid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresgid_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getresgid_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getresgid(req, ctx);
    }

    /* Identity: groups. */

    if (nr == h->getgroups) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getgroups_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getgroups_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getgroups(req, ctx);
    }

    /* Identity: set*. */

    if (nr == h->setuid)
        return dispatch_set_id(req, ctx, forward_setuid);
    if (nr == h->setreuid)
        return dispatch_set_id(req, ctx, forward_setreuid);
    if (nr == h->setresuid)
        return dispatch_set_id(req, ctx, forward_setresuid);
    if (nr == h->setgid)
        return dispatch_set_id(req, ctx, forward_setgid);
    if (nr == h->setregid)
        return dispatch_set_id(req, ctx, forward_setregid);
    if (nr == h->setresgid)
        return dispatch_set_id(req, ctx, forward_setresgid);
    if (nr == h->setgroups)
        return dispatch_set_id(req, ctx, forward_setgroups);
    if (nr == h->setfsgid)
        return dispatch_set_id(req, ctx, forward_setfsgid);

    /* Legacy eventfd syscall (one arg, no flags). eventfd2 is in the handler
     * table; the raw eventfd(2) syscall does not take a flags argument.
     */
    if (nr == h->eventfd) {
        unsigned int initval = (unsigned int) kbox_syscall_request_arg(req, 0);
        int host_fd = eventfd(initval, 0);
        if (host_fd < 0)
            return kbox_dispatch_errno(errno);
        int tfd = request_addfd(ctx, req, host_fd, 0);
        close(host_fd);
        if (tfd < 0)
            return kbox_dispatch_errno(-tfd);
        track_host_passthrough_fd(ctx->fd_table, tfd);
        return kbox_dispatch_value(tfd);
    }

    /* Legacy pipe syscall: one arg, create host pipe2 and inject via ADDFD. */

    if (nr == h->pipe) {
        pid_t ppid = kbox_syscall_request_pid(req);
        uint64_t remote_pfd = kbox_syscall_request_arg(req, 0);
        if (remote_pfd == 0)
            return kbox_dispatch_errno(EFAULT);

        int host_pfds[2];
        if (pipe(host_pfds) < 0)
            return kbox_dispatch_errno(errno);

        int tfd0 = request_addfd(ctx, req, host_pfds[0], 0);
        if (tfd0 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd0);
        }
        int tfd1 = request_addfd(ctx, req, host_pfds[1], 0);
        if (tfd1 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd1);
        }
        close(host_pfds[0]);
        close(host_pfds[1]);

        track_host_passthrough_fd(ctx->fd_table, tfd0);
        track_host_passthrough_fd(ctx->fd_table, tfd1);

        int gfds[2] = {tfd0, tfd1};
        int pwrc = guest_mem_write(ctx, ppid, remote_pfd, gfds, sizeof(gfds));
        if (pwrc < 0)
            return kbox_dispatch_errno(-pwrc);
        return kbox_dispatch_value(0);
    }

    /* Signals.
     *
     * rt_sigaction: only SIGSYS is denied (reserved for trap mode).
     * All other signals -- including SIGURG (Go async preemption),
     * SIGUSR1/2, SIGALRM, etc. -- pass through to the host kernel
     * via CONTINUE.  SIGSEGV/SIGBUS changes bump the fault handler
     * generation counter so procmem.c reinstalls its handler.
     *
     * rt_sigprocmask: in trap/rewrite mode, emulated to keep the
     * supervisor's SIGSYS unblocked.  In seccomp mode, CONTINUE.
     */

    if (nr == h->rt_sigaction) {
        if (request_uses_trap_signals(req) &&
            kbox_syscall_trap_signal_is_reserved(
                (int) to_c_long_arg(kbox_syscall_request_arg(req, 0)))) {
            if (ctx->verbose) {
                fprintf(stderr,
                        "kbox: reserved SIGSYS handler change denied "
                        "(pid=%u source=%d)\n",
                        kbox_syscall_request_pid(req), req->source);
            }
            return kbox_dispatch_errno(EPERM);
        }
        {
            int signo = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (signo == 11 /* SIGSEGV */ || signo == 7 /* SIGBUS */)
                kbox_procmem_signal_changed();
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->rt_sigprocmask) {
        if (request_uses_trap_signals(req)) {
            long how = to_c_long_arg(kbox_syscall_request_arg(req, 0));
            int blocks_reserved = request_blocks_reserved_sigsys(req, ctx);

            if (blocks_reserved < 0)
                return kbox_dispatch_errno(-blocks_reserved);
            if (how != SIG_UNBLOCK && blocks_reserved) {
                if (ctx->verbose) {
                    fprintf(stderr,
                            "kbox: reserved SIGSYS mask change denied "
                            "(pid=%u source=%d how=%ld)\n",
                            kbox_syscall_request_pid(req), req->source, how);
                }
                return kbox_dispatch_errno(EPERM);
            }
            return emulate_trap_rt_sigprocmask(req, ctx);
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->rt_sigpending) {
        if (request_uses_trap_signals(req))
            return emulate_trap_rt_sigpending(req, ctx);
        return kbox_dispatch_continue();
    }
    if (h->alarm >= 0 && nr == h->alarm)
        return kbox_dispatch_continue();

    /* Signal delivery: PID validation + virtual-to-real translation.
     *
     * kill/tgkill/tkill share PID validation (guest process tree only), virtual
     * PID 1 -> real PID translation, and trap-mode pending signal bookkeeping.
     */

#define IS_GUEST_PID(p) \
    is_guest_process_pid(ctx, kbox_syscall_request_pid(req), (p))

#define DENY_NON_GUEST(pid_val, name)              \
    do {                                           \
        if (!IS_GUEST_PID(pid_val)) {              \
            if (ctx->verbose)                      \
                fprintf(stderr,                    \
                        "kbox: " name              \
                        "(%d) "                    \
                        "denied: not guest PID\n", \
                        (int) (pid_val));          \
            return kbox_dispatch_errno(EPERM);     \
        }                                          \
    } while (0)

    if (nr == h->kill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        if (target == 0 && req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        pid_t check_pid = (target < -1) ? -target : target;
        if (target != 0 && !IS_GUEST_PID(check_pid))
            DENY_NON_GUEST(target, "kill");
        pid_t real = (target == 0 || target == 1) ? ctx->child_pid : target;
        long ret = syscall(SYS_kill, real, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        if (request_uses_trap_signals(req) && real == ctx->child_pid &&
            trap_sigmask_contains_signal(sig))
            (void) kbox_syscall_trap_add_pending_signal(sig);
        return kbox_dispatch_value(0);
    }
    if (nr == h->tgkill) {
        pid_t tgid = (pid_t) kbox_syscall_request_arg(req, 0);
        pid_t tid = (pid_t) kbox_syscall_request_arg(req, 1);
        int sig = (int) kbox_syscall_request_arg(req, 2);
        pid_t caller_tid = kbox_syscall_request_pid(req);
        pid_t caller_tgid = 0;

        if (read_proc_tgid_ppid(caller_tid, &caller_tgid, NULL, NULL) < 0 ||
            caller_tgid <= 0)
            caller_tgid = ctx->child_pid;
        if (!IS_GUEST_PID(tgid) && tgid != caller_tgid)
            DENY_NON_GUEST(tgid, "tgkill");
        /* When the tracee passes its own real tgid in seccomp-notify mode,
         * execute tgkill directly in the tracee via CONTINUE so the kernel
         * fills si_pid = caller_tgid and si_code = SI_TKILL natively.
         */
        if (tgid == caller_tgid && req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        /* In a forked guest subprocess, virtual PID 1 maps to the caller's
         * own thread-group leader rather than the root container init PID, so
         * glibc multi-threaded setxid/pthread tgkill reaches sibling threads.
         */
        pid_t real_tgid = (tgid == 1) ? caller_tgid : tgid;
        pid_t real_tid = (tid == 1) ? caller_tid : tid;
        long ret = syscall(SYS_tgkill, real_tgid, real_tid, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        if (request_uses_trap_signals(req) && real_tid == caller_tid &&
            trap_sigmask_contains_signal(sig))
            (void) kbox_syscall_trap_add_pending_signal(sig);
        return kbox_dispatch_value(0);
    }
    if (nr == h->tkill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        DENY_NON_GUEST(target, "tkill");
        pid_t real_tid = (target == 1) ? kbox_syscall_request_pid(req) : target;
        long ret = syscall(SYS_tkill, real_tid, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        if (request_uses_trap_signals(req) &&
            real_tid == kbox_syscall_request_pid(req) &&
            trap_sigmask_contains_signal(sig))
            (void) kbox_syscall_trap_add_pending_signal(sig);
        return kbox_dispatch_value(0);
    }
#undef DENY_NON_GUEST
#undef IS_GUEST_PID
    if (nr == h->pidfd_send_signal)
        return kbox_dispatch_errno(EPERM);

    /* arch_prctl: intercept SET_FS/GET_FS in trap/rewrite mode. */

    if (nr == h->arch_prctl) {
        if (request_uses_trap_signals(req)) {
            long subcmd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (subcmd == 0x1002 /* ARCH_SET_FS */) {
                kbox_syscall_trap_set_guest_fs(
                    kbox_syscall_request_arg(req, 1));
                return kbox_dispatch_value(0);
            }
            if (subcmd == 0x1003 /* ARCH_GET_FS */) {
                uint64_t out_ptr = kbox_syscall_request_arg(req, 1);
                uint64_t fs = kbox_syscall_trap_get_guest_fs();
                if (out_ptr == 0)
                    return kbox_dispatch_errno(EFAULT);
                int wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                                          out_ptr, &fs, sizeof(fs));
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
                return kbox_dispatch_value(0);
            }
        }
        return kbox_dispatch_continue();
    }

    /* clone: validate namespace and thread flags. */

    if (nr == h->clone) {
        uint64_t cflags = kbox_syscall_request_arg(req, 0);
        if (cflags & CLONE_NEW_MASK) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: namespace flags 0x%llx "
                        "(pid=%u)\n",
                        (unsigned long long) (cflags & CLONE_NEW_MASK),
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
        /* CLONE_VM|CLONE_VFORK: the child shares the parent's address space,
         * and kbox performs an exec by rewriting the pathname in tracee
         * memory. The rewrite therefore lands in the parent too, which then
         * resumes with "/proc/self/fd/N" where its own path used to be, and
         * every later fork in that process execs the stale descriptor
         * (posix_spawn, popen and system all take this path). clone's flags
         * arrive in a register and cannot be rewritten the way clone3's struct
         * can, so remember the parent and let the exec path snapshot and undo
         * its own writes when the parent leaves vfork. */
        if ((cflags & (CLONE_VM | CLONE_VFORK)) == (CLONE_VM | CLONE_VFORK)) {
            pid_t vp = (pid_t) kbox_syscall_request_pid(req);
            ctx->vfork_parents[ctx->vfork_parent_next %
                               (sizeof(ctx->vfork_parents) /
                                sizeof(ctx->vfork_parents[0]))] = vp;
            ctx->vfork_parent_next++;
            if (ctx->verbose)
                fprintf(stderr, "kbox: clone: vfork parent recorded (pid=%d)\n",
                        (int) vp);
        }
        if ((cflags & CLONE_THREAD) && request_uses_trap_signals(req)) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: CLONE_THREAD in trap/rewrite mode "
                        "(pid=%u, use --syscall-mode=seccomp)\n",
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif
        if (!(cflags & (CLONE_THREAD | CLONE_FILES)))
            kbox_dispatch_snapshot_fork(ctx, kbox_syscall_request_pid(req));
        return kbox_dispatch_continue();
    }

    if ((h->fork >= 0 && nr == h->fork) || (h->vfork >= 0 && nr == h->vfork)) {
        kbox_dispatch_snapshot_fork(ctx, kbox_syscall_request_pid(req));
        return kbox_dispatch_continue();
    }

    /* Memory mapping: invalidate path cache, then forward/CONTINUE. */

    if (nr == h->mmap) {
        invalidate_translated_path_cache(ctx);
        return forward_mmap(req, ctx);
    }
    if (nr == h->munmap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }
    if (nr == h->mprotect) {
        invalidate_translated_path_cache(ctx);
        return forward_mprotect(req, ctx);
    }
    if (nr == h->mremap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }

    /* prlimit64: GET is safe, SET is restricted. */

    if (nr == h->prlimit64) {
        uint64_t new_limit_ptr = kbox_syscall_request_arg(req, 2);
        if (new_limit_ptr == 0)
            return kbox_dispatch_continue();
        int resource = (int) kbox_syscall_request_arg(req, 1);
        if (resource == 4 /* RLIMIT_CORE */ || resource == 9 /* RLIMIT_AS */)
            return kbox_dispatch_continue();
        if (ctx->verbose)
            fprintf(stderr, "kbox: prlimit64 SET resource=%d denied\n",
                    resource);
        return kbox_dispatch_errno(EPERM);
    }

    /* readlink: TOCTOU risk, forward to LKL via readlinkat. */

    if (nr == h->readlink) {
        char path[4096];
        int ret = guest_mem_read_string(ctx, kbox_syscall_request_pid(req),
                                        kbox_syscall_request_arg(req, 0), path,
                                        sizeof(path));
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        long bufsiz = (long) kbox_syscall_request_arg(req, 2);
        char buf[4096];
        if (bufsiz > (long) sizeof(buf))
            bufsiz = (long) sizeof(buf);
        long lret =
            kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, path, buf, bufsiz);
        if (lret < 0)
            return kbox_dispatch_from_lkl(lret);
        ret = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                              kbox_syscall_request_arg(req, 1), buf,
                              (size_t) lret);
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        return kbox_dispatch_value(lret);
    }

    /* Default: deny unknown syscalls. */
    if (ctx->verbose)
        fprintf(stderr, "kbox: DENY unknown syscall nr=%d (pid=%u)\n", nr,
                kbox_syscall_request_pid(req));
    return kbox_dispatch_errno(ENOSYS);
}

struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif_ptr)
{
    struct kbox_syscall_request req;

    if (kbox_syscall_request_from_notif(notif_ptr, &req) < 0)
        return kbox_dispatch_errno(EINVAL);
    return kbox_dispatch_request(ctx, &req);
}
