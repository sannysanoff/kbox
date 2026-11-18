/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SECCOMP_H
#define KBOX_SECCOMP_H

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fd-table.h"
#include "kbox/path.h"
#include "procmem.h"
#include "seccomp-defs.h"
#include "syscall-nr.h"
#include "syscall-trap-signal.h"

struct kbox_dispatch {
    enum {
        KBOX_DISPATCH_CONTINUE,
        KBOX_DISPATCH_RETURN,
        KBOX_DISPATCH_DEFERRED,
    } kind;
    int64_t val;
    int error;
};

struct kbox_web_ctx;
struct kbox_fd_inject_ops;

#define KBOX_PATH_SHADOW_CACHE_MAX 8
#define KBOX_TRANSLATED_PATH_CACHE_MAX 8
#define KBOX_LITERAL_PATH_CACHE_MAX 8

struct kbox_path_shadow_cache_entry {
    int valid;
    int memfd;
    char path[KBOX_MAX_PATH];
    struct stat host_stat;
};

struct kbox_translated_path_cache_entry {
    int valid;
    unsigned generation;
    char guest_path[KBOX_MAX_PATH];
    char translated[KBOX_MAX_PATH];
};

struct kbox_literal_path_cache_entry {
    int valid;
    unsigned generation;
    pid_t pid;
    uint64_t guest_addr;
    char translated[KBOX_MAX_PATH];
};

enum kbox_syscall_source {
    KBOX_SYSCALL_SOURCE_SECCOMP = 0,
    KBOX_SYSCALL_SOURCE_TRAP,
    KBOX_SYSCALL_SOURCE_REWRITE,
};

struct kbox_syscall_regs {
    int nr;
    uint64_t instruction_pointer;
    uint64_t args[6];
};

struct kbox_syscall_request {
    enum kbox_syscall_source source;
    pid_t pid;
    uint64_t cookie;
    int nr;
    uint64_t instruction_pointer;
    uint64_t args[6];
    struct kbox_guest_mem guest_mem;
};

static inline pid_t kbox_syscall_request_pid(
    const struct kbox_syscall_request *req)
{
    return req->pid;
}

static inline uint64_t kbox_syscall_request_cookie(
    const struct kbox_syscall_request *req)
{
    return req->cookie;
}

static inline uint64_t kbox_syscall_request_arg(
    const struct kbox_syscall_request *req,
    size_t idx)
{
    return idx < 6 ? req->args[idx] : 0;
}

#define KBOX_PENDING_ACCEPTS_MAX 64
#define KBOX_PROC_FD_TABLES_MAX 128
#define KBOX_PID_TGID_CACHE_MAX 256
#define KBOX_HOST_BINDS_MAX 32

#define KBOX_LKL_DIRFD_HOST_BIND (-3)
#define KBOX_LKL_DIRFD_HOST_BIND_RO (-4)

struct kbox_host_bind {
    char host_path[KBOX_MAX_PATH];
    char guest_path[KBOX_MAX_PATH];
    size_t guest_len;
    int readonly;
    /* Source was an "nfs://<name>[/subdir]" reference rather than a host path;
     * the daemon bind-mounts it instead of the dispatch layer redirecting it.
     */
    int is_nfs;
};

struct kbox_proc_fd_entry {
    pid_t tgid;
    int owned;
    struct kbox_fd_table *table;
    char host_cwd[KBOX_MAX_PATH];
    /* Working directory of the process inside LKL. LKL has one cwd for the
     * whole container, so each process keeps its own here and the dispatcher
     * switches LKL to it before serving that process (a `mkdir -p` child that
     * chdir()s must not move its parent's cwd). Empty = not yet known. */
    char lkl_cwd[KBOX_MAX_PATH];
};

#define KBOX_PENDING_FORKS_MAX 64

struct kbox_pending_fork {
    pid_t parent_tgid;
    struct kbox_fd_table *table;
    char host_cwd[KBOX_MAX_PATH];
    char lkl_cwd[KBOX_MAX_PATH];
};

struct kbox_pid_tgid_entry {
    pid_t pid;
    pid_t tgid;
};

struct kbox_pending_accept {
    int active;
    struct kbox_syscall_request req;
    long listen_fd;
    int flags;
    uint64_t addr_ptr;
    uint64_t len_ptr;
    unsigned int in_len;
};

/* A blocking datagram recvfrom that the supervisor must not wait for.
 *
 * The dispatcher is one thread: it receives a notification, runs the handler,
 * answers. A blocking recvfrom on a shadow socket therefore stalls every other
 * syscall of the whole guest, including the other threads of the same process.
 * Python's asyncio test helpers run a UDP echo server in a thread; the echo
 * thread blocked in recvfrom and the main thread never got its own sendto
 * handled, so test_asyncio hung. The request is parked here instead and the
 * main loop completes it when data arrives.
 */
struct kbox_pending_recv {
    int active;
    struct kbox_syscall_request req;
    long fd;
    uint64_t buf_ptr;
    uint64_t src_ptr;
    uint64_t addrlen_ptr;
    size_t len;
    long flags;
    unsigned int addrlen;
    long deadline_ms; /* CLOCK_MONOTONIC, -1 = no SO_RCVTIMEO */
};

#define KBOX_PENDING_RECVS_MAX 16

/* A blocking recvmsg(2) that has to wait for a datagram.
 *
 * The dispatcher answers every notification for the container on one thread, so
 * waiting inside it stops the guest's other threads (the sending thread of the
 * same process among them) from being served at all. The notification is parked
 * instead and completed by kbox_dispatch_poll_pending.
 */
struct kbox_pending_recvmsg {
    int active;
    struct kbox_syscall_request req;
    long fd;
    uint64_t msg_ptr;
    long flags;
    long deadline_ms;
};

#define KBOX_PENDING_RECVMSGS_MAX 8

struct kbox_supervisor_ctx {
    const struct kbox_sysnrs *sysnrs;
    const struct kbox_host_nrs *host_nrs;
    struct kbox_fd_table *fd_table;
    int listener_fd;
    int proc_self_fd_dirfd;
    int proc_mem_fd;
    int inherited_fds_tracked;
    pid_t child_pid;
    const char *host_root;
    int verbose;
    int root_identity;
    uid_t override_uid;
    gid_t override_gid;
    int normalize;
    char own_ip[32];
    /* network_mode: host. INET sockets are real pod sockets, not LKL ones. */
    int host_net;
    const struct kbox_guest_mem_ops *guest_mem_ops;
    struct kbox_guest_mem active_guest_mem;
    const struct kbox_fd_inject_ops *fd_inject_ops;
    struct kbox_web_ctx *web;
    unsigned active_writeback_shadows;
    /* Set once this container's LKL task answers file I/O with EINTR no
     * matter what: LKL never resets a task's signal state, so the remaining
     * calls have to run on a fresh task (see dispatch_on_fresh_task). */
    int lkl_task_poisoned;
    unsigned path_translation_generation;
    struct kbox_path_shadow_cache_entry
        path_shadow_cache[KBOX_PATH_SHADOW_CACHE_MAX];
    struct kbox_translated_path_cache_entry
        translated_path_cache[KBOX_TRANSLATED_PATH_CACHE_MAX];
    struct kbox_literal_path_cache_entry
        literal_path_cache[KBOX_LITERAL_PATH_CACHE_MAX];

    /* LRU stat cache: avoids repeated LKL inode lookups for fstat on the
     * same FD.  Keyed by lkl_fd.  Invalidated on write/truncate/close.
     */
#ifdef KBOX_STAT_CACHE_SIZE
#define KBOX_STAT_CACHE_MAX KBOX_STAT_CACHE_SIZE
#else
#define KBOX_STAT_CACHE_MAX 16
#endif
#if KBOX_STAT_CACHE_MAX > 0
#define KBOX_STAT_CACHE_ENABLED 1
#define KBOX_STAT_CACHE_STORAGE_MAX KBOX_STAT_CACHE_MAX
#else
#define KBOX_STAT_CACHE_ENABLED 0
#define KBOX_STAT_CACHE_STORAGE_MAX 1
#endif
    struct {
        long lkl_fd; /* -1 = empty slot */
        struct stat st;
    } stat_cache[KBOX_STAT_CACHE_STORAGE_MAX];

    struct kbox_pending_accept pending_accepts[KBOX_PENDING_ACCEPTS_MAX];
    size_t pending_accept_count;
    struct kbox_pending_recv pending_recvs[KBOX_PENDING_RECVS_MAX];
    size_t pending_recv_count;
    struct kbox_pending_recvmsg pending_recvmsgs[KBOX_PENDING_RECVMSGS_MAX];
    size_t pending_recvmsg_count;

    struct kbox_fd_table *root_fd_table;
    struct kbox_proc_fd_entry *proc_fds;
    size_t proc_fd_count;
    struct kbox_proc_fd_entry *active_proc;
    struct kbox_pending_fork *pending_forks;
    size_t pending_fork_count;
    /* umask the guest last set. A file created on a bind mount is created by
     * the supervisor's kernel, which applies the supervisor's umask, so the
     * creation is corrected to this mask explicitly. */
    unsigned guest_umask;
    /* wait4/waitid was just dispatched. The child may still have been alive at
     * that moment, so the dead-process shadows cannot be flushed yet; the next
     * syscall of the parent is the first point where they can be. */
    int pending_reap;
    struct kbox_pid_tgid_entry pid_tgid_cache[KBOX_PID_TGID_CACHE_MAX];

    const struct kbox_host_bind *host_binds;
    size_t host_bind_count;
    char host_cwd[KBOX_MAX_PATH];
    /* What LKL's cwd currently is (see kbox_proc_fd_entry.lkl_cwd). */
    char lkl_cwd_cur[KBOX_MAX_PATH];
    /* Absolute guest path of the executable, used to synthesize
     * /proc/self/exe: /proc is the host's procfs, so the magic links of the
     * guest's own process would otherwise describe kboxd. */
    char guest_exe[KBOX_MAX_PATH];
    /* Per-process guest executable paths. guest_exe above is what the
     * container was started with, but /proc/self/exe has to name the binary
     * the *calling* process is running: the dynamic loader derives $ORIGIN
     * from it, so a container-wide answer breaks every binary that finds its
     * libraries relative to itself (libjli.so was the first casualty). */
    struct {
        pid_t pid;
        char path[KBOX_MAX_PATH];
    } exe_map[64];
    /* /proc is the container's own procfs in LKL, not the host's. */
    int private_proc;
    /* Pids that issued clone(CLONE_VM|CLONE_VFORK). Their child shares the
     * address space, so an in-place exec rewrite corrupts them; the rewrite is
     * snapshotted and undone once the parent leaves vfork. */
    pid_t vfork_parents[8];
    unsigned vfork_parent_next;
    /* Exec rewrites that landed in a vfork parent's memory, waiting for that
     * parent to resume: the parent is suspended until the child execs, so the
     * first syscall it makes is the signal that the bytes can go back. */
    struct kbox_vfork_pending {
        pid_t parent;
        uint64_t addr;
        size_t len;
        unsigned char *saved;
    } vfork_pending[4];

    /* Optional external child-exit notification (used by multi-threaded
     * daemon mode where a central reaper handles SIGCHLD for all children).
     * When exit_notify_fd >= 0, supervise_loop polls it instead of creating a
     * per-thread signalfd(SIGCHLD) and reads exit status from *exit_status_ptr.
     */
    int exit_notify_fd;
    int *exit_status_ptr;
};

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h);
int kbox_install_seccomp_trap(const struct kbox_host_nrs *h);
int kbox_install_seccomp_trap_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count);
int kbox_install_seccomp_rewrite_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count);
int kbox_notify_recv(int listener_fd, void *notif);
int kbox_notify_send(int listener_fd, const void *resp);
int kbox_notify_respond(int listener_fd,
                        uint64_t id,
                        const struct kbox_dispatch *d);
/* A writeback that outstayed its budget is left running on its own thread; its
 * LKL descriptor must never be closed or reused while that thread may still be
 * inside a call on it. */
int kbox_lkl_fd_is_abandoned(long lkl_fd);
void kbox_dispatch_poll_pending(struct kbox_supervisor_ctx *ctx);
int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags);
int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags);
int kbox_syscall_request_init_from_regs(struct kbox_syscall_request *out,
                                        enum kbox_syscall_source source,
                                        pid_t pid,
                                        uint64_t cookie,
                                        const struct kbox_syscall_regs *regs,
                                        const struct kbox_guest_mem *guest_mem);
void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req);
void kbox_dispatch_cleanup_proc_fds(struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif);
int kbox_syscall_request_from_notif(const void *notif,
                                    struct kbox_syscall_request *out);
struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req);
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out);
struct kbox_dispatch kbox_dispatch_continue(void);
struct kbox_dispatch kbox_dispatch_errno(int err);
struct kbox_dispatch kbox_dispatch_value(int64_t val);
struct kbox_dispatch kbox_dispatch_from_lkl(long ret);
int kbox_run_supervisor(const struct kbox_sysnrs *sysnrs,
                        const char *command,
                        const char *const *args,
                        int nargs,
                        const char *host_root,
                        int exec_memfd,
                        int verbose,
                        int root_identity,
                        int normalize,
                        struct kbox_web_ctx *web);
int kbox_run_supervisor_volumes(const struct kbox_sysnrs *sysnrs,
                                const char *command,
                                const char *const *args,
                                int nargs,
                                const char *host_root,
                                int exec_memfd,
                                int verbose,
                                int root_identity,
                                int normalize,
                                struct kbox_web_ctx *web,
                                const struct kbox_host_bind *host_binds,
                                size_t host_bind_count);
int kbox_supervise_ctx(struct kbox_supervisor_ctx *ctx);
int kbox_supervisor_send_fd(int sock, int fd);
int kbox_supervisor_recv_fd(int sock);
int kbox_supervisor_prepare_child_security(void);
int kbox_parse_host_volume(const char *spec, struct kbox_host_bind *out);
int kbox_ensure_lkl_bind_stubs(const struct kbox_sysnrs *sysnrs,
                               const struct kbox_host_bind *binds,
                               size_t count);
int kbox_resolve_host_bind_at(const struct kbox_supervisor_ctx *ctx,
                              long raw_dirfd,
                              const char *guest_path,
                              char *host_out,
                              size_t host_out_size,
                              int *ro_out);

#define KBOX_IO_CHUNK_LEN (128 * 1024)

#endif /* KBOX_SECCOMP_H */
