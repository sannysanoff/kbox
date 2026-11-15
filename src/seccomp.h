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
    const struct kbox_guest_mem_ops *guest_mem_ops;
    struct kbox_guest_mem active_guest_mem;
    const struct kbox_fd_inject_ops *fd_inject_ops;
    struct kbox_web_ctx *web;
    unsigned active_writeback_shadows;
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

    struct kbox_fd_table *root_fd_table;
    struct kbox_proc_fd_entry *proc_fds;
    size_t proc_fd_count;
    struct kbox_proc_fd_entry *active_proc;
    struct kbox_pid_tgid_entry pid_tgid_cache[KBOX_PID_TGID_CACHE_MAX];

    const struct kbox_host_bind *host_binds;
    size_t host_bind_count;
    char host_cwd[KBOX_MAX_PATH];
    /* Absolute guest path of the executable, used to synthesize
     * /proc/self/exe: /proc is the host's procfs, so the magic links of the
     * guest's own process would otherwise describe kboxd. */
    char guest_exe[KBOX_MAX_PATH];
    /* /proc is the container's own procfs in LKL, not the host's. */
    int private_proc;

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
