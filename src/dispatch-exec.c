/* SPDX-License-Identifier: MIT */

/* Exec, mmap, mprotect, and clone3 handlers for the seccomp dispatch engine.
 *
 * trap_userspace_exec performs in-process binary replacement for trap/rewrite
 * mode. forward_execve handles both seccomp-unotify pathname rewriting and
 * trap-mode userspace exec.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "kbox/elf.h"
#include "kbox/path.h"
#include "loader-launch.h"
#include "procmem.h"
#include "rewrite.h"
#include "shadow-fd.h"
#include "syscall-nr.h"
#include "syscall-trap-signal.h"
#include "syscall-trap.h"

/* AT_EMPTY_PATH flag for execveat: indicates fexecve() usage. Defined here to
 * avoid pulling in the full linux/fcntl.h.
 */
#define KBOX_AT_EMPTY_PATH 0x1000

/* Load biases for the userspace ELF loader. Must match
 * prepare_userspace_launch. The loader places main and interpreter ELFs at
 * these fixed virtual addresses, and the stack just below stack_top.
 */
#define KBOX_EXEC_MAIN_LOAD_BIAS 0x600000000000ULL
#define KBOX_EXEC_INTERP_LOAD_BIAS 0x610000000000ULL
#define KBOX_EXEC_STACK_TOP 0x700000010000ULL

/* Alternate stack region for userspace re-exec. During re-exec SIGSYS handler
 * is running on the old guest stack, so we cannot unmap it until after
 * transferring to the new binary. Place the new stack at a different address;
 * the old stack region is reclaimed by the subsequent munmap in
 * teardown_old_guest_mappings during the NEXT re-exec.
 */
#define KBOX_EXEC_REEXEC_STACK_TOP 0x6F0000010000ULL

/* Maximum entries in argv or envp for userspace exec. */
#define KBOX_EXEC_MAX_ARGS 4096

/* Track which stack region is in use by the current guest. The initial launch
 * uses KBOX_EXEC_STACK_TOP; re-exec alternates between the two addresses. The
 * signal handler runs on the current guest's stack, so we must not unmap it
 * during re-exec.
 */
static uint64_t reexec_current_stack_top;

/* mmap dispatch: if the FD is a virtual FD with no host shadow, create the
 * shadow on demand (lazy shadow) and inject it into the tracee at the same FD
 * number, then CONTINUE so the host kernel mmaps the real fd.
 *
 * Lazy shadow creation avoids the memfd_create + file-copy cost at every open.
 * The shadow is only materialized when the guest actually mmaps.
 */
struct kbox_dispatch forward_mmap(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    /* W^X enforcement for mmap in trap/rewrite mode. */
    if (request_uses_trap_signals(req)) {
        int prot = (int) kbox_syscall_request_arg(req, 2);
        int mmap_flags = (int) kbox_syscall_request_arg(req, 3);
        long mmap_fd = to_dirfd_arg(kbox_syscall_request_arg(req, 4));
        if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: mmap denied: "
                        "W^X violation (prot=0x%x, pid=%u)\n",
                        prot, kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EACCES);
        }
        if (mmap_fd != -1 && (mmap_flags & MAP_SHARED) != 0 &&
            (prot & PROT_EXEC) != 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: mmap denied: shared executable file mapping "
                        "(prot=0x%x flags=0x%x fd=%ld pid=%u)\n",
                        prot, mmap_flags, mmap_fd,
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EACCES);
        }
    }

    long fd = to_dirfd_arg(kbox_syscall_request_arg(req, 4));

    if (fd == -1)
        return kbox_dispatch_continue();

    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (lkl_fd >= 0) {
        long host = kbox_fd_table_get_host_fd(ctx->fd_table, fd);
        if (host == -1 || host == KBOX_FD_LOCAL_ONLY_SHADOW) {
            /* Only create lazy shadows for read-only/private mappings.
             * Writable MAP_SHARED mappings on LKL files cannot be supported
             * via memfd (writes would go to the copy, not LKL).
             */
            int mmap_flags = (int) kbox_syscall_request_arg(req, 3);
            int mmap_prot = (int) kbox_syscall_request_arg(req, 2);
            if ((mmap_flags & MAP_SHARED) && (mmap_prot & PROT_WRITE))
                return kbox_dispatch_errno(ENODEV);

            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            int memfd = -1;
            int own_memfd = 0;
            if (host == KBOX_FD_LOCAL_ONLY_SHADOW && entry &&
                entry->shadow_sp >= 0) {
                memfd = entry->shadow_sp;
            } else {
                memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
                if (memfd < 0)
                    return kbox_dispatch_errno(ENODEV);
                kbox_shadow_seal(memfd);
                own_memfd = 1;
            }
            int injected = request_addfd_at(ctx, req, memfd, (int) fd, 0);
            if (injected < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(ENODEV);
            }
            /* Mark that a shadow was injected so repeated mmaps do not
             * re-create it. Use -2 as a sentinel: host_fd >= 0 means
             * "supervisor-owned shadow fd" (closed on remove). host_fd == -2
             * means "tracee-owned shadow, don't close in supervisor."
             * fd_table_remove only closes host_fd when host_fd >= 0 AND
             * shadow_sp < 0, so -2 is safe.
             */
            kbox_fd_table_set_host_fd(ctx->fd_table, fd,
                                      KBOX_FD_HOST_SAME_FD_SHADOW);
            if (entry && own_memfd)
                entry->shadow_sp = memfd;
        }
    }

    return kbox_dispatch_continue();
}

/* W^X enforcement for mprotect in trap/rewrite mode.
 *
 * Reject simultaneous PROT_WRITE|PROT_EXEC to prevent JIT spray attacks.
 * On writable->executable transitions in trap/rewrite mode, scan the promoted
 * region and fail closed if it contains syscall instructions.
 *
 * In seccomp mode, this is a no-op: CONTINUE lets the host kernel handle it.
 */
struct kbox_dispatch forward_mprotect(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    uint64_t addr = kbox_syscall_request_arg(req, 0);
    uint64_t len = kbox_syscall_request_arg(req, 1);
    int prot = (int) kbox_syscall_request_arg(req, 2);

    /* In seccomp mode (supervisor), just pass through. */
    if (!request_uses_trap_signals(req))
        return kbox_dispatch_continue();

    /* W^X enforcement: reject PROT_WRITE | PROT_EXEC. */
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: mprotect denied: W^X violation at 0x%llx len=%llu "
                    "(pid=%u)\n",
                    (unsigned long long) addr, (unsigned long long) len,
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EACCES);
    }

    if ((prot & PROT_EXEC) != 0) {
        int alias_rc = guest_range_has_shared_file_write_mapping(
            kbox_syscall_request_pid(req), addr, len);
        if (alias_rc < 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: mprotect denied: cannot inspect shared "
                        "mapping state at 0x%llx len=%llu (pid=%u)\n",
                        (unsigned long long) addr, (unsigned long long) len,
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EACCES);
        }
        if (alias_rc > 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: mprotect denied: executable promotion of "
                        "shared writable file mapping at 0x%llx len=%llu "
                        "(pid=%u)\n",
                        (unsigned long long) addr, (unsigned long long) len,
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EACCES);
        }
        {
            struct kbox_rewrite_runtime *runtime =
                kbox_rewrite_runtime_active();

            if (kbox_rewrite_runtime_promote_exec_region(runtime, addr, len) <
                0) {
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: mprotect denied: scan-on-X failed at "
                            "0x%llx len=%llu (pid=%u)\n",
                            (unsigned long long) addr, (unsigned long long) len,
                            kbox_syscall_request_pid(req));
                return kbox_dispatch_errno(EACCES);
            }
        }
    }

    /* Clean pages can proceed. Pages with runtime-emitted syscall sites are
     * denied by scan-on-X above.
     */
    return kbox_dispatch_continue();
}

/* clone3 namespace-flag sanitization. */

/* CLONE_NEW* flags that clone3 can smuggle in via clone_args.flags. The BPF
 * deny-list blocks unshare/setns, but clone3 bypasses it unless we check here.
 */
struct kbox_dispatch forward_clone3(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    uint64_t flags;
    int rc;

    /* clone3(struct clone_args *args, size_t size). flags is the first uint64_t
     * field in clone_args. We only need to read the first 8 bytes.
     */
    rc =
        guest_mem_read(ctx, kbox_syscall_request_pid(req),
                       kbox_syscall_request_arg(req, 0), &flags, sizeof(flags));
    if (rc < 0) {
        /* Can't read tracee memory; fail closed with EPERM.
         *
         * CONTINUE is unsafe here: a tracee can clear dumpability via
         * prctl(PR_SET_DUMPABLE, 0), causing process_vm_readv to fail with
         * EPERM. If we CONTINUE, clone3 reaches host kernel with unchecked
         * namespace flags: a sandbox escape. Returning EPERM is the only safe
         * option.
         */
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: cannot read clone_args "
                    "(pid=%u, rc=%d)\n",
                    kbox_syscall_request_pid(req), rc);
        return kbox_dispatch_errno(EPERM);
    }

    if (flags & CLONE_NEW_MASK) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: namespace flags 0x%llx "
                    "(pid=%u)\n",
                    (unsigned long long) (flags & CLONE_NEW_MASK),
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EPERM);
    }

    /* In trap/rewrite mode, block thread creation (CLONE_THREAD).
     * Multi-threaded guests require --syscall-mode=seccomp.
     */
    /* vfork. kbox performs an exec by rewriting the pathname in the tracee's
     * memory, which is unsafe for a child that shares the parent's address
     * space: the rewrite lands in the parent's stack, so after the child
     * execs the parent resumes with "/proc/self/fd/N" where its own path used
     * to be and every later fork execs that stale descriptor (initdb's
     * bootstrap, popen, system all go through CLONE_VM|CLONE_VFORK).
     *
     * Turn it into a plain fork. The child still execs immediately and the
     * parent still waits for it to exit, which is all posix_spawn and popen
     * need; the only difference is that the parent may run alongside the child
     * until it execs, which nothing in this path observes.
     */
    if (flags & CLONE_VFORK) {
        flags &= ~(uint64_t) (CLONE_VFORK | CLONE_VM | CLONE_SIGHAND |
                              CLONE_THREAD);
        flags |= SIGCHLD;
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3: vfork downgraded to fork (pid=%u)\n",
                    kbox_syscall_request_pid(req));
    }

    if ((flags & CLONE_THREAD) && request_uses_trap_signals(req)) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: CLONE_THREAD in trap/rewrite mode "
                    "(pid=%u, use --syscall-mode=seccomp)\n",
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EPERM);
    }

    /* Write the validated flags back to the guest's clone_args struct to
     * narrow the TOCTOU window: if a sibling thread mutated the flags between
     * our read and the host kernel's re-read, this overwrites the mutation.
     *
     * A residual race remains (sibling writes after our write-back but before
     * the host kernel reads), but for single-threaded guests -- kbox's normal
     * mode -- the risk is zero.
     */
    int wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                              kbox_syscall_request_arg(req, 0), &flags,
                              sizeof(flags));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_continue();
}

/* Safely count a null-terminated pointer array in guest address space.
 * Uses process_vm_readv to avoid SIGSEGV on bad guest pointers.
 * Returns the count (not including the final NULL), or -EFAULT on bad memory.
 */
static long count_user_ptrs_safe(uint64_t arr_addr, size_t max_count)
{
    size_t n = 0;
    uint64_t ptr;

    if (arr_addr == 0)
        return -EFAULT;

    while (n < max_count) {
        uint64_t offset, probe_addr;
        int rc;
        if (__builtin_mul_overflow((uint64_t) n, sizeof(uint64_t), &offset) ||
            __builtin_add_overflow(arr_addr, offset, &probe_addr))
            return -EFAULT;
        rc = kbox_current_read(probe_addr, &ptr, sizeof(ptr));
        if (rc < 0)
            return -EFAULT;
        if (ptr == 0)
            return (long) n;
        n++;
    }

    return -E2BIG;
}

/* Safely measure the length of a guest string.
 * Returns the length (not including NUL), or -EFAULT on bad memory.
 */
static long strlen_user_safe(uint64_t str_addr)
{
    char buf[256];
    size_t total = 0;

    if (str_addr == 0)
        return -EFAULT;

    for (;;) {
        int rc = kbox_current_read(str_addr + total, buf, sizeof(buf));
        if (rc < 0)
            return -EFAULT;
        for (size_t i = 0; i < sizeof(buf); i++) {
            if (buf[i] == '\0')
                return (long) (total + i);
        }
        total += sizeof(buf);
        if (total > (size_t) (256 * 1024))
            return -ENAMETOOLONG;
    }
}

/* Safely read a single guest pointer (8 bytes). */
static int read_user_ptr(uint64_t addr, uint64_t *out)
{
    return kbox_current_read(addr, out, sizeof(*out));
}

/* Safely copy a guest string into a destination buffer.
 * Returns the string length (not including NUL), or -EFAULT.
 */
static long copy_user_string(uint64_t str_addr, char *dst, size_t dst_size)
{
    return kbox_current_read_string(str_addr, dst, dst_size);
}

/* Tear down old guest code/data mappings and the stale stack at the
 * new stack address.  The current guest stack (which the SIGSYS
 * handler is running on) is at the OTHER address and left alone.
 * It leaks one stack-sized region until the next re-exec cycle.
 */
static void teardown_old_guest_mappings(uint64_t new_stack_top)
{
    /* Main binary region: up to 256 MB from the load bias. */
    munmap((void *) (uintptr_t) KBOX_EXEC_MAIN_LOAD_BIAS, 256UL * 1024 * 1024);
    /* Interpreter region: up to 256 MB from the load bias. */
    munmap((void *) (uintptr_t) KBOX_EXEC_INTERP_LOAD_BIAS,
           256UL * 1024 * 1024);
    /* Unmap any stale stack at the new stack address.  On the first
     * re-exec (new = REEXEC), this is a no-op (nothing mapped there).
     * On the second re-exec (new = STACK_TOP), this unmaps the
     * initial launch stack.  Subsequent cycles alternate and reclaim.
     */
    munmap((void *) (uintptr_t) (new_stack_top - 16UL * 1024 * 1024),
           16UL * 1024 * 1024 + 0x10000UL);
}

/* Perform userspace exec for trap mode.  Called from inside the SIGSYS
 * handler when the guest calls execve/execveat.  This replaces the
 * current process image without a real exec syscall, preserving the
 * SIGSYS handler and seccomp filter chain.
 *
 * The function is noreturn on success: it transfers control to the new
 * binary's entry point.  On failure, it returns a dispatch with errno.
 */
static struct kbox_dispatch trap_userspace_exec(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int exec_memfd,
    const char *pathname,
    int is_execveat)
{
    unsigned char *elf_buf = NULL;
    size_t elf_buf_len = 0;
    char interp_path[256];
    int interp_memfd = -1;
    int ilen = 0;
    struct kbox_loader_launch_spec spec;
    struct kbox_loader_launch launch = {0};
    struct kbox_syscall_trap_ip_range ranges[KBOX_LOADER_MAX_MAPPINGS];
    struct kbox_loader_exec_range exec_ranges[KBOX_LOADER_MAX_MAPPINGS];
    size_t exec_count = 0;
    size_t range_count = 0;
    unsigned char random_bytes[KBOX_LOADER_RANDOM_SIZE];

    /* execve(path, argv, envp): argv=args[1], envp=args[2]
     * execveat(dirfd, path, argv, envp, flags): argv=args[2], envp=args[3]
     *
     * In trap mode these are guest pointers in our address space, but still
     * guest-controlled.  All accesses must use safe reads (process_vm_readv)
     * so bad pointers yield -EFAULT instead of crashing the SIGSYS handler.
     */
    uint64_t argv_addr = kbox_syscall_request_arg(req, is_execveat ? 2 : 1);
    uint64_t envp_addr = kbox_syscall_request_arg(req, is_execveat ? 3 : 2);
    long argc_long = count_user_ptrs_safe(argv_addr, KBOX_EXEC_MAX_ARGS);
    long envc_long = count_user_ptrs_safe(envp_addr, KBOX_EXEC_MAX_ARGS);
    size_t argc, envc;

    if (argc_long < 0) {
        close(exec_memfd);
        return kbox_dispatch_errno(argc_long == -E2BIG ? EINVAL : EFAULT);
    }
    if (envc_long < 0) {
        close(exec_memfd);
        return kbox_dispatch_errno(envc_long == -E2BIG ? EINVAL : EFAULT);
    }
    argc = (size_t) argc_long;
    envc = (size_t) envc_long;
    if (argc == 0) {
        close(exec_memfd);
        return kbox_dispatch_errno(EINVAL);
    }

    /* Deep-copy argv and envp into a single mmap'd arena. Using mmap instead of
     * malloc/strdup because we are inside the SIGSYS handler and glibc's
     * allocator is not async-signal-safe.
     *
     * Two passes: first measure total size (via safe string length reads), then
     * copy. All guest pointer reads use process_vm_readv.
     */
    size_t arena_size = (argc + envc) * sizeof(char *);
    for (size_t i = 0; i < argc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(argv_addr + i * sizeof(uint64_t), &str_addr) < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        slen = strlen_user_safe(str_addr);
        if (slen < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        arena_size += (size_t) slen + 1;
    }
    for (size_t i = 0; i < envc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(envp_addr + i * sizeof(uint64_t), &str_addr) < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        slen = strlen_user_safe(str_addr);
        if (slen < 0) {
            close(exec_memfd);
            return kbox_dispatch_errno(EFAULT);
        }
        arena_size += (size_t) slen + 1;
    }
    arena_size = (arena_size + 4095) & ~(size_t) 4095;

    char *arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        close(exec_memfd);
        return kbox_dispatch_errno(ENOMEM);
    }
    size_t arena_used = 0;
    char **argv_copy = (char **) (arena + arena_used);
    arena_used += argc * sizeof(char *);
    char **envp_copy = (char **) (arena + arena_used);
    arena_used += envc * sizeof(char *);
    for (size_t i = 0; i < argc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(argv_addr + i * sizeof(uint64_t), &str_addr) < 0)
            goto fail_arena;
        slen = copy_user_string(str_addr, arena + arena_used,
                                arena_size - arena_used);
        if (slen < 0)
            goto fail_arena;
        argv_copy[i] = arena + arena_used;
        arena_used += (size_t) slen + 1;
    }
    for (size_t i = 0; i < envc; i++) {
        uint64_t str_addr;
        long slen;
        if (read_user_ptr(envp_addr + i * sizeof(uint64_t), &str_addr) < 0)
            goto fail_arena;
        slen = copy_user_string(str_addr, arena + arena_used,
                                arena_size - arena_used);
        if (slen < 0)
            goto fail_arena;
        envp_copy[i] = arena + arena_used;
        arena_used += (size_t) slen + 1;
    }

    /* Check for PT_INTERP (dynamic binary needing an interpreter). */
    if (kbox_read_elf_header_window_fd(exec_memfd, &elf_buf, &elf_buf_len) ==
        0) {
        uint64_t pt_offset, pt_filesz;

        ilen = kbox_find_elf_interp_loc(elf_buf, elf_buf_len, interp_path,
                                        sizeof(interp_path), &pt_offset,
                                        &pt_filesz);
        munmap(elf_buf, elf_buf_len);
        elf_buf = NULL;

        if (ilen < 0) {
            ilen = -ENOEXEC;
            goto fail_early;
        }

        if (ilen > 0) {
            long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                              interp_path, O_RDONLY, 0);
            if (interp_lkl < 0) {
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: trap exec %s: cannot open "
                            "interpreter %s: %s\n",
                            pathname, interp_path, kbox_err_text(interp_lkl));
                ilen = (int) interp_lkl;
                goto fail_early;
            }

            interp_memfd = kbox_shadow_create(ctx->sysnrs, interp_lkl);
            lkl_close_and_invalidate(ctx, interp_lkl);

            if (interp_memfd < 0) {
                ilen = interp_memfd;
                goto fail_early;
            }
        }
    }
    /* else: kbox_read_elf_header_window_fd failed, elf_buf is still NULL.
     * Nothing to unmap. Treat as static binary (no interpreter).
     */

    /* Generate random bytes for AT_RANDOM auxv entry. Use the raw syscall to
     * avoid depending on sys/random.h availability.
     */
    memset(random_bytes, 0x42, sizeof(random_bytes));
#ifdef __NR_getrandom
    {
        long gr =
            syscall(__NR_getrandom, random_bytes, sizeof(random_bytes), 0);
        (void) gr;
    }
#endif

    /* Pick a stack address that does not collide with old guest stack (which we
     * are currently running on from inside the SIGSYS handler).
     * Alternate between two stack tops so the old one survives until the next
     * re-exec reclaims it.
     */
    uint64_t new_stack_top =
        (reexec_current_stack_top == KBOX_EXEC_REEXEC_STACK_TOP)
            ? KBOX_EXEC_STACK_TOP
            : KBOX_EXEC_REEXEC_STACK_TOP;

    /* Build the loader launch spec. Use the same load biases as initial launch
     * so the address space layout is consistent.
     */
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = exec_memfd;
    spec.interp_fd = interp_memfd;
    spec.argv = (const char *const *) argv_copy;
    spec.argc = argc;
    spec.envp = (const char *const *) envp_copy;
    spec.envc = envc;
    spec.execfn = pathname;
    spec.random_bytes = random_bytes;
    spec.page_size = (uint64_t) sysconf(_SC_PAGESIZE);
    spec.stack_top = new_stack_top;
    spec.main_load_bias = KBOX_EXEC_MAIN_LOAD_BIAS;
    spec.interp_load_bias = KBOX_EXEC_INTERP_LOAD_BIAS;
    spec.uid = ctx->root_identity ? 0 : (uint32_t) getuid();
    spec.euid = ctx->root_identity ? 0 : (uint32_t) getuid();
    spec.gid = ctx->root_identity ? 0 : (uint32_t) getgid();
    spec.egid = ctx->root_identity ? 0 : (uint32_t) getgid();
    spec.secure = 0;

    /* Tear down old guest code/data mappings BEFORE materializing new ones
     * (MAP_FIXED_NOREPLACE requires the addresses to be free). But do NOT
     * teardown before reading the memfds; the reads use pread which doesn't
     * depend on the old mappings.
     */
    teardown_old_guest_mappings(new_stack_top);

    {
        int launch_rc = kbox_loader_prepare_launch(&spec, &launch);
        if (launch_rc < 0) {
            const char msg[] = "kbox: trap exec: loader prepare failed\n";
            ssize_t n = write(STDERR_FILENO, msg, sizeof(msg) - 1);
            (void) n;
            _exit(127);
        }
    }

    /* The memfds have been read into launch buffers; close them. */
    close(exec_memfd);
    if (interp_memfd >= 0)
        close(interp_memfd);

    /* Collect executable ranges from the new layout for the BPF filter. The new
     * filter is appended to the filter chain; old filter is harmless (matches
     * unmapped addresses).
     */
    if (kbox_loader_collect_exec_ranges(
            &launch, exec_ranges, KBOX_LOADER_MAX_MAPPINGS, &exec_count) < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: trap exec %s: cannot collect exec ranges\n",
                    pathname);
        kbox_loader_launch_reset(&launch);
        _exit(127);
    }
    for (size_t i = 0; i < exec_count; i++) {
        ranges[i].start = (uintptr_t) exec_ranges[i].start;
        ranges[i].end = (uintptr_t) exec_ranges[i].end;
    }
    range_count = exec_count;

    /* Install a new BPF RET_TRAP filter covering the new binary's executable
     * ranges. seccomp filters form a chain; calling seccomp(SET_MODE_FILTER)
     * adds to it rather than replacing.
     */
    if (kbox_install_seccomp_trap_ranges(ctx->host_nrs, ranges, range_count) <
        0) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: trap exec %s: cannot install new BPF filter\n",
                    pathname);
        kbox_loader_launch_reset(&launch);
        _exit(127);
    }

    /* Clean up CLOEXEC entries from the FD table, matching what a
     * real exec would do.
     */
    close_cloexec_with_writeback(ctx);

    /* If the original launch used rewrite mode, re-apply binary rewriting to
     * the new binary. This patches syscall instructions in the newly loaded
     * executable segments and sets up trampoline regions, promoting the new
     * binary from Tier 1 (SIGSYS ~3us) to Tier 2 (~41ns) for rewritten sites.
     *
     * If rewrite installation fails (e.g., trampoline allocation), the binary
     * still works correctly via the SIGSYS handler (Tier 1).
     */
    if (req->source == KBOX_SYSCALL_SOURCE_REWRITE) {
        /* Static: runtime is stored globally via store_active_rewrite_runtime
         * and must survive past the noreturn transfer_to_guest. Single-threaded
         * trap mode guarantees no concurrent re-exec.
         */
        static struct kbox_rewrite_runtime rewrite_rt;
        kbox_rewrite_runtime_reset(&rewrite_rt);
        if (kbox_rewrite_runtime_install(&rewrite_rt, ctx, &launch) == 0) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: trap exec %s: rewrite installed "
                        "(%zu trampoline regions)\n",
                        pathname, rewrite_rt.trampoline_region_count);
        } else {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: trap exec %s: rewrite failed, "
                        "falling back to SIGSYS\n",
                        pathname);
        }
    }

#if defined(__x86_64__)
    /* Reset the guest FS base to the host (kbox) FS base. We are inside the
     * SIGSYS handler where FS already points to kbox's TLS. The new binary
     * starts with no TLS set up; it will call arch_prctl(ARCH_SET_FS) during
     * libc init to establish its own. Until then, SIGSYS handler entry should
     * see FS == host FS and the save/restore becomes a no-op, which is correct.
     */
    {
        uint64_t host_fs = 0;

        kbox_syscall_trap_host_arch_prctl_get_fs(&host_fs);
        kbox_syscall_trap_set_guest_fs(host_fs);
    }
#endif

    if (ctx->verbose)
        fprintf(stderr,
                "kbox: trap exec %s: transferring to new image "
                "pc=0x%llx sp=0x%llx\n",
                pathname, (unsigned long long) launch.transfer.pc,
                (unsigned long long) launch.transfer.sp);

    /* Record which stack the new guest is using. The next re-exec will pick the
     * other address and reclaim this one.
     */
    reexec_current_stack_top = new_stack_top;

    /* Free staging buffers before transferring. The image regions (mmap'd guest
     * code/data/stack) must survive.
     */
    munmap(arena, arena_size);
    if (launch.main_elf && launch.main_elf_len > 0)
        munmap(launch.main_elf, launch.main_elf_len);
    launch.main_elf = NULL;
    if (launch.interp_elf && launch.interp_elf_len > 0)
        munmap(launch.interp_elf, launch.interp_elf_len);
    launch.interp_elf = NULL;
    kbox_loader_stack_image_reset(&launch.layout.stack);

    /* Unblock SIGSYS before transferring. We are inside the SIGSYS handler,
     * which runs with SIGSYS blocked (SA_SIGINFO default).
     * Since we jump to the new entry point instead of returning from the
     * handler, the kernel never restores the pre-handler signal mask. The new
     * binary needs SIGSYS unblocked so the BPF RET_TRAP filter can deliver it.
     */
    {
        uint64_t mask[2] = {0, 0};
        unsigned int signo = SIGSYS - 1;
        mask[signo / 64] = 1ULL << (signo % 64);
        kbox_syscall_trap_host_rt_sigprocmask_unblock(mask,
                                                      8 /* kernel sigset_t */);
    }

    /* Transfer control to the new binary.  This is noreturn. */
    kbox_loader_transfer_to_guest(&launch.transfer);

fail_arena:
    munmap(arena, arena_size);
    close(exec_memfd);
    return kbox_dispatch_errno(EFAULT);

fail_early:
    munmap(arena, arena_size);
    close(exec_memfd);
    if (interp_memfd >= 0)
        close(interp_memfd);
    return kbox_dispatch_errno((int) (-ilen));
}

/* Handle execve/execveat from inside the image.
 *
 * For fexecve (execveat with AT_EMPTY_PATH on a host memfd): CONTINUE, the host
 * kernel handles it directly. This is the initial exec path from image.c.
 *
 * For in-image exec (e.g. shell runs /bin/ls):
 *   1. Read the pathname from tracee memory
 *   2. Open the binary from LKL, create a memfd
 *   3. Check for PT_INTERP; if dynamic, extract interpreter into a second memfd
 *      and patch PT_INTERP to /proc/self/fd/N
 *   4. Inject memfds into the tracee via ADDFD
 *   5. Overwrite the pathname in tracee memory with /proc/self/fd/N
 *   6. CONTINUE: kernel re-reads the rewritten path and execs
 *
 * The seccomp-unotify guarantees the tracee is blocked during steps 1-5, and
 * the kernel has not yet copied the pathname (getname happens after the seccomp
 * check), so the overwrite is race-free.
 */
static int read_tracee_sp(pid_t pid, uint64_t *sp_out)
{
    char pbuf[64];
    char sbuf[512];
    int fd;
    ssize_t n;

    snprintf(pbuf, sizeof(pbuf), "/proc/%d/syscall", (int) pid);
    fd = open(pbuf, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    n = read(fd, sbuf, sizeof(sbuf) - 1);
    close(fd);
    if (n <= 0)
        return -ENOENT;
    sbuf[n] = '\0';

    /* Format: "<nr> <arg0> <arg1> <arg2> <arg3> <arg4> <arg5> <sp> <ip>" */
    char *p = sbuf;
    for (int col = 0; col < 7; col++) {
        while (*p && *p != ' ' && *p != '\t')
            p++;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            return -ENOENT;
    }
    errno = 0;
    uint64_t sp = (uint64_t) strtoull(p, NULL, 16);
    if (errno || sp < 4096)
        return -EINVAL;
    *sp_out = sp;
    return 0;
}

static int write_guest_mem_any(const struct kbox_supervisor_ctx *ctx,
                               pid_t pid,
                               uint64_t addr,
                               const void *buf,
                               size_t len)
{
    int rc = guest_mem_write(ctx, pid, addr, buf, len);
    if (rc < 0)
        rc = guest_mem_write_force(ctx, pid, addr, buf, len);
    return rc;
}

#define MAX_EXEC_RELOC 32

struct exec_str_reloc {
    uint64_t old_ptr;
    size_t offset;
    size_t len_with_nul;
    char str[KBOX_MAX_PATH];
};

struct exec_slot_update {
    uint64_t slot_addr;
    size_t reloc_idx;
};

static int relocate_overlapping_exec_vecs(const struct kbox_supervisor_ctx *ctx,
                                          pid_t pid,
                                          uint64_t path_addr,
                                          size_t new_bytes,
                                          uint64_t argv_addr,
                                          uint64_t envp_addr)
{
    struct exec_str_reloc relocs[MAX_EXEC_RELOC];
    struct exec_slot_update slots[MAX_EXEC_RELOC * 2];
    size_t reloc_cnt = 0;
    size_t slot_cnt = 0;
    size_t total_bytes = 0;
    uint64_t win_end = path_addr + (uint64_t) new_bytes;
    uint64_t vecs[2] = {argv_addr, envp_addr};

    for (int vi = 0; vi < 2; vi++) {
        uint64_t base = vecs[vi];
        if (!base)
            continue;
        for (size_t idx = 0; idx < 1024; idx++) {
            uint64_t ptr = 0;
            uint64_t slot_addr = base + (uint64_t) idx * sizeof(uint64_t);
            if (guest_mem_read(ctx, pid, slot_addr, &ptr, sizeof(ptr)) < 0 ||
                ptr == 0)
                break;

            if (ptr >= win_end)
                continue;
            if (ptr < path_addr && path_addr - ptr >= KBOX_MAX_PATH)
                continue;

            size_t found = (size_t) -1;
            for (size_t r = 0; r < reloc_cnt; r++) {
                if (relocs[r].old_ptr == ptr) {
                    found = r;
                    break;
                }
            }
            if (found == (size_t) -1) {
                char tmp[KBOX_MAX_PATH];
                if (guest_mem_read_string(ctx, pid, ptr, tmp, sizeof(tmp)) < 0)
                    continue;
                size_t slen = strlen(tmp) + 1;
                if (ptr < path_addr && ptr + (uint64_t) slen <= path_addr)
                    continue;
                if (reloc_cnt >= MAX_EXEC_RELOC)
                    return -E2BIG;
                found = reloc_cnt++;
                relocs[found].old_ptr = ptr;
                relocs[found].offset = total_bytes;
                relocs[found].len_with_nul = slen;
                memcpy(relocs[found].str, tmp, slen);
                total_bytes += slen;
            }
            if (slot_cnt >= MAX_EXEC_RELOC * 2)
                return -E2BIG;
            slots[slot_cnt].slot_addr = slot_addr;
            slots[slot_cnt].reloc_idx = found;
            slot_cnt++;
        }
    }

    if (reloc_cnt == 0)
        return 0;

    uint64_t sp = 0;
    int rc = read_tracee_sp(pid, &sp);
    if (rc < 0)
        return rc;

    char *packed = malloc(total_bytes);
    if (!packed)
        return -ENOMEM;
    for (size_t r = 0; r < reloc_cnt; r++)
        memcpy(packed + relocs[r].offset, relocs[r].str, relocs[r].len_with_nul);

    /* Place packed strings safely below tracee stack pointer (past redzone). */
    uint64_t scratch = (sp - 512 - (uint64_t) total_bytes) & ~(uint64_t) 15;
    rc = write_guest_mem_any(ctx, pid, scratch, packed, total_bytes);
    free(packed);
    if (rc < 0)
        return rc;

    for (size_t s = 0; s < slot_cnt; s++) {
        uint64_t new_ptr = scratch + (uint64_t) relocs[slots[s].reloc_idx].offset;
        rc = write_guest_mem_any(ctx, pid, slots[s].slot_addr, &new_ptr,
                                 sizeof(new_ptr));
        if (rc < 0)
            return rc;
    }
    return 0;
}


/* Rewrite a #! script so the host kernel can exec it.
 *
 * binfmt_script resolves the shebang to a host path, which for a guest script
 * names an interpreter that does not exist outside LKL. The interpreter is
 * opened and shadowed inside the guest instead, injected into the tracee, and
 * the shebang is rewritten to /proc/self/fd/<n>; the kernel then execs the
 * injected interpreter and passes the script as argv[1]. The script itself is
 * rebuilt as a fresh memfd (new shebang line, then the body from the first
 * newline on) and handed back through *exec_memfd, to be injected without
 * O_CLOEXEC so it is still open when the interpreter tries to read it.
 *
 * Returns 0, or -errno.
 */
static int rewrite_script_shebang(struct kbox_supervisor_ctx *ctx,
                                  const struct kbox_syscall_request *req,
                                  int *exec_memfd, const char *pathbuf)
{
    unsigned char hdr[512];
    ssize_t hn = pread(*exec_memfd, hdr, sizeof(hdr), 0);
    if (hn < 3 || hdr[0] != '#' || hdr[1] != '!')
        return -ENOEXEC;

    size_t i = 2;
    while (i < (size_t) hn && (hdr[i] == ' ' || hdr[i] == '\t'))
        i++;
    size_t interp_start = i;
    while (i < (size_t) hn && hdr[i] != '\n' && hdr[i] != ' ' &&
           hdr[i] != '\t')
        i++;
    size_t interp_len = i - interp_start;
    if (interp_len == 0 || interp_len >= 256)
        return -ENOEXEC;

    char interp[256];
    memcpy(interp, hdr + interp_start, interp_len);
    interp[interp_len] = '\0';

    while (i < (size_t) hn && (hdr[i] == ' ' || hdr[i] == '\t'))
        i++;
    size_t arg_start = i;
    while (i < (size_t) hn && hdr[i] != '\n')
        i++;
    size_t arg_len = i - arg_start;

    off_t body = -1;
    for (ssize_t k = 0; k < hn; k++) {
        if (hdr[k] == '\n') {
            body = (off_t) k + 1;
            break;
        }
    }
    if (body < 0)
        return -ENOEXEC;

    long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, interp,
                                      O_RDONLY, 0);
    if (interp_lkl < 0)
        return (int) interp_lkl;

    int interp_memfd = kbox_shadow_create(ctx->sysnrs, interp_lkl);
    lkl_close_and_invalidate(ctx, interp_lkl);
    if (interp_memfd < 0)
        return interp_memfd;

    /* The interpreter is a program in its own right: when it is dynamically
     * linked its PT_INTERP names the guest loader, which the host kernel
     * cannot open either. Patch it to an injected memfd of the loader, the
     * same way the ELF path does for the executable. */
    {
        unsigned char *elf_buf = NULL;
        size_t elf_buf_len = 0;

        if (kbox_read_elf_header_window_fd(interp_memfd, &elf_buf,
                                           &elf_buf_len) == 0) {
            char loader[256];
            uint64_t pt_offset, pt_filesz;
            int llen = kbox_find_elf_interp_loc(elf_buf, elf_buf_len, loader,
                                                sizeof(loader), &pt_offset,
                                                &pt_filesz);
            munmap(elf_buf, elf_buf_len);

            if (llen > 0) {
                long loader_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                                  loader, O_RDONLY, 0);
                if (loader_lkl >= 0) {
                    int loader_memfd =
                        kbox_shadow_create(ctx->sysnrs, loader_lkl);
                    lkl_close_and_invalidate(ctx, loader_lkl);
                    if (loader_memfd >= 0) {
                        int tracee_loader_fd = request_addfd(
                            ctx, req, loader_memfd, O_CLOEXEC);
                        close(loader_memfd);
                        if (tracee_loader_fd >= 0) {
                            char patched[64];
                            int plen = snprintf(patched, sizeof(patched),
                                                "/proc/self/fd/%d",
                                                tracee_loader_fd);
                            char patch[256];
                            size_t pl = (size_t) pt_filesz;
                            if (pl > sizeof(patch))
                                pl = sizeof(patch);
                            memset(patch, 0, pl);
                            memcpy(patch, patched, (size_t) plen);
                            if (pwrite(interp_memfd, patch, pl,
                                       (off_t) pt_offset) != (ssize_t) pl) {
                                close(interp_memfd);
                                return -EIO;
                            }
                        }
                    }
                }
            }
        }
    }

    int tracee_interp_fd = request_addfd(ctx, req, interp_memfd, O_CLOEXEC);
    close(interp_memfd);
    if (tracee_interp_fd < 0)
        return tracee_interp_fd;

    /* The kernel sets argv[0] to the interpreter path it was given, and
     * busybox picks its applet from basename(argv[0]) -- "/proc/self/fd/10"
     * would look for an applet called "10". Point the shebang at a symlink
     * that keeps the interpreter's own name and resolves, in the tracee's
     * context, to the injected memfd. */
    /* The interpreter is referenced by descriptor, not by a symlink under the
     * daemon's /tmp: that directory is the supervisor's, the guest has its own
     * /tmp (a tmpfs), and a shebang naming a path only the daemon can see makes
     * the kernel answer ENOENT for the whole exec. Scripts run from initdb,
     * popen and other spawn helpers died exactly that way.
     *
     * The cost is that argv[0] of the interpreter reads "/proc/self/fd/<n>",
     * which matters only to applets that dispatch on their own name (busybox).
     */
    char interp_name[128];
    {
        const char *slash = strrchr(interp, '/');
        snprintf(interp_name, sizeof(interp_name), "%s",
                 (slash && slash[1]) ? slash + 1 : interp);
    }
    const char *interp_ref = NULL;

    char shebang[512];
    int shebang_len;
    if (!interp_ref) {
        /* Fall back to the memfd path: fine for interpreters that do not
         * dispatch on argv[0], broken for busybox. */
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: exec %s: no interpreter symlink, argv[0] will be "
                    "%s\n",
                    pathbuf, interp_name);
        static char fallback[64];
        snprintf(fallback, sizeof(fallback), "/proc/self/fd/%d",
                 tracee_interp_fd);
        interp_ref = fallback;
    }

    if (arg_len > 0 && arg_len < 128)
        shebang_len = snprintf(shebang, sizeof(shebang), "#!%s %.*s\n",
                               interp_ref, (int) arg_len, hdr + arg_start);
    else
        shebang_len = snprintf(shebang, sizeof(shebang), "#!%s\n",
                               interp_ref);
    if (shebang_len <= 0 || (size_t) shebang_len >= sizeof(shebang))
        return -ENAMETOOLONG;

    int script_memfd = (int) syscall(SYS_memfd_create, "kbox-script", 0);
    if (script_memfd < 0)
        return -errno;

    if (write(script_memfd, shebang, (size_t) shebang_len) !=
        (ssize_t) shebang_len)
        goto fail;

    char *buf = malloc(65536);
    if (!buf)
        goto fail;
    for (;;) {
        ssize_t n = pread(*exec_memfd, buf, 65536, body);
        if (n < 0) {
            free(buf);
            goto fail;
        }
        if (n == 0)
            break;
        if (write(script_memfd, buf, (size_t) n) != n) {
            free(buf);
            goto fail;
        }
        body += n;
    }
    free(buf);

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec %s: shebang %s -> /proc/self/fd/%d\n",
                pathbuf, interp, tracee_interp_fd);

    close(*exec_memfd);
    *exec_memfd = script_memfd;
    return 0;

fail:
    {
        int saved = errno ? errno : EIO;
        close(script_memfd);
        return -saved;
    }
}

static struct kbox_dispatch forward_execve_impl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_execveat);


/* Undo an exec rewrite that landed in a vfork parent's memory.
 *
 * A vfork child shares its parent's address space, and the exec path rewrites
 * the pathname in place (and relocates argv/envp when it does not fit). The
 * parent is suspended until the child execs, so the bytes can be restored as
 * soon as it leaves the vfork wait -- otherwise the parent resumes with
 * "/proc/self/fd/N" where its own path used to be and every later fork in it
 * execs a descriptor that belongs to the child.
 */
static pid_t tracee_parent_of(pid_t pid)
{
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    char *paren = strrchr(buf, ')');
    if (!paren)
        return -1;
    pid_t pp = -1;
    if (sscanf(paren + 2, "%*c %d", &pp) != 1)
        return -1;
    return pp;
}

static int vfork_parent_recorded(const struct kbox_supervisor_ctx *ctx,
                                 pid_t pp)
{
    size_t n = sizeof(ctx->vfork_parents) / sizeof(ctx->vfork_parents[0]);
    for (size_t i = 0; i < n; i++) {
        if (ctx->vfork_parents[i] == pp)
            return 1;
    }
    return 0;
}

struct kbox_dispatch forward_execve(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx,
                                    int is_execveat)
{
    struct kbox_dispatch d = forward_execve_impl(req, ctx, is_execveat);
    if (ctx->verbose && d.kind == KBOX_DISPATCH_RETURN && d.error) {
        char pbuf[KBOX_MAX_PATH] = {0};
        (void) guest_mem_read_string(
            ctx, kbox_syscall_request_pid(req),
            kbox_syscall_request_arg(req, is_execveat ? 1 : 0), pbuf,
            sizeof(pbuf));
        fprintf(stderr, "kbox: exec denied: %s path=%s (pid=%u)\n",
                kbox_err_text(-d.error), pbuf,
                (unsigned) kbox_syscall_request_pid(req));
    }
    return d;
}

static struct kbox_dispatch forward_execve_impl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_execveat)
{
    pid_t pid = kbox_syscall_request_pid(req);

    /* Detect fexecve: execveat(fd, "", argv, envp, AT_EMPTY_PATH). This is the
     * initial exec from image.c on the host memfd. Let the kernel handle it
     * directly.
     */
    if (is_execveat) {
        long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
        if (flags & KBOX_AT_EMPTY_PATH)
            return kbox_dispatch_continue();
    }

    /* Read pathname from tracee memory. */
    uint64_t path_addr = is_execveat ? kbox_syscall_request_arg(req, 1)
                                     : kbox_syscall_request_arg(req, 0);
    char pathbuf[KBOX_MAX_PATH];
    int rc =
        guest_mem_read_string(ctx, pid, path_addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Already a descriptor path: that descriptor is a host fd kbox injected
     * (the exec memfd itself, on a re-exec through /proc/self/exe), so the
     * host kernel can resolve it directly and LKL cannot resolve it at all. */
    if (strncmp(pathbuf, "/proc/self/fd/", 14) == 0 ||
        strncmp(pathbuf, "/proc/thread-self/fd/", 21) == 0)
        return kbox_dispatch_continue();

    /* Resolve host bind mount or translate path for LKL. */
    char translated[KBOX_MAX_PATH];
    int bind_ro = 0;
    long raw_dirfd =
        is_execveat ? to_dirfd_arg(kbox_syscall_request_arg(req, 0))
                    : AT_FDCWD_LINUX;
    int brc = kbox_resolve_host_bind_at(ctx, raw_dirfd, pathbuf, translated,
                                        sizeof(translated), &bind_ro);
    if (brc < 0)
        return kbox_dispatch_errno(-brc);

    int exec_memfd;
    if (brc > 0) {
        int hfd = open(translated, O_RDONLY | O_CLOEXEC);
        if (hfd < 0)
            return kbox_dispatch_errno(errno);
        exec_memfd = kbox_shadow_create_from_host_fd(hfd);
        close(hfd);
    } else {
        rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root,
                                         translated, sizeof(translated));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);

        /* Virtual paths (/proc, /sys, /dev) are not executable binaries.
         * Return ENOENT/EACCES rather than CONTINUE to avoid a TOCTOU window
         * where a sibling thread could swap the path after validation.
         */
        if (kbox_is_lkl_virtual_path(translated))
            return kbox_dispatch_errno(EACCES);


        /* Open the binary from LKL. */
        long lkl_fd = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                      O_RDONLY, 0);
        if (lkl_fd < 0)
            return kbox_dispatch_errno((int) (-lkl_fd));

        /* Create a memfd with the binary contents. */
        exec_memfd = kbox_shadow_create(ctx->sysnrs, lkl_fd);
        lkl_close_and_invalidate(ctx, lkl_fd);
    }

    if (exec_memfd < 0)
        return kbox_dispatch_errno(-exec_memfd);

    /* Trap mode: the SIGSYS handler and BPF filter do not survive a real exec,
     * so perform a userspace exec instead. This replaces the process image
     * in-place (unmap old, map new, jump to entry) without invoking kernel's
     * execve. On success the function does not return.
     */
    if (request_uses_trap_signals(req))
        return trap_userspace_exec(req, ctx, exec_memfd, pathbuf, is_execveat);

    /* Non-ELF executables are #! scripts. The host kernel would run
     * binfmt_script on the memfd and resolve the shebang to a *host* path,
     * which does not exist, so kbox used to answer ENOEXEC and leave the
     * script to the calling shell. That works for shells and breaks every
     * program that execs a script and expects the kernel to honour the
     * shebang -- gosu, su-exec, tini, env -- which is how official images
     * re-exec their entrypoints.
     *
     * Instead, rewrite the shebang to the interpreter's injected memfd and let
     * binfmt_script do the rest: the kernel execs /proc/self/fd/<interp> and
     * passes the script as argv[1]. The script fd therefore has to survive the
     * exec, which is why this branch injects it without O_CLOEXEC.
     */
    int exec_fd_cloexec = O_CLOEXEC;
    {
        unsigned char elf_magic[4];
        if (pread(exec_memfd, elf_magic, 4, 0) != 4 ||
            memcmp(elf_magic, "\x7f" "ELF", 4) != 0) {
            int rewritten = rewrite_script_shebang(ctx, req, &exec_memfd,
                                                   pathbuf);
            if (rewritten < 0 && ctx->verbose)
                fprintf(stderr, "kbox: exec %s: shebang rewrite failed: %s\n",
                        pathbuf, kbox_err_text(rewritten));
            if (rewritten < 0) {
                close(exec_memfd);
                return kbox_dispatch_errno(-rewritten);
            }
            exec_fd_cloexec = 0;
        }
    }

    /* Check for PT_INTERP (dynamic binary). */
    {
        unsigned char *elf_buf = NULL;
        size_t elf_buf_len = 0;

        if (kbox_read_elf_header_window_fd(exec_memfd, &elf_buf,
                                           &elf_buf_len) == 0) {
            char interp_path[256];
            uint64_t pt_offset, pt_filesz;
            int ilen = kbox_find_elf_interp_loc(
                elf_buf, elf_buf_len, interp_path, sizeof(interp_path),
                &pt_offset, &pt_filesz);

            munmap(elf_buf, elf_buf_len);

            if (ilen < 0) {
                close(exec_memfd);
                return kbox_dispatch_errno(ENOEXEC);
            }

            if (ilen > 0) {
                /* Dynamic binary. Extract the interpreter from LKL and inject
                 * it into the tracee.
                 */
                long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                                  interp_path, O_RDONLY, 0);
                if (interp_lkl < 0) {
                    if (ctx->verbose)
                        fprintf(stderr,
                                "kbox: exec %s: cannot open "
                                "interpreter %s: %s\n",
                                pathbuf, interp_path,
                                kbox_err_text(interp_lkl));
                    close(exec_memfd);
                    return kbox_dispatch_errno((int) (-interp_lkl));
                }

                int interp_memfd = kbox_shadow_create(ctx->sysnrs, interp_lkl);
                lkl_close_and_invalidate(ctx, interp_lkl);

                if (interp_memfd < 0) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(-interp_memfd);
                }

                /* Inject the interpreter memfd first so we know its FD number
                 * in the tracee for the PT_INTERP patch. O_CLOEXEC is safe: the
                 * kernel resolves /proc/self/fd/N via open_exec() before
                 * begin_new_exec() closes CLOEXEC descriptors.
                 */
                int tracee_interp_fd =
                    request_addfd(ctx, req, interp_memfd, O_CLOEXEC);
                close(interp_memfd);

                if (tracee_interp_fd < 0) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(-tracee_interp_fd);
                }

                /* Patch PT_INTERP in the exec memfd to point at the injected
                 * interpreter: /proc/self/fd/<N>.
                 */
                char new_interp[64];
                int new_len = snprintf(new_interp, sizeof(new_interp),
                                       "/proc/self/fd/%d", tracee_interp_fd);

                if ((uint64_t) (new_len + 1) > pt_filesz) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(ENOMEM);
                }

                char patch[256];
                size_t patch_len = (size_t) pt_filesz;
                if (patch_len > sizeof(patch))
                    patch_len = sizeof(patch);
                memset(patch, 0, patch_len);
                memcpy(patch, new_interp, (size_t) new_len);

                if (pwrite(exec_memfd, patch, patch_len, (off_t) pt_offset) !=
                    (ssize_t) patch_len) {
                    close(exec_memfd);
                    return kbox_dispatch_errno(EIO);
                }

                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: exec %s: interpreter %s "
                            "-> /proc/self/fd/%d\n",
                            pathbuf, interp_path, tracee_interp_fd);
            }
        } else {
            munmap(elf_buf, elf_buf_len);
        }
    }

    /* Inject the exec memfd into the tracee. O_CLOEXEC keeps the tracee's FD
     * table clean after exec succeeds.
     */
    int tracee_exec_fd = request_addfd(ctx, req, exec_memfd, exec_fd_cloexec);
    close(exec_memfd);

    if (tracee_exec_fd < 0)
        return kbox_dispatch_errno(-tracee_exec_fd);

    if (ctx->verbose) {
        char fdp[64];
        struct stat st;
        snprintf(fdp, sizeof(fdp), "/proc/%d/fd/%d", (int) pid, tracee_exec_fd);
        fprintf(stderr, "kbox: exec %s: tracee fd %d present=%d\n", pathbuf,
                tracee_exec_fd, stat(fdp, &st) == 0);
    }

    /* Overwrite the pathname in the tracee's memory with /proc/self/fd/<N>.
     * Relocate any overlapping argv[]/envp[] strings (including aliased
     * argv[0] and short pathnames packed adjacent to argv[1..]) below the
     * tracee stack pointer before overwriting path_addr.
     */
    char new_path[64];
    int new_path_len = snprintf(new_path, sizeof(new_path), "/proc/self/fd/%d",
                                tracee_exec_fd);
    size_t total_write = (size_t) (new_path_len + 1);

    uint64_t argv_addr = is_execveat ? kbox_syscall_request_arg(req, 2)
                                     : kbox_syscall_request_arg(req, 1);
    uint64_t envp_addr = is_execveat ? kbox_syscall_request_arg(req, 3)
                                     : kbox_syscall_request_arg(req, 2);

    /* If this is a vfork child, the parent shares these pages and is suspended
     * until this exec completes. Record what is about to be rewritten so the
     * parent's memory can be put back when it resumes -- otherwise it wakes up
     * with "/proc/self/fd/N" where its own path used to be and every later
     * fork in it execs a descriptor that belongs to this child. */
    {
        pid_t pp = tracee_parent_of(pid);
        if (pp > 0 && vfork_parent_recorded(ctx, pp)) {
            uint64_t lo = path_addr < argv_addr ? path_addr : argv_addr;
            uint64_t hi = path_addr > argv_addr ? path_addr : argv_addr;
            const uint64_t margin = 32768;
            lo = lo > margin ? lo - margin : 0;
            size_t len = (size_t) (hi + margin - lo);
            if (len > 65536)
                len = 65536;
            for (size_t i = 0;
                 i < sizeof(ctx->vfork_pending) / sizeof(ctx->vfork_pending[0]);
                 i++) {
                struct kbox_vfork_pending *slot = &ctx->vfork_pending[i];
                if (slot->saved)
                    continue;
                unsigned char *buf = malloc(len);
                if (!buf)
                    break;
                if (guest_mem_read(ctx, pid, lo, buf, len) != 0) {
                    free(buf);
                    break;
                }
                slot->parent = pp;
                slot->addr = lo;
                slot->len = len;
                slot->saved = buf;
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: exec: vfork parent %d snapshotted "
                            "0x%llx+%zu\n",
                            (int) pp, (unsigned long long) lo, len);
                break;
            }
        }
    }

    rc = relocate_overlapping_exec_vecs(ctx, pid, path_addr, total_write,
                                        argv_addr, envp_addr);
    if (rc < 0 && ctx->verbose) {
        fprintf(stderr, "kbox: exec %s: vector relocation skipped (%s)\n",
                pathbuf, strerror(-rc));
    }

    rc = write_guest_mem_any(ctx, pid, path_addr, new_path, total_write);
    if (rc < 0) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: exec %s: cannot rewrite "
                    "pathname: %s\n",
                    pathbuf, strerror(-rc));
        return kbox_dispatch_errno(ENOEXEC);
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec %s -> /proc/self/fd/%d\n", pathbuf,
                tracee_exec_fd);

    /* Clean up CLOEXEC entries from the FD table, matching what a successful
     * exec will do in the kernel.
     *
     * This is still conservative: if exec later fails, tracee resumes after we
     * have already purged those mappings. That rollback problem is preferable
     * to keeping stale mappings alive across a successful exec, which misroutes
     * future FD operations in the new image.
     */
    close_cloexec_with_writeback(ctx);

    /* Invalidate the cached /proc/pid/mem FD. After exec, the kernel may revoke
     * access to the old FD even though the PID is the same (credential check
     * against the new binary). Forcing a reopen on the next write ensures we
     * have valid access.
     */
    if (ctx->proc_mem_fd >= 0) {
        close(ctx->proc_mem_fd);
        ctx->proc_mem_fd = -1;
    }

    return kbox_dispatch_continue();
}
