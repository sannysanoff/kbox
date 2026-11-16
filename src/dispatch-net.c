/* SPDX-License-Identifier: MIT */

/* Network syscall handlers for the seccomp dispatch engine. */

/* The single address the LKL guest owns on its slirp interface. Kept in step
 * with GUEST_IP_STR in net-slirp.c: a connect aimed at the container's own pod
 * address is retargeted here, because that is where its listeners really live.
 */
/* unused, kept out of the way */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "net.h"

/* Shadow socket design:
 *   1. Create an LKL network socket inside LKL's network stack
 *   2. Create a host socketpair (sp[0]=supervisor, sp[1]=tracee)
 *   3. Inject sp[1] into the tracee via ADDFD
 *   4. Register sp[0]+lkl_fd with the SLIRP event loop
 *   5. The event loop pumps data between sp[0] and the LKL socket
 *
 * The tracee sees a real host FD, so poll/epoll/read/write all work natively
 * via the host kernel. Only control-plane ops (connect, getsockopt, etc.) need
 * explicit forwarding.
 *
 * INET sockets with SLIRP active get a shadow socket bridge so data flows
 * through the host kernel socketpair (bypassing BKL contention in blocking LKL
 * recv/send calls). Non-INET sockets and INET sockets without SLIRP use the
 * standard virtual FD path.
 *
 * Limitation: listen/accept on shadow sockets fail because AF_UNIX socketpair
 * doesn't support inbound connections. Server sockets must be used without
 * --net or via a future deferred-bridge approach.
 */
static int attach_shadow_socket(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                long lkl_fd,
                                int base_type,
                                int sock_flags,
                                int64_t *out_fd)
{
    int sp[2];
    if (socketpair(AF_UNIX, base_type | SOCK_CLOEXEC, 0, sp) < 0)
        return -errno;

    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    if (sock_flags & SOCK_NONBLOCK)
        fcntl(sp[1], F_SETFL, O_NONBLOCK);

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(sp[0]);
        close(sp[1]);
        return -EMFILE;
    }

    if (kbox_net_register_socket((int) lkl_fd, sp[0], base_type) < 0) {
        close(sp[0]);
        close(sp[1]);
        if (sock_flags & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
        *out_fd = (int64_t) vfd;
        return 0;
    }

    uint32_t addfd_flags = (sock_flags & SOCK_CLOEXEC) ? O_CLOEXEC : 0;
    int host_fd = request_addfd(ctx, req, sp[1], addfd_flags);
    if (host_fd < 0) {
        kbox_net_deregister_socket((int) lkl_fd);
        close(sp[1]);
        kbox_fd_table_remove(ctx->fd_table, vfd);
        return host_fd;
    }
    kbox_fd_table_set_host_fd(ctx->fd_table, vfd, host_fd);

    /* The ADDFD-injected host_fd may land on a low FD number that already
     * has a SHADOW_ONLY entry (from pipe tracking or inherited FD scan).
     * Overwrite it so resolve_lkl_socket finds the LKL socket via the
     * direct lookup path instead of returning the stale SHADOW_ONLY.
     */
    if (host_fd != vfd) {
        struct kbox_fd_entry *low = fd_table_entry(ctx->fd_table, host_fd);
        if (low && low->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
            kbox_fd_table_remove(ctx->fd_table, host_fd);
    }

    struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, vfd);
    if (e) {
        e->shadow_sp = sp[1];
        if (sock_flags & SOCK_CLOEXEC)
            e->cloexec = 1;
    }

    *out_fd = (int64_t) host_fd;
    return 0;
}

struct kbox_dispatch forward_socket(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long domain = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long type_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long protocol = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    int base_type = (int) type_raw & 0xFF;

    long ret = kbox_lkl_socket(ctx->sysnrs, domain, type_raw, protocol);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long lkl_fd = ret;

    /* Virtual FD path when shadow bridge is not applicable:
     * - SLIRP/net loop not active
     * - Non-INET domain (AF_UNIX, AF_NETLINK, etc.)
     * - Non-stream/datagram type (SOCK_RAW, etc.): socketpair(AF_UNIX) only
     *   supports SOCK_STREAM and SOCK_DGRAM
     */
    if (!kbox_net_is_active() ||
        (domain != 2 /* AF_INET */ && domain != 10 /* AF_INET6 */) ||
        (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
        if (vfd < 0) {
            lkl_close_and_invalidate(ctx, lkl_fd);
            return kbox_dispatch_errno(EMFILE);
        }
        if (type_raw & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
        return kbox_dispatch_value((int64_t) vfd);
    }

    int64_t out_fd = -1;
    int rc = attach_shadow_socket(req, ctx, lkl_fd, base_type, (int) type_raw,
                                  &out_fd);
    if (rc < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(-rc);
    }
    return kbox_dispatch_value(out_fd);
}

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd);

struct kbox_dispatch forward_bind(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_bind(ctx->sysnrs, lkl_fd, buf, (long) len);
    return kbox_dispatch_from_lkl(ret);
}

/* Resolve LKL FD and optional FD-table entry from a tracee FD. */
static long resolve_lkl_socket_entry(struct kbox_supervisor_ctx *ctx,
                                     long fd,
                                     struct kbox_fd_entry **entry_out)
{
    if (entry_out)
        *entry_out = NULL;

    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0) {
        if (entry_out)
            *entry_out = fd_table_entry(ctx->fd_table, fd);
        return lkl_fd;
    }
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
        return lkl_fd;

    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0) {
        struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, vfd);
        if (entry_out)
            *entry_out = e;
        return e ? e->lkl_fd : -1;
    }

    return -1;
}

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd)
{
    return resolve_lkl_socket_entry(ctx, fd, NULL);
}

struct kbox_dispatch forward_listen(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long backlog = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long ret = kbox_lkl_listen(ctx->sysnrs, lkl_fd, backlog);
    if (ret == 0 && entry && entry->shadow_sp >= 0 && kbox_net_is_active())
        kbox_net_set_listening((int) lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch complete_accept_result(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long listen_lkl_fd,
    uint64_t addr_ptr,
    uint64_t len_ptr,
    unsigned int in_len,
    unsigned int out_len,
    const uint8_t *addr,
    long client_lkl,
    int flags)
{
    /* Drain any listening readiness token from the host socketpair and re-arm
     * notification in case additional backlog connections remain.
     */
    if (entry && entry->shadow_sp >= 0 && kbox_net_is_active()) {
        char drain[16];
        while (recv(entry->shadow_sp, drain, sizeof(drain), MSG_DONTWAIT) > 0)
            ;
        kbox_net_clear_listening_notify((int) listen_lkl_fd);
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr, "kbox: net: accept done lkl=%ld -> cleared notify\n",
                    listen_lkl_fd);
    }

    if (client_lkl < 0) {
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr, "kbox: net: accept incomplete rc=%ld\n", client_lkl);
        return kbox_dispatch_from_lkl(client_lkl);
    }

    pid_t pid = kbox_syscall_request_pid(req);
    if (addr_ptr != 0) {
        unsigned int write_len = out_len < in_len ? out_len : in_len;
        if (write_len > 0) {
            int wrc = guest_mem_write(ctx, pid, addr_ptr, addr, write_len);
            if (wrc < 0) {
                lkl_close_and_invalidate(ctx, client_lkl);
                return kbox_dispatch_errno(-wrc);
            }
        }
        int wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
        if (wrc < 0) {
            lkl_close_and_invalidate(ctx, client_lkl);
            return kbox_dispatch_errno(-wrc);
        }
    }

    /* The accepted connection keeps its shadow: the shadow is what tells the
     * tracee its socket became readable, and dropping it makes the very first
     * read block forever. Whatever strands the answer on the second
     * self-connection, it is not the shadow's existence.
     */
    /* Every accepted connection gets a shadow when one can be made. A socket
     * that lives only inside LKL has no host descriptor, and the epoll calls
     * are passed straight to the host, so registering such a socket fails with
     * EBADF -- postgres aborts every backend on exactly that. Without a shadow
     * the connection still works for plain read and write, so a failure to
     * attach one falls back to a bare virtual descriptor.
     */
    int64_t out_fd = -1;
    int rc = -1;
    if (kbox_net_is_active())
        rc = attach_shadow_socket(req, ctx, client_lkl, SOCK_STREAM, flags,
                                  &out_fd);
    if (rc < 0) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, client_lkl, 0);
        if (vfd < 0) {
            lkl_close_and_invalidate(ctx, client_lkl);
            return kbox_dispatch_errno(EMFILE);
        }
        if (flags & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr, "kbox: net: accepted no-shadow vfd=%ld\n", vfd);
        return kbox_dispatch_value((int64_t) vfd);
    }
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: net: accepted lkl=%ld vfd=%lld\n", client_lkl,
                (long long) out_fd);
    return kbox_dispatch_value(out_fd);
}

static struct kbox_dispatch defer_pending_accept(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long listen_fd,
    int flags,
    uint64_t addr_ptr,
    uint64_t len_ptr,
    unsigned int in_len)
{
    for (size_t i = 0; i < KBOX_PENDING_ACCEPTS_MAX; i++) {
        if (!ctx->pending_accepts[i].active) {
            if (getenv("KBOX_NET_TRACE"))
                fprintf(stderr,
                        "kbox: net: accept deferred slot=%zu listen=%ld "
                        "count=%d\n",
                        i, listen_fd, ctx->pending_accept_count + 1);
            ctx->pending_accepts[i].active = 1;
            ctx->pending_accepts[i].req = *req;
            ctx->pending_accepts[i].listen_fd = listen_fd;
            ctx->pending_accepts[i].flags = flags;
            ctx->pending_accepts[i].addr_ptr = addr_ptr;
            ctx->pending_accepts[i].len_ptr = len_ptr;
            ctx->pending_accepts[i].in_len = in_len;
            ctx->pending_accept_count++;
            return (struct kbox_dispatch){.kind = KBOX_DISPATCH_DEFERRED};
        }
    }
    return kbox_dispatch_errno(EAGAIN);
}

static long try_accept4_nonblock(const struct kbox_sysnrs *sysnrs,
                                 long lkl_fd,
                                 int *was_nonblock_out,
                                 void *addr,
                                 unsigned int *out_len,
                                 int flags)
{
    long lfl = kbox_lkl_fcntl(sysnrs, lkl_fd, F_GETFL, 0);
    int nonblock = (lfl >= 0 && (lfl & O_NONBLOCK)) ? 1 : 0;

    if (was_nonblock_out)
        *was_nonblock_out = nonblock;

    if (!nonblock && lfl >= 0)
        kbox_lkl_fcntl(sysnrs, lkl_fd, F_SETFL, lfl | O_NONBLOCK);
    long client_lkl = kbox_lkl_accept4(sysnrs, lkl_fd, addr, out_len, flags);
    if (!nonblock && lfl >= 0)
        kbox_lkl_fcntl(sysnrs, lkl_fd, F_SETFL, lfl);
    return client_lkl;
}

void kbox_dispatch_poll_pending(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || ctx->pending_accept_count == 0 || ctx->listener_fd < 0)
        return;

    for (size_t i = 0; i < KBOX_PENDING_ACCEPTS_MAX; i++) {
        struct kbox_pending_accept *pa = &ctx->pending_accepts[i];
        if (!pa->active)
            continue;

        uint64_t id = kbox_syscall_request_cookie(&pa->req);
        if (ioctl(ctx->listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ID_VALID, &id) <
            0) {
            pa->active = 0;
            ctx->pending_accept_count--;
            continue;
        }

        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: net: accept retry slot=%zu listen=%ld count=%d\n", i,
                    pa->listen_fd, ctx->pending_accept_count);
        struct kbox_syscall_request saved_req = pa->req;
        kbox_dispatch_prepare_request_ctx(ctx, &saved_req);

        struct kbox_fd_entry *entry = NULL;
        long lkl_fd = resolve_lkl_socket_entry(ctx, pa->listen_fd, &entry);
        if (lkl_fd < 0) {
            struct kbox_dispatch d = kbox_dispatch_errno(EBADF);
            pa->active = 0;
            ctx->pending_accept_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        uint8_t addr[4096];
        unsigned int out_len = pa->addr_ptr != 0 ? pa->in_len : 0;
        long client_lkl = try_accept4_nonblock(
            ctx->sysnrs, lkl_fd, NULL, pa->addr_ptr ? addr : NULL,
            pa->addr_ptr ? &out_len : NULL, pa->flags);
        if (client_lkl == -EAGAIN || client_lkl == -EWOULDBLOCK)
            continue;

        uint64_t addr_ptr = pa->addr_ptr;
        uint64_t len_ptr = pa->len_ptr;
        unsigned int in_len = pa->in_len;
        int flags = pa->flags;

        pa->active = 0;
        ctx->pending_accept_count--;

        struct kbox_dispatch d = complete_accept_result(
            &saved_req, ctx, entry, lkl_fd, addr_ptr, len_ptr, in_len, out_len,
            addr, client_lkl, flags);
        kbox_notify_respond(ctx->listener_fd, id, &d);
    }
}

static struct kbox_dispatch dispatch_accept_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int flags)
{
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);

    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);
    unsigned int in_len = 0;

    if (addr_ptr != 0) {
        if (len_ptr == 0)
            return kbox_dispatch_errno(EFAULT);
        int rrc = guest_mem_read(ctx, pid, len_ptr, &in_len, sizeof(in_len));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
        if ((int) in_len < 0)
            return kbox_dispatch_errno(EINVAL);
        if (in_len > 4096)
            in_len = 4096;
    }

    uint8_t addr[4096];
    unsigned int out_len = 0;
    int nonblock = 0;
    long client_lkl = -EAGAIN;

    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: net: accept enter lkl=%ld listener_fd=%d src=%d\n",
                lkl_fd, ctx->listener_fd, (int) req->source);
    for (;;) {
        out_len = addr_ptr != 0 ? in_len : 0;
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP &&
            ctx->listener_fd >= 0) {
            client_lkl = try_accept4_nonblock(
                ctx->sysnrs, lkl_fd, &nonblock, addr_ptr ? addr : NULL,
                addr_ptr ? &out_len : NULL, flags);
        } else {
            long lfl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
            nonblock = (lfl >= 0 && (lfl & O_NONBLOCK)) ? 1 : 0;
            client_lkl = kbox_lkl_accept4(ctx->sysnrs, lkl_fd,
                                          addr_ptr ? addr : NULL,
                                          addr_ptr ? &out_len : NULL, flags);
        }
        if (client_lkl != -EAGAIN && client_lkl != -EWOULDBLOCK)
            break;
        if (nonblock)
            break;
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP &&
            ctx->listener_fd >= 0) {
            return defer_pending_accept(req, ctx, fd, flags, addr_ptr, len_ptr,
                                        in_len);
        }
        struct pollfd lpfd = {
            .fd = (int) lkl_fd,
            .events = POLLIN,
            .revents = 0,
        };
        struct timespec ts = {0, 50 * 1000 * 1000};
        long pr = kbox_lkl_ppoll(ctx->sysnrs, &lpfd, 1, &ts, NULL, 0);
        if (pr < 0 && pr != -EINTR) {
            client_lkl = pr;
            break;
        }
    }

    return complete_accept_result(req, ctx, entry, lkl_fd, addr_ptr, len_ptr,
                                  in_len, out_len, addr, client_lkl, flags);
}

struct kbox_dispatch forward_accept(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    return dispatch_accept_common(req, ctx, 0);
}

struct kbox_dispatch forward_accept4(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return dispatch_accept_common(req, ctx, flags);
}

struct kbox_dispatch forward_connect(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (ctx->verbose && len >= sizeof(struct sockaddr_in) &&
        ((struct sockaddr_in *) buf)->sin_family == AF_INET) {
        struct sockaddr_in *d = (struct sockaddr_in *) buf;
        char dstr[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &d->sin_addr, dstr, sizeof(dstr));
        fprintf(stderr, "kbox: net: connect fd=%ld lkl_fd=%ld -> %s:%u own=%s\n",
                fd, lkl_fd, dstr, (unsigned) ntohs(d->sin_port),
                ctx->own_ip[0] ? ctx->own_ip : "-");
    }

    /* A connect aimed at the container's own address is left alone: the LKL
     * interface owns that address, so the listener is reached locally without
     * leaving the container. Retargeting it to slirp's fixed guest address was
     * wrong -- that address carries no listener, and the connect came back
     * refused instead of being served. Keep the trace until the own-address
     * path is proven on every image we run.
     */
    long ret = kbox_lkl_connect(ctx->sysnrs, lkl_fd, buf, (long) len);

    /* A loopback connect often comes back EINPROGRESS even though both ends are
     * inside this kernel. The tracee then waits for POLLOUT on the socketpair,
     * which is a host fd and does not know about LKL's handshake, so the guest's
     * poll+SO_ERROR loop can miss it and the connect looks hung. For a blocking
     * socket, finish the handshake here instead of handing it back.
     */
    if (ret == -EINPROGRESS) {
        long fl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
        int blocking = !(fl >= 0 && (fl & O_NONBLOCK));
        if (blocking) {
            struct pollfd wp = {
                .fd = (int) lkl_fd,
                .events = POLLOUT,
                .revents = 0,
            };
            struct timespec wts = {5, 0};
            long pr = kbox_lkl_ppoll(ctx->sysnrs, &wp, 1, &wts, NULL, 0);
            if (pr > 0 && (wp.revents & POLLOUT) &&
                !(wp.revents & (POLLERR | POLLHUP)))
                ret = 0;
        }
    }
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: net: connect ret lkl_fd=%ld -> %ld\n", lkl_fd,
                ret);

    /* Propagate -EINPROGRESS directly for nonblocking sockets. The tracee's
     * poll(POLLOUT) on the AF_UNIX socketpair returns immediately (spurious
     * wakeup), but getsockopt(SO_ERROR) is forwarded to the LKL socket and
     * returns the real handshake status. The tracee retries poll+getsockopt
     * until SO_ERROR clears; standard nonblocking connect flow.
     */
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_getsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    uint64_t optlen_ptr = kbox_syscall_request_arg(req, 4);

    if (optval_ptr == 0 || optlen_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Read the optlen from tracee. */
    unsigned int optlen;
    int rrc = guest_mem_read(ctx, pid, optlen_ptr, &optlen, sizeof(optlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096];
    unsigned int out_len = optlen;

    long ret = kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, level, optname, optval,
                                   &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* Write min(out_len, optlen) to avoid leaking stack data. */
    unsigned int write_len = out_len < optlen ? out_len : optlen;
    int wrc = guest_mem_write(ctx, pid, optval_ptr, optval, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, optlen_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_setsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    long optlen = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    if (optlen < 0 || optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096] = {0};
    if (optval_ptr != 0 && optlen > 0) {
        int rrc = guest_mem_read(ctx, pid, optval_ptr, optval, (size_t) optlen);
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }

    long ret = kbox_lkl_setsockopt(ctx->sysnrs, lkl_fd, level, optname,
                                   optval_ptr ? optval : NULL, optlen);
    return kbox_dispatch_from_lkl(ret);
}

typedef long (*sockaddr_query_fn)(const struct kbox_sysnrs *s,
                                  long fd,
                                  void *addr,
                                  void *addrlen);

static struct kbox_dispatch forward_sockaddr_query(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    sockaddr_query_fn query)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);

    if (addr_ptr == 0 || len_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    unsigned int addrlen;
    int rrc = guest_mem_read(ctx, pid, len_ptr, &addrlen, sizeof(addrlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (addrlen > 4096)
        addrlen = 4096;

    uint8_t addr[4096];
    unsigned int out_len = addrlen;

    long ret = query(ctx->sysnrs, lkl_fd, addr, &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    unsigned int write_len = out_len < addrlen ? out_len : addrlen;
    int wrc = guest_mem_write(ctx, pid, addr_ptr, addr, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getsockname(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(req, ctx, kbox_lkl_getsockname);
}

struct kbox_dispatch forward_getpeername(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    return forward_sockaddr_query(req, ctx, kbox_lkl_getpeername);
}

struct kbox_dispatch forward_shutdown(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long how = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_shutdown(ctx->sysnrs, lkl_fd, how);
    return kbox_dispatch_from_lkl(ret);
}

/* For shadow sockets with a destination address, forward the data + address
 * directly to the LKL socket. This is needed for unconnected UDP (DNS resolver
 * uses sendto with sockaddr_in without prior connect).
 *
 * sendto(fd, buf, len, flags, dest_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=dest_addr, args[5]=addrlen
 */
struct kbox_dispatch forward_sendto(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t dest_ptr = kbox_syscall_request_arg(req, 4);
    if (dest_ptr == 0)
        return kbox_dispatch_continue(); /* no dest addr: stream data path */

    /* Has a destination address: forward via LKL sendto. */
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    int64_t addrlen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 5));

    if (len_raw < 0 || addrlen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    size_t addrlen = (size_t) addrlen_raw;

    if (len > 65536)
        len = 65536;
    if (addrlen > 128)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[65536];
    uint8_t addr[128];

    int rrc = guest_mem_read(ctx, pid, buf_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    rrc = guest_mem_read(ctx, pid, dest_ptr, addr, addrlen);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                               addr, (long) addrlen);
    return kbox_dispatch_from_lkl(ret);
}

/* For shadow sockets, receive data + source address from the LKL socket and
 * write them back to the tracee.
 *
 * recvfrom(fd, buf, len, flags, src_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=src_addr, args[5]=addrlen
 */
struct kbox_dispatch forward_recvfrom(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t src_ptr = kbox_syscall_request_arg(req, 4);
    if (src_ptr == 0)
        return kbox_dispatch_continue(); /* no addr buffer: stream path */

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t addrlen_ptr = kbox_syscall_request_arg(req, 5);

    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    if (len > 65536)
        len = 65536;

    unsigned int addrlen = 0;
    if (addrlen_ptr != 0) {
        int rrc =
            guest_mem_read(ctx, pid, addrlen_ptr, &addrlen, sizeof(addrlen));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }
    if (addrlen > 128)
        addrlen = 128;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int out_addrlen = addrlen;

    long ret = kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                                 addr, &out_addrlen);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    int wrc = guest_mem_write(ctx, pid, buf_ptr, buf, (size_t) ret);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    if (src_ptr != 0 && out_addrlen > 0) {
        unsigned int write_len = out_addrlen < addrlen ? out_addrlen : addrlen;
        wrc = guest_mem_write(ctx, pid, src_ptr, addr, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (addrlen_ptr != 0) {
        wrc = guest_mem_write(ctx, pid, addrlen_ptr, &out_addrlen,
                              sizeof(out_addrlen));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(ret);
}

/* Intercept for shadow sockets so that msg_name (source
 * address) is populated from the LKL socket, not the AF_UNIX socketpair.
 *
 * recvmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 */
struct kbox_dispatch forward_recvmsg(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io(fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t msg_ptr = kbox_syscall_request_arg(req, 1);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (msg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    struct {
        uint64_t msg_name;
        uint32_t msg_namelen;
        uint32_t __pad0;
        uint64_t msg_iov;
        uint64_t msg_iovlen;
        uint64_t msg_control;
        uint64_t msg_controllen;
        int msg_flags;
    } mh;
    int rrc = guest_mem_read(ctx, pid, msg_ptr, &mh, sizeof(mh));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    /* No msg_name: for connected stream sockets, CONTINUE via socketpair. */
    if (mh.msg_name == 0 || mh.msg_namelen == 0)
        return kbox_dispatch_continue();

    /* Read all iovecs to determine total buffer capacity. */
    if (mh.msg_iovlen == 0)
        return kbox_dispatch_value(0);

    size_t niov = (size_t) mh.msg_iovlen;
    if (niov > 64)
        niov = 64;

    struct {
        uint64_t iov_base;
        uint64_t iov_len;
    } iovs[64];
    rrc = guest_mem_read(ctx, pid, mh.msg_iov, iovs, niov * sizeof(iovs[0]));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    size_t total_cap = 0;
    for (size_t v = 0; v < niov; v++)
        total_cap += (size_t) iovs[v].iov_len;
    if (total_cap > 65536)
        total_cap = 65536;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int addrlen = mh.msg_namelen < sizeof(addr)
                               ? mh.msg_namelen
                               : (unsigned int) sizeof(addr);
    unsigned int out_addrlen = addrlen;

    long ret = kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) total_cap,
                                 flags, addr, &out_addrlen);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* Scatter received data across tracee iov buffers. */
    size_t written = 0;
    for (size_t v = 0; v < niov && written < (size_t) ret; v++) {
        size_t chunk = (size_t) ret - written;
        if (chunk > (size_t) iovs[v].iov_len)
            chunk = (size_t) iovs[v].iov_len;
        if (chunk > 0 && iovs[v].iov_base != 0) {
            int wrc2 = guest_mem_write(ctx, pid, iovs[v].iov_base,
                                       buf + written, chunk);
            if (wrc2 < 0)
                return kbox_dispatch_errno(-wrc2);
            written += chunk;
        }
    }

    /* Write source address to tracee msg_name. */
    if (out_addrlen > 0) {
        unsigned int write_len =
            out_addrlen < mh.msg_namelen ? out_addrlen : mh.msg_namelen;
        int awrc = guest_mem_write(ctx, pid, mh.msg_name, addr, write_len);
        if (awrc < 0)
            return kbox_dispatch_errno(-awrc);
    }

    /* Update msg_namelen in the msghdr. */
    int nwrc =
        guest_mem_write(ctx, pid, msg_ptr + 8 /* offset of msg_namelen */,
                        &out_addrlen, sizeof(out_addrlen));
    if (nwrc < 0)
        return kbox_dispatch_errno(-nwrc);

    /* Zero msg_controllen and msg_flags: the recvfrom path does not
     * produce ancillary data. Without this, CMSG_FIRSTHDR() in the
     * tracee would parse uninitialized memory from the msg_control
     * buffer.
     */
    uint64_t zero8 = 0;
    int zero4 = 0;
    int cwrc;
    /* msg_controllen is at offset 40 (after msg_control at 32). */
    cwrc = guest_mem_write(ctx, pid, msg_ptr + 40, &zero8, sizeof(zero8));
    if (cwrc < 0)
        return kbox_dispatch_errno(-cwrc);
    /* msg_flags is at offset 48. */
    cwrc = guest_mem_write(ctx, pid, msg_ptr + 48, &zero4, sizeof(zero4));
    if (cwrc < 0)
        return kbox_dispatch_errno(-cwrc);

    return kbox_dispatch_value(ret);
}
