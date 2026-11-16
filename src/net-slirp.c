/* SPDX-License-Identifier: MIT */

/* User-mode networking via minislirp.
 *
 * Bridges LKL's virtio-net device with a SLIRP instance to provide outbound
 * TCP/UDP networking without privileges.
 *
 * Threading model:
 *   - LKL's virtio-net poll callback is called from an LKL kernel thread and
 *     must block until data is available.
 *   - SLIRP's callback-based poll cycle runs on the event loop thread.
 *   - Bridge via pipe: SLIRP output -> write length-prefixed frame to pipe ->
 *     LKL poll callback unblocks -> RX delivery.
 *   - LKL TX callback -> slirp_input() can be called directly (same address
 *     space, LKL is single-threaded for I/O).
 *   - Shadow sockets: dispatch thread registers socketpair+LKL FD via command
 *     pipe; event loop pumps data between them.
 *
 * Compiled only when KBOX_HAS_SLIRP is defined.
 */

#ifdef KBOX_HAS_SLIRP

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/uio.h>
#include <unistd.h>

/* minislirp headers */
/* cppcheck-suppress missingInclude */
#include "libslirp.h"
#include "lkl-wrap.h"
#include "net.h"

/* Guest network configuration */
#define GUEST_IP_STR "10.0.2.15"
#define GUEST_MASK 24
#define STR(x) #x
#define XSTR(x) STR(x)
#define GATEWAY_IP_STR "10.0.2.2"
#define DNS_IP_STR "10.0.2.3"

/* Maximum Ethernet frame size.  Must fit in uint16_t length header. */
#define MAX_PKT_SIZE 65535

/* Maximum number of shadow sockets tracked by the event loop */
#define MAX_SHADOW_SOCKETS 1024

/* Maximum pollfd entries: SLIRP FDs + shadow sockets + wakeup pipe */
#define MAX_POLLFDS 2048

/* RX pipe: length-prefixed framing. */

/* SLIRP -> LKL packet delivery uses a pipe with 2-byte length headers. Without
 * framing, consecutive writes can coalesce and corrupt packets.
 *
 *   [ uint16_t len ][ payload bytes ... ]
 */
static int rx_pipe[2] = {-1, -1};

/* TX pipe: LKL net_tx callback -> event loop -> slirp_input.
 * libslirp is NOT thread-safe, so slirp_input must only be called from event
 * loop thread. Same length-prefixed framing as RX.
 */
static int tx_pipe[2] = {-1, -1};

/* Shared state: event loop running flag (used by multiple threads). */
static int slirp_running; /* accessed via __atomic builtins */

/* Detected syscall ABI, stored during kbox_net_configure. */
static const struct kbox_sysnrs *net_sysnrs;

/* Gate: blocks the LKL poll thread during boot and interface config.
 *
 * lkl_netdev_add creates a poll thread that immediately calls ops->poll. If the
 * poll thread runs during boot or configuration, it competes for the LKL CPU
 * (BKL) and causes deadlocks in lkl_if_up / SIOCSIFADDR.
 *
 * Solution: ops->poll blocks on this flag until configuration is done. The main
 * thread configures the interface uncontested, then opens the gate. The poll
 * thread wakes up and starts normal operation.
 */
static int net_ready; /* __atomic: 0 = gate closed, 1 = gate open */

/* RX packet queue (lock-free SPSC ring buffer). */

/* LKL's virtio-net driver holds the Big Kernel Lock (BKL) during the
 * ops->poll/ops->rx callback cycle. If ops->rx blocks (e.g., waiting on the
 * rx_pipe), ALL other lkl_syscall() calls deadlock; including lkl_if_up,
 * kbox_lkl_socket, kbox_lkl_connect, etc.
 *
 * Solution: a dedicated reader thread consumes rx_pipe into this queue.
 * ops->poll checks if the queue is non-empty (instant, no blocking).
 * ops->rx pops one packet from the queue (instant, no blocking).
 * The BKL is held for microseconds, not milliseconds.
 */
#define RX_QUEUE_SIZE 128
#define RX_QUEUE_MASK (RX_QUEUE_SIZE - 1)

struct rx_packet {
    uint16_t len;
    uint8_t data[MAX_PKT_SIZE];
};

static struct rx_packet rx_queue[RX_QUEUE_SIZE];
static volatile unsigned rx_head; /* written by reader thread */
static volatile unsigned rx_tail; /* written by LKL RX callback */
static int rx_eventfd = -1;       /* signaled when queue non-empty */

/* Reader thread: blocks on rx_pipe, enqueues packets. */
static pthread_t rx_reader_thread;

static void *rx_reader_loop(void *arg)
{
    (void) arg;

    while (__atomic_load_n(&slirp_running, __ATOMIC_RELAXED)) {
        /* Read length-prefixed frame from rx_pipe. */
        uint16_t pkt_len;
        ssize_t n;
        do {
            n = read(rx_pipe[0], &pkt_len, sizeof(pkt_len));
        } while (n < 0 && errno == EINTR);
        if (n != (ssize_t) sizeof(pkt_len))
            break;

        if (pkt_len == 0)
            continue; /* wakeup signal, not a real packet */

        /* Read payload. */
        uint8_t buf[MAX_PKT_SIZE];
        size_t remaining = pkt_len;
        size_t offset = 0;
        while (remaining > 0) {
            n = read(rx_pipe[0], buf + offset, remaining);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                goto out;
            offset += (size_t) n;
            remaining -= (size_t) n;
        }

        /* Enqueue into ring buffer. */
        unsigned head = __atomic_load_n(&rx_head, __ATOMIC_RELAXED);
        unsigned tail = __atomic_load_n(&rx_tail, __ATOMIC_RELAXED);
        unsigned next = (head + 1) & RX_QUEUE_MASK;
        if (next == tail) {
            /* Queue full: drop packet. */
            continue;
        }
        rx_queue[head].len = pkt_len;
        memcpy(rx_queue[head].data, buf, pkt_len);
        __atomic_store_n(&rx_head, next, __ATOMIC_RELEASE);

        /* Signal the eventfd to wake net_poll. */
        uint64_t val = 1;
        n = write(rx_eventfd, &val, sizeof(val));
        (void) n;
    }

out:
    return NULL;
}

/* SLIRP instance and LKL netdev. */

static Slirp *slirp_instance;
static struct lkl_netdev slirp_netdev;
static struct lkl_dev_net_ops slirp_netdev_ops;
static int lkl_netdev_id = -1;

/* Event loop state. */

static pthread_t slirp_thread;

/* Wakeup pipe: write a byte to wake the event loop from poll. */
static int wakeup_pipe[2] = {-1, -1};

/* Shadow socket table. */

#define DGRAM_ADDR_QUEUE_LEN 64

struct dgram_addr_entry {
    uint8_t addr[128];
    unsigned int addrlen;
};

struct shadow_socket {
    int lkl_fd;        /* LKL-side socket FD */
    int supervisor_fd; /* supervisor end of the socketpair */
    int sock_type;     /* SOCK_STREAM or SOCK_DGRAM */
    int listening;     /* 1 after listen() on this socket */
    int listen_notified;
    int lkl_eof;         /* 1 after LKL recvfrom returned 0 (peer FIN) */
    int sp_eof;          /* 1 after read(supervisor_fd) returned 0 */
    int lkl_wr_shutdown; /* 1 after SHUT_WR forwarded to LKL */
    int sp_wr_shutdown;  /* 1 after SHUT_WR sent to supervisor_fd */
    size_t to_lkl_off;
    size_t to_lkl_len;
    uint8_t to_lkl_buf[65536];
    size_t to_supervisor_off;
    size_t to_supervisor_len;
    uint8_t to_supervisor_buf[65536];
    struct dgram_addr_entry pending_dgram_addr;
    struct dgram_addr_entry dgram_q[DGRAM_ADDR_QUEUE_LEN];
    unsigned int dgram_head;
    unsigned int dgram_tail;
    uint64_t gen;
    int active;
};

static struct shadow_socket shadow_sockets[MAX_SHADOW_SOCKETS];
static uint64_t next_shadow_gen = 1;
static pthread_mutex_t shadow_lock = PTHREAD_MUTEX_INITIALIZER;

/* SLIRP timers (sorted linked list). */

struct slirp_timer {
    int64_t expire_ms;
    SlirpTimerCb cb;
    void *cb_opaque;
    struct slirp_timer *next;
    int in_list; /* 1 if currently linked */
};

static struct slirp_timer *timer_head;

static void timer_unlink(struct slirp_timer *t)
{
    if (!t->in_list)
        return;
    struct slirp_timer **pp = &timer_head;
    while (*pp) {
        if (*pp == t) {
            *pp = t->next;
            t->next = NULL;
            t->in_list = 0;
            return;
        }
        pp = &(*pp)->next;
    }
    t->in_list = 0;
}

static void timer_insert_sorted(struct slirp_timer *t)
{
    timer_unlink(t);
    struct slirp_timer **pp = &timer_head;
    while (*pp && (*pp)->expire_ms <= t->expire_ms)
        pp = &(*pp)->next;
    t->next = *pp;
    *pp = t;
    t->in_list = 1;
}

static void *cb_timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
    (void) opaque;
    struct slirp_timer *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;
    t->cb = cb;
    t->cb_opaque = cb_opaque;
    t->expire_ms = INT64_MAX;
    return t;
}

static void cb_timer_free(void *timer, void *opaque)
{
    (void) opaque;
    struct slirp_timer *t = timer;
    if (!t)
        return;
    timer_unlink(t);
    free(t);
}

static void cb_timer_mod(void *timer, int64_t expire_time, void *opaque)
{
    (void) opaque;
    struct slirp_timer *t = timer;
    if (!t)
        return;
    t->expire_ms = expire_time;
    timer_insert_sorted(t);
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void fire_expired_timers(void)
{
    int64_t current = now_ms();
    while (timer_head && timer_head->expire_ms <= current) {
        struct slirp_timer *t = timer_head;
        timer_head = t->next;
        t->next = NULL;
        t->in_list = 0;
        t->expire_ms = INT64_MAX;
        t->cb(t->cb_opaque);
    }
}

static int next_timer_timeout_ms(void)
{
    if (!timer_head || timer_head->expire_ms == INT64_MAX)
        return -1;
    int64_t delta = timer_head->expire_ms - now_ms();
    if (delta < 0)
        return 0;
    if (delta > INT_MAX)
        return INT_MAX;
    return (int) delta;
}

/* SLIRP callbacks. */

/* Write a complete buffer to a file descriptor, retrying on short writes. */
static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        remaining -= (size_t) n;
    }
    return (ssize_t) len;
}

/* slirp_send_packet is only called from the SLIRP event loop thread (single
 * writer), but we use write_all to handle short writes on large packets that
 * exceed PIPE_BUF. The RX pipe reader (net_rx) runs on a single LKL thread, so
 * framing integrity is maintained as long as there is exactly one writer.
 */
static ssize_t slirp_send_packet(const void *buf, size_t len, void *opaque)
{
    (void) opaque;
    if (len > MAX_PKT_SIZE)
        return -1;

    /* Write length header, then payload. */
    uint16_t hdr = (uint16_t) len;
    if (write_all(rx_pipe[1], &hdr, sizeof(hdr)) < 0)
        return -1;
    if (len > 0 && write_all(rx_pipe[1], buf, len) < 0)
        return -1;
    return (ssize_t) len;
}

static void slirp_guest_error(const char *msg, void *opaque)
{
    (void) opaque;
    fprintf(stderr, "kbox: slirp error: %s\n", msg);
}

static int64_t slirp_clock_get_ns(void *opaque)
{
    (void) opaque;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void slirp_register_poll_fd(int fd, void *opaque)
{
    (void) fd;
    (void) opaque;
}

static void slirp_unregister_poll_fd(int fd, void *opaque)
{
    (void) fd;
    (void) opaque;
}

static void slirp_register_poll_socket(slirp_os_socket fd, void *opaque)
{
    (void) fd;
    (void) opaque;
}

static void slirp_unregister_poll_socket(slirp_os_socket fd, void *opaque)
{
    (void) fd;
    (void) opaque;
}

static void slirp_notify(void *opaque)
{
    (void) opaque;
    /* Wake the event loop so it picks up new SLIRP state. */
    char c = 'W';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
}

static const SlirpCb slirp_callbacks = {
    .send_packet = slirp_send_packet,
    .guest_error = slirp_guest_error,
    .clock_get_ns = slirp_clock_get_ns,
    .timer_new = cb_timer_new,
    .timer_free = cb_timer_free,
    .timer_mod = cb_timer_mod,
    .register_poll_fd = slirp_register_poll_fd,
    .unregister_poll_fd = slirp_unregister_poll_fd,
    .notify = slirp_notify,
    .register_poll_socket = slirp_register_poll_socket,
    .unregister_poll_socket = slirp_unregister_poll_socket,
};

/* Callback-based SLIRP poll integration. */

struct poll_ctx {
    struct pollfd pfds[MAX_POLLFDS];
    int shadow_slots[MAX_SHADOW_SOCKETS];
    uint64_t shadow_gens[MAX_SHADOW_SOCKETS];
    int count;
    int slirp_base; /* index where SLIRP entries start */
};

static int add_poll_cb(slirp_os_socket fd, int events, void *opaque)
{
    struct poll_ctx *ctx = opaque;
    if (ctx->count >= MAX_POLLFDS)
        return -1;
    int idx = ctx->count++;
    ctx->pfds[idx].fd = fd;
    ctx->pfds[idx].events = 0;
    ctx->pfds[idx].revents = 0;
    if (events & SLIRP_POLL_IN)
        ctx->pfds[idx].events |= POLLIN;
    if (events & SLIRP_POLL_OUT)
        ctx->pfds[idx].events |= POLLOUT;
    if (events & SLIRP_POLL_PRI)
        ctx->pfds[idx].events |= POLLPRI;
    return idx;
}

static int get_revents_cb(int idx, void *opaque)
{
    struct poll_ctx *ctx = opaque;
    if (idx < 0 || idx >= ctx->count)
        return 0;
    int revents = 0;
    short r = ctx->pfds[idx].revents;
    if (r & POLLIN)
        revents |= SLIRP_POLL_IN;
    if (r & POLLOUT)
        revents |= SLIRP_POLL_OUT;
    if (r & POLLPRI)
        revents |= SLIRP_POLL_PRI;
    if (r & POLLERR)
        revents |= SLIRP_POLL_ERR;
    if (r & POLLHUP)
        revents |= SLIRP_POLL_HUP;
    return revents;
}

/* Shadow socket I/O pump. */

/* For each registered shadow socket, the event loop:
 *   1. Adds supervisor_fd to the pollfd array (POLLIN)
 *   2. After poll, reads data from supervisor_fd and writes to LKL socket
 *   3. Reads from LKL socket (non-blocking) and writes to supervisor_fd
 *
 * This bridges the tracee's real socketpair with the LKL network stack.
 */

/* MSG_DONTWAIT flag (same across all Linux ABIs). */
#define LKL_MSG_DONTWAIT 0x40

/* ioctl constants (architecture-independent SIOC* values). */
#define LKL_SIOCSIFFLAGS 0x8914
#define LKL_SIOCSIFADDR 0x8916
#define LKL_SIOCSIFNETMASK 0x891C
#define LKL_IFF_UP 0x1
#define LKL_IFF_RUNNING 0x40
#define LKL_SIOCADDRT 0x890B
#define LKL_SIOCDELRT 0x890C

static void retire_shadow_socket(struct shadow_socket *sock)
{
    sock->active = 0;
    if (sock->supervisor_fd >= 0) {
        close(sock->supervisor_fd);
        sock->supervisor_fd = -1;
    }
}

static int shadow_flush_to_lkl(struct shadow_socket *sock)
{
    while (sock->to_lkl_len > 0) {
        long r = kbox_lkl_sendto(
            net_sysnrs, sock->lkl_fd, sock->to_lkl_buf + sock->to_lkl_off,
            (long) sock->to_lkl_len, LKL_MSG_DONTWAIT, NULL, 0);
        if (r > 0) {
            sock->to_lkl_off += (size_t) r;
            sock->to_lkl_len -= (size_t) r;
            if (sock->to_lkl_len == 0)
                sock->to_lkl_off = 0;
            continue;
        }
        if (r == -EAGAIN || r == -EWOULDBLOCK || r == -EINPROGRESS ||
            r == -EALREADY)
            return 0;
        return -1;
    }
    if (sock->sp_eof && !sock->lkl_wr_shutdown &&
        sock->sock_type == SOCK_STREAM && net_sysnrs) {
        kbox_lkl_shutdown(net_sysnrs, sock->lkl_fd, 1 /* SHUT_WR */);
        sock->lkl_wr_shutdown = 1;
    }
    return 0;
}

static void push_dgram_addr_locked(struct shadow_socket *sock)
{
    if (sock->sock_type != SOCK_DGRAM || sock->pending_dgram_addr.addrlen == 0)
        return;

    unsigned int next_tail = (sock->dgram_tail + 1) % DGRAM_ADDR_QUEUE_LEN;
    if (next_tail == sock->dgram_head)
        sock->dgram_head = (sock->dgram_head + 1) % DGRAM_ADDR_QUEUE_LEN;
    sock->dgram_q[sock->dgram_tail] = sock->pending_dgram_addr;
    sock->dgram_tail = next_tail;
    sock->pending_dgram_addr.addrlen = 0;
}

static int shadow_flush_to_supervisor(struct shadow_socket *sock)
{
    while (sock->to_supervisor_len > 0) {
        ssize_t n = write(sock->supervisor_fd,
                          sock->to_supervisor_buf + sock->to_supervisor_off,
                          sock->to_supervisor_len);
        if (n > 0) {
            sock->to_supervisor_off += (size_t) n;
            sock->to_supervisor_len -= (size_t) n;
            if (sock->to_supervisor_len == 0) {
                sock->to_supervisor_off = 0;
                push_dgram_addr_locked(sock);
            }
            continue;
        }
        if (n < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return 0;
        return -1;
    }
    if (sock->lkl_eof && !sock->sp_wr_shutdown &&
        sock->sock_type == SOCK_STREAM && sock->supervisor_fd >= 0) {
        shutdown(sock->supervisor_fd, SHUT_WR);
        sock->sp_wr_shutdown = 1;
    }
    return 0;
}

static int shadow_nonfatal_recv_error(const struct shadow_socket *sock, long r)
{
    if (r == -EAGAIN || r == -EWOULDBLOCK)
        return 1;

    /* Stream sockets can report "not connected" or "invalid" while the
     * guest-visible socketpair is already live and the TCP state machine is
     * still settling.  The event loop probes with recvfrom(MSG_DONTWAIT) on
     * every iteration, so treating these as fatal tears down the bridge before
     * the first guest write().
     */
    if (sock->sock_type == SOCK_STREAM && (r == -ENOTCONN || r == -EINVAL))
        return 1;

    return 0;
}

static int pump_shadow_lkl_read(struct shadow_socket *sock)
{
    void *addr_arg = NULL;
    unsigned int *addrlen_arg = NULL;
    if (sock->sock_type == SOCK_DGRAM) {
        sock->pending_dgram_addr.addrlen =
            (unsigned int) sizeof(sock->pending_dgram_addr.addr);
        addr_arg = sock->pending_dgram_addr.addr;
        addrlen_arg = &sock->pending_dgram_addr.addrlen;
    }

    long r =
        kbox_lkl_recvfrom(net_sysnrs, sock->lkl_fd, sock->to_supervisor_buf,
                          (long) sizeof(sock->to_supervisor_buf),
                          LKL_MSG_DONTWAIT, addr_arg, addrlen_arg);
    if (r > 0) {
        sock->to_supervisor_off = 0;
        sock->to_supervisor_len = (size_t) r;
        if (shadow_flush_to_supervisor(sock) < 0)
            retire_shadow_socket(sock);
        return 1;
    }
    if (r == 0) {
        sock->pending_dgram_addr.addrlen = 0;
        if (sock->sock_type == SOCK_STREAM) {
            sock->lkl_eof = 1;
            if (sock->to_supervisor_len == 0 && !sock->sp_wr_shutdown &&
                sock->supervisor_fd >= 0) {
                shutdown(sock->supervisor_fd, SHUT_WR);
                sock->sp_wr_shutdown = 1;
            }
        }
        return 0;
    }
    sock->pending_dgram_addr.addrlen = 0;
    if (!shadow_nonfatal_recv_error(sock, r))
        retire_shadow_socket(sock);
    return 0;
}

static int pump_shadow_sockets(struct poll_ctx *ctx, int shadow_base)
{
    int shadow_cnt = ctx->count - shadow_base;
    int progressed = 0;
    struct pollfd lkl_pfds[MAX_SHADOW_SOCKETS];
    int lkl_slots[MAX_SHADOW_SOCKETS];
    int npoll = 0;

    pthread_mutex_lock(&shadow_lock);
    for (int si = 0; si < shadow_cnt; si++) {
        int slot = ctx->shadow_slots[si];
        int pidx = shadow_base + si;
        if (slot < 0 || slot >= MAX_SHADOW_SOCKETS ||
            !shadow_sockets[slot].active ||
            shadow_sockets[slot].gen != ctx->shadow_gens[si] ||
            shadow_sockets[slot].supervisor_fd != ctx->pfds[pidx].fd)
            continue;

        struct shadow_socket *sock = &shadow_sockets[slot];

        if (sock->listening) {
            if (ctx->pfds[pidx].revents & (POLLHUP | POLLERR | POLLNVAL)) {
                retire_shadow_socket(sock);
                continue;
            }
            if (!sock->listen_notified && net_sysnrs &&
                npoll < MAX_SHADOW_SOCKETS) {
                lkl_pfds[npoll].fd = sock->lkl_fd;
                lkl_pfds[npoll].events = POLLIN;
                lkl_pfds[npoll].revents = 0;
                lkl_slots[npoll] = slot;
                npoll++;
            }
            continue;
        }

        /* Retry any buffered stream data before reading more. */
        if (shadow_flush_to_lkl(sock) < 0 ||
            shadow_flush_to_supervisor(sock) < 0) {
            retire_shadow_socket(sock);
            continue;
        }

        /* supervisor_fd -> LKL socket (non-blocking via sendto). For datagram
         * sockets, drain up to 8 queued messages (e.g. glibc sendmmsg A+AAAA)
         * in one pass.
         */
        if ((ctx->pfds[pidx].revents & POLLIN) && sock->to_lkl_len == 0 &&
            !sock->sp_eof) {
            int max_reads = (sock->sock_type == SOCK_DGRAM) ? 8 : 1;
            for (int riter = 0; riter < max_reads && sock->to_lkl_len == 0;
                 riter++) {
                ssize_t n = read(sock->supervisor_fd, sock->to_lkl_buf,
                                 sizeof(sock->to_lkl_buf));
                if (n > 0) {
                    sock->to_lkl_off = 0;
                    sock->to_lkl_len = (size_t) n;
                    progressed = 1;
                    if (shadow_flush_to_lkl(sock) < 0) {
                        retire_shadow_socket(sock);
                        break;
                    }
                } else if (n == 0) {
                    /* Tracee closed write half (shutdown SHUT_WR) or closed FD;
                     * keep the slot alive until POLLHUP/deregister if
                     * LKL->tracee direction may still carry responses.
                     */
                    sock->sp_eof = 1;
                    if (shadow_flush_to_lkl(sock) < 0) {
                        retire_shadow_socket(sock);
                    }
                    break;
                } else {
                    if (errno != EAGAIN && errno != EWOULDBLOCK &&
                        errno != EINTR)
                        retire_shadow_socket(sock);
                    break;
                }
            }
        }

        if (!sock->active)
            continue;

        if (ctx->pfds[pidx].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            retire_shadow_socket(sock);
            continue;
        }

        if (!sock->lkl_eof && sock->to_supervisor_len == 0 && net_sysnrs &&
            npoll < MAX_SHADOW_SOCKETS) {
            lkl_pfds[npoll].fd = sock->lkl_fd;
            lkl_pfds[npoll].events = POLLIN;
            lkl_pfds[npoll].revents = 0;
            lkl_slots[npoll] = slot;
            npoll++;
        }

        /* Buffered data left over means another pass is needed right away. */
        if (sock->to_lkl_len > 0 || sock->to_supervisor_len > 0)
            progressed = 1;
    }

    if (npoll > 0 && net_sysnrs) {
        /* Flush pending LKL IRQs once so socket readiness is up to date. */
        kbox_lkl_getuid(net_sysnrs);

        struct timespec zero_ts = {0, 0};
        long pr = kbox_lkl_ppoll(net_sysnrs, lkl_pfds, (unsigned long) npoll,
                                 &zero_ts, NULL, 0);
        if (pr > 0) {
            for (int k = 0; k < npoll; k++) {
                short rev = lkl_pfds[k].revents;
                if (rev == 0)
                    continue;
                struct shadow_socket *sock = &shadow_sockets[lkl_slots[k]];
                if (!sock->active)
                    continue;
                if (sock->listening) {
                    if (!sock->listen_notified &&
                        (rev & (POLLIN | POLLERR | POLLHUP))) {
                        char wake = 'A';
                        ssize_t wn = write(sock->supervisor_fd, &wake, 1);
                        if (wn == 1)
                            sock->listen_notified = 1;
                    }
                    if (getenv("KBOX_NET_TRACE"))
                        fprintf(stderr,
                                "kbox: net: listen slot=%d lkl=%d notified=%d "
                                "pr=%ld revents=%#x\n",
                                lkl_slots[k], sock->lkl_fd,
                                sock->listen_notified, pr, (unsigned) rev);
                } else if (rev & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
                    progressed |= pump_shadow_lkl_read(sock);
                }
            }
        } else if (pr < 0) {
            /* Fallback if one entry in lkl_pfds was invalid. */
            for (int k = 0; k < npoll; k++) {
                struct shadow_socket *sock = &shadow_sockets[lkl_slots[k]];
                if (!sock->active)
                    continue;
                if (sock->listening) {
                    struct pollfd lpfd = {
                        .fd = sock->lkl_fd,
                        .events = POLLIN,
                        .revents = 0,
                    };
                    long spr =
                        kbox_lkl_ppoll(net_sysnrs, &lpfd, 1, &zero_ts, NULL, 0);
                    if (spr > 0 &&
                        (lpfd.revents & (POLLIN | POLLERR | POLLHUP))) {
                        char wake = 'A';
                        ssize_t wn = write(sock->supervisor_fd, &wake, 1);
                        if (wn == 1)
                            sock->listen_notified = 1;
                    }
                } else {
                    progressed |= pump_shadow_lkl_read(sock);
                }
            }
        }
    }
    pthread_mutex_unlock(&shadow_lock);
    return progressed;
}

/* LKL virtio-net callbacks (iovec-based). */

/* TX: LKL sends a packet.  Gather iovecs and write a length-prefixed frame to
 * the TX pipe. The event loop thread reads it and calls slirp_input (libslirp
 * is NOT thread-safe, all access must be serialized on the event loop thread).
 *
 * Called from LKL kernel context (single TX thread).
 */
static int net_tx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
    (void) nd;

    /* Gather iovecs into a contiguous buffer. */
    static uint8_t tx_buf[MAX_PKT_SIZE];
    size_t total = 0;
    for (int i = 0; i < cnt; i++) {
        if (total + iov[i].iov_len > MAX_PKT_SIZE)
            return -1;
        memcpy(tx_buf + total, iov[i].iov_base, iov[i].iov_len);
        total += iov[i].iov_len;
    }

    /* Write length-prefixed frame to TX pipe. */
    uint16_t hdr = (uint16_t) total;
    if (write_all(tx_pipe[1], &hdr, sizeof(hdr)) < 0)
        return -1;
    if (total > 0 && write_all(tx_pipe[1], tx_buf, total) < 0)
        return -1;

    /* Wake the event loop to process the TX packet. */
    char c = 'T';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
    return 0;
}

/* RX: LKL polls for incoming packets.
 * Read a length-prefixed frame from the RX pipe, scatter into iovecs. This
 * blocks until a frame is available (LKL calls this from its internal thread
 * when it needs a packet).
 */

/* RX: pop one packet from the queue, scatter into iovecs.
 *
 * Called with LKL's BKL held.  Returns instantly because the rx_reader_thread
 * already buffered the packet in the ring.
 */
static int net_rx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
    (void) nd;

    unsigned head = __atomic_load_n(&rx_head, __ATOMIC_ACQUIRE);
    unsigned tail = __atomic_load_n(&rx_tail, __ATOMIC_RELAXED);
    /* no data: must return -1, not 0 (0-byte completion triggers infinite
     * kworker refill loop in LKL)
     */
    if (head == tail)
        return -1;

    struct rx_packet *pkt = &rx_queue[tail];
    uint16_t pkt_len = pkt->len;

    size_t copied = 0;
    for (int i = 0; i < cnt && copied < pkt_len; i++) {
        size_t chunk = pkt_len - copied;
        if (chunk > iov[i].iov_len)
            chunk = iov[i].iov_len;
        memcpy(iov[i].iov_base, pkt->data + copied, chunk);
        copied += chunk;
    }

    __atomic_store_n(&rx_tail, (tail + 1) & RX_QUEUE_MASK, __ATOMIC_RELEASE);
    return (int) copied;
}

/* Poll: check if RX data is available in the queue.
 *
 * Called with LKL's BKL held. If the queue is empty, sleep briefly on eventfd
 * (50ms) so the thread doesn't busy-spin. The short timeout ensures the BKL is
 * released periodically so other LKL threads (lkl_if_up, socket operations) can
 * make progress.
 */
static int net_poll(struct lkl_netdev *nd)
{
    (void) nd;

    /* Gate: sleep until post-boot configuration completes.
     * The poll thread is started by lkl_netdev_add (pre-boot). If it runs
     * virtio_process_queue before lkl_if_up finishes, the kworker refill path
     * can starve lkl_cpu_get callers.
     */
    if (!__atomic_load_n(&net_ready, __ATOMIC_ACQUIRE)) {
        usleep(50000);
        if (!__atomic_load_n(&slirp_running, __ATOMIC_RELAXED))
            return LKL_DEV_NET_POLL_HUP;
        return 0; /* no RX, no TX while gated */
    }

    if (!__atomic_load_n(&slirp_running, __ATOMIC_RELAXED))
        return LKL_DEV_NET_POLL_HUP;

    int flags = LKL_DEV_NET_POLL_TX;
    unsigned head = __atomic_load_n(&rx_head, __ATOMIC_ACQUIRE);
    unsigned tail = __atomic_load_n(&rx_tail, __ATOMIC_RELAXED);
    if (head != tail) {
        uint64_t val;
        ssize_t n = read(rx_eventfd, &val, sizeof(val));
        (void) n;
        flags |= LKL_DEV_NET_POLL_RX;
    } else {
        struct pollfd pfd = {.fd = rx_eventfd, .events = POLLIN};
        if (poll(&pfd, 1, 100) > 0) {
            uint64_t val;
            ssize_t n = read(rx_eventfd, &val, sizeof(val));
            (void) n;
            if (!__atomic_load_n(&slirp_running, __ATOMIC_RELAXED))
                return LKL_DEV_NET_POLL_HUP;
            flags |= LKL_DEV_NET_POLL_RX;
        }
    }
    if (!__atomic_load_n(&slirp_running, __ATOMIC_RELAXED))
        return LKL_DEV_NET_POLL_HUP;
    return flags;
}

/* Poll HUP: wake the poll callback by writing to the RX pipe.
 * LKL calls this to interrupt a blocking poll.
 */
static void net_poll_hup(struct lkl_netdev *nd)
{
    (void) nd;
    /* Write a zero-length frame to unblock the RX read, and wake eventfd. */
    uint16_t zero = 0;
    ssize_t n = write(rx_pipe[1], &zero, sizeof(zero));
    (void) n;
    if (rx_eventfd >= 0) {
        uint64_t one = 1;
        n = write(rx_eventfd, &one, sizeof(one));
        (void) n;
    }
}

static void net_free(struct lkl_netdev *nd)
{
    (void) nd;
}

/* Drain the TX pipe: read length-prefixed frames and feed them to SLIRP.
 * Must be called from the event loop thread (libslirp is not thread-safe).
 */
static void drain_tx_pipe(void)
{
    static uint8_t tx_drain_buf[MAX_PKT_SIZE];

    for (;;) {
        /* Check if a frame header is available before blocking read. */
        struct pollfd pfd = {.fd = tx_pipe[0], .events = POLLIN};
        if (poll(&pfd, 1, 0) <= 0)
            break;

        uint16_t pkt_len;
        ssize_t n = read(tx_pipe[0], &pkt_len, sizeof(pkt_len));
        if (n != sizeof(pkt_len))
            break;
        if (pkt_len == 0)
            break;

        size_t remaining = pkt_len;
        size_t offset = 0;
        while (remaining > 0) {
            n = read(tx_pipe[0], tx_drain_buf + offset, remaining);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                return;
            offset += (size_t) n;
            remaining -= (size_t) n;
        }

        slirp_input(slirp_instance, tx_drain_buf, (int) pkt_len);
    }
}

/* SLIRP event loop thread. */

static void *slirp_event_loop(void *arg)
{
    (void) arg;
    struct poll_ctx ctx;
    int busy = 0; /* shadow pump moved data: iterate again without blocking */

    while (__atomic_load_n(&slirp_running, __ATOMIC_RELAXED)) {
        ctx.count = 0;

        /* Slot 0: wakeup pipe */
        ctx.pfds[ctx.count].fd = wakeup_pipe[0];
        ctx.pfds[ctx.count].events = POLLIN;
        ctx.pfds[ctx.count].revents = 0;
        ctx.count++;


        /* Let SLIRP add its FDs via callback. */
        uint32_t slirp_timeout = UINT32_MAX;
        ctx.slirp_base = ctx.count;
        slirp_pollfds_fill_socket(slirp_instance, &slirp_timeout, add_poll_cb,
                                  &ctx);

        /* Add shadow socket supervisor FDs. */
        int shadow_base = ctx.count;
        int has_data_sockets = 0;
        pthread_mutex_lock(&shadow_lock);
        for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
            if (!shadow_sockets[i].active)
                continue;
            if (ctx.count >= MAX_POLLFDS)
                break;
            int si = ctx.count - shadow_base;
            if (si >= MAX_SHADOW_SOCKETS)
                break;
            ctx.shadow_slots[si] = i;
            ctx.shadow_gens[si] = shadow_sockets[i].gen;
            if (!shadow_sockets[i].listening && !shadow_sockets[i].lkl_eof)
                has_data_sockets = 1;
            ctx.pfds[ctx.count].fd = shadow_sockets[i].supervisor_fd;
            ctx.pfds[ctx.count].events =
                (shadow_sockets[i].listening || shadow_sockets[i].sp_eof)
                    ? 0
                    : POLLIN;
            ctx.pfds[ctx.count].revents = 0;
            ctx.count++;
        }
        pthread_mutex_unlock(&shadow_lock);

        /* Compute timeout: min of SLIRP timeout, timer timeout, 100ms cap
         * (or 5ms when active data sockets may receive local LKL packets).
         */
        int timeout_ms = has_data_sockets ? 5 : 100;
        if (slirp_timeout != UINT32_MAX && (int) slirp_timeout < timeout_ms)
            timeout_ms = (int) slirp_timeout;
        int timer_ms = next_timer_timeout_ms();
        if (timer_ms >= 0 && timer_ms < timeout_ms)
            timeout_ms = timer_ms;
        /* LKL does not signal the host when a shadowed socket receives data,
         * so those sockets are only drained by an explicit probe. Without a
         * short cap every request/response hop waits for the 100 ms timeout,
         * which shows up as ~300 ms per round trip inside the guest.
         */
        if (shadow_base < ctx.count && timeout_ms > 2)
            timeout_ms = 2;
        if (busy)
            timeout_ms = 0;

        int ret = poll(ctx.pfds, (nfds_t) ctx.count, timeout_ms);
        if (ret < 0 && errno != EINTR)
            break;

        /* Drain wakeup pipe. */
        if (ctx.pfds[0].revents & POLLIN) {
            char drain[64];
            while (read(wakeup_pipe[0], drain, sizeof(drain)) > 0)
                ;
        }

        /* Drain TX pipe: forward LKL-originated packets to SLIRP. This is the
         * only place slirp_input is called, ensuring all libslirp access is
         * serialized on this thread.
         */
        drain_tx_pipe();

        /* Let SLIRP process its events (select_error only on actual error). */
        slirp_pollfds_poll(slirp_instance, ret < 0, get_revents_cb, &ctx);

        /* Fire expired timers. */
        fire_expired_timers();

        /* Pump shadow socket data. */
        if (shadow_base < ctx.count)
            busy = pump_shadow_sockets(&ctx, shadow_base);
        else
            busy = 0;
    }
    return NULL;
}

/* Public API. */

/* Pre-boot device registration.
 *
 * LKL requires netdev to be registered BEFORE lkl_start_kernel. The kernel
 * probes the device during boot; registering after boot causes deadlocks
 * because the async probe thread holds the kernel lock while the caller tries
 * to do ioctl-based configuration.
 */
int kbox_net_add_device(void)
{
    SlirpConfig cfg;

    /* Create pipes. */
    if (pipe(rx_pipe) < 0) {
        fprintf(stderr, "kbox: net: pipe failed: %s\n", strerror(errno));
        return -1;
    }
    if (pipe(wakeup_pipe) < 0) {
        fprintf(stderr, "kbox: net: wakeup pipe failed: %s\n", strerror(errno));
        goto err_rx_pipe;
    }
    if (pipe(tx_pipe) < 0) {
        fprintf(stderr, "kbox: net: tx pipe failed: %s\n", strerror(errno));
        goto err_wakeup_pipe;
    }
    fcntl(wakeup_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(wakeup_pipe[1], F_SETFL, O_NONBLOCK);
    /* tx_pipe[0] stays blocking: drain_tx_pipe must read complete
     * length-prefixed frames atomically.
     */

    memset(shadow_sockets, 0, sizeof(shadow_sockets));
    for (int si = 0; si < MAX_SHADOW_SOCKETS; si++) {
        shadow_sockets[si].supervisor_fd = -1;
        shadow_sockets[si].lkl_fd = -1;
    }

    /* Create eventfd for RX queue signaling. */
    rx_eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (rx_eventfd < 0) {
        fprintf(stderr, "kbox: net: eventfd failed: %s\n", strerror(errno));
        goto err_tx_pipe;
    }
    rx_head = rx_tail = 0;

    /* Initialize SLIRP with explicit network configuration. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 4;
    cfg.restricted = 0;
    cfg.in_enabled = 1;
    inet_pton(AF_INET, "10.0.2.0", &cfg.vnetwork);
    inet_pton(AF_INET, "255.255.255.0", &cfg.vnetmask);
    inet_pton(AF_INET, GATEWAY_IP_STR, &cfg.vhost);
    inet_pton(AF_INET, DNS_IP_STR, &cfg.vnameserver);
    inet_pton(AF_INET, GUEST_IP_STR, &cfg.vdhcp_start);

    slirp_instance = slirp_new(&cfg, &slirp_callbacks, NULL);
    if (!slirp_instance) {
        fprintf(stderr, "kbox: net: slirp_new failed\n");
        goto err_tx_pipe;
    }

    /* Start the SLIRP event loop and RX reader threads. */
    __atomic_store_n(&slirp_running, 1, __ATOMIC_RELAXED);
    if (pthread_create(&slirp_thread, NULL, slirp_event_loop, NULL) != 0) {
        fprintf(stderr, "kbox: net: event loop thread failed: %s\n",
                strerror(errno));
        goto err_eventfd;
    }
    if (pthread_create(&rx_reader_thread, NULL, rx_reader_loop, NULL) != 0) {
        fprintf(stderr, "kbox: net: rx reader thread failed: %s\n",
                strerror(errno));
        goto err_event_thread;
    }

    /* Register the LKL virtio-net device (probed during boot). */
    slirp_netdev_ops.tx = net_tx;
    slirp_netdev_ops.rx = net_rx;
    slirp_netdev_ops.poll = net_poll;
    slirp_netdev_ops.poll_hup = net_poll_hup;
    slirp_netdev_ops.free = net_free;
    slirp_netdev.ops = &slirp_netdev_ops;
    slirp_netdev.has_vnet_hdr = 0;

    struct lkl_netdev_args nargs;
    memset(&nargs, 0, sizeof(nargs));

    lkl_netdev_id = lkl_netdev_add(&slirp_netdev, &nargs);
    if (lkl_netdev_id < 0) {
        fprintf(stderr, "kbox: net: lkl_netdev_add failed: %d\n",
                lkl_netdev_id);
        goto err_thread;
    }

    fprintf(stderr, "kbox: net: device registered (id=%d)\n", lkl_netdev_id);
    return 0;

err_thread:
    __atomic_store_n(&slirp_running, 0, __ATOMIC_RELAXED);
    net_poll_hup(&slirp_netdev); /* wake rx_reader_thread */
    pthread_join(rx_reader_thread, NULL);
err_event_thread:
    __atomic_store_n(&slirp_running, 0, __ATOMIC_RELAXED);
    {
        char c = 'Q';
        ssize_t n = write(wakeup_pipe[1], &c, 1);
        (void) n;
    }
    pthread_join(slirp_thread, NULL);
err_eventfd:
    close(rx_eventfd);
    rx_eventfd = -1;
    slirp_cleanup(slirp_instance);
    slirp_instance = NULL;
err_tx_pipe:
    close(tx_pipe[0]);
    close(tx_pipe[1]);
    tx_pipe[0] = tx_pipe[1] = -1;
err_wakeup_pipe:
    close(wakeup_pipe[0]);
    close(wakeup_pipe[1]);
    wakeup_pipe[0] = wakeup_pipe[1] = -1;
err_rx_pipe:
    close(rx_pipe[0]);
    close(rx_pipe[1]);
    rx_pipe[0] = rx_pipe[1] = -1;
    return -1;
}

/* Post-boot interface configuration.
 *
 * The poll thread is gated (blocked in ops->poll) so LKL CPU is uncontested.
 * Configure the interface synchronously, then open the gate to let the poll
 * thread start normal operation.
 */
#define LKL_NR_IOCTL 29

static int configure_ipv4_iface(long sock,
                                const char *ifname,
                                const char *ip_str,
                                const char *mask_str)
{
    _Static_assert(sizeof(struct ifreq) == 40,
                   "struct ifreq must be 40 bytes (64-bit Linux ABI)");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    /* 1. Bring interface UP. */
    ifr.ifr_flags = LKL_IFF_UP | LKL_IFF_RUNNING;
    long ret = lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCSIFFLAGS, (long) &ifr,
                            0, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "kbox: net: %s SIOCSIFFLAGS: %ld\n", ifname, ret);
        return -1;
    }

    /* 2. Set IP address via SIOCSIFADDR. */
    memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &addr->sin_addr);
    ret =
        lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCSIFADDR, (long) &ifr, 0, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "kbox: net: %s SIOCSIFADDR: %ld\n", ifname, ret);
        return -1;
    }

    /* 3. Set netmask via SIOCSIFNETMASK. */
    memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, mask_str, &addr->sin_addr);
    ret = lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCSIFNETMASK, (long) &ifr, 0,
                       0, 0);
    if (ret < 0) {
        fprintf(stderr, "kbox: net: %s SIOCSIFNETMASK: %ld\n", ifname, ret);
        return -1;
    }
    return 0;
}

static int host_route_ioctl(const struct kbox_sysnrs *sysnrs,
                            unsigned long cmd,
                            const char *ifname,
                            const char *ip_str)
{
    long sock = kbox_lkl_socket(sysnrs, 2 /* AF_INET */, 2 /* SOCK_DGRAM */, 0);
    if (sock < 0)
        return (int) sock;

    char devname[16];
    snprintf(devname, sizeof(devname), "%s", ifname);

    struct rtentry rt;
    memset(&rt, 0, sizeof(rt));
    rt.rt_dst.sa_family = AF_INET;
    if (inet_pton(AF_INET, ip_str, &rt.rt_dst.sa_data[2]) != 1) {
        kbox_lkl_close(sysnrs, sock);
        return -EINVAL;
    }
    rt.rt_genmask.sa_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.255", &rt.rt_genmask.sa_data[2]);
    rt.rt_flags = 0x0005; /* RTF_UP | RTF_HOST */
    rt.rt_dev = devname;

    long ret =
        lkl_syscall6(LKL_NR_IOCTL, sock, (long) cmd, (long) &rt, 0, 0, 0);
    kbox_lkl_close(sysnrs, sock);
    return (int) ret;
}

int kbox_net_add_host_route(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str)
{
    int ret = host_route_ioctl(sysnrs, LKL_SIOCADDRT, ifname, ip_str);
    return (ret < 0 && ret != -EEXIST) ? -1 : 0;
}

int kbox_net_del_host_route(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str)
{
    int ret = host_route_ioctl(sysnrs, LKL_SIOCDELRT, ifname, ip_str);
    return (ret < 0 && ret != -ESRCH) ? -1 : 0;
}

int kbox_net_configure_ipv4(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str,
                            const char *mask_str,
                            const char *gw_str)
{
    long sock = kbox_lkl_socket(sysnrs, 2 /* AF_INET */, 2 /* SOCK_DGRAM */, 0);
    if (sock < 0) {
        fprintf(stderr, "kbox: net: ipv4 ioctl socket failed: %ld\n", sock);
        return -1;
    }

    if (configure_ipv4_iface(sock, ifname, ip_str, mask_str) < 0)
        return -1;

    if (gw_str && gw_str[0]) {
        _Static_assert(sizeof(struct rtentry) == 120,
                       "struct rtentry must be 120 bytes (kernel ABI)");
        char devname[16];
        snprintf(devname, sizeof(devname), "%s", ifname);

        if (strcmp(mask_str, "255.255.255.255") == 0) {
            struct rtentry host_rt;
            memset(&host_rt, 0, sizeof(host_rt));
            host_rt.rt_dst.sa_family = AF_INET;
            inet_pton(AF_INET, gw_str, &host_rt.rt_dst.sa_data[2]);
            host_rt.rt_genmask.sa_family = AF_INET;
            inet_pton(AF_INET, "255.255.255.255",
                      &host_rt.rt_genmask.sa_data[2]);
            host_rt.rt_flags = 0x0005; /* RTF_UP | RTF_HOST */
            host_rt.rt_dev = devname;

            long hret = lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCADDRT,
                                     (long) &host_rt, 0, 0, 0);
            if (hret < 0 && hret != -EEXIST) {
                fprintf(stderr, "kbox: net: %s host route %s SIOCADDRT: %ld\n",
                        ifname, gw_str, hret);
                return -1;
            }
        }

        struct rtentry rt;
        memset(&rt, 0, sizeof(rt));
        rt.rt_dst.sa_family = AF_INET;
        rt.rt_genmask.sa_family = AF_INET;
        rt.rt_gateway.sa_family = AF_INET;
        inet_pton(AF_INET, gw_str, &rt.rt_gateway.sa_data[2]);
        rt.rt_flags = 0x0003; /* RTF_UP | RTF_GATEWAY */
        rt.rt_dev = devname;

        long ret = lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCADDRT, (long) &rt,
                                0, 0, 0);
        if (ret < 0) {
            fprintf(stderr, "kbox: net: %s SIOCADDRT: %ld\n", ifname, ret);
            return -1;
        }
    }

    return 0;
}

int kbox_net_configure(const struct kbox_sysnrs *sysnrs)
{
    net_sysnrs = sysnrs;

    /* Write /etc/resolv.conf. */
    long fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, "/etc/resolv.conf",
                              0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
    if (fd >= 0) {
        const char *resolv = "nameserver " DNS_IP_STR "\n";
        kbox_lkl_write(sysnrs, fd, resolv, (long) strlen(resolv));
        kbox_lkl_close(sysnrs, fd);
    }

    long sock = kbox_lkl_socket(sysnrs, 2 /* AF_INET */, 2 /* SOCK_DGRAM */, 0);
    if (sock < 0) {
        fprintf(stderr, "kbox: net: helper socket failed: %ld\n", sock);
        __atomic_store_n(&net_ready, 1, __ATOMIC_RELEASE);
        return -1;
    }

    /* Bring up loopback (127.0.0.1/8) for local connections. */
    (void) configure_ipv4_iface(sock, "lo", "127.0.0.1", "255.0.0.0");

    char eth_name[16];
    snprintf(eth_name, sizeof(eth_name), "eth%d", lkl_netdev_id);
    if (configure_ipv4_iface(sock, eth_name, GUEST_IP_STR, "255.255.255.0") <
        0) {
        __atomic_store_n(&net_ready, 1, __ATOMIC_RELEASE);
        return -1;
    }

    fprintf(stderr, "kbox: net: interface up (%s/%d)\n", GUEST_IP_STR,
            GUEST_MASK);

    /* Open the gate: let the poll thread process packets (ARP). */
    __atomic_store_n(&net_ready, 1, __ATOMIC_RELEASE);

    /* 4. Set default gateway via SIOCADDRT. */
    _Static_assert(sizeof(struct rtentry) == 120,
                   "struct rtentry must be 40 bytes (kernel ABI)");
    struct rtentry rt;
    memset(&rt, 0, sizeof(rt));
    rt.rt_dst.sa_family = AF_INET;
    rt.rt_genmask.sa_family = AF_INET;
    rt.rt_gateway.sa_family = AF_INET;

    /* Gateway address at offset 2 in sockaddr_in (after sa_family). */
    inet_pton(AF_INET, GATEWAY_IP_STR, &rt.rt_gateway.sa_data[2]);
    rt.rt_flags = 0x0003; /* RTF_UP | RTF_GATEWAY */

    long ret =
        lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCADDRT, (long) &rt, 0, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "kbox: net: SIOCADDRT: %ld\n", ret);
        __atomic_store_n(&net_ready, 1, __ATOMIC_RELEASE);
        return -1;
    }

    /* Don't close socket here; close(socket) after SIOCSIFFLAGS can deadlock on
     * rtnl_lock. Leak is acceptable.
     */

    fprintf(stderr, "kbox: net: initialized (%s/%d gw %s dns %s)\n",
            GUEST_IP_STR, GUEST_MASK, GATEWAY_IP_STR, DNS_IP_STR);
    return 0;
}

void kbox_net_cleanup(void)
{
    if (!__atomic_load_n(&slirp_running, __ATOMIC_RELAXED))
        return;

    __atomic_store_n(&slirp_running, 0, __ATOMIC_RELAXED);

    /* Wake the event loop and RX reader so they exit. */
    char c = 'Q';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
    net_poll_hup(&slirp_netdev); /* wake rx_reader_thread via rx_pipe */

    pthread_join(slirp_thread, NULL);
    pthread_join(rx_reader_thread, NULL);

    /* Close all shadow sockets. */
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (shadow_sockets[i].supervisor_fd >= 0) {
            close(shadow_sockets[i].supervisor_fd);
            shadow_sockets[i].supervisor_fd = -1;
        }
        shadow_sockets[i].active = 0;
    }

    if (slirp_instance) {
        slirp_cleanup(slirp_instance);
        slirp_instance = NULL;
    }

    /* Free timers. */
    while (timer_head) {
        struct slirp_timer *t = timer_head;
        timer_head = t->next;
        free(t);
    }

    if (rx_eventfd >= 0) {
        close(rx_eventfd);
        rx_eventfd = -1;
    }

    int *pipes[] = {rx_pipe, tx_pipe, wakeup_pipe};
    for (size_t i = 0; i < sizeof(pipes) / sizeof(pipes[0]); i++) {
        if (pipes[i][0] >= 0) {
            close(pipes[i][0]);
            close(pipes[i][1]);
            pipes[i][0] = pipes[i][1] = -1;
        }
    }

    fprintf(stderr, "kbox: net: cleaned up\n");
}

int kbox_net_is_active(void)
{
    return __atomic_load_n(&slirp_running, __ATOMIC_RELAXED) != 0;
}

int kbox_net_register_socket(int lkl_fd, int supervisor_fd, int sock_type)
{
    /* Reserve a slot synchronously under the lock. This prevents the race where
     * multiple callers see the same free slot before the event loop drains the
     * command pipe.
     */
    int reserved = 0;
    pthread_mutex_lock(&shadow_lock);
    /* A closed socket does not always get deregistered -- the close path only
     * does that when the descriptor was known to be a network socket -- and LKL
     * reuses fd numbers immediately. A stale slot then answers every lookup for
     * the new connection and readiness is delivered to a socketpair nobody
     * holds, so the tracee waits forever on a reply that already arrived. The
     * newcomer owns the number now: retire the stale slot. Its supervisor_fd is
     * deliberately not closed here, because that number may already belong to
     * something else.
     */
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (shadow_sockets[i].active && shadow_sockets[i].lkl_fd == lkl_fd) {
            shadow_sockets[i].active = 0;
            shadow_sockets[i].supervisor_fd = -1;
        }
    }
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (!shadow_sockets[i].active) {
            shadow_sockets[i].lkl_fd = lkl_fd;
            shadow_sockets[i].supervisor_fd = supervisor_fd;
            shadow_sockets[i].sock_type = sock_type;
            shadow_sockets[i].listening = 0;
            shadow_sockets[i].listen_notified = 0;
            shadow_sockets[i].lkl_eof = 0;
            shadow_sockets[i].sp_eof = 0;
            shadow_sockets[i].lkl_wr_shutdown = 0;
            shadow_sockets[i].sp_wr_shutdown = 0;
            shadow_sockets[i].to_lkl_off = 0;
            shadow_sockets[i].to_lkl_len = 0;
            shadow_sockets[i].to_supervisor_off = 0;
            shadow_sockets[i].to_supervisor_len = 0;
            shadow_sockets[i].pending_dgram_addr.addrlen = 0;
            shadow_sockets[i].dgram_head = 0;
            shadow_sockets[i].dgram_tail = 0;
            shadow_sockets[i].gen = next_shadow_gen++;
            shadow_sockets[i].active = 1;
            reserved = 1;
            break;
        }
    }
    pthread_mutex_unlock(&shadow_lock);
    if (!reserved)
        return -1;

    /* Wake the event loop to include the new socket in its poll set. */

    /* Wake the event loop. */
    char c = 'R';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
    return 0;
}

static void flush_shadow_socket_to_lkl_locked(struct shadow_socket *sock)
{
    if (!sock->active || sock->listening || sock->supervisor_fd < 0 ||
        !net_sysnrs)
        return;

    for (int iter = 0; iter < 16; iter++) {
        if (sock->to_lkl_len == 0) {
            ssize_t n = read(sock->supervisor_fd, sock->to_lkl_buf,
                             sizeof(sock->to_lkl_buf));
            if (n <= 0)
                break;
            sock->to_lkl_off = 0;
            sock->to_lkl_len = (size_t) n;
        }
        if (shadow_flush_to_lkl(sock) < 0)
            break;
        if (sock->to_lkl_len > 0) {
            struct pollfd wp = {
                .fd = sock->lkl_fd,
                .events = POLLOUT,
                .revents = 0,
            };
            struct timespec wts = {0, 20 * 1000 * 1000};
            if (kbox_lkl_ppoll(net_sysnrs, &wp, 1, &wts, NULL, 0) <= 0 ||
                !(wp.revents & POLLOUT))
                break;
            if (shadow_flush_to_lkl(sock) < 0 || sock->to_lkl_len > 0)
                break;
        }
    }
}

void kbox_net_flush_socket(int lkl_fd)
{
    pthread_mutex_lock(&shadow_lock);
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (shadow_sockets[i].active && shadow_sockets[i].lkl_fd == lkl_fd) {
            flush_shadow_socket_to_lkl_locked(&shadow_sockets[i]);
            break;
        }
    }
    pthread_mutex_unlock(&shadow_lock);
}

int kbox_net_pop_dgram_addr(int lkl_fd,
                            void *addr_out,
                            unsigned int *addrlen_io,
                            int peek)
{
    int found = 0;
    pthread_mutex_lock(&shadow_lock);
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        struct shadow_socket *s = &shadow_sockets[i];
        if (!s->active || s->lkl_fd != lkl_fd)
            continue;
        if (s->dgram_head != s->dgram_tail) {
            const struct dgram_addr_entry *e = &s->dgram_q[s->dgram_head];
            if (addr_out && addrlen_io) {
                unsigned int cp =
                    e->addrlen < *addrlen_io ? e->addrlen : *addrlen_io;
                if (cp > 0)
                    memcpy(addr_out, e->addr, cp);
                *addrlen_io = e->addrlen;
            }
            if (!peek)
                s->dgram_head = (s->dgram_head + 1) % DGRAM_ADDR_QUEUE_LEN;
            found = 1;
        }
        break;
    }
    pthread_mutex_unlock(&shadow_lock);
    return found;
}

void kbox_net_deregister_socket(int lkl_fd)
{
    /* Drain any queued guest-written data into LKL before closing supervisor_fd
     * and the LKL socket (otherwise write()+close() drops the reply).
     * Close supervisor_fd and mark inactive under the lock.
     */
    pthread_mutex_lock(&shadow_lock);
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (shadow_sockets[i].active && shadow_sockets[i].lkl_fd == lkl_fd) {
            flush_shadow_socket_to_lkl_locked(&shadow_sockets[i]);
            retire_shadow_socket(&shadow_sockets[i]);
            break;
        }
    }
    pthread_mutex_unlock(&shadow_lock);

    /* Wake the event loop so it drops the closed supervisor_fd promptly. */
    char c = 'D';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
}

void kbox_net_set_listening(int lkl_fd)
{
    pthread_mutex_lock(&shadow_lock);
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (shadow_sockets[i].active && shadow_sockets[i].lkl_fd == lkl_fd) {
            shadow_sockets[i].listening = 1;
            shadow_sockets[i].listen_notified = 0;
            break;
        }
    }
    pthread_mutex_unlock(&shadow_lock);

    char c = 'L';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
}

void kbox_net_clear_listening_notify(int lkl_fd)
{
    pthread_mutex_lock(&shadow_lock);
    for (int i = 0; i < MAX_SHADOW_SOCKETS; i++) {
        if (shadow_sockets[i].active && shadow_sockets[i].lkl_fd == lkl_fd) {
            shadow_sockets[i].listen_notified = 0;
            break;
        }
    }
    pthread_mutex_unlock(&shadow_lock);

    char c = 'A';
    ssize_t n = write(wakeup_pipe[1], &c, 1);
    (void) n;
}

#else /* !KBOX_HAS_SLIRP */

#include <stdio.h>
#include "net.h"

int kbox_net_add_device(void)
{
    fprintf(stderr, "kbox: net: not compiled with SLIRP support\n");
    return -1;
}

int kbox_net_configure(const struct kbox_sysnrs *sysnrs)
{
    (void) sysnrs;
    return -1;
}

void kbox_net_cleanup(void) {}

int kbox_net_is_active(void)
{
    return 0;
}

int kbox_net_register_socket(int lkl_fd, int supervisor_fd, int sock_type)
{
    (void) lkl_fd;
    (void) supervisor_fd;
    (void) sock_type;
    return -1;
}

int kbox_net_pop_dgram_addr(int lkl_fd,
                            void *addr_out,
                            unsigned int *addrlen_io,
                            int peek)
{
    (void) lkl_fd;
    (void) addr_out;
    (void) addrlen_io;
    (void) peek;
    return 0;
}

void kbox_net_flush_socket(int lkl_fd)
{
    (void) lkl_fd;
}

void kbox_net_deregister_socket(int lkl_fd)
{
    (void) lkl_fd;
}

void kbox_net_set_listening(int lkl_fd)
{
    (void) lkl_fd;
}

void kbox_net_clear_listening_notify(int lkl_fd)
{
    (void) lkl_fd;
}

#endif /* KBOX_HAS_SLIRP */
