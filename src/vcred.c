/* SPDX-License-Identifier: MIT */

#include "vcred.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define VC_MAX 4096
#define OWN_MAX 8192

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static struct {
    pid_t pid;
    struct kbox_vcred c;
} g_vc[VC_MAX];
static int g_vc_n;

static struct {
    dev_t dev;
    ino_t ino;
    uint32_t uid, gid;
    int used;
} g_own[OWN_MAX];

static pid_t parent_of(pid_t pid)
{
    char path[48], buf[512];
    FILE *f;
    size_t n;
    char *p;
    long ppid;

    snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    p = strrchr(buf, ')');
    if (!p || p[1] != ' ')
        return 0;
    /* fields after ')': state ppid ... */
    if (sscanf(p + 2, "%*c %ld", &ppid) != 1)
        return 0;
    return (pid_t) ppid;
}

static int find_locked(pid_t pid)
{
    for (int i = 0; i < g_vc_n; i++)
        if (g_vc[i].pid == pid)
            return i;
    return -1;
}

/* Index of pid's record, creating it from the nearest known ancestor. */
static int ensure_locked(pid_t pid)
{
    struct kbox_vcred c;
    pid_t cur = pid;
    int idx = find_locked(pid);

    if (idx >= 0)
        return idx;
    memset(&c, 0, sizeof(c)); /* root unless an ancestor says otherwise */
    c.had_root = 1;
    for (int depth = 0; depth < 16 && cur > 1; depth++) {
        pid_t pp = parent_of(cur);
        if (pp <= 1)
            break;
        int pi = find_locked(pp);
        if (pi >= 0) {
            c = g_vc[pi].c;
            break;
        }
        cur = pp;
    }
    if (g_vc_n == VC_MAX) {
        /* Full: recycle the oldest slot. */
        memmove(&g_vc[0], &g_vc[1], sizeof(g_vc[0]) * (VC_MAX - 1));
        g_vc_n--;
    }
    g_vc[g_vc_n].pid = pid;
    g_vc[g_vc_n].c = c;
    return g_vc_n++;
}

void kbox_vcred_get(pid_t pid, struct kbox_vcred *out)
{
    pthread_mutex_lock(&g_lock);
    *out = g_vc[ensure_locked(pid)].c;
    pthread_mutex_unlock(&g_lock);
}

static int in_set(uint32_t v, uint32_t a, uint32_t b, uint32_t c)
{
    return v == a || v == b || v == c;
}

int kbox_vcred_setresuid(pid_t pid, int64_t r, int64_t e, int64_t s)
{
    int rc = 0;
    pthread_mutex_lock(&g_lock);
    struct kbox_vcred *c = &g_vc[ensure_locked(pid)].c;
    if (c->euid != 0) {
        if ((r != -1 && !in_set((uint32_t) r, c->ruid, c->euid, c->suid)) ||
            (e != -1 && !in_set((uint32_t) e, c->ruid, c->euid, c->suid)) ||
            (s != -1 && !in_set((uint32_t) s, c->ruid, c->euid, c->suid)))
            rc = -1;
    }
    if (rc == 0) {
        if (r != -1)
            c->ruid = (uint32_t) r;
        if (e != -1)
            c->euid = (uint32_t) e;
        if (s != -1)
            c->suid = (uint32_t) s;
    }
    pthread_mutex_unlock(&g_lock);
    return rc ? -EPERM : 0;
}

int kbox_vcred_setresgid(pid_t pid, int64_t r, int64_t e, int64_t s)
{
    int rc = 0;
    pthread_mutex_lock(&g_lock);
    struct kbox_vcred *c = &g_vc[ensure_locked(pid)].c;
    if (c->euid != 0 && !c->had_root) {
        if ((r != -1 && !in_set((uint32_t) r, c->rgid, c->egid, c->sgid)) ||
            (e != -1 && !in_set((uint32_t) e, c->rgid, c->egid, c->sgid)) ||
            (s != -1 && !in_set((uint32_t) s, c->rgid, c->egid, c->sgid)))
            rc = -1;
    }
    if (rc == 0) {
        if (r != -1)
            c->rgid = (uint32_t) r;
        if (e != -1)
            c->egid = (uint32_t) e;
        if (s != -1)
            c->sgid = (uint32_t) s;
    }
    pthread_mutex_unlock(&g_lock);
    return rc ? -EPERM : 0;
}

int kbox_vcred_setuid(pid_t pid, int64_t u)
{
    struct kbox_vcred c;
    kbox_vcred_get(pid, &c);
    if (c.euid == 0)
        return kbox_vcred_setresuid(pid, u, u, u); /* all three ids */
    return kbox_vcred_setresuid(pid, -1, u, -1);   /* euid only */
}

int kbox_vcred_setgid(pid_t pid, int64_t g)
{
    struct kbox_vcred c;
    kbox_vcred_get(pid, &c);
    if (c.euid == 0 || c.had_root)
        return kbox_vcred_setresgid(pid, g, g, g);
    return kbox_vcred_setresgid(pid, -1, g, -1);
}

int kbox_vcred_setreuid(pid_t pid, int64_t r, int64_t e)
{
    struct kbox_vcred c;
    int64_t s = -1;
    kbox_vcred_get(pid, &c);
    /* Linux: saved id follows the new effective id when the real id is set
     * or the effective id differs from the old real id. */
    if (r != -1 || (e != -1 && (uint32_t) e != c.ruid))
        s = (e != -1) ? e : (int64_t) c.euid;
    if (c.euid != 0) {
        /* ruid may become ruid or euid; euid may become ruid, euid or suid. */
        if (r != -1 && !in_set((uint32_t) r, c.ruid, c.euid, c.euid))
            return -EPERM;
    }
    return kbox_vcred_setresuid(pid, r, e, s);
}

int kbox_vcred_setregid(pid_t pid, int64_t r, int64_t e)
{
    struct kbox_vcred c;
    int64_t s = -1;
    kbox_vcred_get(pid, &c);
    if (r != -1 || (e != -1 && (uint32_t) e != c.rgid))
        s = (e != -1) ? e : (int64_t) c.egid;
    if (c.euid != 0 && !c.had_root) {
        if (r != -1 && !in_set((uint32_t) r, c.rgid, c.egid, c.egid))
            return -EPERM;
    }
    return kbox_vcred_setresgid(pid, r, e, s);
}

int kbox_vcred_may_setgid(pid_t pid)
{
    struct kbox_vcred c;
    kbox_vcred_get(pid, &c);
    return c.euid == 0 || c.had_root;
}

void kbox_vcred_forget(pid_t pid)
{
    pthread_mutex_lock(&g_lock);
    int i = find_locked(pid);
    if (i >= 0) {
        memmove(&g_vc[i], &g_vc[i + 1], sizeof(g_vc[0]) * (g_vc_n - i - 1));
        g_vc_n--;
    }
    pthread_mutex_unlock(&g_lock);
}

void kbox_owner_set(dev_t dev, ino_t ino, int64_t uid, int64_t gid)
{
    int free_slot = -1;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < OWN_MAX; i++) {
        if (g_own[i].used && g_own[i].dev == dev && g_own[i].ino == ino) {
            if (uid != -1)
                g_own[i].uid = (uint32_t) uid;
            if (gid != -1)
                g_own[i].gid = (uint32_t) gid;
            pthread_mutex_unlock(&g_lock);
            return;
        }
        if (!g_own[i].used && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        free_slot = (int) (ino % OWN_MAX); /* table full: overwrite */
    g_own[free_slot].used = 1;
    g_own[free_slot].dev = dev;
    g_own[free_slot].ino = ino;
    g_own[free_slot].uid = uid == -1 ? 0 : (uint32_t) uid;
    g_own[free_slot].gid = gid == -1 ? 0 : (uint32_t) gid;
    pthread_mutex_unlock(&g_lock);
}

void kbox_owner_apply(pid_t pid, struct stat *st)
{
    struct kbox_vcred c;
    int found = 0;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < OWN_MAX; i++) {
        if (g_own[i].used && g_own[i].dev == st->st_dev &&
            g_own[i].ino == st->st_ino) {
            st->st_uid = g_own[i].uid;
            st->st_gid = g_own[i].gid;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (found)
        return;
    kbox_vcred_get(pid, &c);
    if (st->st_uid == getuid())
        st->st_uid = c.euid;
    if (st->st_gid == getgid())
        st->st_gid = c.egid;
}

void kbox_vcred_reset_for_test(void)
{
    pthread_mutex_lock(&g_lock);
    g_vc_n = 0;
    memset(g_own, 0, sizeof(g_own));
    pthread_mutex_unlock(&g_lock);
}
