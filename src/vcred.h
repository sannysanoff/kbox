/* SPDX-License-Identifier: MIT */
#ifndef KBOX_VCRED_H
#define KBOX_VCRED_H

/* Per-process virtual credentials and a file-ownership overlay.
 *
 * kbox runs unprivileged, so the host kernel cannot change a process's uid or
 * a file's owner. Official images do both: their entrypoints chown a data
 * directory and then drop privileges (gosu, su-exec, setpriv, clickhouse su),
 * and the server refuses to start as root or when the directory owner differs
 * from its euid. The guest therefore gets a virtual identity that follows the
 * setuid family's real semantics, and chown records the wanted owner in an
 * overlay that stat reports back.
 */

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

struct kbox_vcred {
    uint32_t ruid, euid, suid;
    uint32_t rgid, egid, sgid;
    /* Set once the process held euid 0. Group-id changes stay permitted
     * afterwards: setpriv and libcap-based droppers change the uid first and
     * rely on capabilities kept across setresuid(), which kbox does not model.
     */
    int had_root;
};

/* True when pid may change group ids / supplementary groups. */
int kbox_vcred_may_setgid(pid_t pid);

/* Copy of pid's credentials. A pid never seen before inherits from its parent
 * (as fork would) and falls back to root. */
void kbox_vcred_get(pid_t pid, struct kbox_vcred *out);

/* setuid family. Arguments of -1 mean "leave unchanged". Return 0 or -errno
 * with Linux semantics: euid 0 may set anything, others only values already in
 * {real, effective, saved}. The gid variants follow the same rule keyed on
 * euid == 0 (stand-in for CAP_SETGID). */
int kbox_vcred_setresuid(pid_t pid, int64_t r, int64_t e, int64_t s);
int kbox_vcred_setresgid(pid_t pid, int64_t r, int64_t e, int64_t s);
int kbox_vcred_setuid(pid_t pid, int64_t u);
int kbox_vcred_setgid(pid_t pid, int64_t g);
int kbox_vcred_setreuid(pid_t pid, int64_t r, int64_t e);
int kbox_vcred_setregid(pid_t pid, int64_t r, int64_t e);

/* Drop a pid's record (called when it execs nothing special; kept for tests).
 */
void kbox_vcred_forget(pid_t pid);

/* Ownership overlay keyed by (device, inode). uid/gid of -1 keep the current
 * value. */
void kbox_owner_set(dev_t dev, ino_t ino, int64_t uid, int64_t gid);

/* Rewrite st_uid/st_gid of a host stat result so the guest sees the virtual
 * identity: an overlay entry wins; otherwise a file owned by the supervisor's
 * real uid/gid appears owned by pid's effective ids. */
void kbox_owner_apply(pid_t pid, struct stat *st);

/* Test hook: forget everything. */
void kbox_vcred_reset_for_test(void);

#endif
