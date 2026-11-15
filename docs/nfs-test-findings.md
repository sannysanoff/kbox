# NFS volume test findings

Measured against ganesha 15.2 (NFSv4.2, port 20490, loopback ext4 export) from
an unprivileged kbox pod, with every result read back on the export itself.
The pod runs with all capabilities dropped, as an unprivileged uid, under the
runtime's default seccomp profile.

## What holds up

A single 64 MB write with `fsync` completes at ~63 MB/s and verifies
byte-identical both inside the guest and on the export. Rename, hard link
(`nlink=2`, same inode), symlink plus readlink, `chmod`, `chown` and `unlink`
behave correctly over NFS. `flock(2)` excludes a second container and releases
cleanly. `fcntl(F_SETLK)` works on a local file. Short append sequences are
correct on NFS: three appends land as AAA, BBB, CCC.

Platform behaviour also survives. Twenty start/stop cycles binding the same
destination all succeeded, with all twenty files on the export and kboxd RSS
growing 201 to 219 MB. Eight containers reading 128 MB each pushed RSS from 219
to 308 MB with no crash and no restart. A server process restart in place keeps
the mount alive: files written after the kill are on the export, and files from
before it still read back.

## What does not hold

**`fcntl(F_SETLK)` on an NFS file kills the daemon.** kboxd dies with SIGSEGV
(exit 139) immediately after `kbox: writable shadow promote ... path=/data/...`
followed by the `fcntl` syscall. Reproducible with one container, no
concurrency. The same call on a local file is fine and `flock` over NFS is
fine, so the fault sits at the join of kbox's writable shadow-fd handling and
the NFS lock path.

**Concurrent writers crash it and lose data.** Four containers writing four
8 MB files into one subdirectory: none of the files reached the export, and
kboxd came back with SIGSEGV.

**Many small appends lose data.** Two thousand appends from one container left
roughly half the bytes on the export, with a run of NUL bytes at the head, and
the daemon restarted underneath. Short sequences are correct, so the loss needs
volume rather than a particular call.

**Every guest runs as uid 0.** `docker run --user 4321:8765` is accepted and
ignored: the shim reports `"User": ""` and hands no identity to the daemon, so
all NFS traffic carries AUTH_SYS uid 0. `chown` to an arbitrary uid does land
on the server, but file creation cannot be attributed to a tenant.

**`O_DIRECT` on NFS returns EFAULT.** The same probe against a host bind
produced no output at all, so the failure sits in the guest-memory path rather
than in NFS.

## A host-bind bug that is not about NFS

Two sequential writes to a **host-bound** path — `printf A > f` then
`printf B >> f` — leave only `B` on the box's own filesystem: the append
overwrites from offset 0. The same two writes on NFS and inside the guest
rootfs are correct. This affects every `-v /host:/dst` volume, not only NFS,
and it silently corrupts logs and append-only files.

## No recovery when the server loses its data

Replacing the ganesha pod — a new `emptyDir`, so new file handles — leaves
kboxd holding the old mount: every container that asks for that volume fails
with `bind ... failed: Stale file handle`, indefinitely. The mount retry loop
only runs at daemon startup, so there is no reconnect and no remount; recovery
there means restarting kboxd.

## Not reached

`timeo`/`retrans` behaviour with injected latency or loss, and the `soft`
versus `hard` distinction, were not measured: they need a proxy in front of the
server to inject delay and drops. Lease renewal beyond a single in-place
restart is likewise unmeasured.
