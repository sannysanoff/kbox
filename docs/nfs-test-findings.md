# NFS volume test findings

Tested against ganesha 15.2 (NFSv4.2, port 20490, loopback ext4 export) from an
unprivileged kbox pod, reading every result back on the server side.

## What holds up

A single 64 MB write with `fsync` completes at ~63 MB/s and reads back
byte-identical, both inside the guest and on the export. Rename, hard link
(`nlink=2`, same inode), symlink plus readlink, `chmod`, `chown` and `unlink`
all behave correctly over NFS. `flock(2)` excludes a second container as it
should. `fcntl(F_SETLK)` on a local file works. Containers start, bind their
subtree and exit cleanly.

## What does not

**`fcntl(F_SETLK)` on an NFS file kills the daemon.** kboxd dies with SIGSEGV
(exit 139) immediately after `kbox: writable shadow promote ... path=/data/...`
followed by the `fcntl` syscall. Reproducible in one container, no concurrency
needed. On a local (non-NFS) file the same binary and the same call are fine,
and `flock` over NFS is fine, so the fault sits at the intersection of kbox's
writable-shadow-fd handling and the NFS lock path — not in LKL's NFS client as
such.

**Concurrent writers crash it and lose data.** Four containers writing four
8 MB files into one subdirectory: none of the files appeared on the export and
kboxd came back with SIGSEGV. Sequential appends are not safe either, without
any concurrency: 2000 small `>>` writes from one container left roughly half
the bytes on the export, with a dozen NUL bytes at the start of the file, and
the daemon restarted underneath.

**Every guest runs as uid 0.** `docker run --user 4321:8765` is accepted and
then ignored: the shim reports `"User": ""` and never passes an identity to the
daemon, so all NFS traffic carries AUTH_SYS uid 0. `chown` to an arbitrary uid
does land on the server, but file creation cannot be attributed to a tenant.

**`O_DIRECT` on NFS returns EFAULT**, and the same probe on a host bind
produced no output at all, so the failure is in the guest-memory path rather
than in NFS.

## Not reached

Ganesha restart with a non-graceless export, lease renewal, `timeo`/`retrans`
behaviour under injected latency or loss, and repeated mount/umount cycles were
not measured. Under the workloads above the daemon dies first, so those tests
would report the crash instead of the NFS behaviour they are meant to measure.
They are worth running once the crash and the small-write corruption are fixed.
