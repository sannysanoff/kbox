# NFS-backed volumes

A service can mount a subtree of an NFS export. The export is declared once in
the daemon config, and services refer to it by a hard-coded scheme name that
carries the handle:

```yaml
# ~/.config/kbox-config.yaml
mounts:
  "nfs:/mounted_here":
    source: 10.0.0.7:/export/data
    options: vers=4.2,proto=tcp,port=20490
```

```bash
docker run -v "nfs:/mounted_here/subdir:/destination" alpine:latest \
  sh -c 'echo hello > /destination/probe.txt'
```

The daemon mounts the export once, retrying with a warning until it succeeds,
and binds the requested subtree into each container's own mount namespace.
Missing subdirectories are created on the export. The export root itself is
never reachable from a container.

## Why the daemon mounts, not the guest

Guest processes in LKL run with no capabilities (`CapEff` is zero by
construction), so a guest `mount(2)` of any filesystem is refused with `EPERM`.
The daemon runs with the kernel's initial credentials, so the mount happens
there and containers only ever see a bind mount of the subtree they asked for.
The same is true at the cluster level: kbox in a Kubernetes pod needs no
capabilities, because every namespace and every mount lives inside the
in-process kernel.

## The addr= detail

`mount(2)` with a raw option string does not resolve the server name — unlike
`mount.nfs`, which always appends `addr=`. Without it the kernel rejects the
mount with `EINVAL`, so kbox derives it from the `source` field and resolves
hostnames on the host, where the daemon's sockets actually leave the pod. That
is what lets `source: ganesha.nfs-test.svc.cluster.local:/` work even though
LKL has no resolver of its own.

## What the server has to be

NFSv4.2 on a single TCP port, which can be above 1024 so the server needs no
privileges either. The export must live on a filesystem that supports file
handles: ganesha's `FSAL_VFS` resolves them with `name_to_handle_at` and
`open_by_handle_at`, and overlayfs or a btrfs subvolume answers `EOPNOTSUPP`,
which the client sees as `EIO` on readdir. A loopback ext4 image is the
portable answer in a container.

## Limits worth knowing

`docker compose` cannot carry this syntax: compose parses volume specs itself,
splits on `:`, and its schema rejects volume names containing `:` or `/`, so
`nfs:/mounted_here/subdir` never reaches the daemon. The same is true of the
`:ro` suffix in `docker run -v`, which the Docker CLI rejects as "too many
colons" before the request is sent. Read-only mounts are accepted by the daemon
(in the `Mounts` form of the API) and by the bind layer, but not expressible
through those two client-side parsers.
