# A container cannot talk to its own listener

Inside a kbox container, connecting to a port that the *same container* is
listening on fails, whether the address used is `127.0.0.1` or the container's
own bridge IP. Connecting to another container by name or IP works.

Evidence, all with `kbox:v62` and unmodified images:

- `python:3-alpine` runs an HTTP server on `0.0.0.0:8099` and immediately asks
  it for `http://127.0.0.1:8099/` and `http://<own ip>:8099/`. Both fail, with
  `URLError [Errno 25] Not a tty` — a wrong errno, the same stale-errno pattern
  seen elsewhere in the dispatcher, so the message means less than the failure.
- `curlimages/curl` in one container reaches `http://auth:8088/` and
  `http://configmanager:8078/` in other containers without trouble.

The consequence is not academic: the Solidus auth service answers a login by
verifying the password, then calling *itself* at
`http://auth:8088/api/v1/internal/auth/system-login` and
`…/get-external-auth-config`. That request never returns, so `POST
/api/v1/auth/login` hangs and the caller times out with no response at all.
Every other link in the chain is healthy — the configuration manager answers
the rule endpoint immediately with `401 {"message":"No auth token"}`, Kafka is
up, Postgres is up. Only the loop back into the same container is broken.

## Where the loop happens

`forward_connect()` hands the address to `kbox_lkl_connect()`, so the connect
is meant to run inside LKL. But a container's bridge IP is also an address the
*host* owns, and the daemon's own port forwarder (`port_accept_thread`) accepts
on the host side and then connects an LKL socket back to
`container_ip:container_port`. A connect whose destination is the container's
own address therefore has two possible paths, and the failing one is the path
that leaves LKL, reaches the daemon's forwarder, and is pumped straight back
into the same container. That round trip needs a second connection to be
serviced inside the same container while the first is still in flight.

## Proposed fix

Decide the path in `forward_connect()` from the destination: if the target is
the container's own address (or loopback, or any address assigned to the
container's own interface), make the connect entirely inside LKL and never
hand it to the host. The rule must be based on the destination, not on the
caller, because the same syscall is legitimate for both cases and the caller
has no way to tell them apart.

Verification is already in place: the `python:3-alpine` self-connect probe
(one server, two connects — loopback and own IP) is the test to keep, and the
auth login endpoint is the end-to-end check.
