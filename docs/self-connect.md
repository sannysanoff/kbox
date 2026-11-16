1|# A container cannot talk to its own listener
2|
3|Inside a kbox container, connecting to a port that the *same container* is
4|listening on fails, whether the address used is `127.0.0.1` or the container's
5|own bridge IP. Connecting to another container by name or IP works.
6|
7|Evidence, all with `kbox:v62` and unmodified images:
8|
9|- `python:3-alpine` runs an HTTP server on `0.0.0.0:8099` and immediately asks
10|  it for `http://127.0.0.1:8099/` and `http://<own ip>:8099/`. Both fail, with
11|  `URLError [Errno 25] Not a tty` — a wrong errno, the same stale-errno pattern
12|  seen elsewhere in the dispatcher, so the message means less than the failure.
13|- `curlimages/curl` in one container reaches `http://auth:8088/` and
14|  `http://configmanager:8078/` in other containers without trouble.
15|
16|The consequence is not academic: the Solidus auth service answers a login by
17|verifying the password, then calling *itself* at
18|`http://auth:8088/api/v1/internal/auth/system-login` and
19|`…/get-external-auth-config`. That request never returns, so `POST
20|/api/v1/auth/login` hangs and the caller times out with no response at all.
21|Every other link in the chain is healthy — the configuration manager answers
22|the rule endpoint immediately with `401 {"message":"No auth token"}`, Kafka is
23|up, Postgres is up. Only the loop back into the same container is broken.
24|
25|## Where the loop happens
26|
27|`forward_connect()` hands the address to `kbox_lkl_connect()`, so the connect
28|is meant to run inside LKL. But a container's bridge IP is also an address the
29|*host* owns, and the daemon's own port forwarder (`port_accept_thread`) accepts
30|on the host side and then connects an LKL socket back to
31|`container_ip:container_port`. A connect whose destination is the container's
32|own address therefore has two possible paths, and the failing one is the path
33|that leaves LKL, reaches the daemon's forwarder, and is pumped straight back
34|into the same container. That round trip needs a second connection to be
35|serviced inside the same container while the first is still in flight.
36|
37|## Proposed fix
38|
39|Decide the path in `forward_connect()` from the destination: if the target is
40|the container's own address (or loopback, or any address assigned to the
41|container's own interface), make the connect entirely inside LKL and never
42|hand it to the host. The rule must be based on the destination, not on the
43|caller, because the same syscall is legitimate for both cases and the caller
44|has no way to tell them apart.
45|
46|Verification is already in place: the `python:3-alpine` self-connect probe
47|(one server, two connects — loopback and own IP) is the test to keep, and the
48|auth login endpoint is the end-to-end check.

## The second self-connection loses its reply

Reproduced with plain Python (`socketserver.ThreadingTCPServer` on `0.0.0.0`,
then three sequential connects to `127.0.0.1` from the same process):

    self 1 ok b'HTTP/1.0 200'
    self 2 FAILED TimeoutError timed out
    self 3 FAILED TimeoutError timed out

The server log shows three `GET / HTTP/1.0" 200` lines, so all three requests
were accepted and answered. The reply of the second and third never reaches the
client. The same shape shows up in a JVM: the inner call is served and logs its
last line, the outer request never returns.

Where to look: `complete_accept_result()` attaches a *shadow* socket to the
accepted connection (`attach_shadow_socket`) when the listening entry has a
shadow and the net layer is active. Shadow-backed sockets have their data
pumped between the host socketpair and LKL by the port-forward path
(`tcp_pump_*`, created in `port_accept_thread`). A connection that never left
the container has no such pump, so a reply written on the shadow side has
nowhere to go. The first connection appears to work, the rest time out.

A fix should make the accepted connection's data path unambiguous for a
self-connect: either always use the LKL socket directly for connections that
never left the container, or create the pump for them too.
