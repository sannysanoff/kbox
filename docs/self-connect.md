1|1|1|1|1|# A container cannot talk to its own listener
2|2|2|2|2|
3|3|3|3|3|Inside a kbox container, connecting to a port that the *same container* is
4|4|4|4|4|listening on fails, whether the address used is `127.0.0.1` or the container's
5|5|5|5|5|own bridge IP. Connecting to another container by name or IP works.
6|6|6|6|6|
7|7|7|7|7|Evidence, all with `kbox:v62` and unmodified images:
8|8|8|8|8|
9|9|9|9|9|- `python:3-alpine` runs an HTTP server on `0.0.0.0:8099` and immediately asks
10|10|10|10|10|  it for `http://127.0.0.1:8099/` and `http://<own ip>:8099/`. Both fail, with
11|11|11|11|11|  `URLError [Errno 25] Not a tty` — a wrong errno, the same stale-errno pattern
12|12|12|12|12|  seen elsewhere in the dispatcher, so the message means less than the failure.
13|13|13|13|13|- `curlimages/curl` in one container reaches `http://auth:8088/` and
14|14|14|14|14|  `http://configmanager:8078/` in other containers without trouble.
15|15|15|15|15|
16|16|16|16|16|The consequence is not academic: the Solidus auth service answers a login by
17|17|17|17|17|verifying the password, then calling *itself* at
18|18|18|18|18|`http://auth:8088/api/v1/internal/auth/system-login` and
19|19|19|19|19|`…/get-external-auth-config`. That request never returns, so `POST
20|20|20|20|20|/api/v1/auth/login` hangs and the caller times out with no response at all.
21|21|21|21|21|Every other link in the chain is healthy — the configuration manager answers
22|22|22|22|22|the rule endpoint immediately with `401 {"message":"No auth token"}`, Kafka is
23|23|23|23|23|up, Postgres is up. Only the loop back into the same container is broken.
24|24|24|24|24|
25|25|25|25|25|## Where the loop happens
26|26|26|26|26|
27|27|27|27|27|`forward_connect()` hands the address to `kbox_lkl_connect()`, so the connect
28|28|28|28|28|is meant to run inside LKL. But a container's bridge IP is also an address the
29|29|29|29|29|*host* owns, and the daemon's own port forwarder (`port_accept_thread`) accepts
30|30|30|30|30|on the host side and then connects an LKL socket back to
31|31|31|31|31|`container_ip:container_port`. A connect whose destination is the container's
32|32|32|32|32|own address therefore has two possible paths, and the failing one is the path
33|33|33|33|33|that leaves LKL, reaches the daemon's forwarder, and is pumped straight back
34|34|34|34|34|into the same container. That round trip needs a second connection to be
35|35|35|35|35|serviced inside the same container while the first is still in flight.
36|36|36|36|36|
37|37|37|37|37|## Proposed fix
38|38|38|38|38|
39|39|39|39|39|Decide the path in `forward_connect()` from the destination: if the target is
40|40|40|40|40|the container's own address (or loopback, or any address assigned to the
41|41|41|41|41|container's own interface), make the connect entirely inside LKL and never
42|42|42|42|42|hand it to the host. The rule must be based on the destination, not on the
43|43|43|43|43|caller, because the same syscall is legitimate for both cases and the caller
44|44|44|44|44|has no way to tell them apart.
45|45|45|45|45|
46|46|46|46|46|Verification is already in place: the `python:3-alpine` self-connect probe
47|47|47|47|47|(one server, two connects — loopback and own IP) is the test to keep, and the
48|48|48|48|48|auth login endpoint is the end-to-end check.
49|49|49|49|
50|50|50|50|## The second self-connection loses its reply
51|51|51|51|
52|52|52|52|Reproduced with plain Python (`socketserver.ThreadingTCPServer` on `0.0.0.0`,
53|53|53|53|then three sequential connects to `127.0.0.1` from the same process):
54|54|54|54|
55|55|55|55|    self 1 ok b'HTTP/1.0 200'
56|56|56|56|    self 2 FAILED TimeoutError timed out
57|57|57|57|    self 3 FAILED TimeoutError timed out
58|58|58|58|
59|59|59|59|The server log shows three `GET / HTTP/1.0" 200` lines, so all three requests
60|60|60|60|were accepted and answered. The reply of the second and third never reaches the
61|61|61|61|client. The same shape shows up in a JVM: the inner call is served and logs its
62|62|62|62|last line, the outer request never returns.
63|63|63|63|
64|64|64|64|Where to look: `complete_accept_result()` attaches a *shadow* socket to the
65|65|65|65|accepted connection (`attach_shadow_socket`) when the listening entry has a
66|66|66|66|shadow and the net layer is active. Shadow-backed sockets have their data
67|67|67|67|pumped between the host socketpair and LKL by the port-forward path
68|68|68|68|(`tcp_pump_*`, created in `port_accept_thread`). A connection that never left
69|69|69|69|the container has no such pump, so a reply written on the shadow side has
70|70|70|70|nowhere to go. The first connection appears to work, the rest time out.
71|71|71|71|
72|72|72|72|A fix should make the accepted connection's data path unambiguous for a
73|73|73|73|self-connect: either always use the LKL socket directly for connections that
74|74|74|74|never left the container, or create the pump for them too.
75|75|75|
76|76|76|### Update: the stale slot
77|77|77|
78|78|78|`kbox_net_register_socket()` looks slots up by `lkl_fd` number, and the close
79|79|79|path only deregisters a descriptor it knows to be a network socket. LKL reuses
80|80|80|fd numbers immediately, so a stale slot kept answering for the *new*
81|81|81|connection and readiness went to a socketpair nobody held. Retiring any active
82|82|82|slot that still carries the same `lkl_fd` before reserving a new one changed
83|83|83|the probe from one success in three to three in four (the one that still fails
84|84|84|is the first request after the server starts).
85|85|
86|86|### Measured on the current image
87|87|
88|88|A probe that opens ten sequential self-connections in one process scored
89|89|**1/10**, and every attempt from the sixth onwards timed out -- so the failure
90|90|is not random noise but a state the daemon settles into. `MAX_SHADOW_SOCKETS` is
91|91|512, so running out of slots is not the cause.
92|92|
93|93|The listening socket's readiness is re-armed in the net layer's event loop
94|94|(`net-slirp.c`, the `sock->listening` branch): when `listen_notified` is clear
95|95|and LKL reports `POLLIN`, one byte is written to the shadow and the flag is
96|96|set; `complete_accept_result` drains that byte and calls
97|97|`kbox_net_clear_listening_notify`. Two things to check next, in this order:
98|98|
99|99|1. Whether the flag is actually cleared on every accept, or whether an accept
100|100|   that returns early (no shadow, `addr_ptr` error) leaves it set forever.
101|101|2. Whether the slot keeps its place in the poll set. The loop walks
102|102|   `shadow_base + si` and skips inactive slots; a slot that is retired and
103|103|   re-registered while the loop holds stale indices would stop waking the
104|104|   listener, which fits "works once, then never again".
105|105|
106|106|The probe is the acceptance criterion: ten out of ten, not one good login.
107|
108|Checked and ruled out: a deferred accept is not leaking. `defer_pending_accept`
109|fills `pending_accepts[]` (`KBOX_PENDING_ACCEPTS_MAX` is 64) and
110|`kbox_dispatch_poll_pending` does retire entries, keeping
111|`pending_accept_count` in step, so a full queue is not what stops the sixth
112|connection. What is left is the `listen_notified` re-arm and the poll-set slot
113|bookkeeping described above.

### Distribution, not a single number

Three runs of ten self-connections on the same image: 7/10, 10/10, 8/10 -- about
83% overall. With `KBOX_NET_TRACE` set on the daemon, the net layer's event loop
logs the listening socket on nearly every iteration as `notified=0 pr=0
revents=0`, i.e. the loop is awake and checking, and LKL simply reports nothing
pending at those moments. The loop's own poll timeout is capped at 100 ms and
the supervisor polls deferred accepts every 5 ms while any are outstanding
(`seccomp-supervisor.c`), so "the daemon was asleep" is not the explanation.

That leaves the failure being a *lost* wakeup rather than a late one: the
connection sits in LKL's accept queue, the guest's waiting accept never
completes, and the client's `recv` times out after six seconds. Instrumentation
is in place (`KBOX_NET_TRACE=1` on the kboxd container); the next step is to log
the deferred-accept queue alongside it, so a failing connection shows whether
the accept was ever queued.
