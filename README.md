# CMXsafe SSH3 identity socket helper

This repository contains the Linux privilege-separation helper used by SSH3 to
create IPv6 TCP and UDP sockets with the identity of the authenticated CMXsafe
account. This includes outbound ephemeral sockets and inbound service sockets.

The helper is an L4 socket factory. It is **not** a policy engine and does not
read, create, enable or disable CMXsafe Security Contexts. The external
CMXsafe enforcer remains deny-by-default and decides whether packets emitted by
the returned socket may travel.

## Security contract

The authenticated UID is the only identity sent by SSH3:

```text
authenticated UID
  -> local passwd entry
  -> canonical 32-hex username
  -> canonical source IPv6
  -> bind(canonical IPv6, ephemeral or service port)
  -> connect(destination) or listen/receive
  -> SCM_RIGHTS back to SSH3
```

The request cannot supply a GID or source address. The daemon obtains the
primary GID and username with `getpwuid_r()` and accepts only a lowercase
32-hex username. For example:

```text
username: 7101f6db2b3978940000aa5500000001
IPv6:     7101:f6db:2b39:7894:0000:aa55:0000:0001
```

Before creating the network socket, the worker clears supplementary groups,
drops its real/effective/saved GID and UID, disables retained capabilities and
sets `no_new_privs`. Only then does it create an `AF_INET6` socket, bind the
canonical source address and connect to the requested destination.

The gateway is a proxy, not a router. The helper creates sockets that originate
inside the gateway namespace. It never forwards L3 packets and does not require
`NET_ADMIN`. CMXsafe's nftables `forward` hook remains an unconditional
anti-routing barrier.

## IPC protocol

SSH3 connects to `/run/ssh3-helper/helper.sock` using Unix `SOCK_SEQPACKET`.
The fixed-size, network-byte-order v1 request contains:

- magic and protocol version;
- operation (`TCP_CONNECT`, `UDP_CONNECT`, `TCP_LISTEN`, `UDP_BIND` or
  `TCP_ACCEPT`);
- random request identifier;
- authenticated UID;
- destination IPv6 and port for connections, or only the service port for a
  listener/bind request.

A service request cannot supply a bind address: those 16 request bytes must be
zero and the daemon always binds the IPv6 derived from the UID. TCP listeners
use a fixed daemon-controlled backlog and UDP service sockets are deliberately
created without `SO_REUSEPORT` or `SO_REUSEADDR`, preventing a second process
from joining the protected service port. Service ports are restricted to
`1024..65535`: the worker creates the socket only after dropping identity and
all capabilities, so privileged ports fail closed instead of weakening that
ordering.

TCP acceptance also crosses the privilege boundary. Calling `accept()` in the
root proxy would create the accepted socket under root even when the listener
belongs to the service UID. `TCP_ACCEPT` therefore carries exactly one
listener descriptor into a short-lived helper worker. The daemon verifies its
owner, family, canonical address, port, type and listening state, drops to the
service identity, and only then calls `accept4()` and returns the connected
descriptor. The Go `identityTCPListener` performs this transparently for every
accepted connection. Extra, missing, UDP, root-owned or endpoint-mismatched
descriptors are rejected.

The response repeats the version and request identifier, returns a structured
status and system errno, and includes exactly one `SCM_RIGHTS` descriptor only
on success. The Go client checks the root peer with `SO_PEERCRED`, applies a
deadline, handles `EAGAIN` through Go's runtime poller, and validates the
returned socket's family, transport, source and destination.

The daemon independently authenticates the SSH3 process with `SO_PEERCRED`.
Its root accept loop never waits for a request body: each accepted client is
handled by a bounded child with receive/send and connect deadlines. This keeps
slow or abandoned clients from blocking new sessions.

## Build

Requirements: Linux, a C++17 compiler, Go 1.21+ and GNU Make.

```bash
make
make test
```

The daemon is written in C++ and links only against the standard Linux C/C++
runtime. The Go client uses `golang.org/x/sys/unix` and is copied into the
pinned SSH3 source tree when building SSH3.

The repository does not currently declare a software license. A distributable
release remains blocked until the repository owner selects and adds one; this
implementation does not guess that legal choice.

## Install

Create the dedicated group, install the daemon and unit, then start it:

```bash
sudo groupadd --system ssh3-helper
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now cmxsafe-ssh3-helper.service
```

The systemd service creates `/run/ssh3-helper` as a private runtime directory,
runs the daemon as root with only `CAP_SETUID` and `CAP_SETGID`, restricts it to
Unix and IPv6 sockets, and applies filesystem, namespace and device hardening.
The socket is `0660 root:ssh3-helper`; the current SSH3 deployment calls it as
root and is additionally checked as UID 0 by the daemon.

## SSH3 integration

The patch is pinned and tested against:

```text
francoismichel/ssh3@5b4b242db02a5cfbb9ebf9dfc5aad2c32e10f245
```

```bash
git clone https://github.com/francoismichel/ssh3.git
cd ssh3
git checkout 5b4b242db02a5cfbb9ebf9dfc5aad2c32e10f245
git apply ../ssh3-uid-helper/ssh3-uid-helper.patch
cp ../ssh3-uid-helper/src/dial_uid.go cmd/
go test ./cmd/ssh3-server
```

Both forwarding handlers use the authenticated `unix_util.User.Uid`. TCP and
UDP are separate helper operations and therefore remain separate Security
Context transports. There is no root-owned fallback: a helper error fails the
forwarding channel closed. The same Go client exposes `listenIdentityTCP` and
`bindIdentityUDP` for gateway components that publish a protected service.

The pinned SSH3 revision implements client-initiated outbound TCP/UDP
forwarding only; it has no server-side protected-service listener to patch.
Consequently the SSH3 patch consumes the two connect operations, while gateway
service components must consume the listener/bind API when they are integrated.
Opening such a service socket directly remains outside this repository's
enforcement reach and is a deployment error.

Only IP sockets that represent a CMXsafe identity belong to this contract.
The pre-authentication SSH3 HTTPS/QUIC endpoint, Unix IPC and SSH-agent Unix
sockets are gateway infrastructure and are not per-user protected-pool
sockets. Client-side local forwarding listeners also live on the SSH3 client,
not inside the CMXsafe gateway. Within the gateway, opening a protected-pool IP
socket directly with `net.Dial*` or `net.Listen*` is a policy bypass.

## Tests

The permanent suite contains:

- Go unit tests for encoding, IPv6-only validation, delayed `SCM_RIGHTS`
  reception, peer authentication and returned-FD validation;
- static security assertions that exclude the `/tmp` endpoint, textual
  UID/GID protocol and IPv4 socket family;
- a disposable privileged-container test that creates canonical client and
  service accounts and proves real TCP/UDP connects, TCP listen, UDP bind,
  canonical IPv6 endpoints and socket UID;
- malformed request, invalid identity, slow-client and worker-saturation
  negative tests, including forged listener descriptors;
- a clean checkout test that applies the patch and compiles the pinned SSH3
  server.

Run the kernel test without changing host accounts:

```bash
docker build -t cmxsafe-ssh3-helper-test -f tests/Dockerfile .
docker run --rm --privileged cmxsafe-ssh3-helper-test
```

The same operation is available as `make test-kernel`.

Run the pinned upstream integration test:

```bash
./tests/test-ssh3-integration.sh
```

The same operation is available as `make test-ssh3`.

The historical IPv4/socket proof-of-concept programs, unauthenticated daemon
v1, textual client and host-specific test orchestrator have been removed. The
repository contains no alternative proxy socket factory that can be built or
used to bypass the helper.

## Operational failure model

- Missing helper: SSH3 rejects the forwarding channel.
- Invalid UID/account/username: the helper returns `INVALID_IDENTITY`.
- Canonical IPv6 not assigned locally: `bind()` fails; no wildcard source is
  substituted.
- Service port already owned: the helper fails closed with `EADDRINUSE`; it
  never shares the protected port.
- Missing Security Context: the socket may be created, but the external
  enforcer blocks its traffic.
- Enforcer unhealthy: gateway readiness remains failed closed; the helper does
  not attempt to repair or bypass policy.
- Dashboard unavailable: the last installed enforcer rules remain active; the
  helper has no dashboard dependency.
