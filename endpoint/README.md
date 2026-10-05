# CMXsafe mirror-socket endpoint daemon

`cmxsafe-endpointd` is the endpoint-side address manager used by an SSH3
Mirror Socket integration. It places explicitly leased IPv6 `/128` addresses
on a daemon-owned dummy interface. It is intentionally small and Linux-only.

## Security model

The Unix peer identity (`PID`, `UID`, and `GID`) comes exclusively from
`SO_PEERCRED`; the protocol has no caller-supplied process owner field. PID reuse is
prevented from inheriting leases by also recording field 22 (`starttime`) from
`/proc/PID/stat`. The caller supplies a short hexadecimal channel `lease_id` so
concurrent channels in one process have independent references. A release
succeeds only for the same peer identity, scope, and lease ID that created it.

The daemon creates its dedicated dummy interface with `NLM_F_EXCL` and refuses
to adopt a pre-existing interface. Likewise, an address that already exists
but is not represented by a live in-memory lease is rejected rather than
claimed or deleted. It never scans or reconciles arbitrary kernel addresses.
Kernel changes precede state changes, so a failed Netlink add/delete leaves the
lease table unchanged. On a clean shutdown only addresses represented in that
table and the interface created by this process are removed.

Other hardening includes a non-world-writable socket-parent requirement,
refusal to replace any existing socket path, mode `0660`, five-second I/O timeouts,
one newline-delimited request per connection, 256-byte frames, and global and
per-peer lease limits. Access should additionally be restricted through the
socket's owning group in production.

## Protocol v1

The canonical wire form used by SSH3 is ASCII, tab-separated and newline
terminated:

```
v1<TAB>ping
v1<TAB>ensure<TAB>peer<TAB>01a2<TAB>2001:db8::10
v1<TAB>release<TAB>peer<TAB>01a2<TAB>2001:db8::10
```

`<TAB>` above denotes one literal tab byte. The current parser additionally
accepts space separators and omission of the `v1` prefix as legacy
compatibility syntax; clients should not generate those forms. Scope
is either `peer` (the remote Identity Socket address mirrored locally) or
`self`; leases in the two scopes are distinct. `lease_id` is 1–32 hexadecimal
characters. Responses are single-line JSON
objects with `"version":1` and `"ok":true|false`. An unauthorized release
returns `{"version":1,"ok":false,"error":"not_owner"}`.

## Build and test

```sh
make -C endpoint
make -C endpoint test
# Optional; requires unshare(1), ip(8), and CAP_SYS_ADMIN/CAP_NET_ADMIN:
make -C endpoint test-privileged
```

The default compiler flags include `-Wall -Wextra -Werror`. The unprivileged
test suite runs the real daemon with `--dry-run`, exercises versioned and legacy
framing, IPv6 normalization, scope isolation, idempotency, peer isolation and
input bounds. `--dry-run` is for tests only and does not configure networking.

Production execution requires root or `CAP_NET_ADMIN`, an existing secure
`/run/cmxsafe` directory, and a dedicated interface name:

```sh
install -d -o root -g cmxsafe -m 0750 /run/cmxsafe
./endpoint/cmxsafe-endpointd serve \
  --socket /run/cmxsafe/endpointd.sock --iface cmxmirror0
```

An abnormal termination can leave the socket pathname and dedicated interface
behind. The daemon will refuse to replace or adopt either; an administrator
must inspect and remove those specific objects before restarting. This
conservative failure mode avoids deleting an interface, address, or socket
owned by another component.

## Current boundary

This component manages endpoint IPv6 identity aliases. Preserving a particular
transport source port, policy routing, and Netfilter enforcement remain the
responsibility of the SSH3/CMXsafe integration and are not claimed here.
