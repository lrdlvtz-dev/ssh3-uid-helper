#!/bin/sh
set -eu

helper=/work/helper/build/cmxsafe-ssh3-helper
endpointd=/work/helper/endpoint/cmxsafe-endpointd
probe=/work/helper/tests/mirror_net.py
tmp=$(mktemp -d)
pids=""
namespaces="cmx-gw cmx-ep cmx-peer"
identity=20010db8020000000000000000000010
identity_ip=2001:db8:200::10
identity_uid=45678
gw_ip=2001:db8:100::10
endpoint_ip=2001:db8:100::20
peer_link_ip=2001:db8:100::30
peer_ip=2001:db8:300::30
udp_peer_ip=2001:db8:300::31

cleanup() {
    for pid in $pids; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    for ns in $namespaces; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del cmx-br0 2>/dev/null || true
    userdel "$identity" 2>/dev/null || true
    groupdel "$identity" 2>/dev/null || true
    rm -rf "$tmp" /run/cmxsafe-e2e /run/ssh3-helper
}
trap cleanup EXIT INT TERM

fail() {
    echo "mirror E2E: $*" >&2
    for log in "$tmp"/*.log "$tmp"/*.stdout; do
        test -f "$log" || continue
        echo "--- $(basename "$log") ---" >&2
        tail -40 "$log" >&2
    done
    exit 1
}
wait_file() {
    file=$1
    for _ in $(seq 1 100); do test -e "$file" && return 0; sleep 0.1; done
    fail "timed out waiting for $file"
}
wait_lines() {
    file=$1 expected=$2
    for _ in $(seq 1 100); do
        count=$(wc -l < "$file" 2>/dev/null || echo 0)
        test "$count" -ge "$expected" && return 0
        sleep 0.1
    done
    fail "timed out waiting for $expected records in $file"
}
wait_port() {
    ns=$1 needle=$2
    for _ in $(seq 1 100); do
        ip netns exec "$ns" ss -lnt | grep -F "$needle" >/dev/null && return 0
        sleep 0.1
    done
    fail "timed out waiting for listener $needle in $ns"
}
wait_udp_port() {
    ns=$1 needle=$2
    for _ in $(seq 1 100); do
        ip netns exec "$ns" ss -lnu | grep -F "$needle" >/dev/null && return 0
        sleep 0.1
    done
    fail "timed out waiting for UDP socket $needle in $ns"
}
assert_records() {
    python3 - "$1" "$2" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
expected = json.loads(sys.argv[2])
actual = sorted((row["peer_ip"], row["peer_port"], row["payload"]) for row in rows)
want = sorted(tuple(row) for row in expected)
if actual != want:
    raise SystemExit(f"records differ: actual={actual!r} expected={want!r}")
PY
}

test "$(id -u)" -eq 0
test -x "$helper" && test -x "$endpointd"
mkdir -p /run/cmxsafe-e2e
chmod 0700 /run/cmxsafe-e2e
mkdir -p /run/ssh3-helper
chmod 0750 /run/ssh3-helper

ip link add cmx-br0 type bridge
ip link set cmx-br0 up
index=10
for ns in $namespaces; do
    ip netns add "$ns"
    ip link add "veth-$index" type veth peer name eth0 netns "$ns"
    ip link set "veth-$index" master cmx-br0
    ip link set "veth-$index" up
    ip -n "$ns" link set lo up
    ip -n "$ns" link set eth0 up
    ip -n "$ns" addr add "2001:db8:100::$index/64" dev eth0 nodad
    index=$((index + 10))
done
ip -n cmx-gw addr add "$identity_ip/128" dev lo nodad
ip -n cmx-peer addr add "$peer_ip/128" dev lo nodad
ip -n cmx-peer addr add "$udp_peer_ip/128" dev lo nodad
ip -n cmx-ep route add "$identity_ip/128" via "$gw_ip"
ip -n cmx-peer route add "$identity_ip/128" via "$gw_ip"
ip -n cmx-gw route add "$peer_ip/128" via "$peer_link_ip"
ip -n cmx-gw route add "$udp_peer_ip/128" via "$peer_link_ip"
ip netns exec cmx-gw sysctl -q -w net.ipv6.conf.all.forwarding=1

groupadd -g "$identity_uid" "$identity"
useradd -m -u "$identity_uid" -g "$identity_uid" -s /bin/sh "$identity"
install -d -m 0700 -o "$identity_uid" -g "$identity_uid" "/home/$identity/.ssh3"
ssh-keygen -q -t ed25519 -N '' -f "$tmp/key"
install -m 0600 -o "$identity_uid" -g "$identity_uid" "$tmp/key.pub" \
    "/home/$identity/.ssh3/authorized_identities"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=cmxsafe-e2e' \
    -addext "subjectAltName=IP:$gw_ip" -keyout "$tmp/tls.key" -out "$tmp/tls.crt" \
    >/dev/null 2>&1

ip netns exec cmx-gw "$helper" --socket /run/ssh3-helper/helper.sock \
    --socket-group "$identity" --allowed-uid 0 >"$tmp/helper.log" 2>&1 &
helper_pid=$!; pids="$pids $helper_pid"
wait_file /run/ssh3-helper/helper.sock
ip netns exec cmx-ep "$endpointd" serve --socket /run/cmxsafe-e2e/endpointd.sock \
    --iface cmxmirror0 >"$tmp/endpointd.log" 2>&1 &
endpointd_pid=$!; pids="$pids $endpointd_pid"
wait_file /run/cmxsafe-e2e/endpointd.sock

: >"$tmp/direct.records"
: >"$tmp/reverse.records"
: >"$tmp/direct-udp.records"
: >"$tmp/reverse-udp.records"
ip netns exec cmx-ep python3 "$probe" serve --bind "$endpoint_ip@18443" \
    --records "$tmp/direct.records" >"$tmp/direct-service.log" 2>&1 &
pids="$pids $!"
ip netns exec cmx-ep python3 "$probe" serve --bind "$endpoint_ip@29090" \
    --records "$tmp/reverse.records" --delay 1.5 >"$tmp/reverse-service.log" 2>&1 &
pids="$pids $!"
ip netns exec cmx-ep python3 "$probe" udp-serve --bind "$endpoint_ip@18444" \
    --records "$tmp/direct-udp.records" >"$tmp/direct-udp-service.log" 2>&1 &
pids="$pids $!"
ip netns exec cmx-ep python3 "$probe" udp-serve --bind "$endpoint_ip@29091" \
    --records "$tmp/reverse-udp.records" >"$tmp/reverse-udp-service.log" 2>&1 &
pids="$pids $!"
wait_port cmx-ep 18443
wait_port cmx-ep 29090
wait_udp_port cmx-ep 18444
wait_udp_port cmx-ep 29091

SSH3_LOG_FILE="$tmp/server.log" \
ip netns exec cmx-gw ssh3-server -bind "[$gw_ip]:4433" -url-path /mirror-e2e \
    -cert "$tmp/tls.crt" -key "$tmp/tls.key" >"$tmp/server.stdout" 2>&1 &
server_pid=$!; pids="$pids $server_pid"
wait_udp_port cmx-gw 4433

CMXSAFE_ENDPOINTD_SOCK=/run/cmxsafe-e2e/endpointd.sock \
ip netns exec cmx-ep ssh3 -insecure -privkey "$tmp/key" \
    -forward-tcp "28080/::1@18443/$endpoint_ip" \
    -forward-udp "28081/::1@18444/$endpoint_ip" \
    -reverse-tcp "29090/$endpoint_ip@29443/$identity_ip" \
    -reverse-udp "29091/$endpoint_ip@29444/$identity_ip" \
    "$identity@[$gw_ip]:4433/mirror-e2e" sleep 120 >"$tmp/client.log" 2>&1 &
client_pid=$!; pids="$pids $client_pid"
wait_port cmx-ep 28080
wait_port cmx-gw 29443
wait_udp_port cmx-ep 28081
wait_udp_port cmx-gw 29444

# Two simultaneous direct channels must preserve P and never cross payloads.
ip netns exec cmx-ep python3 "$probe" probe --source ::1@31001 \
    --destination ::1@28080 --payload direct-a & d1=$!
ip netns exec cmx-ep python3 "$probe" probe --source ::1@31002 \
    --destination ::1@28080 --payload direct-b & d2=$!
wait "$d1"; wait "$d2"
wait_lines "$tmp/direct.records" 2
assert_records "$tmp/direct.records" \
    "[[\"$identity_ip\",31001,\"direct-a\"],[\"$identity_ip\",31002,\"direct-b\"]]"

# Occupying canonical IPv6:P in the gateway must fail closed.
ip netns exec cmx-gw python3 "$probe" hold --bind "$identity_ip@31003" --seconds 20 &
occupied_pid=$!; pids="$pids $occupied_pid"
wait_port cmx-gw 31003
ip netns exec cmx-ep python3 "$probe" probe --source ::1@31003 \
    --destination ::1@28080 --payload must-not-arrive --timeout 3 --expect-failure
test "$(wc -l < "$tmp/direct.records")" -eq 2

# Two reverse peers create independent leases for the same /128.
ip netns exec cmx-peer python3 "$probe" probe --source "$peer_ip@32001" \
    --destination "$identity_ip@29443" --payload reverse-a & r1=$!
ip netns exec cmx-peer python3 "$probe" probe --source "$peer_ip@32002" \
    --destination "$identity_ip@29443" --payload reverse-b & r2=$!
wait_lines "$tmp/reverse.records" 2
ip -n cmx-ep -6 addr show dev cmxmirror0 | grep -F "$peer_ip/128" >/dev/null \
    || fail "endpointd did not install peer /128"
wait "$r1"; wait "$r2"
assert_records "$tmp/reverse.records" \
    "[[\"$peer_ip\",32001,\"reverse-a\"],[\"$peer_ip\",32002,\"reverse-b\"]]"
for _ in $(seq 1 50); do
    if ! ip -n cmx-ep -6 addr show dev cmxmirror0 | grep -F "$peer_ip/128" >/dev/null; then break; fi
    sleep 0.1
done
ip -n cmx-ep -6 addr show dev cmxmirror0 | grep -F "$peer_ip/128" >/dev/null \
    && fail "peer /128 remained after final channel release"

# UDP uses the same strict tuples: the target observes canonical identity:P in
# the direct direction and the real peer tuple in the reverse direction.
ip netns exec cmx-ep python3 "$probe" udp-probe --source ::1@31011 \
    --destination ::1@28081 --payload direct-udp || fail "direct UDP echo failed"
wait_lines "$tmp/direct-udp.records" 1
assert_records "$tmp/direct-udp.records" \
    "[[\"$identity_ip\",31011,\"direct-udp\"]]"
ip netns exec cmx-peer python3 "$probe" udp-probe --source "$udp_peer_ip@32011" \
    --destination "$identity_ip@29444" --payload reverse-udp || fail "reverse UDP echo failed"
wait_lines "$tmp/reverse-udp.records" 1
assert_records "$tmp/reverse-udp.records" \
    "[[\"$udp_peer_ip\",32011,\"reverse-udp\"]]"
ip -n cmx-ep -6 addr show dev cmxmirror0 | grep -F "$udp_peer_ip/128" >/dev/null \
    || fail "endpointd did not install UDP peer /128"

# endpointd absence must fail the reverse channel closed.
kill "$endpointd_pid"
wait "$endpointd_pid" || true
rm -f /run/cmxsafe-e2e/endpointd.sock
ip netns exec cmx-peer python3 "$probe" probe --source "$peer_ip@32003" \
    --destination "$identity_ip@29443" --payload no-endpointd --timeout 3 --expect-failure
test "$(wc -l < "$tmp/reverse.records")" -eq 2
kill -0 "$helper_pid" && kill -0 "$server_pid" && kill -0 "$client_pid"

echo "CMXsafe strict mirror E2E passed: direct/reverse TCP+UDP tuples and replies, /128 lease/refcount/release, negatives, and concurrent channel isolation"
