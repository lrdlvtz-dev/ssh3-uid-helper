#!/bin/sh
set -eu

binary=${1:-/opt/cmxsafe/bin/cmxsafe-ssh3-helper}
repo=$(dirname -- "$0")
repo=$(cd -- "$repo/.." && pwd)
tmp_dir=$(mktemp -d)
identity=fd000000000000000000000000000010
identity_uid=45678
identity_gid=45678
service_identity=fd000000000000000000000000000020
service_uid=45679
service_gid=45679
daemon_pid=""
service_pid=""
slow_pids=""

cleanup() {
    for pid in $slow_pids $daemon_pid $service_pid; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    nft delete table inet cmxsafe_helper_test 2>/dev/null || true
    ip -6 addr del fd00::10/128 dev lo 2>/dev/null || true
    ip -6 addr del fd00::20/128 dev lo 2>/dev/null || true
    userdel "$identity" 2>/dev/null || true
    groupdel "$identity" 2>/dev/null || true
    userdel "$service_identity" 2>/dev/null || true
    groupdel "$service_identity" 2>/dev/null || true
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

command -v useradd >/dev/null
command -v ip >/dev/null
[ "$(id -u)" -eq 0 ]

# A zero receive timeout disables SO_RCVTIMEO and would let slow clients hold
# the complete worker pool forever. Configuration must fail closed.
if "$binary" --request-timeout-ms 0 >"$tmp_dir/zero-timeout.log" 2>&1; then
    echo "helper accepted a disabled request timeout" >&2
    exit 1
fi

groupadd -g "$identity_gid" "$identity"
useradd -M -u "$identity_uid" -g "$identity_gid" -s /usr/sbin/nologin "$identity"
groupadd -g "$service_gid" "$service_identity"
useradd -M -u "$service_uid" -g "$service_gid" -s /usr/sbin/nologin "$service_identity"
chown root:"$identity_gid" "$tmp_dir"
chmod 0750 "$tmp_dir"
ip -6 addr add fd00::10/128 dev lo nodad
ip -6 addr add fd00::20/128 dev lo nodad

"$binary" \
    --socket "$tmp_dir/helper.sock" \
    --socket-group "$identity" \
    --allowed-uid 0 \
    --max-children 2 \
    --request-timeout-ms 1200 \
    --connect-timeout-ms 2000 >"$tmp_dir/daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 50); do
    [ -S "$tmp_dir/helper.sock" ] && break
    sleep 0.1
done
[ -S "$tmp_dir/helper.sock" ]
[ "$(stat -c '%a:%u:%g' "$tmp_dir/helper.sock")" = "660:0:$identity_gid" ]

python3 "$repo/tests/helper_services.py" \
    "$tmp_dir/helper.sock" "$service_uid" "$tmp_dir/services.ready" &
service_pid=$!
for _ in $(seq 1 50); do
    [ -f "$tmp_dir/services.ready" ] && break
    sleep 0.1
done
[ -f "$tmp_dir/services.ready" ]

python3 "$repo/tests/helper_client.py" tcp "$tmp_dir/helper.sock" "$identity_uid"
python3 "$repo/tests/helper_client.py" udp "$tmp_dir/helper.sock" "$identity_uid"
CMXSAFE_HELPER_INTEGRATION=1 \
CMXSAFE_HELPER_TEST_UID="$identity_uid" \
CMXSAFE_HELPER_TEST_SERVICE_UID="$service_uid" \
CMXSAFE_HELPER_TEST_SOCKET="$tmp_dir/helper.sock" \
    go test -run TestRealDaemonTCPAndUDP \
      "$repo/src/dial_uid.go" "$repo/src/dial_uid_integration_test.go"
python3 "$repo/tests/helper_client.py" invalid-identity "$tmp_dir/helper.sock"
python3 "$repo/tests/helper_client.py" malformed "$tmp_dir/helper.sock"
python3 "$repo/tests/helper_client.py" invalid-packets "$tmp_dir/helper.sock"
python3 "$repo/tests/helper_client.py" service-conflicts "$tmp_dir/helper.sock" "$service_uid"
python3 "$repo/tests/helper_client.py" invalid-listener-fds "$tmp_dir/helper.sock" "$service_uid"
runuser -u "$identity" -- python3 "$repo/tests/helper_client.py" unauthorized "$tmp_dir/helper.sock" "$identity_uid"

# Exact Security Context tuples are exceptions before a pool-wide guard. Revoke
# both transports and prove that the helper does not bypass external policy.
nft -f - <<'NFT'
table inet cmxsafe_helper_test {
    set allowed_tcp {
        type ipv6_addr . ipv6_addr . inet_service
        elements = { fd00::10 . fd00::20 . 18443 }
    }
    set allowed_udp {
        type ipv6_addr . ipv6_addr . inet_service
        elements = { fd00::10 . fd00::20 . 15353 }
    }
    chain output {
        type filter hook output priority -10; policy accept;
        meta l4proto 58 accept
        ct state established,related accept
        ip6 saddr . ip6 daddr . tcp dport @allowed_tcp accept
        ip6 saddr . ip6 daddr . udp dport @allowed_udp accept
        ip6 saddr fd00::/16 drop
        ip6 daddr fd00::/16 drop
    }
    chain input {
        type filter hook input priority -10; policy accept;
        meta l4proto 58 accept
        ct state established,related accept
        ip6 saddr . ip6 daddr . tcp dport @allowed_tcp accept
        ip6 saddr . ip6 daddr . udp dport @allowed_udp accept
        ip6 saddr fd00::/16 drop
        ip6 daddr fd00::/16 drop
    }
}
NFT
python3 "$repo/tests/helper_client.py" tcp "$tmp_dir/helper.sock" "$identity_uid"
python3 "$repo/tests/helper_client.py" udp "$tmp_dir/helper.sock" "$identity_uid"
nft delete element inet cmxsafe_helper_test allowed_tcp '{ fd00::10 . fd00::20 . 18443 }'
nft delete element inet cmxsafe_helper_test allowed_udp '{ fd00::10 . fd00::20 . 15353 }'
python3 "$repo/tests/helper_client.py" tcp-blocked "$tmp_dir/helper.sock" "$identity_uid"
python3 "$repo/tests/helper_client.py" udp-blocked "$tmp_dir/helper.sock" "$identity_uid"
nft delete table inet cmxsafe_helper_test

# Two incomplete clients consume the deliberately small worker budget. The
# daemon must reject another client promptly instead of blocking its root loop.
python3 "$repo/tests/helper_client.py" slow "$tmp_dir/helper.sock" 3 &
slow_pids="$slow_pids $!"
python3 "$repo/tests/helper_client.py" slow "$tmp_dir/helper.sock" 3 &
slow_pids="$slow_pids $!"
sleep 0.2
python3 - "$tmp_dir/helper.sock" <<'PY'
import socket, struct, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.settimeout(1)
started = time.monotonic()
s.connect(sys.argv[1])
reply = s.recv(24)
assert len(reply) == 24
assert struct.unpack("!IHHQII", reply)[2] == 6
assert time.monotonic() - started < 1
PY

sleep 2
python3 "$repo/tests/helper_client.py" tcp "$tmp_dir/helper.sock" "$identity_uid"
kill -0 "$daemon_pid"

echo 'daemon kernel integration tests passed'
