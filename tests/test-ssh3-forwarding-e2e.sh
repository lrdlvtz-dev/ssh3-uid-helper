#!/bin/sh
set -eu

repo=$(dirname -- "$0")
repo=$(cd -- "$repo/.." && pwd)
helper=${1:-/src/build/cmxsafe-ssh3-helper}
ssh3=${2:-/opt/ssh3/bin/ssh3}
ssh3_server=${3:-/opt/ssh3/bin/ssh3-server}
tmp_dir=$(mktemp -d)
identity=fd000000000000000000000000000010
identity_uid=45678
service_identity=fd000000000000000000000000000020
service_uid=45679
pids=""

cleanup() {
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    ip -6 addr del fd00::10/128 dev lo 2>/dev/null || true
    ip -6 addr del fd00::20/128 dev lo 2>/dev/null || true
    userdel "$identity" 2>/dev/null || true
    groupdel "$identity" 2>/dev/null || true
    userdel "$service_identity" 2>/dev/null || true
    groupdel "$service_identity" 2>/dev/null || true
    rm -rf "$tmp_dir" /run/ssh3-helper
}
trap cleanup EXIT INT TERM

[ "$(id -u)" -eq 0 ]
for executable in "$helper" "$ssh3" "$ssh3_server"; do
    [ -x "$executable" ]
done

groupadd -g "$identity_uid" "$identity"
useradd -m -u "$identity_uid" -g "$identity_uid" -s /bin/sh "$identity"
groupadd -g "$service_uid" "$service_identity"
useradd -M -u "$service_uid" -g "$service_uid" -s /usr/sbin/nologin "$service_identity"
ip -6 addr add fd00::10/128 dev lo nodad
ip -6 addr add fd00::20/128 dev lo nodad

install -d -m 0700 -o "$identity_uid" -g "$identity_uid" "/home/$identity/.ssh3"
ssh-keygen -q -t ed25519 -N '' -f "$tmp_dir/identity-key"
install -m 0600 -o "$identity_uid" -g "$identity_uid" \
    "$tmp_dir/identity-key.pub" "/home/$identity/.ssh3/authorized_identities"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout "$tmp_dir/tls.key" -out "$tmp_dir/tls.crt" >/dev/null 2>&1

install -d -m 0750 -o root -g "$identity_uid" /run/ssh3-helper
"$helper" --socket /run/ssh3-helper/helper.sock --socket-group "$identity" \
    --allowed-uid 0 --request-timeout-ms 1200 --connect-timeout-ms 2000 \
    >"$tmp_dir/helper.log" 2>&1 &
pids="$pids $!"
for _ in $(seq 1 50); do
    [ -S /run/ssh3-helper/helper.sock ] && break
    sleep 0.1
done
[ -S /run/ssh3-helper/helper.sock ]

# Direct forwarding targets live at the server's reach.
python3 "$repo/tests/helper_services.py" /run/ssh3-helper/helper.sock \
    "$service_uid" "$tmp_dir/services.ready" >"$tmp_dir/services.log" 2>&1 &
pids="$pids $!"
for _ in $(seq 1 50); do
    [ -f "$tmp_dir/services.ready" ] && break
    sleep 0.1
done
[ -f "$tmp_dir/services.ready" ]

# Reverse forwarding targets live at the SSH3 client's reach.
python3 "$repo/tests/forwarding_echo.py" tcp ::1 29090 >"$tmp_dir/reverse-tcp.log" 2>&1 &
pids="$pids $!"
python3 "$repo/tests/forwarding_echo.py" udp ::1 29091 >"$tmp_dir/reverse-udp.log" 2>&1 &
pids="$pids $!"

SSH3_LOG_FILE="$tmp_dir/ssh3-server.log" "$ssh3_server" \
    -bind 127.0.0.1:4433 -url-path /cmxsafe-forwarding \
    -cert "$tmp_dir/tls.crt" -key "$tmp_dir/tls.key" \
    >"$tmp_dir/ssh3-server.stdout" 2>&1 &
pids="$pids $!"
server_pid=$!
sleep 1
kill -0 "$server_pid"

"$ssh3" -insecure -privkey "$tmp_dir/identity-key" \
    -forward-tcp '28080/::1@18443/fd00::20' \
    -forward-udp '28081/::1@15353/fd00::20' \
    -reverse-tcp '29090/::1@29443/fd00::10' \
    -reverse-udp '29091/::1@26353/fd00::10' \
    "$identity@127.0.0.1:4433/cmxsafe-forwarding" sleep 30 \
    >"$tmp_dir/ssh3-client.log" 2>&1 &
pids="$pids $!"
client_pid=$!

python3 "$repo/tests/forwarding_probe.py" tcp ::1 28080 direct-tcp
python3 "$repo/tests/forwarding_probe.py" udp ::1 28081 direct-udp
python3 "$repo/tests/forwarding_probe.py" tcp fd00::10 29443 reverse-tcp
python3 "$repo/tests/forwarding_probe.py" udp fd00::10 26353 reverse-udp
kill -0 "$server_pid"
kill -0 "$client_pid"

echo 'SSH3 direct/reverse TCP/UDP forwarding E2E passed'
