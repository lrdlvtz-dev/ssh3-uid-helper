#!/bin/sh
set -eu

binary=$(realpath "${1:-./cmxsafe-endpointd}")
command -v unshare >/dev/null 2>&1 || { echo "SKIP: unshare is unavailable"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "SKIP: ip is unavailable"; exit 77; }

unshare --net --mount-proc sh -eu -c '
  binary=$1
  work=$(mktemp -d)
  chmod 700 "$work"
  socket=$work/endpointd.sock
  ready=$work/ready
  release=$work/release
  "$binary" serve --socket "$socket" --iface cmxmirror-test &
  daemon=$!
  trap '\''kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; rm -rf "$work"'\'' EXIT
  i=0
  while [ ! -S "$socket" ]; do
    i=$((i + 1)); [ "$i" -lt 100 ] || exit 1; sleep 0.01
  done
  python3 - "$socket" "$ready" "$release" <<'\''PY'\'' &
import json, os, socket, sys, time
sock, ready, release = sys.argv[1:]
def call(command):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock); s.sendall(command + b"\n")
    data = b""
    while not data.endswith(b"\n"): data += s.recv(4096)
    s.close(); return json.loads(data)
assert call(b"v1\tensure\tpeer\t2001:db8::99")["ok"]
open(ready, "w").close()
while not os.path.exists(release): time.sleep(.01)
assert call(b"v1\trelease\tpeer\t2001:db8::99")["ok"]
PY
  client=$!
  i=0
  while [ ! -f "$ready" ]; do
    i=$((i + 1)); [ "$i" -lt 100 ] || exit 1; sleep 0.01
  done
  ip -6 addr show dev cmxmirror-test | grep -q "2001:db8::99/128"
  : > "$release"
  wait "$client"
  ! ip -6 addr show dev cmxmirror-test | grep -q "2001:db8::99/128"
  kill "$daemon"; wait "$daemon"
  trap - EXIT
  rm -rf "$work"
  echo "endpointd privileged namespace test: PASS"
' sh "$binary"
