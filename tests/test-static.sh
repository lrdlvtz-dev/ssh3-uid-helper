#!/bin/sh
set -eu

repo=$(dirname -- "$0")
repo=$(cd -- "$repo/.." && pwd)

[ ! -e "$repo/src/helper_daemon.cpp" ]
[ ! -e "$repo/src/helper_client.cpp" ]
[ ! -e "$repo/src/run_all_tests.sh" ]
[ ! -e "$repo/test_report.txt" ]
[ ! -e "$repo/src/echo_client.cpp" ]
[ ! -e "$repo/src/echo_server.cpp" ]
[ ! -e "$repo/src/fd_sender_uid.cpp" ]
[ ! -e "$repo/src/uid_socket.cpp" ]

grep -Fq 'SOCK_SEQPACKET' "$repo/src/helper_daemon_v2.cpp"
grep -Fq '/run/ssh3-helper/helper.sock' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'getpwuid_r' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'setgroups(0, nullptr)' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'bind(socket_fd.value' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'AF_INET6' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'IPV6_V6ONLY' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'MSG_NOSIGNAL' "$repo/src/helper_daemon_v2.cpp"
grep -Fq 'kListenTcp = 3' "$repo/src/protocol.h"
grep -Fq 'kBindUdp = 4' "$repo/src/protocol.h"
grep -Fq 'kAcceptTcp = 5' "$repo/src/protocol.h"
grep -Fq 'listenIdentityTCP' "$repo/src/dial_uid.go"
grep -Fq 'bindIdentityUDP' "$repo/src/dial_uid.go"
grep -Fq 'accept_identity_socket' "$repo/src/helper_daemon_v2.cpp"
[ ! -e "$repo/tests/echo_servers.py" ]

if grep -Fq '/tmp/ssh3-helper.sock' "$repo/src/helper_daemon_v2.cpp" "$repo/src/dial_uid.go"; then
    echo 'insecure /tmp endpoint remains in production code' >&2
    exit 1
fi
if grep -Eq 'gid=|host=|sscanf' "$repo/src/helper_daemon_v2.cpp" "$repo/src/dial_uid.go"; then
    echo 'legacy textual request protocol remains in production code' >&2
    exit 1
fi
if grep -Eq 'AF_INET[^6]' "$repo/src/helper_daemon_v2.cpp"; then
    echo 'IPv4 socket family remains in the daemon' >&2
    exit 1
fi

if grep -Eq 'net\.(Dial|DialTCP|DialUDP|Listen|ListenTCP|ListenUDP)\(' "$repo/src/dial_uid.go"; then
    echo 'production Go client opens a protected IP socket directly' >&2
    exit 1
fi

if grep -Eq 'SO_REUSEPORT' "$repo/src/helper_daemon_v2.cpp"; then
    echo 'service sockets must not permit competing port owners' >&2
    exit 1
fi

grep -Fq 'dialIdentityTCP' "$repo/ssh3-uid-helper.patch"
grep -Fq 'dialIdentityUDP' "$repo/ssh3-uid-helper.patch"

echo 'static security checks passed'
