#!/usr/bin/env python3
"""Small IPv6 peer recorder/probe used only by the privileged mirror E2E."""

import argparse
import json
import socket
import threading
import time


def address(value):
    host, port = value.rsplit("@", 1)
    return host, int(port)


def append_record(path, record, lock):
    with lock, open(path, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, sort_keys=True) + "\n")
        output.flush()


def serve(args):
    lock = threading.Lock()
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address(args.bind))
    server.listen(16)

    def handle(connection, peer):
        with connection:
            data = connection.recv(4096)
            append_record(args.records, {"peer_ip": peer[0], "peer_port": peer[1],
                                         "payload": data.decode("ascii")}, lock)
            if args.delay:
                time.sleep(args.delay)
            connection.sendall(b"reply:" + data)

    while True:
        connection, peer = server.accept()
        threading.Thread(target=handle, args=(connection, peer), daemon=True).start()


def probe(args):
    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    client.settimeout(args.timeout)
    client.bind(address(args.source))
    try:
        client.connect(address(args.destination))
        client.sendall(args.payload.encode("ascii"))
        reply = client.recv(4096)
    except OSError:
        if args.expect_failure:
            return
        raise
    finally:
        client.close()
    expected = ("reply:" + args.payload).encode("ascii")
    if args.expect_failure:
        if reply == expected:
            raise SystemExit("connection unexpectedly completed end to end")
        return
    if reply != expected:
        raise SystemExit(f"bad reply: {reply!r}, expected {expected!r}")


def hold(args):
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind(address(args.bind))
    listener.listen(1)
    time.sleep(args.seconds)


def udp_serve(args):
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind(address(args.bind))
    lock = threading.Lock()
    seen = set()
    while True:
        data, peer = server.recvfrom(4096)
        key = (peer[0], peer[1], data)
        if key not in seen:
            seen.add(key)
            append_record(args.records, {"peer_ip": peer[0], "peer_port": peer[1],
                                         "payload": data.decode("ascii")}, lock)
        server.sendto(b"reply:" + data, peer)


def udp_probe(args):
    client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    client.settimeout(min(0.25, args.timeout))
    client.bind(address(args.source))
    expected = ("reply:" + args.payload).encode("ascii")
    deadline = time.monotonic() + args.timeout
    reply = None
    try:
        while time.monotonic() < deadline:
            client.sendto(args.payload.encode("ascii"), address(args.destination))
            try:
                candidate, _ = client.recvfrom(4096)
            except TimeoutError:
                continue
            if candidate == expected:
                reply = candidate
                break
    except OSError:
        if args.expect_failure:
            return
        raise
    finally:
        client.close()
    if args.expect_failure:
        if reply == expected:
            raise SystemExit("UDP exchange unexpectedly completed end to end")
        return
    if reply != expected:
        raise SystemExit(f"bad UDP reply: {reply!r}, expected {expected!r}")


parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="command", required=True)
p = sub.add_parser("serve")
p.add_argument("--bind", required=True)
p.add_argument("--records", required=True)
p.add_argument("--delay", type=float, default=0)
p.set_defaults(function=serve)
p = sub.add_parser("probe")
p.add_argument("--source", required=True)
p.add_argument("--destination", required=True)
p.add_argument("--payload", required=True)
p.add_argument("--timeout", type=float, default=8)
p.add_argument("--expect-failure", action="store_true")
p.set_defaults(function=probe)
p = sub.add_parser("hold")
p.add_argument("--bind", required=True)
p.add_argument("--seconds", type=float, default=30)
p.set_defaults(function=hold)
p = sub.add_parser("udp-serve")
p.add_argument("--bind", required=True)
p.add_argument("--records", required=True)
p.set_defaults(function=udp_serve)
p = sub.add_parser("udp-probe")
p.add_argument("--source", required=True)
p.add_argument("--destination", required=True)
p.add_argument("--payload", required=True)
p.add_argument("--timeout", type=float, default=8)
p.add_argument("--expect-failure", action="store_true")
p.set_defaults(function=udp_probe)
arguments = parser.parse_args()
arguments.function(arguments)
