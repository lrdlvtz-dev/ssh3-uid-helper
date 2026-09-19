#!/usr/bin/env python3
"""Small TCP/UDP echo endpoint used by the disposable SSH3 forwarding E2E."""

import socket
import sys


def serve_tcp(address: str, port: int) -> None:
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(8)
    while True:
        connection, _ = listener.accept()
        with connection:
            data = connection.recv(4096)
            if data:
                connection.sendall(data)


def serve_udp(address: str, port: int) -> None:
    service = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    service.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    service.bind((address, port))
    while True:
        data, peer = service.recvfrom(4096)
        service.sendto(data, peer)


if __name__ == "__main__":
    transport, bind_address, bind_port = sys.argv[1:4]
    if transport == "tcp":
        serve_tcp(bind_address, int(bind_port))
    elif transport == "udp":
        serve_udp(bind_address, int(bind_port))
    else:
        raise SystemExit(f"unsupported transport: {transport}")
