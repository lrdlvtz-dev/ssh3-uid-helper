#!/usr/bin/env python3
"""Echo services whose protected sockets are obtained from the helper."""

import array
import os
import select
import socket
import struct
import sys
import threading

MAGIC = 0x434D5848
VERSION = 1
REQUEST = struct.Struct("!IHHQIHH16s")
RESPONSE = struct.Struct("!IHHQII")


def request_service(path, uid, operation, port, passed_fd=None):
    request_id = (operation << 56) | port
    payload = REQUEST.pack(
        MAGIC, VERSION, operation, request_id, uid, port, 0, b"\x00" * 16
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(5)
    connection.connect(path)
    if passed_fd is None:
        connection.sendall(payload)
    else:
        rights = array.array("i", [passed_fd])
        connection.sendmsg(
            [payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())]
        )
    response, ancillary, flags, _ = connection.recvmsg(
        RESPONSE.size, socket.CMSG_SPACE(4)
    )
    assert len(response) == RESPONSE.size and not flags
    magic, version, status, reply_id, system_errno, reserved = RESPONSE.unpack(response)
    if operation == 5 and status == 5 and system_errno in (11, 110):
        return None
    actual = (magic, version, status, reply_id, system_errno, reserved)
    expected = (MAGIC, VERSION, 0, request_id, 0, 0)
    assert actual == expected, (actual, expected)
    descriptors = array.array("i")
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
    assert len(descriptors) == 1
    assert os.fstat(descriptors[0]).st_uid == uid
    return socket.socket(fileno=descriptors[0])


def serve_tcp(path, listener, uid):
    while True:
        readable, _, _ = select.select([listener], [], [], 1)
        if not readable:
            continue
        connection = request_service(path, uid, 5, listener.getsockname()[1], listener.fileno())
        if connection is None:
            continue
        with connection:
            assert os.fstat(connection.fileno()).st_uid == uid
            data = connection.recv(4096)
            if data:
                connection.sendall(data)


def serve_udp(service):
    while True:
        data, peer = service.recvfrom(4096)
        service.sendto(data, peer)


def main():
    path, uid_text, ready_path = sys.argv[1:4]
    uid = int(uid_text)
    tcp = request_service(path, uid, 3, 18443)
    udp = request_service(path, uid, 4, 15353)
    assert tcp.family == socket.AF_INET6 and tcp.getsockname()[:2] == ("fd00::20", 18443)
    assert udp.family == socket.AF_INET6 and udp.getsockname()[:2] == ("fd00::20", 15353)
    threading.Thread(target=serve_tcp, args=(path, tcp, uid), daemon=True).start()
    threading.Thread(target=serve_udp, args=(udp,), daemon=True).start()
    with open(ready_path, "x", encoding="ascii") as ready:
        ready.write("ready\n")
    threading.Event().wait()


if __name__ == "__main__":
    main()
