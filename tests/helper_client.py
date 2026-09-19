#!/usr/bin/env python3
import array
import ipaddress
import os
import socket
import struct
import sys
import time

MAGIC = 0x434D5848
VERSION = 1
REQUEST = struct.Struct("!IHHQIHH16s")
RESPONSE = struct.Struct("!IHHQII")


def exchange(path, uid, operation, destination, port, expected_status=0, hold=0):
    request_id = 0x1122334455667788
    payload = REQUEST.pack(
        MAGIC,
        VERSION,
        operation,
        request_id,
        uid,
        port,
        0,
        ipaddress.IPv6Address(destination).packed,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(5)
    connection.connect(path)
    if hold:
        time.sleep(hold)
        return
    connection.sendall(payload)
    response, ancillary, flags, _ = connection.recvmsg(RESPONSE.size, socket.CMSG_SPACE(4))
    assert len(response) == RESPONSE.size and not flags, (len(response), flags)
    magic, version, status, reply_id, system_errno, reserved = RESPONSE.unpack(response)
    assert magic == MAGIC and version == VERSION and reserved == 0
    assert status == expected_status, (status, system_errno)
    if status != 0:
        assert not ancillary
        return
    assert reply_id == request_id
    descriptors = array.array("i")
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
    assert len(descriptors) == 1, descriptors
    fd = descriptors[0]
    identity_socket = socket.socket(fileno=fd)
    expected_source = str(ipaddress.IPv6Address("fd00::10"))
    assert identity_socket.family == socket.AF_INET6
    assert identity_socket.getsockname()[0] == expected_source, identity_socket.getsockname()
    peer = identity_socket.getpeername()
    assert peer[0] == str(ipaddress.IPv6Address(destination)) and peer[1] == port, peer
    assert os.fstat(fd).st_uid == uid, os.fstat(fd)
    message = b"cmxsafe-identity-test"
    identity_socket.sendall(message)
    assert identity_socket.recv(4096) == message
    identity_socket.close()


def malformed(path):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(5)
    connection.connect(path)
    connection.sendall(b"legacy-text-request")
    response = connection.recv(RESPONSE.size)
    _, _, status, _, _, _ = RESPONSE.unpack(response)
    assert status == 1, status


def expect_raw_status(path, payload, expected, passed_fds=None):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(5)
    connection.connect(path)
    if passed_fds:
        rights = array.array("i", passed_fds)
        connection.sendmsg(
            [payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())]
        )
    else:
        connection.sendall(payload)
    response = connection.recv(RESPONSE.size)
    assert len(response) == RESPONSE.size
    assert RESPONSE.unpack(response)[2] == expected, RESPONSE.unpack(response)


def invalid_packets(path):
    valid = bytearray(REQUEST.pack(
        MAGIC, VERSION, 1, 7, 45678, 443, 0,
        ipaddress.IPv6Address("fd00::20").packed,
    ))
    cases = []
    wrong_magic = bytearray(valid)
    wrong_magic[0] ^= 1
    cases.append((wrong_magic, 1))
    wrong_version = bytearray(valid)
    wrong_version[5] = 2
    cases.append((wrong_version, 1))
    wrong_operation = bytearray(valid)
    wrong_operation[7] = 99
    cases.append((wrong_operation, 1))
    wrong_reserved = bytearray(valid)
    wrong_reserved[23] = 1
    cases.append((wrong_reserved, 1))
    zero_port = bytearray(valid)
    zero_port[20:22] = b"\x00\x00"
    cases.append((zero_port, 4))
    loopback = bytearray(valid)
    loopback[24:40] = ipaddress.IPv6Address("::1").packed
    cases.append((loopback, 4))
    cases.append((valid + b"x", 1))
    listener_with_address = bytearray(valid)
    listener_with_address[6:8] = struct.pack("!H", 3)
    cases.append((listener_with_address, 4))
    accept_without_fd = bytearray(valid)
    accept_without_fd[6:8] = struct.pack("!H", 5)
    accept_without_fd[24:40] = b"\x00" * 16
    cases.append((accept_without_fd, 1))
    for payload, expected in cases:
        expect_raw_status(path, payload, expected)


def service_conflicts(path, service_uid):
    for operation, port in ((3, 18443), (4, 15353)):
        payload = REQUEST.pack(
            MAGIC, VERSION, operation, operation, service_uid, port, 0, b"\x00" * 16
        )
        expect_raw_status(path, payload, 5)


def invalid_listener_fds(path, service_uid):
    request = REQUEST.pack(
        MAGIC, VERSION, 5, 9, service_uid, 19444, 0, b"\x00" * 16
    )
    fake_listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    fake_listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    fake_listener.bind(("fd00::20", 19444))
    fake_listener.listen(1)
    expect_raw_status(path, request, 8, [fake_listener.fileno()])

    def owned_tcp(address, port, *, listening=True, ipv6_only=1):
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, ipv6_only)
        listener.bind((address, port))
        if listening:
            listener.listen(1)
        os.fchown(listener.fileno(), service_uid, service_uid)
        return listener

    wrong_address = owned_tcp("fd00::10", 19444)
    expect_raw_status(path, request, 8, [wrong_address.fileno()])

    wrong_port = owned_tcp("fd00::20", 19446)
    expect_raw_status(path, request, 8, [wrong_port.fileno()])

    not_listening = owned_tcp("fd00::20", 19447, listening=False)
    not_listening_request = REQUEST.pack(
        MAGIC, VERSION, 5, 11, service_uid, 19447, 0, b"\x00" * 16
    )
    expect_raw_status(path, not_listening_request, 8, [not_listening.fileno()])

    udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp.bind(("fd00::20", 19445))
    udp_request = REQUEST.pack(
        MAGIC, VERSION, 5, 10, service_uid, 19445, 0, b"\x00" * 16
    )
    expect_raw_status(path, udp_request, 8, [udp.fileno()])
    expect_raw_status(path, request, 1, [fake_listener.fileno(), udp.fileno()])
    fake_listener.close()
    wrong_address.close()
    wrong_port.close()
    not_listening.close()
    udp.close()


def unauthorized(path):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(5)
    connection.connect(path)
    response = connection.recv(RESPONSE.size)
    assert len(response) == RESPONSE.size
    assert RESPONSE.unpack(response)[2] == 2, RESPONSE.unpack(response)


def udp_blocked(path, uid):
    request_id = 0x8877665544332211
    payload = REQUEST.pack(
        MAGIC, VERSION, 2, request_id, uid, 15353, 0,
        ipaddress.IPv6Address("fd00::20").packed,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection.settimeout(5)
    connection.connect(path)
    connection.sendall(payload)
    response, ancillary, _, _ = connection.recvmsg(RESPONSE.size, socket.CMSG_SPACE(4))
    assert RESPONSE.unpack(response)[2] == 0
    descriptors = array.array("i")
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
    assert len(descriptors) == 1
    identity_socket = socket.socket(fileno=descriptors[0])
    identity_socket.settimeout(1)
    try:
        identity_socket.send(b"must-be-blocked")
    except PermissionError:
        return
    try:
        identity_socket.recv(4096)
    except TimeoutError:
        return
    raise AssertionError("UDP crossed the deny-by-default guard without a grant")


if __name__ == "__main__":
    command = sys.argv[1]
    path = sys.argv[2]
    if command == "tcp":
        exchange(path, int(sys.argv[3]), 1, "fd00::20", 18443)
    elif command == "udp":
        exchange(path, int(sys.argv[3]), 2, "fd00::20", 15353)
    elif command == "invalid-identity":
        exchange(path, 0, 1, "fd00::20", 18443, expected_status=3)
    elif command == "tcp-blocked":
        exchange(path, int(sys.argv[3]), 1, "fd00::20", 18443, expected_status=5)
    elif command == "udp-blocked":
        udp_blocked(path, int(sys.argv[3]))
    elif command == "slow":
        exchange(path, 0, 1, "fd00::20", 18443, hold=float(sys.argv[3]))
    elif command == "malformed":
        malformed(path)
    elif command == "invalid-packets":
        invalid_packets(path)
    elif command == "service-conflicts":
        service_conflicts(path, int(sys.argv[3]))
    elif command == "invalid-listener-fds":
        invalid_listener_fds(path, int(sys.argv[3]))
    elif command == "unauthorized":
        unauthorized(path)
    else:
        raise SystemExit(f"unknown command: {command}")
