#!/usr/bin/env python3
"""Retry a TCP/UDP echo round trip while an SSH3 forwarding is starting."""

import socket
import sys
import time


transport, address, port_text, payload_text = sys.argv[1:5]
kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
payload = payload_text.encode("ascii")
deadline = time.monotonic() + 15
last_error: OSError | None = None

while time.monotonic() < deadline:
    connection = socket.socket(socket.AF_INET6, kind)
    connection.settimeout(1)
    try:
        connection.connect((address, int(port_text)))
        connection.sendall(payload)
        received = connection.recv(len(payload))
        if received == payload:
            raise SystemExit(0)
        raise OSError(f"unexpected echo: {received!r}")
    except OSError as error:
        last_error = error
        time.sleep(0.2)
    finally:
        connection.close()

raise SystemExit(f"{transport} forwarding probe failed: {last_error}")
