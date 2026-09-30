#!/usr/bin/env python3
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def request(path, command):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    client.connect(path)
    client.sendall((command + "\n").encode())
    response = b""
    while not response.endswith(b"\n"):
        response += client.recv(4096)
    client.close()
    return json.loads(response)


def main():
    binary = os.path.abspath(sys.argv[1])
    # The daemon rejects world-writable parents, hence a private mkdtemp directory.
    with tempfile.TemporaryDirectory(prefix="endpointd-") as directory:
        path = str(pathlib.Path(directory) / "endpointd.sock")
        daemon = subprocess.Popen([binary, "serve", "--dry-run", "--socket", path],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if os.path.exists(path):
                    break
                if daemon.poll() is not None:
                    raise RuntimeError(daemon.stderr.read().decode())
                time.sleep(0.01)
            assert request(path, "v1 ping")["ok"] is True
            first = request(path, "v1\tensure\tpeer\t01\t2001:0db8::1")
            assert first == {"version": 1, "ok": True, "created": True,
                             "scope": "peer", "lease_id": "01",
                             "ipv6": "2001:db8::1", "refcount": 1}
            again = request(path, "ensure peer 01 2001:db8::1")
            assert again["ok"] and not again["created"] and again["refcount"] == 1
            # A second channel in the same process gets an independent lease.
            second = request(path, "v1 ensure peer 02 2001:db8::1")
            assert second["ok"] and second["created"] and second["refcount"] == 2
            released = request(path, "v1\trelease\tpeer\t01\t2001:db8::1")
            assert released["ok"] and released["released"] and released["refcount"] == 1
            assert request(path, "release peer 01 2001:db8::1")["error"] == "not_owner"
            assert request(path, "release peer 02 2001:db8::1")["refcount"] == 0
            assert request(path, "ensure peer 03 not-an-ip")["error"] == "invalid_ipv6"
            assert request(path, "ensure peer not_hex! 2001:db8::1")["error"] == "invalid_request"

            # A distinct process cannot release this process's lease (SO_PEERCRED authority).
            assert request(path, "ensure peer aa 2001:db8::2")["ok"]
            code = """
import json,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[1])
s.sendall(b'release peer aa 2001:db8::2\\n')
print(s.recv(4096).decode(), end='')
"""
            child = subprocess.check_output([sys.executable, "-c", code, path], text=True)
            assert json.loads(child)["error"] == "not_owner"

            # Strict framing and bounded input.
            assert request(path, "unknown")["error"] == "invalid_request"
            oversized = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            oversized.connect(path)
            oversized.sendall(b"x" * 300 + b"\n")
            assert json.loads(oversized.recv(4096))["error"] == "frame_too_large"
            oversized.close()
        finally:
            daemon.terminate()
            daemon.wait(timeout=3)
            if daemon.returncode not in (0, -15):
                raise RuntimeError(daemon.stderr.read().decode())
    print("endpointd unprivileged tests: PASS")


if __name__ == "__main__":
    main()
