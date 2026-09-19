#!/usr/bin/env python3
"""Reject direct IP socket creation in patched SSH3 server forwarding handlers."""

import pathlib
import re
import sys


def function_source(source: str, name: str) -> str:
    match = re.search(rf"(?m)^func {re.escape(name)}\(.*", source)
    if match is None:
        raise SystemExit(f"missing SSH3 forwarding handler: {name}")
    following = re.search(r"(?m)^func ", source[match.end() :])
    end = len(source) if following is None else match.end() + following.start()
    return source[match.start() : end]


def require_only_helper(source: str, name: str, required: tuple[str, ...]) -> None:
    body = function_source(source, name)
    for token in required:
        if token not in body:
            raise SystemExit(f"{name} does not use required helper path {token}")
    forbidden = (
        "net.Dial",
        "net.Listen",
        "ListenUDPWithAutoMulticast",
        "ListenUDPReuse",
        "syscall.Socket",
        "unix.Socket",
    )
    for token in forbidden:
        if token in body:
            raise SystemExit(f"{name} bypasses helper through {token}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_ssh3_forwarding.py CMD_SSH3_SERVER_GO")
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    require_only_helper(source, "handleTCPForwardingChannel", ("dialIdentityTCP",))
    require_only_helper(source, "handleUDPForwardingChannel", ("dialIdentityUDP",))
    require_only_helper(
        source,
        "handleTCPReverseForwardingChannel",
        ("listenIdentityTCP", ".AcceptTCP()", "<-ctx.Done()", "conn.Close()"),
    )
    require_only_helper(
        source,
        "handleUDPReverseForwardingChannel",
        ("bindIdentityUDP", "<-ctx.Done()", "conn.Close()"),
    )
    print("SSH3 forwarding socket guard passed")


if __name__ == "__main__":
    main()
