#!/usr/bin/python3
"""H1-only Crashpad argv adapter for an active upload-denial witness.

This file is never installed or used by Quarry.  The H1 browser bundle places
it at Chromium's expected ``chrome_crashpad_handler`` path.  It enables uploads
in Chromium's isolated Crashpad database, adds a literal fixture URL, and then
executes the attested distribution handler.  The inherited network filter is
already active before this adapter is exec'd.
"""
from __future__ import annotations

import fcntl
import os
import pathlib
import socket
import struct
import sys
import time


_ACTUAL = "/usr/lib/chromium/chrome_crashpad_handler"
_UPLOAD_URL = "http://10.203.0.1:9090/upload"
_MAGIC = 0x43506473


def _enable_uploads(database: pathlib.Path) -> None:
    database.mkdir(parents=True, exist_ok=True)
    for name in ("attachments", "completed", "new", "pending"):
        (database / name).mkdir(exist_ok=True)
    settings = database / "settings.dat"
    descriptor = os.open(settings, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        body = os.read(descriptor, 4096)
        if body:
            if len(body) < 40:
                raise RuntimeError("Crashpad settings are truncated")
            magic, version, options = struct.unpack_from("<III", body)
            if magic != _MAGIC or version != 1:
                raise RuntimeError("Crashpad settings identity mismatch")
            mutable = bytearray(body)
            struct.pack_into("<I", mutable, 8, options | 1)
            body = bytes(mutable)
        else:
            body = struct.pack(
                "<IIIIq16s", _MAGIC, 1, 1, 0, 0, os.urandom(16),
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.write(descriptor, body)
        os.ftruncate(descriptor, len(body))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _seed_report(database: pathlib.Path) -> str:
    report_id = "11111111-1111-4111-8111-111111111111"
    dump = database / "pending" / f"{report_id}.dmp"
    metadata = database / "pending" / f"{report_id}.meta"
    dump.write_bytes(b"MDMP\x00quarry-active-upload-denial-witness\n")
    # ReportMetadata on Linux/x86_64: version, attempts, last-attempt time,
    # creation time, attributes, and ABI tail padding.  Attribute bit 1 makes
    # this an explicit one-shot request independent of Chrome consent state.
    metadata.write_bytes(struct.pack(
        "<iiqqB7x", 1, 0, 0, int(time.time()), 2,
    ))
    return report_id


def _standalone(database: pathlib.Path) -> None:
    _enable_uploads(database)
    _seed_report(database)
    handler, keeper = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET, 0,
    )
    child = os.fork()
    if child == 0:
        handler.close()
        try:
            while keeper.recv(4096):
                pass
        except OSError:
            pass
        os._exit(0)
    keeper.close()
    os.dup2(handler.fileno(), 7, inheritable=True)
    if handler.fileno() != 7:
        handler.close()
    arguments = [
        "--monitor-self",
        "--monitor-self-annotation=ptype=crashpad-handler",
        f"--database={database}",
        "--annotation=plat=Linux",
        "--annotation=prod=Chrome_Linux",
        "--annotation=ver=148.0.7778.178",
        "--initial-client-fd=7",
        "--shared-client-connection",
        f"--url={_UPLOAD_URL}",
        "--no-rate-limit",
        "--no-upload-gzip",
    ]
    os.execve(_ACTUAL, [_ACTUAL, *arguments], dict(os.environ))


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--standalone":
        _standalone(pathlib.Path(sys.argv[2]))
        return 127
    arguments = list(sys.argv[1:])
    databases = [
        value.split("=", 1)[1] for value in arguments
        if value.startswith("--database=")
    ]
    if len(databases) != 1:
        raise RuntimeError("expected one Crashpad database argument")
    _enable_uploads(pathlib.Path(databases[0]))
    if any(value.startswith("--url=") for value in arguments):
        raise RuntimeError("Chromium unexpectedly supplied an upload URL")
    arguments.extend((
        f"--url={_UPLOAD_URL}", "--no-rate-limit", "--no-upload-gzip",
    ))
    os.execve(_ACTUAL, [_ACTUAL, *arguments], dict(os.environ))
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
