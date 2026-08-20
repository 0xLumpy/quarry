#!/usr/bin/python3
"""H1-only tracee that drops mediator readability before an INET connect."""
from __future__ import annotations

import ctypes
import errno
import json
import socket


def main() -> int:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise RuntimeError("PR_SET_DUMPABLE failed")
    handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        handle.setblocking(False)
        observed = int(handle.connect_ex(("10.203.0.1", 9090)))
    finally:
        handle.close()
    print(json.dumps({"connect_errno": observed}, sort_keys=True), flush=True)
    return 0 if observed in {errno.EPERM, errno.EACCES} else 1


if __name__ == "__main__":
    raise SystemExit(main())
