#!/usr/bin/python3
"""Candidate-bound local producer for C-OUTPUT runner cases.

The helper deliberately owns behavior only. Every byte it writes is supplied
by a tracked fixture path admitted in the source argv, so the contract can bind
the emitted payload to the candidate identity rather than to test constants.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path


def _payload(path: str, encoding: str) -> bytes:
    body = Path(path).read_bytes()
    if encoding == "hex":
        return bytes.fromhex(body.decode("ascii", "strict").strip())
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        required=True,
        choices=("empty", "malformed", "truncated", "non_utf8", "partial", "timeout", "signal"),
    )
    parser.add_argument("--payload")
    parser.add_argument("--encoding", choices=("raw", "hex"), default="raw")
    parser.add_argument("--stderr")
    args = parser.parse_args()
    if args.case == "timeout":
        time.sleep(60)
        return 0
    if args.case == "signal":
        os.kill(os.getpid(), signal.SIGTERM)
        return 70  # pragma: no cover - SIGTERM ends the process.
    if args.payload is not None:
        sys.stdout.buffer.write(_payload(args.payload, args.encoding))
        sys.stdout.buffer.flush()
    if args.stderr is not None:
        sys.stderr.buffer.write(Path(args.stderr).read_bytes())
        sys.stderr.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
