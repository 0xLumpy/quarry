#!/usr/bin/env python3
"""Validate C-OUTPUT serialized receipt *shapes* without emitting evidence.

Raw JSON has no authenticated envelope or resolver.  This source-substrate
utility can diagnose its strict shape only; it intentionally cannot produce a
matrix, release record, or accepting C-OUTPUT result.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from quarry_recon import output_contract


def _read(path: Path, label: str):
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid {label} {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-manifest", type=Path, required=True)
    parser.add_argument("--raw-receipt", type=Path, action="append", required=True,
                        help="serialized shape-only diagnostic (never authenticated evidence)")
    parser.add_argument("--output", type=Path,
                        help="unsupported: this source substrate never emits a matrix")
    args = parser.parse_args(argv)
    try:
        manifest = _read(args.fixture_manifest, "fixture manifest")
        for path in args.raw_receipt:
            output_contract.validate_raw_receipt(
                _read(path, "raw receipt"), fixture_manifest=manifest, accepting=False,
            )
    except output_contract.OutputContractError as exc:
        raise SystemExit(f"C-OUTPUT-CONTRACT remains open: {exc}") from exc
    raise SystemExit(
        "C-OUTPUT-CONTRACT remains open: serialized raw receipts are shape-only diagnostics; "
        "no authenticated resolver or accepting matrix producer is registered",
    )


if __name__ == "__main__":
    raise SystemExit(main())
