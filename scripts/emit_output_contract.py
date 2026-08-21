#!/usr/bin/env python3
"""Canonical C-OUTPUT-CONTRACT collector; it does not execute or promote H1."""
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
    parser.add_argument("--raw-receipt", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        matrix = output_contract.collect_case_matrix(
            fixture_manifest=_read(args.fixture_manifest, "fixture manifest"),
            receipts=[_read(path, "raw receipt") for path in args.raw_receipt],
        )
        output_contract.validate_case_matrix(matrix)
    except output_contract.OutputContractError as exc:
        raise SystemExit(f"C-OUTPUT-CONTRACT remains open: {exc}") from exc
    args.output.write_bytes(output_contract.evidence.canonical_json_bytes(matrix) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
