#!/usr/bin/env python3
"""Fail unless Bandit's high-severity findings equal the reviewed exception set."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "release/evidence/security-exceptions-v1.json"


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _version(value: str) -> tuple[int, int, int]:
    pieces = value.split(".")
    if len(pieces) != 3 or any(not piece.isdigit() for piece in pieces):
        raise ValueError(f"non-canonical release version: {value!r}")
    return tuple(int(piece) for piece in pieces)  # type: ignore[return-value]


def _read_manifest() -> dict[str, Any]:
    document = json.loads(MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=_object)
    if set(document) != {"exceptions", "policy", "schema_version"}:
        raise ValueError("security exception manifest has unexpected fields")
    if document["schema_version"] != "quarry.security-exceptions.v1":
        raise ValueError("unsupported security exception schema")
    if document["policy"] != {
        "bandit_confidence": "HIGH",
        "bandit_severity": "HIGH",
        "unexpected_findings": "fail",
    }:
        raise ValueError("security exception policy is not fail-closed")
    return document


def _expected(document: dict[str, Any], project_version: tuple[int, int, int]) -> list[dict[str, Any]]:
    fields = {
        "code_sha256", "expires_before", "line", "owner", "path", "rationale", "test_id"
    }
    result = []
    identities: set[tuple[str, str, int]] = set()
    for row in document["exceptions"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError("security exception row has unexpected fields")
        if (
            not isinstance(row["path"], str)
            or not row["path"].startswith("src/quarry_recon/")
            or pathlib.PurePosixPath(row["path"]).is_absolute()
            or ".." in pathlib.PurePosixPath(row["path"]).parts
        ):
            raise ValueError("security exception path is not canonical")
        if not isinstance(row["line"], int) or isinstance(row["line"], bool) or row["line"] < 1:
            raise ValueError("security exception line is invalid")
        if not isinstance(row["test_id"], str) or not row["test_id"]:
            raise ValueError("security exception test_id is invalid")
        if not isinstance(row["code_sha256"], str) or len(row["code_sha256"]) != 64:
            raise ValueError("security exception code digest is invalid")
        int(row["code_sha256"], 16)
        if not isinstance(row["owner"], str) or not row["owner"].strip():
            raise ValueError("security exception owner is missing")
        if not isinstance(row["rationale"], str) or len(row["rationale"].strip()) < 20:
            raise ValueError("security exception rationale is missing")
        expiry = _version(row["expires_before"])
        if project_version >= expiry:
            raise ValueError(f"expired security exception: {row['path']}:{row['line']}")
        identity = (row["path"], row["test_id"], row["line"])
        if identity in identities:
            raise ValueError("duplicate security exception identity")
        identities.add(identity)
        result.append({
            "code_sha256": row["code_sha256"],
            "line": row["line"],
            "path": row["path"],
            "test_id": row["test_id"],
        })
    return sorted(result, key=lambda row: (row["path"], row["line"], row["test_id"]))


def _observed() -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["bandit", "-q", "-r", "src", "-lll", "-f", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"bandit failed ({completed.returncode}): {completed.stderr.strip()}")
    report = json.loads(completed.stdout, object_pairs_hook=_object)
    if report.get("errors"):
        raise RuntimeError(f"bandit reported scan errors: {report['errors']!r}")
    result = []
    for row in report.get("results", []):
        if row.get("issue_severity") != "HIGH" or row.get("issue_confidence") != "HIGH":
            raise RuntimeError("bandit -lll returned a finding outside the requested policy")
        result.append({
            "code_sha256": hashlib.sha256(row["code"].encode("utf-8")).hexdigest(),
            "line": row["line_number"],
            "path": row["filename"],
            "test_id": row["test_id"],
        })
    return sorted(result, key=lambda row: (row["path"], row["line"], row["test_id"]))


def main() -> int:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    expected = _expected(_read_manifest(), _version(project["project"]["version"]))
    observed = _observed()
    if observed != expected:
        print("Bandit high-severity findings differ from reviewed exceptions.", file=sys.stderr)
        print(json.dumps({"expected": expected, "observed": observed}, indent=2), file=sys.stderr)
        return 1
    print(f"Bandit high-severity exception set is exact ({len(observed)} reviewed findings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
