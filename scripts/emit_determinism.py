#!/usr/bin/env python3
"""Emit a candidate-independent B-DETERMINISM paired artifact-tree diff."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from collections.abc import Sequence
from pathlib import Path

from quarry_recon import release_evidence, report_truth, run_manifest


ROOT = Path(__file__).resolve().parents[1]
JOB_ID = ".github/workflows/ci.yml#jobs.offline[python-version=3.12,shard=0]"
MAX_INPUT_BYTES = 1024 * 1024


def _sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _canonical(value: object) -> bytes:
    return release_evidence.canonical_json_bytes(value) + b"\n"


def _read_bounded(path: Path, label: str) -> bytes:
    with path.open("rb") as handle:
        body = handle.read(MAX_INPUT_BYTES + 1)
    if len(body) > MAX_INPUT_BYTES:
        raise SystemExit(f"{label} exceeds the {MAX_INPUT_BYTES}-byte input bound")
    return body


def _fixture(data: bytes) -> dict:
    document = json.loads(data)
    if data != _canonical(document):
        raise SystemExit("determinism fixture is not canonical JSON")
    if (
        document.get("schema_version") != "quarry.determinism-fixture.v1"
        or document.get("release") != "0.3.10"
    ):
        raise SystemExit("unsupported determinism fixture")
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        raise SystemExit("determinism fixture must have exactly three artifacts")
    expected_builders = ("release-evidence", "run-manifest", "report-truth")
    paths = []
    for index, row in enumerate(artifacts):
        if not isinstance(row, dict) or set(row) != {"builder", "document", "path"}:
            raise SystemExit("determinism fixture artifact is incomplete")
        path = row["path"]
        if (
            row["builder"] != expected_builders[index]
            or type(row["document"]) is not dict
            or not isinstance(path, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", path) is None
        ):
            raise SystemExit("determinism fixture artifact is invalid")
        paths.append(path)
    if paths != sorted(paths) or len(set(paths)) != 3:
        raise SystemExit("determinism fixture paths must be sorted and unique")
    return document


def _builder(name: str, document: object) -> bytes:
    if name == "release-evidence":
        return release_evidence.canonical_json_bytes(document) + b"\n"
    if name == "run-manifest":
        return run_manifest.canonical_json_bytes(document)
    if name == "report-truth":
        if not isinstance(document, dict):
            raise SystemExit("report-truth fixture document must be an object")
        return report_truth.canonical_json_bytes(document)
    raise SystemExit("unsupported determinism fixture builder")


def _tree(root: Path, artifacts: list[object], run_id: str) -> dict:
    for row in artifacts:
        if not isinstance(row, dict):
            raise SystemExit("determinism fixture artifact is not an object")
        path, builder, document = (
            row.get("path"),
            row.get("builder"),
            row.get("document"),
        )
        if not isinstance(path, str) or not isinstance(builder, str):
            raise SystemExit("determinism fixture artifact is incomplete")
        (root / path).write_bytes(_builder(builder, document))
    files = []
    for path in sorted(root.iterdir(), key=lambda value: value.name):
        # Open every retained artifact and hash its actual bytes, never a claimed digest.
        with path.open("rb") as handle:
            body = handle.read()
        files.append({"bytes": len(body), "digest": _sha256(body), "path": path.name})
    return {
        "files": files,
        "id": run_id,
        "tree_digest": release_evidence.canonical_digest(files),
    }


def _differences(left: dict, right: dict) -> list[dict]:
    left_by_path = {row["path"]: row for row in left["files"]}
    right_by_path = {row["path"]: row for row in right["files"]}
    return [
        {"left": left_by_path.get(path), "path": path, "right": right_by_path.get(path)}
        for path in sorted(set(left_by_path) | set(right_by_path))
        if left_by_path.get(path) != right_by_path.get(path)
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--h0-fragment", required=True, type=Path)
    parser.add_argument("--job-instance-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.job_instance_id != JOB_ID:
        raise SystemExit("determinism must bind the exact Python 3.12 shard-0 job")
    fixture_body = _read_bounded(args.fixture, "determinism fixture")
    fixture = _fixture(fixture_body)
    # The H0 shard report remains a retained, re-hashed input; it is not a string claim.
    h0_fragment = _read_bounded(args.h0_fragment, "H0 fragment")
    with (
        tempfile.TemporaryDirectory(prefix="quarry-determinism-a-") as left_dir,
        tempfile.TemporaryDirectory(prefix="quarry-determinism-b-") as right_dir,
    ):
        left = _tree(Path(left_dir), fixture["artifacts"], "run-1")
        right = _tree(Path(right_dir), fixture["artifacts"], "run-2")
    differences = _differences(left, right)
    if left["tree_digest"] != right["tree_digest"]:
        raise SystemExit("determinism fixture produced distinct output tree identities")
    args.output.write_bytes(
        _canonical(
            {
                "artifact_differences": len(differences),
                "artifact_type": "artifact-tree-diff-fragment",
                "differences": differences,
                "fixture_digest": left["tree_digest"],
                "fixture_manifest_digest": _sha256(fixture_body),
                "h0_fragment_digest": _sha256(h0_fragment),
                "job_instance_id": args.job_instance_id,
                "release": "0.3.10",
                "runs": [left, right],
                "schema_version": "quarry.determinism-tree-diff-fragment.v1",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
