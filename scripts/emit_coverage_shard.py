#!/usr/bin/env python3
"""Emit one bounded, canonical coverage fragment from an existing H0 shard run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        + b"\n"
    )


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _positive_lines(values: object, path: str) -> list[int]:
    if not isinstance(values, list) or any(
        type(value) is not int or value < 1 for value in values
    ):
        raise SystemExit(f"coverage JSON has invalid {path} lines")
    result = sorted(set(values))
    if len(result) != len(values):
        raise SystemExit(f"coverage JSON has duplicate {path} lines")
    return result


def _arcs(values: object, path: str) -> list[list[int]]:
    if not isinstance(values, list):
        raise SystemExit(f"coverage JSON has invalid {path} branches")
    result = []
    for value in values:
        if (
            not isinstance(value, list)
            or len(value) != 2
            or any(type(part) is not int for part in value)
        ):
            raise SystemExit(f"coverage JSON has invalid {path} branch arc")
        result.append(value)
    normalized = [list(value) for value in sorted(set(map(tuple, result)))]
    if len(normalized) != len(result):
        raise SystemExit(f"coverage JSON has duplicate {path} branches")
    return normalized


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage-json", required=True, type=Path)
    parser.add_argument("--coverage-data", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--h0-fragment", required=True, type=Path)
    parser.add_argument("--job-instance-id", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_bytes())
    roster = policy.get("source_roster")
    if not isinstance(roster, list) or roster != sorted(set(roster)):
        raise SystemExit("coverage policy source roster is not canonical")
    if args.job_instance_id not in policy.get("h0_job_ids", []):
        raise SystemExit("coverage job is not in the frozen policy")
    report = json.loads(args.coverage_json.read_bytes())
    meta = report.get("meta")
    if (
        not isinstance(meta, dict)
        or meta.get("format") != 3
        or meta.get("version") != "7.15.4"
        or meta.get("branch_coverage") is not True
        or meta.get("show_contexts") is not True
    ):
        raise SystemExit("coverage JSON meta is not the frozen branch-coverage format")
    files = report.get("files")
    if not isinstance(files, dict) or set(files) != set(roster):
        raise SystemExit("coverage JSON source roster differs from the frozen policy")
    normalized = []
    for path in roster:
        item = files[path]
        if not isinstance(item, dict) or not isinstance(item.get("summary"), dict):
            raise SystemExit("coverage JSON file body or summary is not an object")
        statements = _positive_lines(
            item.get("executed_lines", []) + item.get("missing_lines", []), path
        )
        executed = _positive_lines(item.get("executed_lines", []), path)
        contexts = item.get("contexts")
        expected_contexts = {str(line) for line in executed}
        if (
            not isinstance(contexts, dict)
            or not expected_contexts.issubset(contexts)
            or any(values != [args.job_instance_id] for values in contexts.values())
        ):
            raise SystemExit(
                "coverage JSON contexts do not bind exactly one frozen job"
            )
        possible = _arcs(
            item.get("executed_branches", []) + item.get("missing_branches", []), path
        )
        executed_branches = _arcs(item.get("executed_branches", []), path)
        if not set(executed).issubset(statements) or not set(
            map(tuple, executed_branches)
        ).issubset(map(tuple, possible)):
            raise SystemExit("coverage JSON execution facts exceed their universe")
        summary = item["summary"]
        expected = {
            "num_statements": len(statements),
            "covered_lines": len(executed),
            "num_branches": len(possible),
            "covered_branches": len(executed_branches),
        }
        if any(summary.get(name) != value for name, value in expected.items()):
            raise SystemExit(
                "coverage JSON summary does not reconcile with normalized facts"
            )
        normalized.append(
            {
                "executed_branches": executed_branches,
                "executed_lines": executed,
                "path": path,
                "possible_branches": possible,
                "statements": statements,
            }
        )
    fragment = {
        "config_digest": _digest(args.config),
        "coverage_policy_digest": _digest(args.policy),
        "coverage_version": "7.15.4",
        "files": normalized,
        "h0_fragment_digest": _digest(args.h0_fragment),
        "job_instance_id": args.job_instance_id,
        "raw_coverage_data_digest": _digest(args.coverage_data),
        "schema_version": "quarry.coverage-shard.v1",
        "source_roster": roster,
    }
    args.output.write_bytes(_canonical(fragment))


if __name__ == "__main__":
    main()
