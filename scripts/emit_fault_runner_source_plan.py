#!/usr/bin/env python3
"""Emit the exact, explicitly non-promoting C-FAULT-RUNNER source plan."""

from __future__ import annotations

import argparse
from pathlib import Path

from quarry_recon import fault_runner_evidence as fault_runner


ROOT = Path(__file__).resolve().parents[1]


def _inputs() -> dict[str, bytes]:
    return {
        name: (ROOT / path).read_bytes()
        for name, path in fault_runner.INPUT_PATHS.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-identity-digest", required=True)
    parser.add_argument("--case-manifest-output", type=Path, required=True)
    parser.add_argument("--source-plan-output", type=Path, required=True)
    args = parser.parse_args(argv)
    bodies = _inputs()
    manifest = fault_runner.canonical_case_manifest_bytes()
    if bodies["fault-runner-case-manifest"] != manifest:
        parser.error("committed fault-runner manifest is not the frozen v1 roster")
    plan = fault_runner.build_source_plan(
        candidate_identity_digest=args.candidate_identity_digest,
        input_bodies=bodies,
    )
    args.case_manifest_output.write_bytes(manifest)
    args.source_plan_output.write_bytes(
        fault_runner.canonical_source_plan_bytes(
            plan,
            candidate_identity_digest=args.candidate_identity_digest,
            input_bodies=bodies,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
