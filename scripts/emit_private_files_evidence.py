#!/usr/bin/env python3
"""Emit deterministic OPEN C-PRIVATE-FILES source-substrate artifacts."""
from __future__ import annotations

import argparse
from pathlib import Path

from quarry_recon import private_files_evidence as private_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-identity-digest", required=True)
    parser.add_argument("--h0-evidence-instance-id", default="instance-00")
    parser.add_argument("--h1-evidence-instance-id", default="instance-01")
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output_directory.mkdir(parents=True, exist_ok=True)
    artifacts = private_files.build_source_substrate(
        candidate_identity_digest=args.candidate_identity_digest,
        h0_evidence_instance_id=args.h0_evidence_instance_id,
        h1_evidence_instance_id=args.h1_evidence_instance_id,
    )
    for name, document in artifacts.items():
        (args.output_directory / f"{name}.json").write_bytes(private_files.canonical_json_bytes(document))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
