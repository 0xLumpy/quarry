#!/usr/bin/env python3
"""Emit the bounded, execution-free C-SOURCE-REGISTRY reconciliation artifact."""
from __future__ import annotations

import argparse
from pathlib import Path

from quarry_recon import source_registry_evidence as registry


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-identity-digest", required=True)
    parser.add_argument("--h0-evidence-instance-id", default="instance-00")
    parser.add_argument("--h1-evidence-instance-id", default="instance-01")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    bodies = {name: (ROOT / path).read_bytes() for name, path in registry._INPUT_PATHS.items()}
    args.output.write_bytes(registry.canonical_json_bytes(registry.build(
        candidate_identity_digest=args.candidate_identity_digest, input_bodies=bodies,
        h0_evidence_instance_id=args.h0_evidence_instance_id,
        h1_evidence_instance_id=args.h1_evidence_instance_id,
    )))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
