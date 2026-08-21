#!/usr/bin/env python3
"""Emit the bounded, explicitly non-promoting C-PATH-IDENTITY artifacts."""
from __future__ import annotations

import argparse
from pathlib import Path

from quarry_recon import path_identity_evidence as path_identity


ROOT = Path(__file__).resolve().parents[1]


def _inputs() -> dict[str, bytes]:
    return {
        name: (ROOT / path).read_bytes()
        for name, path in path_identity.INPUT_PATHS.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-identity-digest", required=True)
    parser.add_argument("--property-corpus-output", type=Path, required=True)
    parser.add_argument("--containment-decisions-output", type=Path, required=True)
    args = parser.parse_args(argv)
    bodies = _inputs()
    corpus = path_identity.canonical_property_corpus_bytes()
    if bodies["path-identity-corpus"] != corpus:
        parser.error("committed property corpus is not the canonical bounded roster")
    decisions = path_identity.build_containment_decisions(
        candidate_identity_digest=args.candidate_identity_digest,
        input_bodies=bodies,
    )
    args.property_corpus_output.write_bytes(corpus)
    args.containment_decisions_output.write_bytes(
        path_identity.canonical_containment_decisions_bytes(
            decisions,
            candidate_identity_digest=args.candidate_identity_digest,
            input_bodies=bodies,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
