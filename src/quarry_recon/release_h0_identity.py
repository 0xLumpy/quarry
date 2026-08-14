"""Bounded-child entry point for private H0 candidate identity collection."""
from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) != 5 or sys.argv[1] != "--repository" or sys.argv[3] != "--git":
        return 64
    repository = sys.argv[2]
    git_executable = sys.argv[4]
    if not os.path.isabs(repository) or not os.path.isabs(git_executable):
        return 64

    # Isolated Python has no ambient editable/user path.  Authority comes only
    # from the exact private candidate containing this launcher.
    candidate_src = os.path.join(repository, "src")
    sys.path.insert(0, candidate_src)
    from quarry_recon import release_evidence as evidence

    if os.path.realpath(evidence.__file__) != os.path.join(
        os.path.realpath(candidate_src), "quarry_recon", "release_evidence.py"
    ):
        return 65
    identity = evidence.collect_candidate_identity(
        repository,
        evidence.RELEASE_SCOPE,
        git_executable=git_executable,
        inputs=evidence.FUTURE_RUNNER_INPUTS,
    )
    body = evidence.canonical_json_bytes(identity)
    offset = 0
    while offset < len(body):
        written = os.write(sys.stdout.fileno(), body[offset:])
        if written <= 0:
            return 74
        offset += written
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
