"""H1 synthetic transport-admission receipt for C-SOURCE-REGISTRY."""
from __future__ import annotations

from pathlib import Path

import pytest

from quarry_recon import source_registry_evidence as registry


ROOT = Path(__file__).resolve().parents[1]
pytestmark = [pytest.mark.integration, pytest.mark.requires_tool("pytest")]


def test_h1_synthetic_transport_admission_receipt():
    """Observe only ``transport_door`` admission; do not launch an adapter or tool."""
    bodies = {name: (ROOT / path).read_bytes() for name, path in registry._INPUT_PATHS.items()}
    artifact = registry.build(candidate_identity_digest="sha256:" + "a" * 64, input_bodies=bodies)
    receipt = artifact["h1_synthetic_admission"]["receipt"]
    assert receipt["nodeid"] == "tests/test_source_registry_h1_contract.py::test_h1_synthetic_transport_admission_receipt"
    assert receipt["result"] == "pass"
    assert registry.verify(artifact, input_bodies=bodies) == artifact
