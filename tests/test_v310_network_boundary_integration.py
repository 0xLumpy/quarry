"""H1 witness registration for the root-netns network-boundary adversary."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence


pytestmark = [
    pytest.mark.integration,
    pytest.mark.requires_tool("ip"),
    pytest.mark.requires_tool("sudo"),
]


def test_network_boundary_adversary_emits_a_clean_bounded_diagnostic():
    sudo = shutil.which("sudo")
    if sudo is None or not pathlib.Path("/usr/sbin/ip").is_file():
        if os.environ.get("GITHUB_ACTIONS") == "true":
            pytest.fail("hosted H1 runner is missing declared sudo/ip capabilities")
        pytest.skip("requires sudo and iproute2 root network-namespace authority")
    authority = subprocess.run([sudo, "-n", "true"], capture_output=True, text=True)
    assert authority.returncode == 0, authority.stderr[-4000:]
    helper = pathlib.Path(__file__).with_name("helpers") / "v310_network_boundary_h1.py"
    source = pathlib.Path(__file__).parents[1] / "src"
    completed = subprocess.run(
        [sudo, "-n", "env", f"PYTHONPATH={source}",
         "PYTHONDONTWRITEBYTECODE=1", sys.executable, str(helper)],
        env=os.environ,
        capture_output=True, text=True, timeout=45,
    )
    assert len(completed.stdout.encode("utf-8")) <= 64 * 1024
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    assert lines, completed.stderr[-4000:]
    diagnostic = json.loads(lines[-1])
    assert diagnostic["schema_version"] == "quarry.network-boundary-h1.v1"
    assert diagnostic["acceptance_errors"] == [], diagnostic
    assert completed.returncode == 0, diagnostic
    identity = {"candidate": "integration-fixture"}
    environment = {
        "architecture": "x86_64",
        "isolation_profile": "sha256:" + "b" * 64,
        "lane": "H1-tool-integration",
        "os": "linux",
        "python": "3.12.13",
        "runner_image": "sha256:" + "a" * 64,
    }
    artifact = {
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-NETWORK-BOUNDARY",
        "instances": [{
            "diagnostic": diagnostic,
            "environment": {
                key: environment[key] for key in environment if key != "lane"
            },
            "identity": {
                "lane": environment["lane"], "python": environment["python"],
                "runner_image": environment["runner_image"],
            },
        }],
        "release": "0.3.10",
        "schema_version": contracts.NETWORK_BOUNDARY_TRACE_SCHEMA,
    }
    assert contracts._validate_network_boundary_trace(
        contracts.canonical_json_line(artifact),
        identity=identity, support={"environments": [environment]},
    ) == artifact
