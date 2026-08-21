"""Focused frozen-policy and candidate findings schema checks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence
from scripts import emit_static_security as producer


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline


def test_static_security_policy_is_exact_and_source_bound():
    body = (ROOT / contracts.STATIC_SECURITY_POLICY_PATH).read_bytes()
    policy = contracts.read_static_security_policy(body)
    schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["static-security-policy-schema"]).read_bytes()
    )
    assert list(Draft202012Validator(schema).iter_errors(policy)) == []
    assert policy["unsafe_apis"] == ["subprocess.Popen", "subprocess.run", "yaml.load"]
    assert policy["dependency_manifest"]["digest"] == contracts.raw_sha256(
        (ROOT / "pyproject.toml").read_bytes()
    )
    changed = copy.deepcopy(policy)
    changed["h0_property_tests"]["nodes"].pop()
    with pytest.raises(evidence.EvidenceError):
        contracts.read_static_security_policy(contracts.canonical_json_line(changed))


def test_security_findings_schema_rejects_unknown_and_incomplete_objects():
    schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["security-findings-schema"]).read_bytes()
    )
    validator = Draft202012Validator(schema)
    assert list(validator.iter_errors({"artifact_type": "security-findings"}))
    assert list(validator.iter_errors({"unexpected": True}))


def test_raw_fragment_schema_and_reader_are_strict(tmp_path, monkeypatch):
    policy_path = ROOT / contracts.STATIC_SECURITY_POLICY_PATH
    policy = contracts.read_static_security_policy(policy_path.read_bytes())
    h0_fragment = tmp_path / "h0.json"
    output = tmp_path / "security.json"
    h0_fragment.write_bytes(b"{}\n")
    monkeypatch.setattr(producer, "_tracked_secret_scan", lambda: None)
    monkeypatch.setattr(producer, "_bandit", lambda _policy: ([], []))
    monkeypatch.setattr(
        producer,
        "_unsafe_inventory",
        lambda _apis: [
            {**row, "source": "ast"} for row in policy["ast_inventory"]["entries"]
        ],
    )
    monkeypatch.setattr(
        producer.argparse.ArgumentParser,
        "parse_args",
        lambda _self: SimpleNamespace(
            h0_fragment=h0_fragment,
            job_instance_id=contracts._STATIC_SECURITY_JOB_ID,
            output=output,
            policy=policy_path,
        ),
    )
    assert producer.main() == 0
    body = output.read_bytes()
    document = contracts.read_static_security_fragment(body)
    schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["static-security-fragment-schema"]).read_bytes()
    )
    assert list(Draft202012Validator(schema).iter_errors(document)) == []
    changed = copy.deepcopy(document)
    changed["findings"] = [
        {
            "api": "B999",
            "id": "bandit-test",
            "line": 1,
            "path": "src/quarry_recon/example.py",
            "source": "ast",
        }
    ]
    changed["unsuppressed_findings"] = 1
    with pytest.raises(evidence.EvidenceError, match="source"):
        contracts.read_static_security_fragment(contracts.canonical_json_line(changed))
    assert list(Draft202012Validator(schema).iter_errors(changed))


def test_secret_scan_uses_an_exact_argument_vector(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[:3] == ["git", "ls-files", "-z"]:
            return SimpleNamespace(returncode=0, stdout=b"a.py\0b.py\0")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(producer.subprocess, "run", run)
    producer._tracked_secret_scan()
    assert calls[1][0] == [
        "detect-secrets-hook",
        "--baseline",
        ".secrets.baseline",
        "--no-verify",
        "a.py",
        "b.py",
    ]
    assert all("sh" not in call[0][:1] for call in calls)
