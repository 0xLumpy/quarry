"""Focused B-DETERMINISM fixture, paired-root producer and parser tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence
from scripts import emit_determinism as producer


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline


def _fragment(tmp_path: Path) -> bytes:
    h0 = tmp_path / "h0.json"
    output = tmp_path / "diff.json"
    h0.write_bytes(b"{}\n")
    assert (
        producer.main(
            [
                "--fixture",
                str(ROOT / contracts.MANIFEST_PATHS["determinism-fixture"]),
                "--h0-fragment",
                str(h0),
                "--job-instance-id",
                contracts._DETERMINISM_JOB_ID,
                "--output",
                str(output),
            ]
        )
        == 0
    )
    return output.read_bytes()


def test_fixture_and_raw_fragment_are_strict_and_byte_recomputed(tmp_path):
    fixture_body = (ROOT / contracts.MANIFEST_PATHS["determinism-fixture"]).read_bytes()
    fixture = contracts.read_determinism_fixture(fixture_body)
    fragment_body = _fragment(tmp_path)
    fragment = contracts.read_determinism_fragment(fragment_body)
    schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["determinism-fragment-schema"]).read_bytes()
    )
    assert list(Draft202012Validator(schema).iter_errors(fragment)) == []
    assert (
        schema["properties"]["artifact_differences"]["maximum"]
        == evidence.MAX_JSON_INTEGER
    )
    assert (
        schema["$defs"]["file"]["properties"]["bytes"]["maximum"]
        == evidence.MAX_JSON_INTEGER
    )
    wrapper_schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["artifact-tree-diff-schema"]).read_bytes()
    )
    assert (
        wrapper_schema["properties"]["artifact_differences"]["maximum"]
        == evidence.MAX_JSON_INTEGER
    )
    assert (
        wrapper_schema["$defs"]["file"]["properties"]["bytes"]["maximum"]
        == evidence.MAX_JSON_INTEGER
    )
    expected = [
        contracts._determinism_expected_tree(fixture, "run-1"),
        contracts._determinism_expected_tree(fixture, "run-2"),
    ]
    assert fragment["runs"] == expected
    assert fragment["fixture_digest"] == expected[0]["tree_digest"]
    assert fragment["artifact_differences"] == 0


def test_fragment_refuses_forged_difference_cardinality_and_tree_digest(tmp_path):
    fragment = contracts.read_determinism_fragment(_fragment(tmp_path))
    forged = copy.deepcopy(fragment)
    forged["artifact_differences"] = 1
    with pytest.raises(evidence.EvidenceError, match="differences"):
        contracts.read_determinism_fragment(contracts.canonical_json_line(forged))
    forged = copy.deepcopy(fragment)
    forged["runs"][0]["tree_digest"] = "sha256:" + "0" * 64
    with pytest.raises(evidence.EvidenceError, match="tree digest"):
        contracts.read_determinism_fragment(contracts.canonical_json_line(forged))
    forged = copy.deepcopy(fragment)
    forged["runs"][0]["files"] = []
    forged["runs"][0]["tree_digest"] = evidence.canonical_digest([])
    with pytest.raises(evidence.EvidenceError, match="exactly three files"):
        contracts.read_determinism_fragment(contracts.canonical_json_line(forged))


def test_producer_rehashes_opened_artifact_bytes(tmp_path, monkeypatch):
    opened = []
    original = Path.open

    def tracked_open(path, *args, **kwargs):
        if path.parent.name.startswith("quarry-determinism-") and args[:1] == ("rb",):
            opened.append(path.name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked_open)
    contracts.read_determinism_fragment(_fragment(tmp_path))
    assert sorted(opened) == [
        "canonical.json",
        "canonical.json",
        "manifest.json",
        "manifest.json",
        "report.json",
        "report.json",
    ]


def test_producer_refuses_a_fixture_path_that_escapes_its_isolated_root(tmp_path):
    fixture = json.loads(
        (ROOT / contracts.MANIFEST_PATHS["determinism-fixture"]).read_bytes()
    )
    fixture["artifacts"][0]["path"] = "../outside.json"
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_bytes(contracts.canonical_json_line(fixture))
    h0 = tmp_path / "h0.json"
    h0.write_bytes(b"{}\n")
    with pytest.raises(SystemExit, match="artifact is invalid"):
        producer.main(
            [
                "--fixture",
                str(fixture_path),
                "--h0-fragment",
                str(h0),
                "--job-instance-id",
                contracts._DETERMINISM_JOB_ID,
                "--output",
                str(tmp_path / "out.json"),
            ]
        )


def test_producer_refuses_an_oversized_input_before_json_parsing(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * producer.MAX_INPUT_BYTES + b"}")
    with pytest.raises(SystemExit, match="input bound"):
        producer.main(
            [
                "--fixture",
                str(oversized),
                "--h0-fragment",
                str(oversized),
                "--job-instance-id",
                contracts._DETERMINISM_JOB_ID,
                "--output",
                str(tmp_path / "out.json"),
            ]
        )
