"""Focused fail-closed tests for the opt-in H0 pytest shard report."""

from __future__ import annotations

import json
import stat
from types import SimpleNamespace

import conftest as collector
import pytest

from quarry_recon import release_evidence as evidence


pytestmark = pytest.mark.offline


class _Config:
    def __init__(self, **values):
        self.values = values

    def getoption(self, name):
        return self.values[name]


def _state(*, selected=("tests/a.py::test_a",), full=None):
    selected = list(selected)
    return {
        "collection_failures": 0,
        "full_h0": list(full if full is not None else selected),
        "output": "unused",
        "reports": {nodeid: {} for nodeid in selected},
        "selected": selected,
    }


def _config():
    return _Config(
        keyword="",
        markexpr="offline",
        quarry_shard_count=2,
        quarry_shard_index=1,
    )


def _report(nodeid, when, outcome, wasxfail=None):
    return SimpleNamespace(nodeid=nodeid, when=when, outcome=outcome, wasxfail=wasxfail)


def _complete(state, nodeid, *, setup=("passed", None), call=("passed", None), teardown=("passed", None)):
    for when, result in (("setup", setup), ("call", call), ("teardown", teardown)):
        if result is not None:
            collector._record_h0_report(state, _report(nodeid, when, *result))


def test_pass_report_is_canonical_and_candidate_agnostic():
    state = _state(selected=("tests/b.py::test_b",), full=("tests/a.py::test_a", "tests/b.py::test_b"))
    _complete(state, "tests/b.py::test_b")
    body = collector._h0_shard_report_bytes(_config(), state, 0)
    document = evidence.read_h0_shard_outcome_report(body)
    assert body == evidence.canonical_json_bytes(document)
    assert document["outcomes"] == {
        "failed": 0, "passed": 1, "skipped": 0, "xfailed": 0, "xpassed": 0,
    }
    assert document["full_h0_roster"] == {
        "count": 2,
        "digest": collector._h0_roster_digest(state["full_h0"]),
    }
    assert document["passed_roster"] == {
        "count": 1,
        "digest": collector._h0_roster_digest(["tests/b.py::test_b"]),
    }
    assert "candidate" not in body.decode("utf-8")


@pytest.mark.parametrize(
    ("setup", "call", "teardown", "expected"),
    [
        (("passed", None), ("skipped", None), ("passed", None), "skipped"),
        (("passed", None), ("skipped", "expected"), ("passed", None), "xfailed"),
        (("passed", None), ("passed", "expected"), ("passed", None), "xpassed"),
        (("failed", None), None, ("skipped", None), "failed"),
        (("passed", None), ("passed", None), ("failed", None), "failed"),
        # Strict XPASS remains an XPASS outcome while the pytest session fails.
        (("passed", None), ("failed", "expected"), ("passed", None), "xpassed"),
    ],
)
def test_phase_composition_preserves_failure_precedence(setup, call, teardown, expected):
    state = _state()
    _complete(state, "tests/a.py::test_a", setup=setup, call=call, teardown=teardown)
    assert collector._h0_node_outcome("tests/a.py::test_a", state["reports"]["tests/a.py::test_a"]) == expected


def test_duplicate_unknown_and_incomplete_results_are_rejected():
    state = _state()
    collector._record_h0_report(state, _report("tests/a.py::test_a", "setup", "passed"))
    with pytest.raises(pytest.UsageError, match="duplicate"):
        collector._record_h0_report(state, _report("tests/a.py::test_a", "setup", "passed"))
    with pytest.raises(pytest.UsageError, match="unknown result"):
        collector._record_h0_report(state, _report("tests/missing.py::test_a", "setup", "passed"))
    with pytest.raises(pytest.UsageError, match="incomplete"):
        collector._h0_node_outcome("tests/a.py::test_a", state["reports"]["tests/a.py::test_a"])


def test_roster_digest_is_order_invariant_and_rejects_duplicates():
    nodes = ["tests/z.py::test_z", "tests/a.py::test_a"]
    assert collector._h0_roster_digest(nodes) == collector._h0_roster_digest(list(reversed(nodes)))
    with pytest.raises(pytest.UsageError, match="duplicate"):
        collector._h0_roster_digest([nodes[0], nodes[0]])


def test_shared_roster_and_shard_helpers_match_the_collector_and_fail_closed():
    nodes = ["tests/z.py::test_z", "tests/a.py::test_a"]
    assert evidence.h0_roster_digest(nodes) == collector._h0_roster_digest(nodes)
    for nodeid in nodes:
        assert evidence.h0_shard_index(nodeid, 7) == collector._test_shard(nodeid, 7)
    with pytest.raises(evidence.EvidenceError, match="1..64"):
        evidence.h0_shard_index(nodes[0], 0)
    with pytest.raises(evidence.EvidenceError, match="duplicate"):
        evidence.h0_roster_digest([nodes[0], nodes[0]])


def test_shards_keep_the_full_digest_and_bind_distinct_selected_digests():
    full = ["tests/a.py::test_a", "tests/b.py::test_b"]
    first = _state(selected=(full[0],), full=full)
    second = _state(selected=(full[1],), full=full)
    _complete(first, full[0])
    _complete(second, full[1])
    first_document = json.loads(collector._h0_shard_report_bytes(_config(), first, 0))
    second_document = json.loads(collector._h0_shard_report_bytes(_config(), second, 0))
    assert first_document["full_h0_roster"] == second_document["full_h0_roster"]
    assert first_document["selected_roster"]["digest"] != second_document["selected_roster"]["digest"]


def test_parser_rejects_noncanonical_oversize_and_unreconciled_documents():
    state = _state()
    _complete(state, "tests/a.py::test_a")
    body = collector._h0_shard_report_bytes(_config(), state, 0)
    with pytest.raises(evidence.EvidenceError, match="canonical"):
        evidence.read_h0_shard_outcome_report(body + b"\n")
    with pytest.raises(evidence.EvidenceError, match="exceeds"):
        evidence.read_h0_shard_outcome_report(b" " * (evidence.MAX_H0_SHARD_OUTCOME_REPORT_BYTES + 1))
    document = json.loads(body)
    document["outcomes"]["passed"] = 0
    with pytest.raises(evidence.EvidenceError, match="reconcile"):
        evidence.validate_h0_shard_outcome_report(document)

    wrong_selection = json.loads(body)
    wrong_selection["mark_expression"] = "offline or integration"
    with pytest.raises(evidence.EvidenceError, match="offline marker"):
        evidence.validate_h0_shard_outcome_report(wrong_selection)
    document = json.loads(body)
    document["session_exit_code"] = 6
    with pytest.raises(evidence.EvidenceError, match="0..5"):
        evidence.validate_h0_shard_outcome_report(document)


def test_create_only_private_writer_for_h0_reports(tmp_path):
    target = tmp_path / "report.json"
    collector._write_new_private(target, b"first", label="H0 shard outcome report")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(pytest.UsageError, match="cannot create H0 shard outcome report"):
        collector._write_new_private(target, b"replacement", label="H0 shard outcome report")


def test_start_refuses_vacuous_or_non_h0_selection():
    rows = [("tests/a.py::test_a", "offline", (), False), ("tests/b.py::test_b", "integration", ("git",), False)]
    config = _Config(quarry_h0_shard_report="out.json", markexpr="offline", keyword="")
    with pytest.raises(pytest.UsageError, match="vacuous"):
        collector._start_h0_shard_report(config, rows, [])
    with pytest.raises(pytest.UsageError, match="only offline"):
        collector._start_h0_shard_report(config, rows, ["tests/b.py::test_b"])


def test_start_requires_the_exact_h0_selection_expression():
    rows = [("tests/a.py::test_a", "offline", (), False)]
    config = _Config(quarry_h0_shard_report="out.json", markexpr="offline or integration", keyword="")
    with pytest.raises(pytest.UsageError, match="exactly '-m offline'"):
        collector._start_h0_shard_report(config, rows, ["tests/a.py::test_a"])


def test_collection_hook_freezes_post_marker_taxonomy_before_sharding(monkeypatch):
    nodes = ["tests/a.py::test_a", "tests/b.py::test_b"]
    shard_index = evidence.h0_shard_index(nodes[0], 2)
    while evidence.h0_shard_index(nodes[1], 2) == shard_index:
        nodes[1] += "x"
    items = [SimpleNamespace(nodeid=nodeid) for nodeid in (*nodes, "tests/i.py::test_i")]

    class Hook:
        def pytest_deselected(self, *, items):
            self.deselected = list(items)

    config = _Config(
        keyword="",
        markexpr="offline",
        quarry_h0_shard_report="report.json",
        quarry_shard_count=2,
        quarry_shard_index=shard_index,
        quarry_taxonomy_manifest=None,
    )
    config.stash = {collector.H0_COLLECTION_FAILURES_KEY: 0}
    config.hook = Hook()
    monkeypatch.setattr(
        collector,
        "_classify_test_item",
        lambda item: (
            ("integration", ("pytest",), False)
            if item.nodeid.endswith("test_i") else ("offline", (), False)
        ),
    )

    hook = collector.pytest_collection_modifyitems(config, items)
    next(hook)
    items[:] = items[:2]  # pytest's marker hook has selected the full offline lane.
    with pytest.raises(StopIteration):
        next(hook)

    taxonomy = evidence.read_pytest_taxonomy(config.stash[collector.TAXONOMY_MANIFEST_KEY])
    assert taxonomy["lanes"][0]["nodes"] == sorted(nodes)
    assert taxonomy["selection"]["selected"] == 2
    state = config.stash[collector.H0_SHARD_REPORT_STATE_KEY]
    assert state["full_h0"] == sorted(nodes)
    assert state["selected"] == [nodes[0]]
