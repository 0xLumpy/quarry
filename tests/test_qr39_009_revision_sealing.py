"""Sealing is keyed off the committed base manifest, and publication is serialized.

Three ways a late callback still reached, or lost, evidence it should not have. `base_finished` recognised
only `finished` (revision.py:81), so a `finalization_failed` run — which commits its manifest before its
views are published — selected the live sink (revision.py:390) and the callback mutated a sealed base. A
present-but-unreadable `state.json` fell through to the manifest check (revision.py:65) and read as
finished, so an unreadable lifecycle authorised a revision. And choosing the next revision was not
serialized against publishing it (revision.py:469 → revision.py:531), so two concurrent imports raced.
"""
import json
import threading

import pytest

from quarry_recon import oob, revision
from quarry_recon.store import Run, fold_run_entity

pytestmark = pytest.mark.offline


def _callback(full_id: str, remote: str) -> str:
    return json.dumps({"protocol": "dns", "unique-id": "csession01", "full-id": full_id, "q-type": "A",
                       "remote-address": remote, "timestamp": "2026-08-10T12:00:00Z"}) + "\n"


def _run_in_state(tmp_path, state: str) -> Run:
    """A run taken through the real transitions to `state`; the manifest commits inside `finalizing`."""
    run = Run.create(tmp_path / "proj", "example.com")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    if state != "finalizing":
        run.write_state(state)
    return run


def _import(run, tmp_path, name: str, full_id: str, remote: str = "203.0.113.9"):
    src = tmp_path / name
    src.write_text(_callback(full_id, remote))
    return oob.import_file(run, src)


# ── a committed manifest seals the run, whatever its state is called ──────────────────────────────
@pytest.mark.parametrize("state", ["finished", "finalization_failed"])
def test_a_committed_manifest_is_never_mutated_by_a_late_callback(tmp_path, state):
    run = _run_in_state(tmp_path, state)
    assert run.manifest_path.exists()
    before = run.manifest_path.read_bytes()

    res = _import(run, tmp_path, "cb.jsonl", "qlate.csession01")

    assert res["revision"] is not None, f"state {state!r} took the live sink and mutated a sealed base"
    assert res["revision"].entity_counts["oob_interaction"] == 1
    assert not (run.dir / "normalized" / "oob_interaction.jsonl").exists()
    assert run.manifest_path.read_bytes() == before
    assert fold_run_entity(run.dir, "oob_interaction").trustworthy   # no count contradicts its own log


def test_a_failed_finalisation_still_takes_revisions(tmp_path):
    run = _run_in_state(tmp_path, "finalization_failed")
    first = _import(run, tmp_path, "a.jsonl", "q1.csession01")["revision"]
    second = _import(run, tmp_path, "b.jsonl", "q2.csession01", "198.51.100.7")["revision"]

    assert (first.revision, second.revision) == (1, 2)
    assert second.entity_counts["oob_interaction"] == 2
    assert run.state == "finalization_failed"      # a supplement never advances the base's own lifecycle


def test_a_run_that_still_owns_its_log_is_untouched(tmp_path):
    run = Run.create(tmp_path / "proj", "example.com")
    run.write_state("running")
    assert revision.base_disposition(run.dir) == (revision.LIVE, "")

    assert _import(run, tmp_path, "cb.jsonl", "q1.csession01")["revision"] is None
    assert run.count("oob_interaction") == 1


# ── an unreadable lifecycle record refuses both paths ─────────────────────────────────────────────
@pytest.mark.parametrize("body", ["{ not json", '"a string"', '{"state": "invented"}', '{"stage": "x"}', "",
                                  '{"state": "unknown"}'])
def test_a_present_but_unreadable_state_refuses_late_evidence(tmp_path, body):
    run = _run_in_state(tmp_path, "finished")
    run.state_path.write_text(body)

    disposition, why = revision.base_disposition(run.dir)
    assert disposition == revision.UNKNOWN and "no known run state" in why
    assert revision.base_finished(run.dir) is False
    with pytest.raises(revision.RevisionError, match="refusing to record late evidence"):
        _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert not (run.dir / "normalized" / "oob_interaction.jsonl").exists()
    assert not (run.dir / "revisions").exists()


def test_the_stores_unreadable_state_and_this_disposition_agree(tmp_path):
    """`Run.state` reports `state.STATE_UNKNOWN` for a lifecycle record it cannot read; a supplement must
    reach the same verdict, or a run the store calls unreadable would still be revisable."""
    from quarry_recon import state as _state

    run = _run_in_state(tmp_path, "finished")
    run.state_path.write_text("{ truncated")

    assert run.state == _state.STATE_UNKNOWN
    assert _state.STATE_UNKNOWN not in _state.RUN_STATES     # never a state a run may legally be in
    assert revision.UNKNOWN == _state.STATE_UNKNOWN          # one word for the fact, across both lanes
    assert revision.base_disposition(run.dir)[0] == revision.UNKNOWN
    assert revision.base_finished(run.dir) is False


def test_a_supplement_never_advances_the_base_lifecycle(tmp_path):
    """A revision is not a finalisation: the base keeps the state it rested in, so its committed manifest
    stays immutable under spine's `finished` guard."""
    from quarry_recon.state import ContractError

    run = _run_in_state(tmp_path, "finished")
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")

    assert run.state == "finished"
    with pytest.raises(ContractError):                       # still guarded after being supplemented
        run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    assert revision.read(run.dir).status == "valid"


def test_a_committed_state_without_a_manifest_refuses_late_evidence(tmp_path):
    run = Run.create(tmp_path / "proj", "example.com")
    run.state_path.write_text(json.dumps({"schema_version": 1, "run_id": run.run_id, "state": "finished"}))

    disposition, why = revision.base_disposition(run.dir)
    assert disposition == revision.UNKNOWN and "manifest is not committed" in why
    with pytest.raises(revision.RevisionError):
        _import(run, tmp_path, "cb.jsonl", "q1.csession01")


def test_a_run_with_no_lifecycle_record_reads_from_its_manifest(tmp_path):
    run = _run_in_state(tmp_path, "finished")
    run.state_path.unlink()                        # written before the lifecycle record existed

    assert revision.base_disposition(run.dir) == (revision.SEALED, "")
    assert _import(run, tmp_path, "cb.jsonl", "q1.csession01")["revision"].revision == 1


# ── publication is serialized ─────────────────────────────────────────────────────────────────────
def test_concurrent_imports_each_keep_their_callback(tmp_path):
    run = _run_in_state(tmp_path, "finished")
    writers = 4
    ready = threading.Barrier(writers)
    faults: list = []

    def publish(i: int) -> None:
        try:
            sink = revision.ingest(run, "oob.import")
            for row in oob.parse_interactsh(_callback(f"qc{i}.csession01", f"203.0.113.{i + 1}")):
                sink.add("oob_interaction", row)
            ready.wait(timeout=20)                 # every writer opened before any of them publishes
            sink.commit(None)
        except BaseException as e:                 # noqa: BLE001
            faults.append(f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=publish, args=(i,)) for i in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert faults == []
    published = revision.read(run.dir)
    assert published.status == "valid" and published.revision == writers
    assert len(published.segments) == writers      # no writer's segment was dropped from the chain
    assert published.entity_counts["oob_interaction"] == writers
    folded = revision.combined_fold(run.dir, "oob_interaction")
    assert folded.status == "valid"
    domains = {r["interaction_domain"] for r in folded.records.values()}
    assert domains == {f"qc{i}.csession01" for i in range(writers)}


def test_a_writer_that_opened_before_another_published_keeps_both(tmp_path):
    run = _run_in_state(tmp_path, "finished")
    stale = revision.ingest(run, "oob.import")     # opened at revision 0
    for row in oob.parse_interactsh(_callback("qslow.csession01", "203.0.113.9")):
        stale.add("oob_interaction", row)

    fast = _import(run, tmp_path, "fast.jsonl", "qfast.csession01", "198.51.100.7")["revision"]
    assert fast.revision == 1

    late = stale.commit(None)                      # must adopt revision 1 rather than publish over it
    assert late.revision == 2
    assert [s["file"] for s in late.segments] == ["rev0001/observations.jsonl", "rev0002/observations.jsonl"]
    assert late.entity_counts["oob_interaction"] == 2
    assert len(revision.combined_fold(run.dir, "oob_interaction").records) == 2
