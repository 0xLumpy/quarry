"""A revision certifies the evidence it was published over, and stays inside the run.

Five ways it did not. Certification digested the manifest but never the entity CONTENTS (revision.py:139),
so swapping `a.example.com` for `b.example.com` at the same count left the revision `valid`. A pointer's
`views.dir` was joined unchecked (revision.py:396), so an absolute path put a run's reports outside the
run. `_resettle` re-merged pending rows without re-running envelope admission (revision.py:551), so two
concurrent writers published past a one-key bound. A fully-refused import returned no refusal signal at
all (revision.py:510), reading as clean success. And supplements were allowed from the FIRST committed
manifest (revision.py:60), so one landing between a run's two seals was uncertified by the second.
"""
import json
import threading

import pytest

from quarry_recon import envelope, oob, revision
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


def _callback(full_id: str, remote: str = "203.0.113.9") -> str:
    return json.dumps({"protocol": "dns", "unique-id": "csession01", "full-id": full_id, "q-type": "A",
                       "remote-address": remote, "timestamp": "2026-08-10T12:00:00Z"}) + "\n"


def _sealed(tmp_path, *, settle: bool = True) -> Run:
    run = Run.create(tmp_path / "proj", "example.com")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    if settle:
        run.write_state("finished")
    return run


def _import(run, tmp_path, name: str, full_id: str):
    src = tmp_path / name
    src.write_text(_callback(full_id))
    return oob.import_file(run, src)


# ── the evidence itself is certified, not only its count ──────────────────────────────────────────
def test_a_same_count_content_swap_uncertifies_the_revision(tmp_path):
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert revision.read(run.dir).status == "valid"

    log = run.dir / "normalized" / "subdomain.jsonl"
    before = len(log.read_text().strip().splitlines())
    log.write_text(log.read_text().replace("a.example.com", "b.example.com"))
    assert len(log.read_text().strip().splitlines()) == before      # the count never moved

    stale = revision.read(run.dir)
    assert stale.status == "unusable" and "base evidence changed" in stale.reason
    assert revision.combined_view(run) is None
    assert revision.certification(run.dir)[0] == "unusable"


def test_evidence_appearing_or_vanishing_uncertifies_the_revision(tmp_path):
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    planted = run.dir / "normalized" / "secret.jsonl"
    planted.write_text(json.dumps({"value": "invented", "kind": "aws"}) + "\n")

    assert revision.read(run.dir).status == "unusable"
    planted.unlink()
    assert revision.read(run.dir).status == "valid"                 # and back, once the base is itself again
    (run.dir / "normalized" / "subdomain.jsonl").unlink()
    assert revision.read(run.dir).status == "unusable"


# ── a pointer may not name a directory outside the run ────────────────────────────────────────────
@pytest.mark.parametrize("planted", ["/tmp/quarry-escape-test", "../../../escape", "rev0002",
                                     "reports", "", "rev0001/../../escape", 17])
def test_a_view_directory_outside_the_revision_is_refused(tmp_path, planted):
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    doc = json.loads(revision.pointer_path(run.dir).read_text())
    doc["views"]["dir"] = planted
    revision.pointer_path(run.dir).write_bytes(revision._pointer_bytes(doc))

    broken = revision.read(run.dir)
    assert broken.status == "unusable" and "view directory" in broken.reason
    assert revision.combined_view(run) is None
    assert revision.reseal_views(run.dir) is None
    assert not (tmp_path.parent / "quarry-escape-test").exists()


def test_an_escaping_view_directory_is_never_created(tmp_path):
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    outside = tmp_path / "OUTSIDE"
    doc = json.loads(revision.pointer_path(run.dir).read_text())
    doc["views"]["dir"] = str(outside)
    revision.pointer_path(run.dir).write_bytes(revision._pointer_bytes(doc))

    assert revision.combined_view(run) is None
    assert not outside.exists(), "a pointer-supplied path created a directory outside the run"


# ── the corpus envelope holds across concurrent writers ───────────────────────────────────────────
def test_concurrent_writers_do_not_publish_past_the_envelope(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    # A committed base records the production v3 declaration.  Narrow only the
    # later supplemental writer; mutating the declaration before publication
    # would correctly make the base manifest non-canonical.
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    ready = threading.Barrier(2)
    faults: list = []

    def publish(i: int) -> None:
        try:
            sink = revision.ingest(run, "oob.import")
            for row in oob.parse_interactsh(_callback(f"qz{i}.csession01")):
                sink.add("oob_interaction", row)
            ready.wait(timeout=20)              # both measured the corpus before either published
            sink.commit(None)
        except BaseException as e:              # noqa: BLE001
            faults.append(f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=publish, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert faults == []
    published = revision.read(run.dir)
    assert published.status == "valid"
    assert published.entity_counts["oob_interaction"] == 1          # the bound held across both writers
    assert len(revision.combined_fold(run.dir, "oob_interaction").records) == 1
    assert published.refused, "the row the envelope turned away was not recorded"


# ── a refused ingest says so to its caller ────────────────────────────────────────────────────────
def test_a_refused_import_reports_its_refusals(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 0)

    res = _import(run, tmp_path, "cb.jsonl", "q1.csession01")

    assert res["parsed"] == 1 and res["added"] == 0
    assert res["refused"] == 1, "a fully-refused import reported clean success"
    assert res["revision"].entity_counts.get("oob_interaction", 0) == 0


def test_an_admitted_import_reports_no_refusals(tmp_path):
    run = _sealed(tmp_path)
    res = _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert (res["added"], res["refused"]) == (1, 0)


def test_a_live_run_reports_a_refusal_count_too(tmp_path):
    run = Run.create(tmp_path / "proj", "example.com")
    run.write_state("running")
    res = _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert res["revision"] is None and res["refused"] == 0          # one shape whichever sink took the rows


# ── late evidence waits for the final seal ────────────────────────────────────────────────────────
def test_a_supplement_is_refused_while_the_manifest_is_mid_flight(tmp_path):
    run = _sealed(tmp_path, settle=False)                           # committed once, still `finalizing`
    assert run.state == "finalizing"
    assert revision.base_disposition(run.dir)[0] == revision.FINALIZING

    with pytest.raises(revision.RevisionError, match="still finalising"):
        _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert not (run.dir / "revisions" / "revision.json").exists()
    assert not (run.dir / "normalized" / "oob_interaction.jsonl").exists()

    run.write_state("finished")
    published = _import(run, tmp_path, "cb.jsonl", "q1.csession01")["revision"]
    assert published.revision == 1
    assert revision.read(run.dir).status == "valid"                 # certified against the FINAL manifest


def test_a_reopened_run_can_still_be_read_while_it_refinalises(tmp_path):
    """Reading is not writing: `quarry report` reopens a run to republish its views and must still render
    the revision, so the read predicate stays true while the write gate is shut."""
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    run.write_state("finalizing")

    assert revision.base_finished(run.dir) is True
    assert revision.combined_view(run) is not None
    with pytest.raises(revision.RevisionError):
        _import(run, tmp_path, "second.jsonl", "q2.csession01")


# ── the signals spine consumes ────────────────────────────────────────────────────────────────────
def test_certification_separates_no_revision_from_a_broken_one(tmp_path):
    run = _sealed(tmp_path)
    assert revision.certification(run.dir) == ("absent", "")

    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert revision.certification(run.dir)[0] == "valid"

    seg = run.dir / "revisions" / "rev0001" / "observations.jsonl"
    seg.write_text(seg.read_text()[:10])
    status, reason = revision.certification(run.dir)
    assert status == "unusable" and reason                          # a caller can tell loss from absence


def test_missing_views_names_a_deleted_view(tmp_path):
    run = _sealed(tmp_path)
    rev = _import(run, tmp_path, "cb.jsonl", "q1.csession01")["revision"]
    assert revision.missing_views(run.dir) == []

    (run.dir / "revisions" / rev.views["dir"] / "HOTLIST.md").unlink()
    assert revision.missing_views(run.dir) == ["HOTLIST.md"]
    assert revision.read(run.dir).status == "valid"                 # a deleted view is rebuildable, not fatal
