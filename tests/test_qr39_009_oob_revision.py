"""A late OOB observation revises a finished run's manifested view instead of mutating it.

At HEAD `quarry oob import`/`poll` called `Run.add` on a run that had already written its manifest: the row
landed in `normalized/oob_interaction.jsonl` while `entity_counts` stayed as finalized, so the run's own
fold read `degraded` — the manifest count contradicted the evidence it certified, and a campaign dropped
the interaction as unusable. These gate the replacement: the base run is immutable, the callback goes to an
append-only supplement segment, and a new generation of the combined view is published with its own
version, counts, digests and reports.
"""
import json
from pathlib import Path

import pytest

from quarry_recon import oob, revision
from quarry_recon.store import Run, fold_run_entity

pytestmark = pytest.mark.offline


def _callback(full_id: str, remote: str, ts: str, protocol: str = "dns") -> str:
    return json.dumps({"protocol": protocol, "unique-id": "csession01", "full-id": full_id,
                       "q-type": "A", "remote-address": remote, "timestamp": ts}) + "\n"


def _finished_run(tmp_path, *, reports: bool = False) -> Run:
    run = Run.create(tmp_path / "proj", "example.com")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_state("running")
    run.write_state("finalizing")          # base commit + views happen inside finalizing, finished after
    run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    if reports:
        from quarry_recon import privfs, triage
        from quarry_recon.config import ScopeMatcher
        privfs.write_private(run.reports / "HOTLIST.md", triage.build(run, ScopeMatcher([], [], [], False)))
    run.write_state("finished")
    return run


def _import(run, tmp_path, name: str, body: str):
    src = tmp_path / name
    src.write_text(body)
    return oob.import_file(run, src)


def _base_bytes(run: Run) -> dict:
    """Every byte of the finished run outside `revisions/` — what may never change again."""
    out = {}
    for p in sorted(run.dir.rglob("*")):
        if p.is_file() and "revisions" not in p.relative_to(run.dir).parts:
            out[str(p.relative_to(run.dir))] = p.read_bytes()
    return out


def test_late_import_revises_the_manifested_view(tmp_path):
    run = _finished_run(tmp_path, reports=True)
    before = _base_bytes(run)
    assert revision.combined_counts(run.dir).get("oob_interaction") is None

    res = _import(run, tmp_path, "cb.jsonl",
                  _callback("qdeadbeef.csession01", "203.0.113.9", "2026-08-10T12:00:00Z"))
    rev = res["revision"]

    assert res["added"] == 1
    assert (rev.revision, rev.status) == (1, "valid")
    assert rev.entity_counts["oob_interaction"] == 1          # the manifested count, not a stale zero
    assert rev.digest and rev.entity_digests["oob_interaction"]
    assert revision.combined_counts(run.dir)["oob_interaction"] == 1
    assert revision.view_identity(run.dir) == (1, rev.digest)
    assert _base_bytes(run) == before                          # the finished run is untouched, byte for byte

    # the base run still certifies itself: no count anywhere contradicts its own log
    assert fold_run_entity(run.dir, "oob_interaction").trustworthy
    combined = revision.combined_fold(run.dir, "oob_interaction")
    assert combined.status == "valid" and len(combined.records) == 1

    revised = (run.dir / "revisions" / rev.views["dir"] / "HOTLIST.md").read_text()
    assert "qdeadbeef.csession01" in revised and "203.0.113.9" in revised
    assert "qdeadbeef" not in (run.reports / "HOTLIST.md").read_text()
    queues = json.loads((run.dir / "revisions" / rev.views["dir"] / "digest.json").read_text())["queues"]
    assert [q["type"] for q in queues["oob"]] == ["oob_interaction"]


def test_each_later_callback_publishes_the_next_generation(tmp_path):
    run = _finished_run(tmp_path)
    first = _import(run, tmp_path, "a.jsonl",
                    _callback("q1.csession01", "203.0.113.9", "2026-08-10T12:00:00Z"))["revision"]
    seg1 = (run.dir / "revisions" / "rev0001" / "observations.jsonl").read_bytes()

    second = _import(run, tmp_path, "b.jsonl",
                     _callback("q2.csession01", "198.51.100.7", "2026-08-10T13:00:00Z"))["revision"]

    assert second.revision == 2 and second.digest != first.digest
    assert second.entity_counts["oob_interaction"] == 2
    assert len(second.segments) == 2                            # append-only: the first segment is kept
    assert (run.dir / "revisions" / "rev0001" / "observations.jsonl").read_bytes() == seg1
    assert len(revision.combined_fold(run.dir, "oob_interaction").records) == 2


def test_a_repeat_of_the_same_callback_publishes_nothing(tmp_path):
    run = _finished_run(tmp_path)
    body = _callback("q1.csession01", "203.0.113.9", "2026-08-10T12:00:00Z")
    assert _import(run, tmp_path, "a.jsonl", body)["revision"].revision == 1
    again = _import(run, tmp_path, "a.jsonl", body)
    assert again["added"] == 0 and again["revision"] is None
    assert revision.read(run.dir).revision == 1


def test_polled_rows_take_the_same_path(tmp_path):
    run = _finished_run(tmp_path)
    rows = oob.parse_interactsh(_callback("q9.csession01", "203.0.113.9", "2026-08-10T14:00:00Z"))
    res = oob.import_polled(run, {"log": str(run.dir / "raw" / "oob" / "session" / "interactions.jsonl")}, rows)
    assert res["added"] == 1 and res["revision"].entity_counts["oob_interaction"] == 1
    assert not (run.dir / "normalized" / "oob_interaction.jsonl").exists()


def test_a_run_that_has_not_finished_still_owns_its_log(tmp_path):
    run = Run.create(tmp_path / "proj", "example.com")
    res = _import(run, tmp_path, "cb.jsonl",
                  _callback("q1.csession01", "203.0.113.9", "2026-08-10T12:00:00Z"))
    assert res["added"] == 1 and res["revision"] is None
    assert run.count("oob_interaction") == 1
    assert not (run.dir / "revisions").exists()


def test_a_mutated_base_run_uncertifies_the_revision(tmp_path):
    run = _finished_run(tmp_path)
    _import(run, tmp_path, "a.jsonl", _callback("q1.csession01", "203.0.113.9", "2026-08-10T12:00:00Z"))

    manifest = json.loads(run.manifest_path.read_text())
    manifest["entity_counts"]["oob_interaction"] = 1           # the old behaviour, backdated into the base
    run.manifest_path.write_text(json.dumps(manifest))

    stale = revision.read(run.dir)
    assert stale.status == "unusable" and "changed after revision 1" in stale.reason
    assert revision.combined_counts(run.dir) == {}
    assert revision.combined_fold(run.dir, "oob_interaction").status == "unknown"
    with pytest.raises(revision.RevisionError):
        _import(run, tmp_path, "b.jsonl", _callback("q2.csession01", "198.51.100.7", "2026-08-10T13:00:00Z"))


def test_a_damaged_segment_fails_closed(tmp_path):
    run = _finished_run(tmp_path)
    _import(run, tmp_path, "a.jsonl", _callback("q1.csession01", "203.0.113.9", "2026-08-10T12:00:00Z"))
    seg = run.dir / "revisions" / "rev0001" / "observations.jsonl"
    seg.write_text(seg.read_text()[:20])

    damaged = revision.read(run.dir)
    assert damaged.status == "unusable" and "revision 1 published" in damaged.reason
    assert revision.combined_counts(run.dir) == {}
    folded = revision.combined_fold(run.dir, "oob_interaction")
    assert folded.status == "unknown" and not folded.records


def test_an_interrupted_publication_is_never_overwritten(tmp_path):
    run = _finished_run(tmp_path)
    _import(run, tmp_path, "a.jsonl", _callback("q1.csession01", "203.0.113.9", "2026-08-10T12:00:00Z"))
    orphan = run.dir / "revisions" / "rev0002" / "observations.jsonl"
    orphan.parent.mkdir()
    orphan.write_text('{"seq": 1, "entity": "oob_interaction", "id": "x", "record": {}}\n')
    assert revision.read(run.dir).orphans == ["rev0002"]

    rev = _import(run, tmp_path, "b.jsonl",
                  _callback("q2.csession01", "198.51.100.7", "2026-08-10T13:00:00Z"))["revision"]
    assert rev.revision == 3
    assert orphan.read_text().startswith('{"seq": 1')          # the interrupted bytes are kept, not reused
    assert [s["file"] for s in rev.segments] == ["rev0001/observations.jsonl", "rev0003/observations.jsonl"]


def test_the_supplement_is_private_and_verbatim(tmp_path):
    from quarry_recon import privfs

    run = _finished_run(tmp_path)
    rev = _import(run, tmp_path, "cb.jsonl",
                  _callback("qdeadbeef.csession01", "203.0.113.9", "2026-08-10T12:00:00Z",
                            protocol="http"))["revision"]
    for p in (run.dir / "revisions").rglob("*"):
        assert privfs.is_private(p), p

    row = json.loads((run.dir / "revisions" / "rev0001" / "observations.jsonl").read_text().splitlines()[0])
    assert row["record"]["interaction_domain"] == "qdeadbeef.csession01"
    assert row["record"]["remote_address"] == "203.0.113.9"     # discovered evidence, never redacted
    assert row["origin"] == "oob.import" and row["fp"]
    raw = run.dir / "revisions" / "raw" / "oob" / "import"
    assert [p.name for p in raw.iterdir()] and not (run.dir / "raw" / "oob").exists()
    assert rev.base["manifest_digest"] and rev.base["run_id"] == run.run_id
