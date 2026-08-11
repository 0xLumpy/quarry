"""Certification reconciles the counts it publishes, and a refusal outlives the import that hit it.

`read()` verified digests but never reconciled the pointer's `entity_counts` against the rows the segments
actually yield (revision.py:257), so a tampered count certified `valid` while `combined_view` returned
None — certification and the view disagreed, and a caller trusting certification exited clean. And a
revision published only the CURRENT writer's envelope refusals (revision.py:713), so the next revision
erased them: an import that reported a gap was followed by a `status` that reported none.
"""
import json

import pytest

from quarry_recon import envelope, oob, revision, store
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


def _callback(full_id: str) -> str:
    return json.dumps({"protocol": "dns", "unique-id": "csession01", "full-id": full_id, "q-type": "A",
                       "remote-address": "203.0.113.9", "timestamp": "2026-08-10T12:00:00Z"}) + "\n"


def _sealed(tmp_path) -> Run:
    run = Run.create(tmp_path / "proj", "example.com")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    run.write_state("finished")
    return run


def _import(run, tmp_path, name: str, full_id: str):
    src = tmp_path / name
    src.write_text(_callback(full_id))
    return oob.import_file(run, src)


def _repoint(run, mutate):
    doc = json.loads(revision.pointer_path(run.dir).read_text())
    mutate(doc)
    revision.pointer_path(run.dir).write_text(json.dumps(doc))


# ── certification and the view never disagree ─────────────────────────────────────────────────────
@pytest.mark.parametrize("mutate, id_", [
    (lambda d: d["entity_counts"].__setitem__("oob_interaction", 5), "supplemented-count-too-high"),
    (lambda d: d["entity_counts"].__setitem__("oob_interaction", 0), "supplemented-count-too-low"),
    (lambda d: d["entity_counts"].__setitem__("subdomain", 99), "base-count-tampered"),
    (lambda d: d["entity_counts"].pop("subdomain"), "base-count-dropped"),
    (lambda d: d["entity_counts"].__setitem__("secret", 3), "count-for-evidence-that-does-not-exist"),
])
def test_a_count_that_does_not_match_the_evidence_is_unusable(tmp_path, mutate, id_):
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    assert revision.certification(run.dir)[0] == "valid"

    _repoint(run, mutate)

    status, reason = revision.certification(run.dir)
    assert status == "unusable" and reason
    assert revision.combined_view(run) is None            # certification and the view agree, always
    assert revision.combined_counts(run.dir) == {}


def test_certification_and_the_view_agree_on_every_mutation(tmp_path):
    """The property the gap violated: no pointer edit may leave certification valid while the view is not."""
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    for mutate in (lambda d: d["entity_counts"].__setitem__("oob_interaction", 7),
                   lambda d: d["entity_counts"].__setitem__("subdomain", 0),
                   lambda d: d["supplement"]["segments"][0].__setitem__("lines", 99),
                   lambda d: d["base"].__setitem__("entity_counts", {"subdomain": 42})):
        run2 = _sealed(tmp_path / f"x{id(mutate)}")
        _import(run2, tmp_path, f"cb{id(mutate)}.jsonl", "q1.csession01")
        _repoint(run2, mutate)
        valid = revision.certification(run2.dir)[0] == "valid"
        assert valid == (revision.combined_view(run2) is not None)


def test_a_dropped_supplement_row_is_unusable_not_merely_degraded(tmp_path):
    run = _sealed(tmp_path)
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    seg = run.dir / "revisions" / "rev0001" / "observations.jsonl"
    row = json.loads(seg.read_text().splitlines()[0])
    row["fp"] = "0" * 32                                   # a row whose recorded identity no longer matches
    body = json.dumps(row) + "\n"
    seg.write_text(body)
    _repoint(run, lambda d: d["supplement"]["segments"][0].update(
        {"bytes": len(body.encode()), "digest": revision._sha(body.encode())}))
    _repoint(run, lambda d: d["supplement"].__setitem__(
        "digest", revision._chain_digest(d["supplement"]["segments"])))

    status, reason = revision.certification(run.dir)
    assert status == "unusable" and "unusable supplement row" in reason


def test_an_untouched_run_still_certifies(tmp_path):
    """The reconciliation must not invent a fault: an honest revision stays valid across republication."""
    run = _sealed(tmp_path)
    first = _import(run, tmp_path, "a.jsonl", "q1.csession01")["revision"]
    second = _import(run, tmp_path, "b.jsonl", "q2.csession01")["revision"]
    assert (first.revision, second.revision) == (1, 2)
    assert revision.certification(run.dir) == ("valid", "")
    assert revision.combined_counts(run.dir)["oob_interaction"] == 2


# ── a refusal outlives the import that hit it ─────────────────────────────────────────────────────
def test_a_refusal_survives_a_later_revision(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 0)
    first = _import(run, tmp_path, "a.jsonl", "q1.csession01")
    assert (first["refused"], first["outstanding"]) == (1, 1)
    monkeypatch.undo()

    second = _import(run, tmp_path, "b.jsonl", "q2.csession01")

    assert second["refused"] == 0                          # this import turned nothing away
    assert second["outstanding"] == 1                      # but the run still owes the earlier one
    assert len(revision.refusals(run.dir)) == 1
    assert revision.refusals(run.dir)[0]["entity"] == "oob_interaction"
    assert revision.certification(run.dir)[0] == "valid"   # owing a refusal is not a broken revision


def test_a_refusal_clears_only_when_the_identity_is_admitted(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 0)
    _import(run, tmp_path, "a.jsonl", "q1.csession01")
    refused_key = revision.refusals(run.dir)[0]["key"]
    monkeypatch.undo()

    _import(run, tmp_path, "other.jsonl", "q2.csession01")
    assert [e["key"] for e in revision.refusals(run.dir)] == [refused_key]   # a different row does not clear it

    _import(run, tmp_path, "a.jsonl", "q1.csession01")      # the refused identity itself, now admitted
    assert revision.refusals(run.dir) == []


def test_refusals_are_reported_as_none_when_nothing_is_published(tmp_path):
    run = _sealed(tmp_path)
    assert revision.refusals(run.dir) == []
    _import(run, tmp_path, "cb.jsonl", "q1.csession01")
    seg = run.dir / "revisions" / "rev0001" / "observations.jsonl"
    seg.write_text(seg.read_text()[:8])
    assert revision.refusals(run.dir) == []                 # a broken revision reports none, never a guess


# ── one committed-manifest rule, not two ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("mutate", [
    lambda m: m["entity_counts"].__setitem__("subdomain", -1),
    lambda m: m["entity_counts"].__setitem__("subdomain", True),
    lambda m: m["entity_counts"].__setitem__("subdomain", 1.0),
    lambda m: m.__setitem__("summary", "not-a-dict"),
    lambda m: m.pop("summary"),
    lambda m: m.__setitem__("entity_counts", []),
])
def test_the_committed_manifest_rule_is_the_stores_own(tmp_path, mutate):
    run = _sealed(tmp_path)
    manifest = json.loads(run.manifest_path.read_text())
    mutate(manifest)
    run.manifest_path.write_text(json.dumps(manifest))

    assert revision._manifest_committed(run.dir) is store.manifest_committed(run.manifest_path)
    assert revision._manifest_committed(run.dir) is False
    assert revision.base_disposition(run.dir)[0] == revision.UNKNOWN    # a damaged manifest is refused
