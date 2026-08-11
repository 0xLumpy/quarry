"""The combined view reaches the campaign union, `quarry report`, and every raw_ref a digest names.

Publishing a revision was only half the acceptance. Three readers still treated a finished run as if
nothing could arrive after it: `campaign.Union.absorb` folded the base run (campaign.py:402), `quarry
report` republished the base run's views (cli.py:1282), and triage named `normalized/oob_interaction.jsonl`
for a row that lives in a supplement segment (triage.py:601).
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from quarry_recon import campaign, oob, revision
from quarry_recon.cli import cli
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


def _callback(full_id: str, remote: str) -> str:
    return json.dumps({"protocol": "dns", "unique-id": "csession01", "full-id": full_id, "q-type": "A",
                       "remote-address": remote, "timestamp": "2026-08-10T12:00:00Z"}) + "\n"


def _profile(tmp_path: Path) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: t\nAPEX_DOMAINS:\n  - example.com\nMODES:\n  PASSIVE_ONLY: true\n")
    return p


def _finished_run(tmp_path) -> Run:
    run = Run.create(tmp_path / "proj", "example.com")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    run.write_state("finished")
    return run


def _late(run, tmp_path, name: str, full_id: str, remote: str):
    src = tmp_path / name
    src.write_text(_callback(full_id, remote))
    return oob.import_file(run, src)["revision"]


def _union(tmp_path) -> campaign.Union:
    return campaign.Union(tmp_path / "recon" / "campaigns" / "c1" / "union.json", create=True)


def _oob_slots(union) -> list:
    return [key for kind, key in union.records if kind == "oob_interaction"]


# ── the campaign union absorbs the combined view ──────────────────────────────────────────────────
def test_a_run_absorbed_after_its_revision_carries_the_late_callback(tmp_path):
    run = _finished_run(tmp_path)
    rev = _late(run, tmp_path, "cb.jsonl", "qlate.csession01", "203.0.113.9")

    out = _union(tmp_path).absorb(run.dir)

    assert out.unusable == {}
    assert out.kinds["oob_interaction"] == {"new": 1, "enriched": 0}
    union = campaign.Union(tmp_path / "recon" / "campaigns" / "c1" / "union.json")
    assert len(_oob_slots(union)) == 1
    assert union.absorbed[run.run_id]["view"] == [rev.revision, rev.digest]


def test_a_run_revised_after_absorption_is_folded_again(tmp_path):
    run = _finished_run(tmp_path)
    union = _union(tmp_path)
    first = union.absorb(run.dir)                       # absorbed while only the base run existed
    assert first.kinds == {"subdomain": {"new": 1, "enriched": 0}}
    assert union.absorbed[run.run_id]["view"] == [0, ""]
    assert not _oob_slots(union)

    rev = _late(run, tmp_path, "cb.jsonl", "qlate.csession01", "203.0.113.9")
    again = union.absorb(run.dir)                       # the view changed, so the short-circuit must not fire

    assert again.kinds["oob_interaction"] == {"new": 1, "enriched": 0}
    assert len(_oob_slots(union)) == 1
    assert union.absorbed[run.run_id]["view"] == [rev.revision, rev.digest]
    assert campaign.Union(union.path).trustworthy      # the ledger's new shape survives a reload


def test_an_unrevised_run_still_replays_its_published_deltas(tmp_path):
    run = _finished_run(tmp_path)
    union = _union(tmp_path)
    first = union.absorb(run.dir)
    replay = union.absorb(run.dir)                       # same view: the deltas, never a second merge's zeroes

    assert (replay.new, replay.enriched, replay.kinds) == (first.new, first.enriched, first.kinds)
    assert replay.absorbed


def test_a_legacy_ledger_without_a_view_still_loads_and_replays(tmp_path):
    run = _finished_run(tmp_path)
    union = _union(tmp_path)
    union.absorb(run.dir)
    pointer = json.loads(union.path.read_text())
    del pointer["absorbed"][run.run_id]["view"]          # the ledger shape written before views were tracked
    union.path.write_text(json.dumps(pointer))

    reopened = campaign.Union(union.path)
    assert reopened.trustworthy
    assert reopened.absorb(run.dir).absorbed             # reads as the base view, so it still short-circuits
    assert not _oob_slots(reopened)


# ── `quarry report` renders the revision ──────────────────────────────────────────────────────────
def test_report_renders_the_revision_not_the_base(tmp_path, monkeypatch):
    from quarry_recon import phases
    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (lambda ctx: None, "Horizontal", False)})
    runner = CliRunner()
    assert runner.invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal"]).exit_code == 0
    run_dir = next(iter((tmp_path / "recon").glob("2*")))

    cb = tmp_path / "cb.jsonl"
    cb.write_text(_callback("qlate.csession01", "203.0.113.9"))
    assert runner.invoke(cli, ["oob", "import", str(cb), "-t", str(_profile(tmp_path))]).exit_code == 0
    rev = revision.read(run_dir)
    base_digest_before = (run_dir / "reports" / "digest.json").read_bytes()

    res = runner.invoke(cli, ["report", "-t", str(_profile(tmp_path))])
    assert res.exit_code == 0, res.stderr
    assert f"revisions/{rev.views['dir']}" in res.output

    revised = json.loads((run_dir / "revisions" / rev.views["dir"] / "digest.json").read_text())
    assert [q["type"] for q in revised["queues"]["oob"]] == ["oob_interaction"]
    assert (run_dir / "reports" / "digest.json").read_bytes() == base_digest_before

    resealed = revision.read(run_dir)
    assert resealed.status == "valid" and resealed.revision == rev.revision
    assert resealed.digest == rev.digest                 # a regenerated view never restates the evidence
    on_disk = (run_dir / "revisions" / resealed.views["dir"] / "digest.json").read_bytes()
    assert resealed.views["files"]["digest.json"] == revision._sha(on_disk)


# ── every raw_ref a revised digest names is a file that exists ────────────────────────────────────
def test_every_raw_ref_in_a_revised_digest_resolves(tmp_path):
    run = _finished_run(tmp_path)
    run.add("url", {"url": "https://a.example.com/x"})
    rev = _late(run, tmp_path, "cb.jsonl", "qlate.csession01", "203.0.113.9")

    digest = json.loads((run.dir / "revisions" / rev.views["dir"] / "digest.json").read_text())
    refs = {item["raw_ref"] for queue in digest["queues"].values() for item in queue}
    assert refs, "the revised digest names no evidence at all"
    for ref in refs:
        assert (run.dir / ref).is_file(), f"{ref} does not exist in {run.dir}"
    assert "revisions/rev0001/observations.jsonl" in refs   # the supplemented row names its own segment
