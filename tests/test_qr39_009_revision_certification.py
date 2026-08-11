"""A revision certifies the base run's EVIDENCE, not its finalisation bookkeeping.

`_base_manifest` pinned a digest over the whole manifest file, so any manifest-changing re-finalisation
uncertified a published revision. `Run.reconcile_finalization` rewrites `summary.faults` and the verdict it
implies when a resumed `quarry report` answers a publication fault — no evidence moves — and the revision
then read `unusable`, `combined_view` returned None, and `report` silently fell back to the base run with
the late OOB rows missing from every view.

The digest is scoped to the evidence-bearing manifest instead. A change to real evidence must still
uncertify, or the fix would have traded one silent loss for a defeated guard.
"""
import json

import pytest
from click.testing import CliRunner

from quarry_recon import revision, triage
from quarry_recon.cli import cli
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


def _profile(tmp_path):
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: t\nAPEX_DOMAINS:\n  - example.com\nMODES:\n  PASSIVE_ONLY: true\n")
    return p


def _callback() -> str:
    return json.dumps({"protocol": "dns", "unique-id": "csession01", "full-id": "qlate.csession01",
                       "q-type": "A", "remote-address": "203.0.113.9",
                       "timestamp": "2026-08-10T12:00:00Z"}) + "\n"


def _one_phase(monkeypatch):
    from quarry_recon import phases
    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (lambda ctx: None, "Horizontal", False)})


def _run_dir(tmp_path):
    return next(iter((tmp_path / "recon").glob("2*")))


def _failed_finalisation(tmp_path, monkeypatch, runner):
    """A run whose base evidence committed but whose hotlist could not publish: `finalization_failed`,
    with a publication fault standing in the committed manifest."""
    _one_phase(monkeypatch)

    def boom(*a, **k):
        raise OSError("reports volume is read-only")

    monkeypatch.setattr(triage, "build", boom)
    assert runner.invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal"]).exit_code == 5
    monkeypatch.undo()
    _one_phase(monkeypatch)
    return _run_dir(tmp_path)


def test_a_fault_clearing_resume_keeps_the_revision_certified(tmp_path, monkeypatch):
    runner = CliRunner(mix_stderr=False)
    run_dir = _failed_finalisation(tmp_path, monkeypatch, runner)
    before = json.loads((run_dir / "manifest.json").read_text())
    assert before["summary"]["faults"], "the run did not record the publication fault this test needs"

    cb = tmp_path / "cb.jsonl"
    cb.write_text(_callback())
    assert runner.invoke(cli, ["oob", "import", str(cb), "-t", str(_profile(tmp_path))]).exit_code == 0
    published = revision.read(run_dir)
    assert (published.status, published.entity_counts["oob_interaction"]) == ("valid", 1)

    res = runner.invoke(cli, ["report", "-t", str(_profile(tmp_path))])
    assert res.exit_code == 0, res.stderr
    assert "no longer certifies" not in res.output

    after = json.loads((run_dir / "manifest.json").read_text())
    assert after["summary"]["faults"] == [], "the resume did not answer the fault, so nothing was proven"
    assert after["summary"]["verdict"] != before["summary"]["verdict"]
    assert {k: v for k, v in after.items() if k != "summary"} == \
           {k: v for k, v in before.items() if k != "summary"}          # no evidence moved

    certified = revision.read(run_dir)
    assert certified.status == "valid" and certified.revision == 1
    view = revision.combined_view(Run.open(tmp_path, "t", run_dir.name))
    assert view is not None and view.count("oob_interaction") == 1
    revised = json.loads((run_dir / "revisions" / certified.views["dir"] / "digest.json").read_text())
    assert [q["type"] for q in revised["queues"]["oob"]] == ["oob_interaction"]
    assert "qlate.csession01" in (run_dir / "revisions" / certified.views["dir"] / "HOTLIST.md").read_text()


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda m: m["entity_counts"].__setitem__("oob_interaction", 1), id="entity_counts"),
    pytest.param(lambda m: m["entity_counts"].__setitem__("subdomain", 99), id="a-count-moves"),
    pytest.param(lambda m: m.__setitem__("tool_runs", [{"tool": "invented"}]), id="tool_runs"),
    pytest.param(lambda m: m.__setitem__("target", "elsewhere.example"), id="target"),
    pytest.param(lambda m: m.__setitem__("envelope", {"forged": True}), id="envelope"),
    pytest.param(lambda m: m["summary"].__setitem__("gaps", [{"tool": "invented"}]), id="summary.gaps"),
    pytest.param(lambda m: m["summary"].__setitem__("coverage", [{"omitted": 5}]), id="summary.coverage"),
])
def test_a_change_to_evidence_still_uncertifies_the_revision(tmp_path, monkeypatch, mutate):
    """The guard is scoped, not removed: everything the manifest records except the answered bookkeeping
    still certifies, `summary.gaps` and `summary.coverage` included."""
    runner = CliRunner(mix_stderr=False)
    _one_phase(monkeypatch)
    assert runner.invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal"]).exit_code == 0
    run_dir = _run_dir(tmp_path)
    cb = tmp_path / "cb.jsonl"
    cb.write_text(_callback())
    assert runner.invoke(cli, ["oob", "import", str(cb), "-t", str(_profile(tmp_path))]).exit_code == 0
    assert revision.read(run_dir).status == "valid"

    manifest = json.loads((run_dir / "manifest.json").read_text())
    mutate(manifest)
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    stale = revision.read(run_dir)
    assert stale.status == "unusable" and "changed after revision 1" in stale.reason
    assert revision.combined_view(Run.open(tmp_path, "t", run_dir.name)) is None


def test_the_digest_ignores_the_answered_bookkeeping_and_nothing_else(tmp_path, monkeypatch):
    """Only `summary.faults` and `summary.verdict` are exempt — the pair `reconcile_finalization` rewrites.
    Reformatting is not evidence either, so the digest is over canonical content, not the file's bytes."""
    runner = CliRunner(mix_stderr=False)
    _one_phase(monkeypatch)
    assert runner.invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal"]).exit_code == 0
    run_dir = _run_dir(tmp_path)
    path = run_dir / "manifest.json"
    base = json.loads(path.read_text())

    def digest_of(doc) -> str:
        path.write_text(json.dumps(doc, indent=2))
        return revision._base_manifest(run_dir)[0]

    original = digest_of(base)

    exempt = json.loads(json.dumps(base))
    exempt["summary"]["faults"] = [{"kind": "publication", "where": "hotlist", "detail": "x",
                                    "challenges_completeness": True}]
    exempt["summary"]["verdict"] = "complete_with_gaps"
    assert digest_of(exempt) == original

    reformatted = json.loads(json.dumps(base))
    path.write_text(json.dumps(reformatted, indent=None, sort_keys=True))
    assert revision._base_manifest(run_dir)[0] == original

    for field in ("gaps", "failures", "tool_status"):
        moved = json.loads(json.dumps(base))
        moved["summary"][field] = [{"invented": field}]
        assert digest_of(moved) != original, f"summary.{field} must still be certified"
