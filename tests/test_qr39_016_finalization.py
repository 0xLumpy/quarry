"""QR39-016 — finalisation is a persisted, contained, resumable state machine.

Base evidence commits on its own; every derived view is idempotent and generation-addressed; a report-only
failure after the base commit leaves the run intact, exits 5, and is resumable by `quarry report`.
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from quarry_recon import state
from quarry_recon.cli import cli
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


def _profile(tmp_path: Path) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: t\nAPEX_DOMAINS:\n  - example.com\nMODES:\n  PASSIVE_ONLY: true\n")
    return p


def _one_phase(monkeypatch, fn=lambda ctx: None):
    from quarry_recon import phases
    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (fn, "Horizontal", False)})


def _invoke(tmp_path, *args):
    return CliRunner().invoke(cli, [args[0], "-t", str(_profile(tmp_path)), *args[1:]])


def _run(tmp_path, monkeypatch, *args):
    _one_phase(monkeypatch)
    return _invoke(tmp_path, "run", "--phases", "horizontal", *args)


def _run_dir(tmp_path) -> Path:
    return next(iter((tmp_path / "recon").glob("2*")))


def _state(tmp_path) -> dict:
    return json.loads((_run_dir(tmp_path) / "state.json").read_text())


def _break_stage(monkeypatch, stage="hotlist"):
    """Fail exactly one derived view, after the base evidence has committed."""
    from quarry_recon import triage
    target = {"hotlist": "build", "digest": "digest_json"}[stage]

    def boom(*a, **k):
        raise OSError("reports volume is read-only")
    monkeypatch.setattr(triage, target, boom)


# ── the state machine is persisted and only the declared transitions are legal ─────────────────────
def test_a_finished_run_walks_the_declared_states(tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch)
    assert res.exit_code == 0, res.stderr
    rec = _state(tmp_path)
    assert rec["state"] == "finished" and rec["schema_version"] == state.SCHEMA_VERSION
    assert rec["run_id"] == _run_dir(tmp_path).name


def test_a_created_run_is_persisted_before_any_phase_runs(tmp_path):
    run = Run.create(tmp_path, "t")
    assert run.state == "created" and run.state_path.exists()


@pytest.mark.parametrize("src,dst", [("created", "finalizing"), ("created", "finished"),
                                     ("running", "finished"), ("finished", "running"),
                                     ("finished", "created")])
def test_illegal_transitions_are_refused(tmp_path, src, dst):
    run = Run.create(tmp_path, "t")
    for step in ("running", "finalizing", "finished"):   # walk to the source state legally
        if run.state == src:
            break
        run.write_state(step)
    assert run.state == src
    with pytest.raises(state.ContractError):
        run.write_state(dst)


# ── base evidence commits independently of the derived views ──────────────────────────────────────
def test_a_report_only_failure_keeps_the_base_run_and_exits_five(tmp_path, monkeypatch):
    _break_stage(monkeypatch)
    res = _run(tmp_path, monkeypatch)
    assert res.exit_code == 5, res.stderr
    d = _run_dir(tmp_path)
    manifest = json.loads((d / "manifest.json").read_text())
    # the base commit survived whole: identity, phases and the entity store are all there
    assert manifest["run_id"] == d.name and manifest["phases_run"] == ["horizontal"]
    assert (d / "run.json").exists() and (d / "normalized").is_dir()
    rec = _state(tmp_path)
    assert rec["state"] == "finalization_failed"
    assert rec["stages"]["hotlist"]["status"] == "failed"
    assert rec["stages"]["exports"]["status"] == "done", "stages before the break still published"


def test_a_finalisation_failure_is_a_publication_fault_in_the_verdict(tmp_path, monkeypatch):
    _break_stage(monkeypatch)
    _run(tmp_path, monkeypatch)
    summary = json.loads((_run_dir(tmp_path) / "manifest.json").read_text())["summary"]
    kinds = [f["kind"] for f in summary["faults"]]
    assert "publication" in kinds, summary["faults"]
    assert summary["verdict"] == "complete_with_gaps"


def test_the_operator_is_told_how_to_resume(tmp_path, monkeypatch):
    _break_stage(monkeypatch)
    res = _run(tmp_path, monkeypatch)
    assert "quarry report" in res.stderr + res.stdout


# ── derived views are idempotent, generation-addressed and resumable ──────────────────────────────
def test_report_resumes_a_failed_finalisation_without_rescanning(tmp_path, monkeypatch):
    _break_stage(monkeypatch)
    assert _run(tmp_path, monkeypatch).exit_code == 5
    monkeypatch.undo()                                   # the reports volume is writable again
    ran = []
    from quarry_recon import phases
    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (lambda ctx: ran.append(1), "H", False)})
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 0, res.stderr
    assert ran == [], "resuming finalisation must not re-run a phase"
    assert _state(tmp_path)["state"] == "finished"
    assert (_run_dir(tmp_path) / "reports" / "HOTLIST.md").exists()


def test_a_resume_that_fails_again_stays_resumable(tmp_path, monkeypatch):
    _break_stage(monkeypatch)
    assert _run(tmp_path, monkeypatch).exit_code == 5
    res = _invoke(tmp_path, "report")                    # still broken
    assert res.exit_code == 5, res.stderr
    assert _state(tmp_path)["state"] == "finalization_failed"


def test_a_published_view_is_generation_addressed_and_skipped_when_current(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    gen = run.generation()
    assert all(s["generation"] == gen for s in run.finalization_stages.values())
    assert run.stage_current("hotlist") and not run.finalization_failed()


def test_finished_run_rejects_new_base_evidence_and_keeps_views_current(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    before = run.generation()
    with pytest.raises(state.ContractError, match="base evidence is sealed"):
        run.add("subdomain", {"host": "a.example.com", "source": "t"})
    assert run.generation() == before
    assert run.stage_current("hotlist"), "a refused base mutation cannot stale a derived view"
