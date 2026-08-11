"""QR39-003 — the verdict is computed only after every fault is committed.

Fault injection must never produce a clean verdict: event-sink degradation, a finalisation break, a
checkpoint challenge and a missing dependency each gate it, whatever order they arrive in.
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from quarry_recon import checkpoint, events, state
from quarry_recon.cli import cli
from quarry_recon.runner import RunResult, Status, skipped
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


@pytest.fixture
def run(tmp_path):
    r = Run.create(tmp_path, "t")
    yield r
    events.reset()


def _profile(tmp_path: Path) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: t\nAPEX_DOMAINS:\n  - example.com\nMODES:\n  PASSIVE_ONLY: true\n")
    return p


# ── event-sink degradation is committed before the verdict, not attached after it ─────────────────
def test_a_lost_event_write_gates_the_verdict(run):
    events.configure(run.dir)
    events._degraded.update({"writes_failed": 3, "first_error": "OSError: no space left on device"})
    run.write_manifest(profile_summary={}, phases_run=["horizontal"])
    manifest = json.loads(run.manifest_path.read_text())
    summary = manifest["summary"]
    assert summary["verdict"] == "complete_with_gaps"
    fault = next(f for f in summary["faults"] if f["where"] == "events.jsonl")
    assert fault["kind"] == "machinery" and fault["challenges_completeness"] is True
    # the loss is still reported in its own field; the verdict no longer ignores it
    assert manifest["observability_degraded"]["writes_failed"] == 3


def test_an_intact_event_sink_stays_clean(run):
    events.configure(run.dir)
    run.write_manifest(profile_summary={}, phases_run=["horizontal"])
    assert json.loads(run.manifest_path.read_text())["summary"]["verdict"] == "complete"


# ── a fault may not arrive after the verdict is sealed ────────────────────────────────────────────
def test_a_fault_committed_after_the_verdict_is_refused(run):
    run._run_summary()
    with pytest.raises(state.ContractError):
        run.commit_fault(state.Fault("machinery", where="late"))
    with pytest.raises(state.ContractError):
        run.commit_gap(state.Gap(source_id="late", kind="unknown"))


def test_an_unsealed_run_reseals_with_the_late_fault(run):
    assert run._run_summary()["verdict"] == "complete"
    run.unseal_verdict()
    run.commit_fault(state.Fault("publication", where="hotlist", detail="volume read-only"))
    assert run._run_summary()["verdict"] == "complete_with_gaps"


def test_only_a_typed_record_may_be_committed(run):
    for bad in ({"kind": "machinery"}, "machinery", None):
        with pytest.raises(state.ContractError):
            run.commit_fault(bad)
        with pytest.raises(state.ContractError):
            run.commit_gap(bad)


def test_a_non_challenging_fault_does_not_gate(run):
    run.commit_fault(state.Fault("diagnostic", where="stderr", detail="could not persist stderr"))
    assert run._run_summary()["verdict"] == "complete"


# ── the source -> tool dependency edge, so a missing binary is attributed to the right name ───────
def test_a_missing_dependency_is_a_gap_even_when_the_source_has_another_name(run):
    # params.oob_probe needs interactsh-client; the skip is recorded under the SOURCE's name, and the
    # declared edge is what the verdict matches against the registry
    run.record("params", skipped("oob_probe", "interactsh-client not installed"),
               depends_on="interactsh-client")
    summary = run._run_summary()
    gap = next(g for g in summary["gaps"] if g["tool"] == "oob_probe")
    assert summary["verdict"] == "complete_with_gaps"
    assert gap["kind"] == "required_tool_missing" and gap["missing_tool"] == "interactsh-client"
    assert any(f["kind"] == "required_tool_missing" for f in summary["faults"])


def test_the_oob_probe_lane_declares_that_edge(run, monkeypatch):
    from quarry_recon.phases import params
    monkeypatch.setattr(params, "have", lambda b: False)
    ctx = type("ctx", (), {"run": run, "echo": lambda *a: None})()
    scope = type("scope", (), {"passive_only": False})()
    assert params._oob_probe(ctx, scope, None) is None
    assert run.tool_runs("params")[0].depends_on == "interactsh-client"
    assert run._run_summary()["verdict"] == "complete_with_gaps"


def test_a_source_skipped_for_its_own_reason_is_not_a_missing_dependency(run):
    run.record("params", skipped("oob_probe", "no SSRF-param candidates"))
    assert run._run_summary()["verdict"] == "complete"


# ── checkpoint challenges are typed gaps, not prose ──────────────────────────────────────────────
def test_a_thinness_checkpoint_carries_a_typed_gap():
    cp = checkpoint.Checkpoint("warn", "probe", "40 resolved hosts but 0 live HTTP services", challenges=True)
    gap = cp.gap()
    assert isinstance(gap, state.Gap) and gap.kind == "unknown"
    assert gap.source_id == "probe.checkpoint" and gap.challenges_completeness is True


def test_a_checkpoint_that_restates_a_tool_status_adds_no_second_gap():
    assert checkpoint.Checkpoint("warn", "probe", "httpx FAILED").gap() is None
    assert checkpoint.Checkpoint("info", "vertical", "one source carried it").gap() is None


def test_the_thinness_rules_challenge_and_reach_the_verdict(run):
    for i in range(20):
        run.add("resolved", {"host": f"h{i}.example.com", "source": "t"})
    cps = checkpoint.evaluate(run, "probe")     # 20 resolved, 0 live
    assert cps and all(c.challenges for c in cps)
    for cp in cps:
        run.commit_gap(cp.gap())
    summary = run._run_summary()
    assert summary["verdict"] == "complete_with_gaps"
    assert any(g["tool"] == "probe.checkpoint" for g in summary["gaps"])


def test_a_run_whose_checkpoint_fires_does_not_finalise_clean(tmp_path, monkeypatch):
    from quarry_recon import phases

    def thin(ctx):
        for i in range(20):
            ctx.run.add("resolved", {"host": f"h{i}.example.com", "source": "t"})
    monkeypatch.setattr(phases, "REGISTRY", {"probe": (thin, "Probe", False)})
    res = CliRunner().invoke(
        cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "probe", "--json"])
    doc = json.loads(res.stdout)
    assert res.exit_code == 4, res.stderr
    assert any(g["source_id"] == "probe.checkpoint" for g in doc["gaps"]), doc["gaps"]


# ── every gap the summary emits names its kind, so nothing is guessed back out of a label ─────────
@pytest.mark.parametrize("status,kind", [(Status.TIMED_OUT, "timeout"), (Status.PARTIAL, "tool_omission"),
                                         (Status.BLOCKED, "unknown")])
def test_every_degraded_status_declares_a_gap_kind(run, status, kind):
    run.record("probe", RunResult("httpx", ["httpx"], status, None, 1.0, None, 0, note="why"))
    gap = run._run_summary()["gaps"][0]
    assert gap["kind"] == kind
    assert state.Gap(source_id=gap["tool"], kind=gap["kind"]).challenges_completeness is True


def test_faults_are_typed_records_on_the_way_out(run):
    run.record("probe", RunResult("httpx", ["httpx"], Status.FAILED, 1, 1.0, None, 0, note="broke"))
    for f in run._run_summary()["faults"]:
        state.validate_serialized("Fault", f)
        assert state.Fault.from_dict(f).challenges_completeness == f["challenges_completeness"]


# ── fault injection never produces a clean verdict ───────────────────────────────────────────────
@pytest.mark.parametrize("inject", [
    lambda r: r.commit_fault(state.Fault("machinery", where="events.jsonl")),
    lambda r: r.commit_fault(state.Fault("publication", where="digest")),
    lambda r: r.commit_fault(state.Fault("phase_exception", where="run")),
    lambda r: r.commit_gap(state.Gap(source_id="probe.checkpoint", kind="unknown")),
    lambda r: r.commit_gap(state.Gap(source_id="crawl.katana", kind="cap", omitted=7)),
    lambda r: r.record("probe", RunResult("httpx", ["x"], Status.FAILED, 1, 1.0, None, 0, note="broke")),
    lambda r: r.record("params", skipped("oob_probe", "interactsh-client not installed"),
                       depends_on="interactsh-client"),
])
def test_injected_faults_never_finalise_clean(run, inject):
    inject(run)
    run.write_manifest(profile_summary={}, phases_run=["probe"])
    summary = json.loads(run.manifest_path.read_text())["summary"]
    assert summary["verdict"] != "complete", summary
    from quarry_recon.exit_contract import from_summary
    assert from_summary("run", summary).exit_code in (4, 5)
