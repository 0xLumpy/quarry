"""Wave B round-2 spine remediations: the exit contract is global, and finalisation is consistent.

One file per remediation group, each named by what it now refuses to do:
  · a re-finalisation reconciles both ways — a resume clears the fault it answered, a failure records one
  · the base commit is contained, so a pre-seal failure is resumable or says so
  · a corrupt lifecycle record fails closed
  · a campaign's own outcome reaches the exit status
  · a terminal is classified per cause
  · Click's own parse errors leave through the contract
  · nothing returns an undocumented exit 1
  · a finished run's verdict is sealed
  · an interrupted campaign is continued rather than re-minted
  · a derived view is addressed by content, and a resume republishes only what is stale
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
    return CliRunner(mix_stderr=False).invoke(cli, [args[0], "-t", str(_profile(tmp_path)), *args[1:]])


def _run(tmp_path, monkeypatch, *args):
    _one_phase(monkeypatch)
    return _invoke(tmp_path, "run", "--phases", "horizontal", *args)


def _run_dir(tmp_path) -> Path:
    return next(iter((tmp_path / "recon").glob("2*")))


def _state(tmp_path) -> dict:
    return json.loads((_run_dir(tmp_path) / "state.json").read_text())


def _summary(tmp_path) -> dict:
    return json.loads((_run_dir(tmp_path) / "manifest.json").read_text())["summary"]


def _break(monkeypatch, module, name):
    def boom(*a, **k):
        raise OSError("the reports volume is read-only")
    monkeypatch.setattr(module, name, boom)


# ── 1. a re-finalisation reconciles in BOTH directions ────────────────────────────────────────────
def test_a_successful_resume_clears_the_fault_it_answered(tmp_path, monkeypatch):
    from quarry_recon import triage
    _break(monkeypatch, triage, "build")
    assert _run(tmp_path, monkeypatch).exit_code == 5
    assert [f["where"] for f in _summary(tmp_path)["faults"] if f["kind"] == "publication"] == ["hotlist"]

    monkeypatch.undo()
    _one_phase(monkeypatch)
    assert _invoke(tmp_path, "report").exit_code == 0
    # the republished view answered the claim, so it may not survive in the manifest
    summary = _summary(tmp_path)
    assert [f for f in summary["faults"] if f["kind"] == "publication"] == []
    assert summary["verdict"] == "complete"
    assert _state(tmp_path)["state"] == "finished"


def test_report_and_a_later_status_cannot_disagree(tmp_path, monkeypatch):
    from quarry_recon import triage
    _break(monkeypatch, triage, "build")
    _run(tmp_path, monkeypatch)
    monkeypatch.undo()
    _one_phase(monkeypatch)
    rep = _invoke(tmp_path, "report")
    st = _invoke(tmp_path, "status")
    assert rep.exit_code == st.exit_code == 0, (rep.stderr, st.stderr)


def test_a_failed_regeneration_of_a_finished_run_reopens_it(tmp_path, monkeypatch):
    from quarry_recon import triage
    assert _run(tmp_path, monkeypatch).exit_code == 0
    assert _state(tmp_path)["state"] == "finished"

    _break(monkeypatch, triage, "build")
    rep = _invoke(tmp_path, "report", "--force")
    assert rep.exit_code == 5, rep.stderr
    assert _state(tmp_path)["state"] == "finalization_failed"
    assert [f["where"] for f in _summary(tmp_path)["faults"] if f["kind"] == "publication"] == ["hotlist"]
    # and the run no longer reads clean to anybody
    assert _invoke(tmp_path, "status").exit_code == 5


def test_the_reopen_is_the_only_way_a_manifest_changes(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    assert run.state == "finished"
    with pytest.raises(state.ContractError):
        run.write_manifest(profile_summary={}, phases_run=["horizontal"])


def test_a_noop_report_leaves_the_committed_manifest_byte_identical(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    before = (_run_dir(tmp_path) / "manifest.json").read_bytes()
    assert _invoke(tmp_path, "report").exit_code == 0
    assert (_run_dir(tmp_path) / "manifest.json").read_bytes() == before


# ── 2. the base commit is contained ───────────────────────────────────────────────────────────────
def test_a_manifest_that_cannot_be_written_is_resumable_not_stuck(tmp_path, monkeypatch):
    from quarry_recon import store
    real = store.Run.write_manifest
    monkeypatch.setattr(store.Run, "write_manifest",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no space left on device")))
    res = _run(tmp_path, monkeypatch)
    assert res.exit_code == 5, res.stderr
    rec = _state(tmp_path)
    assert rec["state"] == "finalization_failed"          # never left mid-flight in `finalizing`
    assert rec["stages"]["manifest"]["status"] == "failed"
    monkeypatch.setattr(store.Run, "write_manifest", real)


def test_report_on_a_run_with_no_committed_manifest_never_exits_zero(tmp_path, monkeypatch):
    from quarry_recon import store
    monkeypatch.setattr(store.Run, "write_manifest",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no space left on device")))
    _run(tmp_path, monkeypatch)
    assert not (_run_dir(tmp_path) / "manifest.json").exists()
    monkeypatch.undo()
    _one_phase(monkeypatch)
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 5, res.stderr
    assert "no committed manifest" in res.stderr


def test_losing_telemetry_still_commits_the_base_evidence(tmp_path, monkeypatch):
    from quarry_recon import metrics
    _break(monkeypatch, metrics, "write")
    res = _run(tmp_path, monkeypatch)
    assert (_run_dir(tmp_path) / "manifest.json").exists(), "telemetry is a view, not the evidence"
    assert res.exit_code == 5
    assert [f["where"] for f in _summary(tmp_path)["faults"] if f["kind"] == "publication"] == ["metrics"]


# ── 3. a corrupt lifecycle record fails closed ────────────────────────────────────────────────────
@pytest.mark.parametrize("body", ["{ not json", '{"state": "banana"}', "[]", ""])
def test_a_present_but_unreadable_state_file_is_never_finished(tmp_path, monkeypatch, body):
    _run(tmp_path, monkeypatch)
    d = _run_dir(tmp_path)
    assert (d / "manifest.json").exists()        # the manifest alone must not be enough to infer finished
    (d / "state.json").write_text(body)
    assert Run.open(tmp_path, "t", d.name).state == state.STATE_UNKNOWN


def test_an_absent_state_file_still_infers_a_legacy_run(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    d = _run_dir(tmp_path)
    (d / "state.json").unlink()
    assert Run.open(tmp_path, "t", d.name).state == "finished"


def test_an_unreadable_record_is_evidence_and_is_not_overwritten(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    d = _run_dir(tmp_path)
    (d / "state.json").write_text("{ not json")
    run = Run.open(tmp_path, "t", d.name)
    for call in (lambda: run.write_state("finalizing"), lambda: run.mark_stage("hotlist", "done")):
        with pytest.raises(state.ContractError):
            call()
    assert (d / "state.json").read_text() == "{ not json"


# ── 4. a campaign's own outcome reaches the exit status ───────────────────────────────────────────
def _ledger(tmp_path, cid, *, stop, detail="", success=False, terminal=None):
    from quarry_recon import campaign as C
    led = C.Campaign(tmp_path, cid)
    led.require()
    child = led.reserve()
    led.started(child, "r1")
    decision = C.Decision(stop=stop, detail=detail)
    decision.terminal = terminal or {}
    object.__setattr__(decision, "stop", stop)
    if success:
        decision.stop = "fixed_point"
    led.finish(decision)
    return led


@pytest.mark.parametrize("stop,terminal,code", [
    ("child_fault", None, 5),                       # a child broke: machinery
    ("terminal", {"machinery": 2}, 5),              # a terminal that is machinery is still machinery
    ("terminal", {"unschedulable": 3}, 4),          # nobody could schedule it: lost coverage
    ("terminal", {"dependency": 1}, 4),
    ("terminal", {"entitlement": 4}, 3),            # the one terminal we chose to live with
    ("terminal", {"entitlement": 1, "machinery": 1}, 5),   # mixed: the most serious wins
    ("no_progress", None, 4),
    ("unknown", None, 4),
    ("max_runs", None, 3),
    ("budget", None, 3),
    ("fixed_point", None, 0),
])
def test_status_campaign_reports_the_ledgers_own_verdict(tmp_path, stop, terminal, code):
    _ledger(tmp_path, "c1", stop=stop, detail="why", terminal=terminal)
    res = _invoke(tmp_path, "status", "--campaign", "c1", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == code, (res.stdout, res.stderr)
    assert doc["campaign_id"] == "c1" and doc["exit_code"] == code


def test_a_campaign_that_never_finished_is_gapped_and_names_the_resume(tmp_path):
    from quarry_recon import campaign as C
    led = C.Campaign(tmp_path, "c-open")
    led.require()
    led.started(led.reserve(), "r1")             # recorded, never finished
    res = _invoke(tmp_path, "status", "--campaign", "c-open", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 4 and "--settle-resume c-open" in doc["remediation"]


# ── 6/7. every exit leaves through the contract, Click's own included ─────────────────────────────
#: `--json` goes FIRST: a trailing option would bind it as its own value, not as a request for a document
@pytest.mark.parametrize("argv,code", [
    (["run", "--json", "--nope"], 2),             # unknown option
    (["run", "--json"], 2),                       # missing a required option
    (["nosuchcommand", "--json"], 2),             # unknown command
    (["doctor", "--json", "--phase"], 2),         # an option missing its argument
])
def test_click_parse_errors_carry_a_document_and_exit_two(argv, code):
    res = CliRunner(mix_stderr=False).invoke(cli, argv)
    doc = json.loads(res.stdout)                  # the whole of stdout parses: prose stayed on stderr
    assert res.exit_code == code and doc["exit_code"] == code
    assert doc["outcome"] == "invalid" and doc["schema_version"] == state.SCHEMA_VERSION
    assert doc["remediation"], "a parse error must still say what was wrong"


def test_a_phases_value_that_looks_like_a_flag_is_a_value_not_a_json_request(tmp_path):
    # `--phases --json` binds `--json` AS the selector; the operator never asked for a document
    res = _invoke(tmp_path, "run", "--phases", "--json")
    assert res.exit_code == 2 and res.stdout == ""
    assert "unknown phase(s): --json" in res.stderr


@pytest.mark.parametrize("argv", [["--help"], ["--version"], ["run", "--help"]])
def test_help_and_version_still_exit_zero(argv):
    res = CliRunner(mix_stderr=False).invoke(cli, argv)
    assert res.exit_code == 0, res.stderr
    assert res.stdout.strip()


def test_no_command_returns_an_undocumented_exit_one(tmp_path, monkeypatch):
    """Every failing surface uses a code the contract declares; 1 is not one of them."""
    seen = {}
    for argv in (["report", "-t", str(_profile(tmp_path))],          # no runs yet
                 ["status", "-t", str(_profile(tmp_path))],
                 ["oob", "poll", "-t", str(_profile(tmp_path))],
                 ["set", "nosuchfile"],
                 ["init", "bad/name"],
                 ["doctor", "--phase", "nosuchphase"],
                 ["install", "--only", "nosuchtool"]):
        res = CliRunner(mix_stderr=False).invoke(cli, argv)
        seen[argv[0] + " " + (argv[1] if len(argv) > 1 else "")] = res.exit_code
        assert res.exit_code in state.EXIT_CODES, (argv, res.exit_code, res.stderr)
        assert res.exit_code != 1, (argv, res.stderr)
    assert seen, seen


def test_lock_drift_is_a_coverage_verdict_not_a_bare_failure(monkeypatch):
    from quarry_recon import cli as cli_mod, registry
    from quarry_recon.registry import Tool
    tool = Tool(bin="subfinder", phase="vertical", role="x", pin="v2.14.0")
    monkeypatch.setattr(Tool, "installed", property(lambda self: True))
    monkeypatch.setattr(registry, "load_tools", lambda: [tool])
    monkeypatch.setattr(cli_mod, "load_tools", lambda: [tool])
    monkeypatch.setattr(registry, "installed_identity", lambda t: "")
    res = CliRunner(mix_stderr=False).invoke(cli, ["lock", "--drift-only", "--json"])
    doc = json.loads(res.stdout)
    assert res.exit_code == 4 and doc["gaps"] and doc["command"] == "lock"


# ── 8. a finished run's verdict is sealed ─────────────────────────────────────────────────────────
def test_a_successful_finalisation_seals_the_verdict(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod
    seen = {}
    real = cli_mod._publish_views

    def spy(run_obj, scope, **kw):
        seen["run"] = run_obj
        return real(run_obj, scope, **kw)

    monkeypatch.setattr(cli_mod, "_publish_views", spy)
    assert _run(tmp_path, monkeypatch).exit_code == 0
    finished_run = seen["run"]
    with pytest.raises(state.ContractError):
        finished_run.commit_fault(state.Fault("machinery", where="late"))
    with pytest.raises(state.ContractError):
        finished_run.commit_gap(state.Gap(source_id="late", kind="unknown"))


def test_the_seal_survives_a_reopen(tmp_path, monkeypatch):
    """The in-instance flag is not the contract: every caller reaches a finished run through `Run.open`."""
    assert _run(tmp_path, monkeypatch).exit_code == 0
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)      # the way report/status/oob reach it
    assert run.state == "finished" and run._verdict_sealed is False
    with pytest.raises(state.ContractError):
        run.commit_fault(state.Fault("machinery", where="late"))
    with pytest.raises(state.ContractError):
        run.commit_gap(state.Gap(source_id="late", kind="unknown"))


def test_the_deliberate_reopen_accepts_records_again(tmp_path, monkeypatch):
    """Sealing unconditionally would close the hole and break the resume `report` depends on."""
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    run.write_state("finalizing")                               # exactly what `report` performs
    run.commit_fault(state.Fault("publication", where="hotlist", detail="volume read-only"))
    run.commit_gap(state.Gap(source_id="probe.checkpoint", kind="unknown"))
    assert run._run_summary()["verdict"] == "complete_with_gaps"


def test_the_manifest_is_the_authority_a_supervisor_reads(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    # a reopened run has no in-process tool ledger, so `summary()` must come off disk, not be recomputed
    assert run.summary() == _summary(tmp_path)


# ── 9. an interrupted campaign is continued, not re-minted ────────────────────────────────────────
def test_a_lone_interrupted_campaign_is_continued_by_default(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, settle as _settle
    seen = {}
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: seen.update(kw) or _settle.Outcome(campaign_id=kw["campaign_id"] or "new",
                                                                       stop="fixed_point", success=True))
    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: "c-open")
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    res = _invoke(tmp_path, "run", "--settle")
    assert res.exit_code == 0, res.stderr
    assert seen["campaign_id"] == "c-open", "a killed campaign must not be re-minted"


def test_the_auto_resume_is_scoped_to_this_target(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, settle as _settle
    asked = {}

    def _resumable(project, target=None):
        asked["target"] = target
        return None

    monkeypatch.setattr(_settle, "resumable", _resumable)
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: _settle.Outcome(campaign_id="c1", stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    _invoke(tmp_path, "run", "--settle")
    # a campaign's union is one target's corpus; resuming another target's would file evidence wrongly
    assert asked["target"] == "t"


def test_an_explicit_id_overrides_the_auto_detect(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, settle as _settle
    seen = {}
    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: "c-auto")
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: seen.update(kw) or _settle.Outcome(campaign_id=kw["campaign_id"],
                                                                        stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    _invoke(tmp_path, "run", "--settle", "--settle-resume", "c-chosen")
    assert seen["campaign_id"] == "c-chosen"


def test_settle_resume_needs_the_axis_it_bounds(tmp_path):
    res = _invoke(tmp_path, "run", "--settle-resume", "c1")
    assert res.exit_code == 2 and "need --settle" in res.stderr


@pytest.mark.parametrize("exc,code", [("AlreadyRun", 6), ("WrongTarget", 6)])
def test_a_refused_campaign_is_refused_not_a_traceback(tmp_path, monkeypatch, exc, code):
    from quarry_recon import cli as cli_mod, settle as _settle

    def _raise(**kw):
        raise getattr(_settle, exc)("nope")

    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: None)
    monkeypatch.setattr(_settle, "settle", _raise)
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == code and doc["outcome"] == "refused"
    assert "Traceback" not in res.stderr


# ── 10. content-addressed views, and a resume that republishes only what is stale ─────────────────
def test_enriching_a_record_in_place_makes_the_views_stale(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    assert run.add("subdomain", {"host": "a.example.com", "source": "x"})
    before, count = run.generation(), run.count("subdomain")
    # `add` answers "was this a NEW identity"; enriching one is False, and still changes what is stored
    run.add("subdomain", {"host": "a.example.com", "source": "y", "tech": "nginx"})
    # the count did not move; the content did, and a view built from the thinner record is stale
    assert run.count("subdomain") == count
    assert run.generation() != before
    assert not run.stage_current("hotlist")


def test_a_resume_republishes_only_the_stale_views(tmp_path, monkeypatch):
    from quarry_recon import triage
    _break(monkeypatch, triage, "build")
    _run(tmp_path, monkeypatch)
    monkeypatch.undo()
    _one_phase(monkeypatch)
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 0, res.stderr
    # exports/digest/checkpoints were published by the run; only the view that failed is republished
    assert "republished hotlist" in res.stdout, res.stdout


def test_force_republishes_everything(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    res = _invoke(tmp_path, "report", "--force")
    assert res.exit_code == 0, res.stderr
    for stage in ("exports", "hotlist", "digest"):
        assert stage in res.stdout


# ── the reconciliation and 009's revision certification must not silently fight ───────────────────
def test_reconciling_the_manifest_does_not_silently_orphan_a_revision(tmp_path, monkeypatch):
    """A revision pins the base manifest digest; reconciling rewrites it. Either the re-certification hook
    exists and keeps it valid, or the loss is stated — never discovered from a report missing rows."""
    from quarry_recon import oob, revision, triage
    _break(monkeypatch, triage, "build")
    _run(tmp_path, monkeypatch)                       # finalization_failed, with a publication fault
    monkeypatch.undo()
    _one_phase(monkeypatch)

    src = tmp_path / "cb.jsonl"
    src.write_text(json.dumps({"protocol": "dns", "unique-id": "csession01", "full-id": "abc.oast.me",
                               "q-type": "A", "remote-address": "203.0.113.9",
                               "timestamp": "2026-08-10T12:00:00Z"}) + "\n")
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    oob.import_file(run, src)
    assert revision.read(run.dir).status == "valid"

    res = _invoke(tmp_path, "report")                 # the resume clears the fault -> manifest changes
    assert res.exit_code == 0, res.stderr
    if revision.read(run.dir).status != "valid":
        assert "no longer certifies" in res.stdout + res.stderr, \
            "a revision invalidated by the reconciliation must be reported, not silently dropped"


# ═══ round 3: nothing fails open ═══════════════════════════════════════════════════════════════════
def _with_revision(tmp_path, monkeypatch):
    """A finished run carrying one certified late-evidence revision."""
    from quarry_recon import oob
    _run(tmp_path, monkeypatch)
    src = tmp_path / "cb.jsonl"
    src.write_text(json.dumps({"protocol": "dns", "unique-id": "c1", "full-id": "abc.oast.me",
                               "q-type": "A", "remote-address": "203.0.113.9",
                               "timestamp": "2026-08-10T12:00:00Z"}) + "\n")
    oob.import_file(Run.open(tmp_path, "t", _run_dir(tmp_path).name), src)
    return _run_dir(tmp_path)


# ── an unusable revision is a gap, never a silent base render ─────────────────────────────────────
def _damage_revision(run_dir: Path) -> None:
    next(iter((run_dir / "revisions").rglob("*.jsonl"))).write_text("{ corrupt\n")


@pytest.mark.parametrize("cmd", ["report", "status"])
def test_an_uncertifiable_revision_is_surfaced_not_rendered_over(tmp_path, monkeypatch, cmd):
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    assert revision.read(d).status == "valid"
    _damage_revision(d)
    assert revision.read(d).status == "unusable"

    res = _invoke(tmp_path, cmd, "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 4, res.stderr          # never 0 while late evidence is missing from the views
    assert any(g["source_id"] == "revision" for g in doc["gaps"]), doc["gaps"]


def test_a_certified_revision_still_reports_clean(tmp_path, monkeypatch):
    _with_revision(tmp_path, monkeypatch)
    assert _invoke(tmp_path, "report").exit_code == 0
    assert _invoke(tmp_path, "status").exit_code == 0


# ── a corrupt manifest is not a commitment ────────────────────────────────────────────────────────
@pytest.mark.parametrize("body", ["{ not json", "[]", "", '{"run_id": "x"}'])
def test_a_damaged_manifest_is_not_committed(tmp_path, monkeypatch, body):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    assert run.manifest_committed()
    (_run_dir(tmp_path) / "manifest.json").write_text(body)
    assert not Run.open(tmp_path, "t", _run_dir(tmp_path).name).manifest_committed()


@pytest.mark.parametrize("cmd,code", [("report", 5), ("status", 4)])
def test_a_damaged_manifest_never_reports_clean(tmp_path, monkeypatch, cmd, code):
    _run(tmp_path, monkeypatch)
    (_run_dir(tmp_path) / "manifest.json").write_text("{ not json")
    res = _invoke(tmp_path, cmd)
    assert res.exit_code == code, res.stderr


def test_a_damaged_manifest_with_no_lifecycle_record_is_unknown(tmp_path, monkeypatch):
    # neither file can say how the run ended, so nothing may infer that it finished
    _run(tmp_path, monkeypatch)
    d = _run_dir(tmp_path)
    (d / "state.json").unlink()
    (d / "manifest.json").write_text("{ not json")
    assert Run.open(tmp_path, "t", d.name).state == state.STATE_UNKNOWN


# ── the re-seal is contained ──────────────────────────────────────────────────────────────────────
def test_a_failing_second_seal_is_recorded_not_left_finalizing(tmp_path, monkeypatch):
    from quarry_recon import store
    real, calls = store.Run.write_manifest, {"n": 0}

    def flaky(self, *a, **k):
        calls["n"] += 1
        if calls["n"] >= 2:                        # the base commit lands, the re-seal does not
            raise OSError("volume went read-only after the base commit")
        return real(self, *a, **k)

    monkeypatch.setattr(store.Run, "write_manifest", flaky)
    res = _run(tmp_path, monkeypatch)
    assert res.exit_code == 5, res.stderr
    rec = _state(tmp_path)
    assert rec["state"] == "finalization_failed"   # not stuck `finalizing` over a manifest since disproved
    assert rec["stages"]["reseal"]["status"] == "failed"


# ── several resumable campaigns is a choice, not a default ────────────────────────────────────────
def test_several_resumable_campaigns_are_refused_and_listed(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, settle as _settle
    minted = {}
    monkeypatch.setattr(_settle, "resumable_campaigns", lambda project, target=None: ["c-a", "c-b"])
    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: None)
    monkeypatch.setattr(_settle, "settle", lambda **kw: minted.update(kw))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 6, res.stderr          # refused: minting here buys child 1 a third time
    assert not minted, "an ambiguous resume must not start a campaign"
    for cid in ("c-a", "c-b"):
        assert cid in doc["remediation"], doc["remediation"]


def test_exactly_one_resumable_campaign_still_continues(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, settle as _settle
    seen = {}
    monkeypatch.setattr(_settle, "resumable_campaigns", lambda project, target=None: ["c-only"])
    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: "c-only")
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: seen.update(kw) or _settle.Outcome(campaign_id=kw["campaign_id"],
                                                                        stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    assert _invoke(tmp_path, "run", "--settle").exit_code == 0
    assert seen["campaign_id"] == "c-only"


# ── a missing view is stale, not certified away ───────────────────────────────────────────────────
def test_a_deleted_revision_view_is_rebuilt(tmp_path, monkeypatch):
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    hot = d / "revisions" / revision.read(d).views["dir"] / "HOTLIST.md"
    assert hot.exists()
    hot.unlink()

    res = _invoke(tmp_path, "report")
    assert res.exit_code == 0, res.stderr
    assert hot.exists(), "a view deleted since it was stamped is stale, however current the stamp looks"
    assert "republished hotlist" in res.stdout
    assert "HOTLIST.md" in revision.read(d).views.get("files", {})


def test_report_renders_the_revision_view_while_it_holds_the_run_finalizing(tmp_path, monkeypatch):
    """`base_disposition` answers whether a supplement may certify now; report asks a different question."""
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    rev_hotlist = d / "revisions" / revision.read(d).views["dir"] / "HOTLIST.md"
    before = rev_hotlist.read_bytes()
    rev_hotlist.unlink()
    _invoke(tmp_path, "report")
    assert rev_hotlist.exists() and rev_hotlist.read_bytes() == before


def test_a_deleted_base_view_is_rebuilt_too(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    hot = _run_dir(tmp_path) / "reports" / "HOTLIST.md"
    hot.unlink()
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 0 and hot.exists()
    assert "republished hotlist" in res.stdout


# ── a revision failure is machinery ───────────────────────────────────────────────────────────────
def test_a_revision_that_cannot_be_certified_is_machinery_not_bad_input(tmp_path, monkeypatch):
    d = _with_revision(tmp_path, monkeypatch)
    _damage_revision(d)
    src = tmp_path / "cb2.jsonl"
    src.write_text(json.dumps({"protocol": "dns", "unique-id": "c2", "full-id": "def.oast.me",
                               "q-type": "A", "remote-address": "203.0.113.9",
                               "timestamp": "2026-08-10T12:00:00Z"}) + "\n")
    res = CliRunner(mix_stderr=False).invoke(
        cli, ["oob", "import", str(src), "-t", str(_profile(tmp_path)), "--json"])
    doc = json.loads(res.stdout)
    assert res.exit_code == 5, res.stderr          # machinery, not exit 2 "invalid input"
    assert doc["faults"] and doc["faults"][0]["kind"] == "machinery"


# ═══ round 3 follow-up: 009's certification/missing-views APIs, and 012's two cli items ════════════
@pytest.mark.parametrize("cmd", ["report", "status"])
def test_absent_late_evidence_is_not_an_unusable_one(tmp_path, monkeypatch, cmd):
    """`absent` and `unusable` must not collapse: only one of them means evidence was lost."""
    from quarry_recon import revision
    _run(tmp_path, monkeypatch)
    assert revision.certification(_run_dir(tmp_path))[0] == "absent"
    assert _invoke(tmp_path, cmd).exit_code == 0


def test_a_deleted_view_does_not_uncertify_the_revision(tmp_path, monkeypatch):
    """A view is derived and rebuildable: losing one is staleness, not a certification failure."""
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    (d / "revisions" / revision.read(d).views["dir"] / "HOTLIST.md").unlink()
    assert revision.certification(d)[0] == "valid"
    assert "HOTLIST.md" in revision.missing_views(d)
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 0 and revision.missing_views(d) == []


def test_a_view_the_pointer_recorded_is_rebuilt_even_when_the_run_dir_looks_whole(tmp_path, monkeypatch):
    """The exports directory is non-empty, so only the pointer knows this particular file went missing."""
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    vdir = d / "revisions" / revision.read(d).views["dir"]
    gone = next(p for p in (vdir / "exports").iterdir())
    gone.unlink()
    assert revision.missing_views(d) == [f"exports/{gone.name}"]
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 0, res.stderr
    assert gone.exists() and "republished exports" in res.stdout


# ── 012: a mistyped campaign id is a bad selector, not broken machinery ───────────────────────────
@pytest.mark.parametrize("argv", [["run", "--settle", "--settle-resume", "../evil"],
                                  ["run", "--settle", "--settle-resume", "a/b"],
                                  ["status", "--campaign", "../evil"]])
def test_an_invalid_campaign_id_exits_two(tmp_path, argv):
    res = _invoke(tmp_path, *argv)
    assert res.exit_code == 2, res.stderr
    assert "Traceback" not in res.stderr


# ── 012: a declared bound reaches the same status on every path ───────────────────────────────────
def _limited_ledger(tmp_path, cid="c-lim", *, verdict="complete_with_limits"):
    from quarry_recon import campaign as C
    led = C.Campaign(tmp_path, cid)
    led.require()
    child = led.reserve()
    led.started(child, "r1")
    led.manifested(child, summary={"verdict": verdict, "remainders": []},
                   absorbed=C.AbsorbResult(), decision=C.Decision(stop="fixed_point"))
    led.finish(C.Decision(stop="fixed_point"))
    return led


def test_a_bounded_child_reports_bounded_from_the_ledger(tmp_path):
    _limited_ledger(tmp_path)
    res = _invoke(tmp_path, "status", "--campaign", "c-lim", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 3, res.stderr           # the same evidence `run` standalone exits 3 for
    assert doc["coverage"] == "intentionally_bounded"


def test_a_clean_child_still_reports_clean(tmp_path):
    _limited_ledger(tmp_path, "c-clean", verdict="complete")
    assert _invoke(tmp_path, "status", "--campaign", "c-clean").exit_code == 0


def test_a_bounded_child_reports_bounded_from_the_campaign_run(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, settle as _settle
    child = _settle.ChildRun(index=1, run_id="r1", verdict="complete_with_limits")
    monkeypatch.setattr(_settle, "resumable_campaigns", lambda project, target=None: [])
    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: None)
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: _settle.Outcome(campaign_id="c1", stop="fixed_point", success=True,
                                                     children=[child]))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 3, res.stderr
    assert doc["coverage"] == "intentionally_bounded" and doc["campaign_id"] == "c1"


# ── an envelope refusal during an OOB import is a gap, not a clean import ─────────────────────────
def test_interactions_refused_past_the_envelope_are_a_gap(tmp_path, monkeypatch):
    from quarry_recon import cli as cli_mod, oob
    _run(tmp_path, monkeypatch)
    src = tmp_path / "cb.jsonl"
    src.write_text(json.dumps({"protocol": "dns", "unique-id": "c1", "full-id": "abc.oast.me",
                               "q-type": "A", "remote-address": "203.0.113.9",
                               "timestamp": "2026-08-10T12:00:00Z"}) + "\n")
    real = oob.import_file
    monkeypatch.setattr(oob, "import_file",
                        lambda *a, **k: {**real(*a, **k), "refused": 3})
    res = CliRunner(mix_stderr=False).invoke(
        cli, ["oob", "import", str(src), "-t", str(_profile(tmp_path)), "--json"])
    doc = json.loads(res.stdout)
    assert res.exit_code == 4, res.stderr
    assert doc["gaps"][0]["source_id"] == "oob" and doc["gaps"][0]["omitted"] == 3


def test_an_import_that_refused_nothing_is_clean(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    src = tmp_path / "cb.jsonl"
    src.write_text(json.dumps({"protocol": "dns", "unique-id": "c1", "full-id": "abc.oast.me",
                               "q-type": "A", "remote-address": "203.0.113.9",
                               "timestamp": "2026-08-10T12:00:00Z"}) + "\n")
    res = CliRunner(mix_stderr=False).invoke(
        cli, ["oob", "import", str(src), "-t", str(_profile(tmp_path))])
    assert res.exit_code == 0, res.stderr


# ═══ round 4: the predicates themselves fail closed ════════════════════════════════════════════════
# ── a commitment is a well-formed record, not a present file ──────────────────────────────────────
@pytest.mark.parametrize("mutate", [
    lambda m: m.update(entity_counts={"subdomain": "lots"}),          # string counter
    lambda m: m.update(entity_counts={"subdomain": -5}),              # negative counter
    lambda m: m.update(entity_counts={"subdomain": True}),            # a bool is not a count
    lambda m: m.update(entity_counts=[]),                             # not a mapping
    lambda m: m.update(summary="broken"),                             # summary not an object
    lambda m: m.pop("summary"),                                       # no summary at all
])
def test_a_malformed_manifest_is_not_committed(tmp_path, monkeypatch, mutate):
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    manifest = json.loads(path.read_text())
    mutate(manifest)
    path.write_text(json.dumps(manifest))
    assert not Run.open(tmp_path, "t", _run_dir(tmp_path).name).manifest_committed()


def test_a_malformed_stored_summary_fails_closed(tmp_path, monkeypatch):
    """Recomputing here would answer from an empty in-process ledger — a clean verdict invented for a
    broken record."""
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["summary"] = "broken"
    path.write_text(json.dumps(manifest))
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    with pytest.raises(state.ContractError):
        run.summary()


@pytest.mark.parametrize("cmd,code", [("report", 5), ("status", 4)])
def test_a_malformed_manifest_never_reports_clean(tmp_path, monkeypatch, cmd, code):
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["entity_counts"] = {"subdomain": "lots"}
    manifest["summary"] = "broken"
    path.write_text(json.dumps(manifest))
    assert _invoke(tmp_path, cmd).exit_code == code


def test_the_committed_rule_is_one_function(tmp_path, monkeypatch):
    """One rule, callable without a Run, so every reader agrees on what a commitment is."""
    from quarry_recon import store
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    assert store.manifest_committed(path)
    assert store.manifest_committed(path) == Run.open(tmp_path, "t", _run_dir(tmp_path).name).manifest_committed()
    assert not store.manifest_committed(tmp_path / "nope.json")


# ── a lifecycle record must be THIS run's, and shaped as this reader understands ──────────────────
@pytest.mark.parametrize("record", [
    {"schema_version": 1, "run_id": "someone-elses-run", "state": "finished", "stages": {}},
    {"run_id": "SELF", "state": "finished", "stages": {}},                       # no schema_version
    {"schema_version": 99, "run_id": "SELF", "state": "finished", "stages": {}},  # unknown version
    {"schema_version": True, "run_id": "SELF", "state": "finished", "stages": {}},  # a bool is not 1
    {"schema_version": 1, "run_id": "SELF", "state": "finished", "stages": []},   # stages not a mapping
    {"schema_version": 1, "run_id": "SELF", "state": "finished", "stages": {"hotlist": "done"}},
    {"schema_version": 1, "run_id": "SELF", "state": "finished"},                 # no stages at all
])
def test_a_foreign_or_malformed_lifecycle_record_is_unknown(tmp_path, monkeypatch, record):
    _run(tmp_path, monkeypatch)
    d = _run_dir(tmp_path)
    record = {k: (d.name if v == "SELF" else v) for k, v in record.items()}
    (d / "state.json").write_text(json.dumps(record))
    run = Run.open(tmp_path, "t", d.name)
    assert run.state == state.STATE_UNKNOWN
    # and nothing downstream crashes on the shape it just refused
    assert run.finalization_stages == {}
    assert run.finalization_failed() is False


def test_a_well_formed_record_is_still_accepted(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    d = _run_dir(tmp_path)
    assert Run.open(tmp_path, "t", d.name).state == "finished"
    assert json.loads((d / "state.json").read_text())["run_id"] == d.name


# ── report's reseal and reconciliation are contained ──────────────────────────────────────────────
def test_a_failing_reconciliation_leaves_a_resumable_run(tmp_path, monkeypatch):
    from quarry_recon import store
    _run(tmp_path, monkeypatch)
    monkeypatch.setattr(store.Run, "reconcile_finalization",
                        lambda self: (_ for _ in ()).throw(OSError("volume read-only")))
    res = _invoke(tmp_path, "report", "--force")
    assert res.exit_code == 5, res.stderr
    rec = _state(tmp_path)
    assert rec["state"] == "finalization_failed"      # not stuck mid-flight in `finalizing`
    assert rec["stages"]["reconcile"]["status"] == "failed"


def test_a_failing_view_reseal_leaves_a_resumable_run(tmp_path, monkeypatch):
    from quarry_recon import revision
    _with_revision(tmp_path, monkeypatch)
    monkeypatch.setattr(revision, "reseal_views",
                        lambda run_dir: (_ for _ in ()).throw(OSError("pointer volume read-only")))
    res = _invoke(tmp_path, "report", "--force")
    assert res.exit_code == 5, res.stderr
    rec = _state(tmp_path)
    assert rec["state"] == "finalization_failed"
    assert rec["stages"]["reseal_views"]["status"] == "failed"


# ── a recorded finalisation failure is machinery, whatever the stale manifest says ────────────────
def test_status_reports_a_recorded_finalisation_failure_as_machinery(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    assert _summary(tmp_path)["verdict"] == "complete"       # the manifest is clean and now stale
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    run.write_state("finalizing")
    run.mark_stage("hotlist", "failed", detail="volume read-only")
    run.write_state("finalization_failed")

    res = _invoke(tmp_path, "status", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 5, res.stderr
    assert doc["outcome"] == "failed"
    assert [f["where"] for f in doc["faults"]] == ["hotlist"]
    assert "quarry report" in doc["remediation"]


def test_a_finalisation_failure_with_no_named_stage_still_reports_machinery(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    run.write_state("finalizing")
    run.write_state("finalization_failed")
    res = _invoke(tmp_path, "status")
    assert res.exit_code == 5, res.stderr


# ── a durable envelope refusal keeps reporting itself ─────────────────────────────────────────────
def _persist_refusal(run_dir: Path, n: int = 2) -> None:
    from quarry_recon import revision
    ptr = json.loads(revision.pointer_path(run_dir).read_text())
    ptr["refused"] = [{"entity": "oob_interaction", "key": f"k{i}", "kind": "keys"} for i in range(n)]
    revision.pointer_path(run_dir).write_text(json.dumps(ptr, indent=2))


@pytest.mark.parametrize("cmd", ["status", "report"])
def test_a_persisted_envelope_refusal_still_gaps_a_later_command(tmp_path, monkeypatch, cmd):
    """The import said so once; the loss is durable, so every later reader must say so too."""
    d = _with_revision(tmp_path, monkeypatch)
    _persist_refusal(d)
    res = _invoke(tmp_path, cmd, "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 4, res.stderr
    gap = next(g for g in doc["gaps"] if g["source_id"] == "oob")
    assert gap["kind"] == "cap" and gap["omitted"] == 2


def test_a_revision_with_nothing_refused_stays_clean(tmp_path, monkeypatch):
    _with_revision(tmp_path, monkeypatch)
    assert _invoke(tmp_path, "status").exit_code == 0
    assert _invoke(tmp_path, "report").exit_code == 0


# ── a campaign nobody can confirm is named, not passed over ───────────────────────────────────────
def test_an_unconfirmable_campaign_is_named_before_minting(tmp_path, monkeypatch):
    from quarry_recon import campaign as C, cli as cli_mod, settle as _settle
    led = C.Campaign(tmp_path, "c-unconf")
    led.require()
    led.started(led.reserve(), "20260101-000000-deadbeef")     # the child directory never existed
    minted = {}
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: minted.update(kw) or _settle.Outcome(
                            campaign_id=kw["campaign_id"] or "c-new", stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)

    res = _invoke(tmp_path, "run", "--settle")
    # round 5: naming the harm was not enough — an unconfirmable campaign now REFUSES by default
    assert res.exit_code == 6, res.stderr
    out = res.stdout + res.stderr
    assert "c-unconf" in out and "no readable creation record" in out   # 012's reason, not one invented here
    assert not minted, "a refused resume must not start a campaign at all"


def test_a_project_with_nothing_to_skip_says_nothing(tmp_path, monkeypatch):
    """The notice is for campaigns actually passed over; a clean project must not grow noise."""
    from quarry_recon import cli as cli_mod, settle as _settle
    monkeypatch.setattr(_settle, "skipped_resumable", lambda project, target=None: [])
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: _settle.Outcome(campaign_id="c1", stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    res = _invoke(tmp_path, "run", "--settle")
    assert "skipped" not in res.stdout + res.stderr


def test_a_campaign_skipped_for_its_target_says_so_accurately(tmp_path, monkeypatch):
    """A campaign the target filter drops is passed over for a stated reason, not called broken."""
    from quarry_recon import cli as cli_mod, settle as _settle
    monkeypatch.setattr(_settle, "skipped_resumable",
                        lambda project, target=None: [("c-other", "it ran against 'other.com'")])
    monkeypatch.setattr(_settle, "resumable_campaigns", lambda project, target=None: [])
    monkeypatch.setattr(_settle, "resumable", lambda project, target=None: None)
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: _settle.Outcome(campaign_id="c1", stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    res = _invoke(tmp_path, "run", "--settle")
    out = res.stdout + res.stderr
    assert "c-other: it ran against 'other.com'" in out
    assert "broken" not in out and "cannot" not in out


# ═══ round 4 follow-up: 012's skipped_resumable / InvalidRunId, 009's durable refusals ═════════════
def _damaged_ledger(tmp_path, cid="c-dmg", *, run_id="../../../etc"):
    """A ledger whose child id points outside the project — damaged machinery, not operator input."""
    from quarry_recon import campaign as C
    led = C.Campaign(tmp_path, cid)
    led.require()
    led.started(led.reserve(), "20260101-000000-deadbeef")
    path = tmp_path / "recon" / "campaigns" / cid / "ledger.json"
    doc = json.loads(path.read_text())
    for child in doc.get("children", []):
        child["run_id"] = run_id
    path.write_text(json.dumps(doc))
    return cid


def test_a_damaged_child_id_is_machinery_not_a_bad_selector(tmp_path):
    """`InvalidCampaignId` is operator input (exit 2); a child id comes from the ledger, so a traversal
    there is damage (exit 5). Neither may escape as a traceback."""
    cid = _damaged_ledger(tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--settle-resume", cid, "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 5, res.stderr
    assert "Traceback" not in res.stderr
    assert doc["faults"] and doc["faults"][0]["kind"] == "machinery"


def test_a_damaged_ledger_read_back_is_a_gap_not_a_crash(tmp_path):
    cid = _damaged_ledger(tmp_path, "c-dmg2")
    res = _invoke(tmp_path, "status", "--campaign", cid, "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 4, res.stderr
    assert "Traceback" not in res.stderr and doc["gaps"]


def test_the_two_invalid_id_classes_take_different_exits(tmp_path):
    """One typo, one damaged record: they must not converge on the same status."""
    typo = _invoke(tmp_path, "run", "--settle", "--settle-resume", "../evil")
    damaged = _invoke(tmp_path, "run", "--settle", "--settle-resume", _damaged_ledger(tmp_path, "c-dmg3"))
    assert (typo.exit_code, damaged.exit_code) == (2, 5)


# ── evidence LOST and evidence INCOMPLETE are different gaps, both exit 4 ─────────────────────────
def test_a_standing_refusal_does_not_uncertify_the_revision(tmp_path, monkeypatch):
    """009's pairing: a refusal is incomplete-but-honest, so certification stays valid."""
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    _persist_refusal(d, 2)
    assert revision.certification(d)[0] == "valid"
    assert len(revision.refusals(d)) == 2


@pytest.mark.parametrize("cmd", ["status", "report"])
def test_the_two_gaps_report_their_own_reason(tmp_path, monkeypatch, cmd):
    d = _with_revision(tmp_path, monkeypatch)
    _persist_refusal(d, 2)
    doc = json.loads(_invoke(tmp_path, cmd, "--json").stdout)
    kinds = {g["source_id"]: g for g in doc["gaps"]}
    assert "oob" in kinds and kinds["oob"]["kind"] == "cap"          # evidence incomplete
    assert "revision" not in kinds, "a standing refusal is not an uncertifiable revision"


def test_an_uncertifiable_revision_reports_no_refusal_gap(tmp_path, monkeypatch):
    """009 reports no refusals for a broken revision rather than guess, so only the lost-evidence gap shows."""
    from quarry_recon import revision
    d = _with_revision(tmp_path, monkeypatch)
    _persist_refusal(d, 2)
    _damage_revision(d)
    assert revision.certification(d)[0] == "unusable" and revision.refusals(d) == []
    doc = json.loads(_invoke(tmp_path, "status", "--json").stdout)
    sources = {g["source_id"] for g in doc["gaps"]}
    assert "revision" in sources and "oob" not in sources


# ── an import reports what STANDS, not only what it turned away ───────────────────────────────────
def test_an_import_that_refused_nothing_still_reports_a_standing_debt(tmp_path, monkeypatch):
    from quarry_recon import oob
    _run(tmp_path, monkeypatch)
    src = tmp_path / "cb.jsonl"
    src.write_text(json.dumps({"protocol": "dns", "unique-id": "c1", "full-id": "abc.oast.me",
                               "q-type": "A", "remote-address": "203.0.113.9",
                               "timestamp": "2026-08-10T12:00:00Z"}) + "\n")
    real = oob.import_file
    monkeypatch.setattr(oob, "import_file",
                        lambda *a, **k: {**real(*a, **k), "refused": 0, "outstanding": 4})
    res = CliRunner(mix_stderr=False).invoke(
        cli, ["oob", "import", str(src), "-t", str(_profile(tmp_path)), "--json"])
    doc = json.loads(res.stdout)
    assert res.exit_code == 4, res.stderr
    assert doc["gaps"][0]["omitted"] == 4, "the run still owes rows even though this ingest refused none"


# ═══ round 5: a summary must be a summary, and unconfirmable evidence refuses by default ═══════════
# ── the required summary structure ────────────────────────────────────────────────────────────────
def test_the_required_summary_keys_are_what_the_writer_emits(tmp_path):
    """The constant may not drift from `_run_summary`, or the guard stops matching what it guards."""
    from quarry_recon import store
    run = Run.create(tmp_path, "t")
    assert set(run._run_summary()) == set(store.SUMMARY_KEYS)


@pytest.mark.parametrize("summary", [
    {},                                                   # a dict, but not a summary
    {"verdict": "complete"},                              # verdict alone proves nothing
    {"faults": [], "verdict": "complete"},                # exactly what the old repair produced
    "broken",
    None,
    [],
])
def test_a_summary_missing_its_required_keys_is_not_committed(tmp_path, monkeypatch, summary):
    from quarry_recon import store
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["summary"] = summary
    path.write_text(json.dumps(manifest))
    assert not store.summary_well_formed(summary)
    assert not store.manifest_committed(path)


def test_an_empty_summary_is_never_repaired_into_a_verdict(tmp_path, monkeypatch):
    """The reported chain: status 4, then report rewrote `{}` to a clean verdict and returned 0."""
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["summary"] = {}
    path.write_text(json.dumps(manifest))

    assert _invoke(tmp_path, "status").exit_code == 4
    res = _invoke(tmp_path, "report")
    assert res.exit_code == 5, res.stderr
    assert json.loads(path.read_text())["summary"] == {}, "reconciliation authored a verdict"


def test_reconciliation_refuses_a_malformed_summary(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    path = _run_dir(tmp_path) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["summary"] = {"verdict": "complete"}
    path.write_text(json.dumps(manifest))
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    assert run.reconcile_finalization() is None
    assert json.loads(path.read_text())["summary"] == {"verdict": "complete"}


def test_a_whole_summary_is_still_accepted(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)
    run = Run.open(tmp_path, "t", _run_dir(tmp_path).name)
    assert run.manifest_committed() and run.summary()["verdict"] == "complete"
    assert _invoke(tmp_path, "status").exit_code == 0


# ── unconfirmable evidence refuses; someone else's does not ───────────────────────────────────────
def _unconfirmable_campaign(tmp_path, cid="c-unconf"):
    from quarry_recon import campaign as C
    led = C.Campaign(tmp_path, cid)
    led.require()
    led.started(led.reserve(), "20260101-000000-deadbeef")   # the child directory never existed
    return cid


def _other_target_campaign(tmp_path, cid="c-other", target="other.com"):
    from quarry_recon import campaign as C
    run_id = "20260101-000000-abcdef01"
    d = tmp_path / "recon" / run_id
    d.mkdir(parents=True)
    (d / "run.json").write_text(json.dumps({"run_id": run_id, "target": target,
                                            "started": "2026-01-01T00:00:00+00:00"}))
    led = C.Campaign(tmp_path, cid)
    led.require()
    led.started(led.reserve(), run_id)
    return cid


def _stub_settle(monkeypatch, tmp_path):
    from quarry_recon import cli as cli_mod, settle as _settle
    calls: list = []
    monkeypatch.setattr(_settle, "settle",
                        lambda **kw: calls.append(kw) or _settle.Outcome(
                            campaign_id=kw["campaign_id"] or "c-fresh", stop="fixed_point", success=True))
    monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
    return calls


def test_an_unconfirmable_campaign_refuses_by_default(tmp_path, monkeypatch):
    """Nobody can say the evidence was ours, so minting over it is the operator's call, not a default."""
    cid = _unconfirmable_campaign(tmp_path)
    calls = _stub_settle(monkeypatch, tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--json")
    doc = json.loads(res.stdout)
    assert res.exit_code == 6, res.stderr
    assert not calls, "a refused resume must not start a campaign"
    assert cid in doc["remediation"] and "--settle-resume" in doc["remediation"]


def test_an_explicit_fresh_start_is_honoured(tmp_path, monkeypatch):
    _unconfirmable_campaign(tmp_path)
    calls = _stub_settle(monkeypatch, tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--settle-resume", "")
    assert res.exit_code == 0, res.stderr
    assert calls[-1]["campaign_id"] is None, "an empty id means mint a new one"


def test_an_explicit_resume_is_honoured(tmp_path, monkeypatch):
    cid = _unconfirmable_campaign(tmp_path)
    calls = _stub_settle(monkeypatch, tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--settle-resume", cid)
    assert res.exit_code == 0, res.stderr
    assert calls[-1]["campaign_id"] == cid


def test_a_campaign_confirmed_as_another_targets_still_starts_normally(tmp_path, monkeypatch):
    """Knowing whose it is, is not failing to: this one is accounted for, so a new campaign just starts."""
    from quarry_recon import settle as _settle
    _other_target_campaign(tmp_path)
    assert _settle.unconfirmable_resumable(tmp_path, "t") == []
    calls = _stub_settle(monkeypatch, tmp_path)
    res = _invoke(tmp_path, "run", "--settle")
    assert res.exit_code == 0, res.stderr
    assert calls and "it ran against 'other.com'" in res.stdout + res.stderr


def test_a_clean_project_starts_without_a_word(tmp_path, monkeypatch):
    calls = _stub_settle(monkeypatch, tmp_path)
    res = _invoke(tmp_path, "run", "--settle")
    assert res.exit_code == 0 and calls
    assert "skipped" not in res.stdout + res.stderr


def test_one_unconfirmable_among_others_still_refuses(tmp_path, monkeypatch):
    """A confirmable skip must not dilute an unconfirmable one into a mere notice."""
    _other_target_campaign(tmp_path)
    cid = _unconfirmable_campaign(tmp_path, "c-lost")
    calls = _stub_settle(monkeypatch, tmp_path)
    res = _invoke(tmp_path, "run", "--settle", "--json")
    assert res.exit_code == 6, res.stderr
    assert not calls
    remediation = json.loads(res.stdout)["remediation"]
    assert cid in remediation and "c-other" not in remediation
