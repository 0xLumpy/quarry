"""Phase 1: Params checkpoint and aggregate writers remain under one Run claim."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from quarry_recon import events, store
from quarry_recon.phases import params
from quarry_recon.runner import RunResult, Status


pytestmark = pytest.mark.offline


class _Context:
    def __init__(self, run):
        self.run = run
        self.http_timeout = 30

    def write_list(self, name, items):
        path = self.run.dir / "work" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(items))
        return path


def _running(tmp_path, run_id):
    run = store.Run.create(tmp_path, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _silence_events(monkeypatch):
    for name in (
        "tool_start", "tool_progress", "tool_finish", "coverage_partial",
        "ledger",
    ):
        monkeypatch.setattr(events, name, lambda *args, **kwargs: None)


def test_nuclei_claim_blocks_seal_through_postprocessing(tmp_path, monkeypatch):
    run = _running(tmp_path, "nuclei-claim")
    ctx = _Context(run)
    findings = run.raw_path("params", "nuclei", "findings.jsonl")
    log = run.raw_path("params", "nuclei", "nuclei.run.log")
    observed = []
    _silence_events(monkeypatch)
    monkeypatch.setattr(params.settings, "concurrency", lambda key, default=None: 1)
    monkeypatch.setattr(params, "_nuclei_templates_fp", lambda: "templates")
    monkeypatch.setattr(params, "_nuclei_mhe", lambda: 0)

    def fake_exec(_tool, command, **_kwargs):
        output = command[command.index("-o") + 1]
        from pathlib import Path
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"template-id":"t","host":"h"}\n')
        try:
            run.begin_finalization()
        except store.ContractError:
            observed.append("blocked")
        return RunResult(
            "nuclei", command, Status.SUCCESS, 0, 0.01, None, 0,
            stderr_tail="Scan completed in 1s\n1 / 1 requests",
        )

    monkeypatch.setattr(params, "exec_tool", fake_exec)
    result = params._nuclei_scan(
        ctx, ["https://acme.example"], findings, log,
        SimpleNamespace(http_rl=0),
    )

    assert observed == ["blocked"]
    assert run.state == "running"
    assert result.status is Status.SUCCESS
    assert findings.is_file()
    assert (findings.parent / "chunks.state.json").is_file()
    assert run._live_artifact_claim_count() == 0


def test_nuclei_state_publication_preserves_prior_on_fault(tmp_path, monkeypatch):
    run = _running(tmp_path, "nuclei-prior")
    ctx = _Context(run)
    state_path = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "params", "nuclei", "chunks.state.json"),
        b'{"prior":true}',
    )
    original = state_path.read_bytes()
    _silence_events(monkeypatch)
    monkeypatch.setattr(params.settings, "concurrency", lambda key, default=None: 1)
    monkeypatch.setattr(params, "_nuclei_templates_fp", lambda: "templates")
    monkeypatch.setattr(params, "_nuclei_mhe", lambda: 0)
    monkeypatch.setattr(params.budget, "publish_bytes", lambda *args, **kwargs: False)

    def fake_exec(_tool, command, **_kwargs):
        from pathlib import Path
        output = Path(command[command.index("-o") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("")
        return RunResult("nuclei", command, Status.SUCCESS, 0, 0.01, None, 0)

    monkeypatch.setattr(params, "exec_tool", fake_exec)
    with pytest.raises(OSError, match="publish state"):
        params._nuclei_scan(
            ctx, ["https://acme.example"],
            run.raw_path("params", "nuclei", "findings.jsonl"),
            run.raw_path("params", "nuclei", "nuclei.run.log"),
            SimpleNamespace(http_rl=0),
        )

    assert state_path.read_bytes() == original
    assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize("writer", ["state", "log", "lines"])
def test_fake_context_cannot_mutate_sealed_managed_artifact(tmp_path, writer):
    run = _running(tmp_path, f"sealed-{writer}")
    path = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "params", "fixture", f"{writer}.txt"),
        b"prior\n",
    )
    run.begin_finalization()
    fake = _Context(SimpleNamespace(dir=run.dir))

    with pytest.raises(store.ContractError):
        if writer == "state":
            params._publish_json_state(fake, path, {"new": True})
        elif writer == "log":
            params._append_run_log(fake, path, "new\n")
        else:
            params._publish_lines(fake, path, ["new"])

    assert path.read_bytes() == b"prior\n"


def test_fake_context_cannot_enter_managed_scan_transaction(tmp_path):
    run = _running(tmp_path, "sealed-fake-transaction")
    fake = _Context(SimpleNamespace(dir=run.dir))
    entered = []

    @params._base_evidence_claimed
    def operation(_ctx):
        entered.append(True)

    with pytest.raises(store.ContractError, match="exact Run owner"):
        operation(fake)
    assert entered == []
