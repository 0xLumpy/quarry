"""Focused non-promoting C-OUTPUT source-contract regressions.

The helper rows below deliberately use the real repository runner and its
private-stage publication seam.  The low-level supervisor is a faithful test
builder: it settles the same descriptor claims and artifact proofs as the
production supervisor, but supplies bytes only from the candidate-bound frozen
fixtures.  It never fabricates an external record: serialized receipt JSON is
validated only as an explicitly unauthenticated shape diagnostic.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import output_contract as contract
from quarry_recon import privfs, release_evidence as evidence, runner
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_repository, runner_supervisor as supervisor, store


ROOT = Path(__file__).resolve().parents[1]
_GIT_PATH = shutil.which("git")
GIT = os.fspath(Path(_GIT_PATH).resolve()) if _GIT_PATH else None
_WORKER_PID = 51231
_TOOL_PID = 51232


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest() -> dict:
    return json.loads((ROOT / contract.FROZEN_FIXTURE_MANIFEST_PATH).read_bytes())


def _git(repository: Path, *arguments: str) -> str:
    assert GIT is not None
    completed = subprocess.run(
        [GIT, "-C", os.fspath(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _candidate_repository(tmp_path: Path, manifest: dict) -> tuple[Path, dict]:
    """Make a real clean Git candidate containing every bound source input."""
    assert GIT is not None
    repository = tmp_path / "candidate"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Quarry C-OUTPUT Test")
    _git(repository, "config", "user.email", "c-output@example.invalid")
    inputs = set(evidence.DEFAULT_IDENTITY_INPUTS.values())
    inputs.update(contract.fixture_identity_inputs(manifest).values())
    for relative in sorted(inputs):
        source = ROOT / relative
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "candidate")
    identity = evidence.collect_candidate_identity(
        repository, "0.3.10", git_executable=GIT,
        inputs=contract.fixture_identity_inputs(manifest),
    )
    return repository, identity


def _running_run(tmp_path: Path, run_id: str) -> store.Run:
    run = store.Run.create(tmp_path / "project", "fixture.example", run_id=run_id)
    run.write_state("running")
    return run


def _write_exact(descriptor: int, body: bytes) -> None:
    view = memoryview(body)
    while view:
        count = os.write(descriptor, view)
        assert count > 0
        view = view[count:]


def _settle_batch(invocation, batch, payload_by_role: dict[protocol.StreamRole, bytes]):
    """Use the real private-stage handoff and retain exact fixture bytes."""
    request = invocation.worker
    claimed_roles = tuple(
        claim.role for claim in request.descriptor_claims
        if claim.role in (protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR)
    )
    assert batch is not None and batch.state == "prepared"
    authority = privfs._prepare_private_stage_transfer_authority(
        batch, request_id=request.request_id,
    )

    def spawn(writer_fds):
        assert len(writer_fds) == len(claimed_roles)
        for role, descriptor in zip(claimed_roles, writer_fds):
            _write_exact(descriptor, payload_by_role[role])
            os.fsync(descriptor)
        return SimpleNamespace(pid=_WORKER_PID)

    _child, authority = privfs._spawn_with_private_stage_handoff(batch, authority, spawn)
    privfs._bind_private_stage_transfer_authority(batch, authority, worker_pid=_WORKER_PID)
    receipt = privfs.transfer_private_stage_handoff(batch, authority)
    return privfs.settle_private_stage_handoff(
        batch,
        receipt,
        worker_reaped=True,
        claims=tuple(
            (request.claim_for(role).claim_id, role.value)
            for role in claimed_roles
        ),
    )


def _output_stream(
    request, role: protocol.StreamRole, *, observed: bytes, retained: bytes,
    terminal: protocol.StreamTerminal,
) -> protocol.StreamSettlement:
    return protocol.StreamSettlement(
        role=role,
        terminal=terminal,
        observed_bytes=len(observed),
        retained_bytes=len(retained),
        observed_sha256=_digest(observed),
        retained_sha256=_digest(retained),
        claim_id=request.claim_for(role).claim_id,
        lines=retained.count(b"\n"),
        detail=None,
    )


def _faithful_outcome(
    invocation, proofs, *, stdout_observed: bytes, stdout_retained: bytes,
    stderr_observed: bytes, stderr_retained: bytes,
    stdout_terminal: protocol.StreamTerminal, stderr_terminal: protocol.StreamTerminal,
    terminal: protocol.ExecutionTerminal, exit_code: int | None, complete: bool,
):
    request = invocation.worker
    empty = b""
    settlement = protocol.WorkerSettlement(
        request_id=request.request_id,
        terminal=terminal,
        launched=True,
        exit_code=exit_code,
        process_group_settled=True,
        # This is the normal cooperative-scope fact: the repository owner,
        # rather than a synthetic tree assertion, settles publication.
        process_tree_settled=False,
        streams=(
            protocol.StreamSettlement(
                role=protocol.StreamRole.STDIN,
                terminal=protocol.StreamTerminal.COMPLETE,
                observed_bytes=0,
                retained_bytes=0,
                observed_sha256=_digest(empty),
                retained_sha256=None,
                claim_id=None,
                lines=0,
                detail=None,
            ),
            _output_stream(
                request, protocol.StreamRole.STDOUT, observed=stdout_observed,
                retained=stdout_retained, terminal=stdout_terminal,
            ),
            _output_stream(
                request, protocol.StreamRole.STDERR, observed=stderr_observed,
                retained=stderr_retained, terminal=stderr_terminal,
            ),
        ),
        worker_pid=_WORKER_PID,
        tool_pid=_TOOL_PID,
        detail=None,
    )
    validated = protocol.ValidatedSettlement(
        worker=settlement,
        mechanically_settled=True,
        containment_assurance=protocol.ContainmentAssurance.COOPERATIVE_SCOPE,
        escape_protected=False,
        tree_proven=False,
        clean_eligible=True,
        capture_complete=complete,
        _authority=protocol._VALIDATION_AUTHORITY,
    )
    return supervisor.ExecutionOutcome(
        reason=(supervisor.ExecutionReason.COMPLETE if complete
                else supervisor.ExecutionReason.INCOMPLETE),
        request_id=request.request_id,
        worker_pid=_WORKER_PID,
        settlement=settlement,
        validated=validated,
        artifact_proofs=proofs,
        worker_returncode=0,
        worker_spawned=True,
        worker_reaped=True,
        control_eof=True,
        go_command_sent=True,
        parent_pipes_closed=True,
        containment_settled=True,
        stages_settled=True,
        _authority=supervisor._EXECUTION_OUTCOME_AUTHORITY,
    )


def _fixture_payload(root: Path, spec: dict | None) -> bytes:
    if spec is None:
        return b""
    source = (root / spec["path"]).read_bytes()
    return bytes.fromhex(source.decode("ascii", "strict").strip()) if spec["encoding"] == "hex" else source


def _faithful_helper_supervisor(root: Path, case: dict):
    """Return a real-stage supervisor seam for one frozen helper case."""
    stdout = _fixture_payload(root, case["fixture"])
    stderr = _fixture_payload(root, case["stderr"])
    stdout_retained = stdout
    stdout_terminal = protocol.StreamTerminal.EOF
    stderr_terminal = protocol.StreamTerminal.EOF
    terminal = protocol.ExecutionTerminal.COMPLETE
    exit_code: int | None = 0
    complete = True
    if case["id"] == "truncated":
        stdout_retained = stdout[:contract.RETAINED_STREAM_CAP_BYTES]
        stdout_terminal = protocol.StreamTerminal.CAPPED
        complete = False
    elif case["id"] == "timeout":
        stdout = stderr = stdout_retained = b""
        stdout_terminal = stderr_terminal = protocol.StreamTerminal.DEADLINE
        terminal = protocol.ExecutionTerminal.TIMED_OUT
        exit_code = None
        complete = False
    elif case["id"] == "signal":
        stdout = stderr = stdout_retained = b""
        exit_code = -15

    payload_by_role = {
        protocol.StreamRole.STDOUT: stdout_retained,
        protocol.StreamRole.STDERR: stderr,
    }

    def execute(invocation, *, stage_batch, deadline, clock, popen_factory):
        assert deadline > clock()
        proofs = _settle_batch(invocation, stage_batch, payload_by_role)
        return _faithful_outcome(
            invocation, proofs,
            stdout_observed=stdout, stdout_retained=stdout_retained,
            stderr_observed=stderr, stderr_retained=stderr,
            stdout_terminal=stdout_terminal, stderr_terminal=stderr_terminal,
            terminal=terminal, exit_code=exit_code, complete=complete,
        )

    return execute


def _helper_argv(root: Path, case: dict, *, wrong_encoding: bool = False) -> list[str]:
    argv = [str(root / "tests/helpers/c_output_fixture.py"), "--case", case["id"]]
    if case["fixture"] is not None:
        encoding = "raw" if wrong_encoding else case["fixture"]["encoding"]
        argv += ["--payload", str(root / case["fixture"]["path"]), "--encoding", encoding]
    if case["stderr"] is not None:
        argv += ["--stderr", str(root / case["stderr"]["path"])]
    return argv


def _run_helper_case(
    monkeypatch, *, root: Path, run: store.Run, manifest: dict, case_id: str,
    wrong_encoding: bool = False,
) -> runner.RunResult:
    case = next(item for item in manifest["cases"] if item["id"] == case_id)
    monkeypatch.setattr(
        runner_repository, "supervise_execution", _faithful_helper_supervisor(root, case),
    )
    return runner.run(
        "c-output-python-helper",
        _helper_argv(root, case, wrong_encoding=wrong_encoding),
        repository=run,
        stdout=runner_repository.RepositoryOutput.publish(
            "raw", "c-output-contract", case_id, "stdout.json",
        ),
        stderr=runner_repository.RepositoryOutput.publish(
            "raw", "c-output-contract", case_id, "stderr.log",
        ),
        timeout=5,
        max_output_bytes=contract.RETAINED_STREAM_CAP_BYTES if case_id == "truncated" else None,
    )


@pytest.mark.offline
def test_committed_frozen_manifest_is_directly_validated():
    manifest = _manifest()
    assert contract.validate_fixture_manifest(manifest) == manifest
    assert contract.fixture_identity_inputs(manifest)[contract.FROZEN_FIXTURE_MANIFEST_INPUT] == (
        contract.FROZEN_FIXTURE_MANIFEST_PATH
    )


@pytest.mark.integration
@pytest.mark.requires_tool("git")
@pytest.mark.skipif(GIT is None, reason="Git is required")
def test_faithful_repository_fixture_builder_produces_all_helper_receipts(tmp_path, monkeypatch):
    manifest = _manifest()
    root, identity = _candidate_repository(tmp_path, manifest)
    run = _running_run(tmp_path, "c-output-helper-cases")
    receipts = []
    results = {}
    for case_id in ("empty", "malformed", "truncated", "non_utf8", "partial", "timeout", "signal"):
        result = _run_helper_case(
            monkeypatch, root=root, run=run, manifest=manifest, case_id=case_id,
        )
        results[case_id] = result
        # Mutability of the compatibility result cannot alter its sealed
        # repository testimony or the effective status we derive from it.
        if case_id == "partial":
            result.status = runner.Status.EMPTY
            result.meta["execution_settlement"]["exit_code"] = 99
        receipt = contract.receipt_from_runner(
            fixture_manifest=manifest, case_id=case_id, run=run,
            candidate_identity=identity, candidate_root=root, result=result,
        )
        assert receipt["effective_status"] == next(
            item for item in manifest["cases"] if item["id"] == case_id
        )["expected"]["effective_status"]
        receipts.append(receipt)

    assert receipts[0]["parser"]["input"]["bytes"] == 0
    assert receipts[0]["parser"]["outcome"] == "empty"
    truncated_case = next(item for item in manifest["cases"] if item["id"] == "truncated")
    truncated_payload = _fixture_payload(root, truncated_case["fixture"])
    assert receipts[2]["parser"] == {
        "complete": False, "input": None, "outcome": "unavailable",
        "parser": "json-array", "records": None,
    }
    assert receipts[2]["streams"][1]["retained_bytes"] == contract.RETAINED_STREAM_CAP_BYTES
    assert receipts[2]["streams"][1]["retained_sha256"] == _digest(
        truncated_payload[:contract.RETAINED_STREAM_CAP_BYTES],
    )
    assert receipts[-2]["parser"]["outcome"] == "unavailable"
    assert receipts[-1]["execution"]["exit_code"] < 0
    assert receipts[4]["effective_status"] == "partial"
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        pass
    else:
        raw_schema = json.loads(
            (ROOT / "release/evidence/schemas/c-output-raw-receipt-v2.schema.json").read_bytes(),
        )
        Draft202012Validator.check_schema(raw_schema)
        validator = Draft202012Validator(raw_schema)
        for receipt in receipts:
            assert list(validator.iter_errors(receipt)) == []
    with pytest.raises(contract.OutputContractError, match="C-OUTPUT remains open"):
        contract.collect_case_matrix(fixture_manifest=manifest, receipts=receipts)
    assert runner.repository_execution_testimony(results["partial"], repository=run)[
        "execution_settlement"
    ]["exit_code"] == 0


@pytest.mark.integration
@pytest.mark.requires_tool("git")
@pytest.mark.skipif(GIT is None, reason="Git is required")
def test_serialized_shape_schema_and_manual_reject_stream_and_case_mutations(tmp_path, monkeypatch):
    """Raw JSON is strict diagnostic shape only, including frozen stream facts."""
    Draft202012Validator = pytest.importorskip("jsonschema").Draft202012Validator
    manifest = _manifest()
    root, identity = _candidate_repository(tmp_path, manifest)
    run = _running_run(tmp_path, "c-output-shape-parity")
    truncated_result = _run_helper_case(
        monkeypatch, root=root, run=run, manifest=manifest, case_id="truncated",
    )
    truncated = contract.receipt_from_runner(
        fixture_manifest=manifest, case_id="truncated", run=run,
        candidate_identity=identity, candidate_root=root, result=truncated_result,
    )
    malformed_result = _run_helper_case(
        monkeypatch, root=root, run=run, manifest=manifest, case_id="malformed",
    )
    malformed = contract.receipt_from_runner(
        fixture_manifest=manifest, case_id="malformed", run=run,
        candidate_identity=identity, candidate_root=root, result=malformed_result,
    )
    schema = json.loads(
        (ROOT / "release/evidence/schemas/c-output-raw-receipt-v2.schema.json").read_bytes(),
    )
    validator = Draft202012Validator(schema)

    def mutate_stream(document: dict, index: int, **fields) -> None:
        # The serialized execution projection and root projection must agree.
        document["streams"][index].update(fields)
        document["execution"]["streams"][index].update(fields)

    def rejected(document: dict) -> None:
        assert list(validator.iter_errors(document))
        with pytest.raises(contract.OutputContractError):
            contract.validate_raw_receipt(document, fixture_manifest=manifest)

    with pytest.raises(contract.OutputContractError, match="no authenticated accepting resolver"):
        contract.validate_raw_receipt(truncated, fixture_manifest=manifest, accepting=True)

    old_capped = copy.deepcopy(truncated)
    mutate_stream(old_capped, 1, retained_bytes=1, retained_sha256=_digest(b"["))
    rejected(old_capped)

    old_eof = copy.deepcopy(malformed)
    mutate_stream(old_eof, 1, retained_bytes=1, retained_sha256=_digest(b"["))
    rejected(old_eof)

    wrong_status = copy.deepcopy(malformed)
    wrong_status["effective_status"] = "empty"
    rejected(wrong_status)

    wrong_terminal = copy.deepcopy(malformed)
    wrong_terminal["execution"]["terminal"] = "timed_out"
    rejected(wrong_terminal)

    wrong_publication = copy.deepcopy(malformed)
    wrong_publication["repository_publication"] = "fenced"
    rejected(wrong_publication)

    wrong_parser = copy.deepcopy(malformed)
    wrong_parser["parser"]["outcome"] = "empty"
    wrong_parser["parser"]["complete"] = True
    wrong_parser["parser"]["records"] = 0
    rejected(wrong_parser)

    identity_extra = copy.deepcopy(malformed)
    identity_extra["launch"]["runtime_identity"]["unexpected"] = True
    rejected(identity_extra)

    identity_row_extra = copy.deepcopy(malformed)
    identity_row_extra["launch"]["runtime_identity"]["identities"][0]["unexpected"] = True
    rejected(identity_row_extra)


@pytest.mark.integration
@pytest.mark.requires_tool("git")
@pytest.mark.skipif(GIT is None, reason="Git is required")
def test_empty_native_receipt_and_final_timestamp_are_attached_once(tmp_path, monkeypatch):
    manifest = _manifest()
    root, identity = _candidate_repository(tmp_path, manifest)
    run = _running_run(tmp_path, "c-output-empty-timestamp")
    run_started = contract._canonical_utc_timestamp(run.started, "test Run.started")
    base = contract._timestamp_value(run_started)
    timestamps = iter((
        (base + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z"),
        (base + timedelta(microseconds=2)).isoformat().replace("+00:00", "Z"),
        "unused",
    ))
    calls = []

    def stamp():
        calls.append(None)
        return next(timestamps)

    monkeypatch.setattr(runner, "_execution_timestamp", stamp)
    result = _run_helper_case(
        monkeypatch, root=root, run=run, manifest=manifest, case_id="empty",
    )
    testimony = runner.repository_execution_testimony(result, repository=run)
    assert len(calls) == 2
    assert testimony["execution_started_at"] == (base + timedelta(microseconds=1)).isoformat().replace(
        "+00:00", "Z",
    )
    assert testimony["execution_finished_at"] == (base + timedelta(microseconds=2)).isoformat().replace(
        "+00:00", "Z",
    )
    assert testimony["native_outputs"] == {
        "clean": True, "policy_count": 0, "committed": [], "uncertain": [],
        "unpublished": [], "current_paths": [], "cleanup_settled": True,
        "claim_retained": False, "fault_operation": None, "fault_type": None,
    }
    receipt = contract.receipt_from_runner(
        fixture_manifest=manifest, case_id="empty", run=run,
        candidate_identity=identity, candidate_root=root, result=result,
    )
    assert receipt["run"]["started_at"] == run_started
    assert receipt["run"]["started_at"].endswith("Z")
    assert receipt["timestamps"] == {
        "started_at": testimony["execution_started_at"],
        "finished_at": testimony["execution_finished_at"],
    }
    malformed_offset = copy.deepcopy(receipt)
    malformed_offset["timestamps"]["started_at"] = receipt["timestamps"]["started_at"].replace(
        "Z", "-00:00",
    )
    with pytest.raises(contract.OutputContractError, match="canonical UTC"):
        contract.validate_raw_receipt(malformed_offset, fixture_manifest=manifest)
    before_run = copy.deepcopy(receipt)
    before_run["timestamps"]["started_at"] = "2000-01-01T00:00:00Z"
    with pytest.raises(contract.OutputContractError, match="does not bracket"):
        contract.validate_raw_receipt(before_run, fixture_manifest=manifest)


@pytest.mark.integration
@pytest.mark.requires_tool("git")
@pytest.mark.skipif(GIT is None, reason="Git is required")
def test_helper_source_and_retained_artifact_symlinks_are_refused(tmp_path, monkeypatch):
    manifest = _manifest()
    root, identity = _candidate_repository(tmp_path, manifest)
    run = _running_run(tmp_path, "c-output-symlink-refusal")
    result = _run_helper_case(
        monkeypatch, root=root, run=run, manifest=manifest, case_id="empty",
    )
    outside = tmp_path / "outside-empty.json"
    outside.write_bytes(b"")
    source = root / "tests/fixtures/c-output-contract/empty.json"
    source.unlink()
    source.symlink_to(outside)
    with pytest.raises(contract.OutputContractError, match="without following links"):
        contract.receipt_from_runner(
            fixture_manifest=manifest, case_id="empty", run=run,
            candidate_identity=identity, candidate_root=root, result=result,
        )

    # Restore a real source file, then replace only the retained run artifact.
    source.unlink()
    source.write_bytes(b"")
    testimony = runner.repository_execution_testimony(result, repository=run)
    retained = Path(testimony["repository_stdout_path"])
    retained.unlink()
    retained.symlink_to(outside)
    with pytest.raises(contract.OutputContractError, match="retained stdout|run authority"):
        contract.receipt_from_runner(
            fixture_manifest=manifest, case_id="empty", run=run,
            candidate_identity=identity, candidate_root=root, result=result,
        )


@pytest.mark.integration
@pytest.mark.requires_tool("git")
@pytest.mark.skipif(GIT is None, reason="Git is required")
def test_helper_receipt_rejects_an_admitted_argv_that_misstates_fixture_encoding(tmp_path, monkeypatch):
    manifest = _manifest()
    root, identity = _candidate_repository(tmp_path, manifest)
    run = _running_run(tmp_path, "c-output-helper-argv")
    result = _run_helper_case(
        monkeypatch, root=root, run=run, manifest=manifest, case_id="non_utf8",
        wrong_encoding=True,
    )
    with pytest.raises(contract.OutputContractError, match="source argv"):
        contract.receipt_from_runner(
            fixture_manifest=manifest, case_id="non_utf8", run=run,
            candidate_identity=identity, candidate_root=root, result=result,
        )


@pytest.mark.offline
def test_native_gitleaks_rows_are_explicitly_open_and_cannot_produce_receipts():
    """AKIA-looking fixture text is not treated as a verified native finding."""
    manifest = _manifest()
    for case_id in ("non_empty", "tool_specific_exit"):
        case = next(item for item in manifest["cases"] if item["id"] == case_id)
        assert case["availability"] == "unavailable-source-substrate"
        assert case["expected"] == {
            "effective_status": "unavailable", "execution_terminal": "not_started", "exit": "none",
            "native": "unavailable",
            "parser": {"complete": False, "outcome": "unavailable", "records": None},
            "repository_publication": "not_requested", "stderr_terminal": "not_started",
            "stdout_terminal": "not_started",
        }
        with pytest.raises(contract.OutputContractError, match="explicitly unavailable"):
            contract.receipt_from_runner(
                fixture_manifest=manifest, case_id=case_id, run=None, candidate_identity=None,
                candidate_root=".", result=None,
            )


@pytest.mark.offline
def test_v2_schemas_are_syntactically_strict_about_the_frozen_manifest():
    Draft202012Validator = pytest.importorskip("jsonschema").Draft202012Validator
    manifest = _manifest()
    for name in (
        "c-output-fixture-manifest-v2.schema.json",
        "c-output-raw-receipt-v2.schema.json",
        "c-output-case-matrix-v2.schema.json",
    ):
        schema = json.loads((ROOT / "release/evidence/schemas" / name).read_bytes())
        Draft202012Validator.check_schema(schema)
    manifest_schema = json.loads(
        (ROOT / "release/evidence/schemas/c-output-fixture-manifest-v2.schema.json").read_bytes(),
    )
    validator = Draft202012Validator(manifest_schema)
    assert list(validator.iter_errors(manifest)) == []
    wrong_cap = copy.deepcopy(manifest)
    wrong_cap["retained_stream_cap_bytes"] = 15
    assert list(validator.iter_errors(wrong_cap))
    with pytest.raises(contract.OutputContractError, match="retained stream cap"):
        contract.validate_fixture_manifest(wrong_cap)
    false_native_claim = copy.deepcopy(manifest)
    false_native_claim["cases"][1]["expected"]["effective_status"] = "success"
    assert list(validator.iter_errors(false_native_claim))
    with pytest.raises(contract.OutputContractError):
        contract.validate_fixture_manifest(false_native_claim)
