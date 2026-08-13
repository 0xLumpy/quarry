"""Phase 1: exported run-descriptor callers retain stable ownership."""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

from quarry_recon import oob, runner_native, runner_protocol, runner_repository, store


pytestmark = pytest.mark.offline


_OWNED_ANCHORS = (
    pytest.param(oob._owned_run_anchor, id="oob"),
    pytest.param(runner_repository._owned_run_anchor, id="repository"),
    pytest.param(runner_native._owned_run_anchor, id="native"),
)
_OWNED_DESCRIPTORS = (
    pytest.param(oob._owned_descriptor, id="oob"),
    pytest.param(runner_repository._owned_descriptor, id="repository"),
    pytest.param(runner_native._owned_descriptor, id="native"),
)


def _running_run(project: Path, run_id: str = "exported-run-anchor") -> store.Run:
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _open_fds() -> set[tuple[int, str]]:
    observed = set()
    if not os.path.isdir("/proc/self/fd"):
        return observed
    for name in os.listdir("/proc/self/fd"):
        try:
            observed.add((int(name), os.readlink(f"/proc/self/fd/{name}")))
        except OSError:
            pass
    return observed


def _executed_lines(function, call) -> set[int]:
    lines = set()

    def trace(frame, event, _arg):
        if frame.f_code is function.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        call()
    finally:
        sys.settrace(previous)
    return lines


def _cancel_once(function, target_line, call, cancellation_type):
    cancellation = cancellation_type(f"owned run anchor cancellation at {target_line}")
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is function.__code__ and event == "line"
                and frame.f_lineno == target_line and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(cancellation_type) as caught:
            call()
    finally:
        sys.settrace(previous)
    assert fired
    assert caught.value is cancellation


def _call_names(node: ast.AST) -> list[tuple[str, int]]:
    calls = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        function = child.func
        if isinstance(function, ast.Attribute):
            calls.append((function.attr, child.lineno))
        elif isinstance(function, ast.Name):
            calls.append((function.id, child.lineno))
    return calls


def _named_function(tree: ast.AST, name: str) -> ast.FunctionDef:
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_exported_run_fd_static_inventory_is_fully_owned():
    package = Path(store.__file__).resolve().parent
    naked = []
    for path in sorted(package.rglob("*.py")):
        if path.name == "store.py":
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        naked.extend(
            (path.relative_to(package).as_posix(), line)
            for name, line in _call_names(tree)
            if name == "_open_run_fd"
        )
    assert naked == []

    expected_sites = {
        Path(oob.__file__).resolve(): 1,
        Path(runner_repository.__file__).resolve(): 1,
        Path(runner_native.__file__).resolve(): 7,
    }
    for path, expected in expected_sites.items():
        tree = ast.parse(path.read_text(), filename=str(path))
        calls = _call_names(tree)
        assert sum(name == "_owned_run_anchor" for name, _line in calls) == expected
        assert sum(name == "_open_run_fd_into" for name, _line in calls) == 1

        descriptor_helper = _named_function(tree, "_owned_descriptor")
        descriptor_calls = _call_names(descriptor_helper)
        assert sum(name == "_OwnedDescriptor" for name, _line in descriptor_calls) == 1
        assert all(name != "release" for name, _line in descriptor_calls)
        if path.name != "runner_native.py":
            assert sum(
                name == "_SettlementOwner" for name, _line in descriptor_calls
            ) == 1
            assert sum(
                name == "_SettlementFence" for name, _line in descriptor_calls
            ) == 2

        run_helper = _named_function(tree, "_owned_run_anchor")
        run_calls = _call_names(run_helper)
        assert sum(name == "_owned_descriptor" for name, _line in run_calls) == 1
        assert sum(name == "_open_run_fd_into" for name, _line in run_calls) == 1
        assert all(name != "release" for name, _line in run_calls)

    migrated_boundaries = {
        Path(oob.__file__).resolve(): ("resolve_session_ref",),
        Path(runner_repository.__file__).resolve(): ("_prepare_stage_batch",),
        Path(runner_native.__file__).resolve(): (
            "_fence_private_stage",
            "_create_owned_file_stage",
            "_create_owned_tree",
            "_fence_owned_file_stage",
            "_open_source_file_into",
            "_publish_file",
            "_publish_file_absence",
            "_publish_tree",
            "_recover_publish_escape",
            "_seed_tree",
        ),
    }
    for path, names in migrated_boundaries.items():
        tree = ast.parse(path.read_text(), filename=str(path))
        for name in names:
            function = _named_function(tree, name)
            direct_raw_allocations = []
            direct_closes = []
            for node in ast.walk(function):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                owner = node.func.value
                if (isinstance(owner, ast.Name) and owner.id == "os"
                        and node.func.attr == "open"):
                    direct_raw_allocations.append(node.lineno)
                if (isinstance(owner, ast.Name) and owner.id == "privfs"
                        and node.func.attr == "open_strict_dir_at"):
                    direct_raw_allocations.append(node.lineno)
                if (isinstance(owner, ast.Name) and owner.id == "os"
                        and node.func.attr == "close"):
                    direct_closes.append(node.lineno)
            assert direct_raw_allocations == [], (name, direct_raw_allocations)
            assert direct_closes == [], (name, direct_closes)


@pytest.mark.parametrize("helper", _OWNED_ANCHORS)
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_owned_run_anchor_settles_a_committed_open_fault(
    tmp_path, monkeypatch, helper, cancellation_type,
):
    run = _running_run(tmp_path)
    before = _open_fds()
    exact = cancellation_type("committed exported run open")
    real_open = store._open_run_fd_into
    fired = False

    def committed_then_raise(destination, *args, **kwargs):
        nonlocal fired
        real_open(destination, *args, **kwargs)
        if not fired:
            fired = True
            raise exact

    monkeypatch.setattr(store, "_open_run_fd_into", committed_then_raise)
    with pytest.raises(cancellation_type) as caught:
        with helper(run):
            pytest.fail("committed-then-fault open unexpectedly yielded")
    assert fired
    assert caught.value is exact
    assert _open_fds() == before


@pytest.mark.parametrize("helper", _OWNED_ANCHORS)
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_owned_run_anchor_settles_every_source_line(
    tmp_path, helper, cancellation_type,
):
    run = _running_run(tmp_path)
    implementation = helper.__wrapped__

    def invoke():
        with helper(run) as anchor:
            observed = os.fstat(anchor)
            assert (observed.st_dev, observed.st_ino) == run._run_directory_identity

    lines = _executed_lines(implementation, invoke)
    assert lines
    for line in sorted(lines):
        before = _open_fds()
        _cancel_once(implementation, line, invoke, cancellation_type)
        assert _open_fds() == before, f"source line {line}"


@pytest.mark.parametrize("helper", _OWNED_DESCRIPTORS)
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_owned_descriptor_settles_a_committed_open_fault(
    tmp_path, monkeypatch, helper, cancellation_type,
):
    before = _open_fds()
    exact = cancellation_type("committed adjacent descriptor open")
    real_open = store._OwnedDescriptor.open
    fired = False

    def committed_then_raise(owner, *args, **kwargs):
        nonlocal fired
        result = real_open(owner, *args, **kwargs)
        if not fired:
            fired = True
            raise exact
        return result

    monkeypatch.setattr(store._OwnedDescriptor, "open", committed_then_raise)
    with pytest.raises(cancellation_type) as caught:
        with helper("exported adjacent test descriptor") as owner:
            owner.open(
                tmp_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
    assert fired
    assert caught.value is exact
    assert _open_fds() == before


@pytest.mark.parametrize("helper", _OWNED_DESCRIPTORS)
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_owned_descriptor_settles_every_source_line(
    tmp_path, helper, cancellation_type,
):
    implementation = helper.__wrapped__

    def invoke():
        with helper("exported adjacent test descriptor") as owner:
            owner.open(
                tmp_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )

    lines = _executed_lines(implementation, invoke)
    assert lines
    for line in sorted(lines):
        before = _open_fds()
        _cancel_once(implementation, line, invoke, cancellation_type)
        assert _open_fds() == before, f"source line {line}"


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_oob_resolution_settles_every_production_source_line(
    tmp_path, cancellation_type,
):
    run = _running_run(tmp_path, "oob-exported-boundary")
    components = ("raw", "oob", "session", "session.json")
    with run._mutation(store.MutationScope.BASE_EVIDENCE):
        run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE, components, b"{}",
        )

    def invoke():
        assert oob.resolve_session_ref(
            run,
            "/".join(components),
            field="session_file",
        ) == run.dir.joinpath(*components)

    lines = _executed_lines(oob.resolve_session_ref, invoke)
    for line in sorted(lines):
        before = _open_fds()
        _cancel_once(
            oob.resolve_session_ref, line, invoke, cancellation_type,
        )
        assert _open_fds() == before, f"source line {line}"


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_oob_resolution_owns_a_committed_file_open_fault(
    tmp_path, monkeypatch, cancellation_type,
):
    run = _running_run(tmp_path, "oob-committed-file-open")
    components = ("raw", "oob", "session", "session.json")
    run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, components, b"{}",
    )
    before = _open_fds()
    exact = cancellation_type("committed OOB file open")
    real_open = store._OwnedDescriptor.open
    fired = False

    def committed_then_raise(owner, path, *args, **kwargs):
        nonlocal fired
        result = real_open(owner, path, *args, **kwargs)
        if path == components[-1] and not fired:
            fired = True
            raise exact
        return result

    monkeypatch.setattr(store._OwnedDescriptor, "open", committed_then_raise)
    with pytest.raises(cancellation_type) as caught:
        oob.resolve_session_ref(
            run, "/".join(components), field="session_file",
        )
    assert fired
    assert caught.value is exact
    assert _open_fds() == before


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_repository_preparation_settles_every_production_source_line(
    tmp_path, cancellation_type,
):
    run = _running_run(tmp_path, "repository-exported-boundary")
    output = runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "stdout.bin",
    )
    invocation = runner_protocol.normalize_invocation(
        request_id="a7" * 16,
        tool="fixture",
        cmd=("fixture",),
        timeout=30,
        raw_path=str(run.dir.joinpath(*output.components)),
        base_environment={},
    )
    policies = ((runner_protocol.StreamRole.STDOUT, output),)

    def invoke():
        batch = runner_repository._prepare_stage_batch(
            run, invocation, policies,
        )
        assert batch is not None
        batch.abort()

    lines = _executed_lines(runner_repository._prepare_stage_batch, invoke)
    for line in sorted(lines):
        before = _open_fds()
        _cancel_once(
            runner_repository._prepare_stage_batch,
            line,
            invoke,
            cancellation_type,
        )
        assert _open_fds() == before, f"source line {line}"
        assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_repository_preparation_owns_a_committed_run_open_fault(
    tmp_path, monkeypatch, cancellation_type,
):
    run = _running_run(tmp_path, "repository-committed-run-open")
    output = runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "stdout.bin",
    )
    invocation = runner_protocol.normalize_invocation(
        request_id="b8" * 16,
        tool="fixture",
        cmd=("fixture",),
        timeout=30,
        raw_path=str(run.dir.joinpath(*output.components)),
        base_environment={},
    )
    policies = ((runner_protocol.StreamRole.STDOUT, output),)
    before = _open_fds()
    exact = cancellation_type("committed repository run open")
    real_open = store._open_run_fd_into
    fired = False

    def committed_then_raise(destination, *args, **kwargs):
        nonlocal fired
        real_open(destination, *args, **kwargs)
        if not fired:
            fired = True
            raise exact

    monkeypatch.setattr(store, "_open_run_fd_into", committed_then_raise)
    with pytest.raises(cancellation_type) as caught:
        runner_repository._prepare_stage_batch(run, invocation, policies)
    assert fired
    assert caught.value is exact
    assert _open_fds() == before
    assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_native_seed_settles_every_production_source_line(
    tmp_path, cancellation_type,
):
    run = _running_run(tmp_path, "native-exported-boundary")
    source = run.create_artifact_dir("raw", "probe", "source")
    (source / "row.bin").write_bytes(b"payload")
    os.chmod(source / "row.bin", 0o600)
    policy = runner_native.RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "probe", "source",
    )
    sequence = 0

    def invoke():
        nonlocal sequence
        destination = tmp_path / f"native-seed-{sequence}"
        sequence += 1
        destination.mkdir(mode=0o700)
        destination_fd = os.open(
            destination,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            runner_native._seed_tree(run, policy, destination_fd)
        finally:
            os.close(destination_fd)

    lines = _executed_lines(runner_native._seed_tree, invoke)
    for line in sorted(lines):
        before = _open_fds()
        _cancel_once(
            runner_native._seed_tree, line, invoke, cancellation_type,
        )
        assert _open_fds() == before, f"source line {line}"


@pytest.mark.parametrize("kind", ["file", "tree"])
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_native_publication_owns_a_committed_candidate_open_fault(
    tmp_path, monkeypatch, kind, cancellation_type,
):
    run = _running_run(tmp_path, f"native-committed-{kind}-open")
    baseline = _open_fds()
    components = ("raw", "probe", f"{kind}-result")
    final = run.dir.joinpath(*components)
    if kind == "file":
        policy = runner_native.RepositoryNativeOutput.file(3, *components)
    else:
        policy = runner_native.RepositoryNativeOutput.tree(
            ((3, ()),), *components,
        )
    transaction = runner_native.prepare_native_outputs(
        run,
        (sys.executable, "-c", "pass", str(final)),
        (policy,),
    )
    private_output = Path(transaction.rewritten_cmd[3])
    if kind == "file":
        private_output.write_bytes(b"candidate")
        os.chmod(private_output, 0o600)
    else:
        row = private_output / "row.bin"
        row.write_bytes(b"candidate")
        os.chmod(row, 0o600)

    exact = cancellation_type(f"committed native {kind} candidate open")
    prefix = f".quarry-native-{kind}-"
    real_open = store._OwnedDescriptor.open
    fired = False

    def committed_then_raise(owner, path, *args, **kwargs):
        nonlocal fired
        result = real_open(owner, path, *args, **kwargs)
        if str(path).startswith(prefix) and not fired:
            fired = True
            raise exact
        return result

    monkeypatch.setattr(store._OwnedDescriptor, "open", committed_then_raise)
    with pytest.raises(cancellation_type) as caught:
        transaction.finish(clean=True)
    receipt = transaction.finish(clean=False)
    assert fired
    assert caught.value is exact
    assert not receipt.clean
    assert len(receipt.unpublished) == 1
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert not final.exists()
    assert not any(
        path.name.startswith(prefix)
        for path in final.parent.iterdir()
    )
    assert run._live_artifact_claim_count() == 0
    assert _open_fds() == baseline
