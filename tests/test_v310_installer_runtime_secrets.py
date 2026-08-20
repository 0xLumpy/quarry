"""V310-05 adversarial contracts: atomic installs, exact launch identity, and credential isolation."""
from __future__ import annotations

import hashlib
import json
import os
import site
import stat
import sys
import tempfile
import time
from pathlib import Path

import pytest

from quarry_recon import (contract, events, oob, registry, runner, runner_native,
                          runner_supervisor, runtime_identity, secrets, store)
from quarry_recon.phases import params, vertical
from quarry_recon.runner import RunResult, Status
from quarry_recon.runner_repository import RepositoryOutput


pytestmark = pytest.mark.offline


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' {body!r}\n")
    path.chmod(0o700)
    return path


def _publish_fixture_runtime(tool: registry.Tool, candidate: Path, executable: Path) -> dict:
    """Create the exact on-disk v1 receipt/pointer shape consumed by runtime admission tests."""
    registry._freeze_candidate_payload(candidate)
    registry._durably_settle_candidate_payload(candidate)
    rows = registry._tree_rows(candidate)
    content_identity = registry._closure_identity(rows)
    receipt = {
        "schema_version": registry._RUNTIME_RECEIPT_SCHEMA,
        "lock_key": registry._safe_lock_key(tool.lock_key or tool.bin),
        "generation": candidate.name,
        "tools": {
            tool.bin: {
                "executable": executable.relative_to(candidate).as_posix(),
                "identity": str(tool.pin or tool.ref),
                "runtime": tool.runtime,
                "content_identity": content_identity,
            },
        },
        "files": rows,
    }
    registry._write_runtime_receipt(candidate, receipt)
    registry._seal_candidate_root(candidate)
    root = candidate.parent.parent
    os.symlink(f"versions/{candidate.name}", root / "current")
    return receipt


def _managed_script_runtime(tmp_path: Path, monkeypatch, *, body: str = "GOOD"):
    monkeypatch.setenv("HOME", str(tmp_path))
    tool = registry.Tool(
        bin="scope-fixture", phase="fixture", role="run-scoped payload fixture",
        runtime="source", ref="deadbeef", install="build scope-fixture",
    )
    root = registry._managed_root(tool)
    candidate = root / "versions" / ("c" * 32)
    executable = candidate / "home" / ".local" / "bin" / tool.bin
    executable.parent.mkdir(parents=True)
    _executable(executable, body)
    _publish_fixture_runtime(tool, candidate, executable)
    monkeypatch.setattr(
        registry, "tool_for_bin",
        lambda name: tool if Path(name).name == tool.bin else None,
    )
    return tool, candidate, executable


def test_after_revalidation_path_substitution_executes_only_the_anchored_identity(tmp_path):
    original = _executable(tmp_path / "adapter", "GOOD")
    prepared = runtime_identity.prepare_launch("fixture", [str(original)])
    try:
        runtime_identity.revalidate_launch(prepared)
        evil = _executable(tmp_path / "evil", "EVIL")
        os.replace(evil, original)  # exact attack window: admission returned, spawn has not happened

        read_fd, write_fd = os.pipe()
        try:
            pid = os.posix_spawn(
                prepared.argv[0], prepared.argv, prepared.environment,
                file_actions=((os.POSIX_SPAWN_DUP2, write_fd, 1),
                              (os.POSIX_SPAWN_CLOSE, read_fd),
                              (os.POSIX_SPAWN_CLOSE, write_fd)),
            )
            os.close(write_fd)
            write_fd = -1
            output = os.read(read_fd, 1024)
            _pid, status = os.waitpid(pid, 0)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)
        assert os.waitstatus_to_exitcode(status) == 0
        assert output.strip() == b"GOOD"
        assert Path(prepared.argv[0]).is_absolute()
        assert Path(prepared.argv[0]).parent == prepared.anchor_root
    finally:
        anchor = prepared.anchor_root
        prepared.close()
    assert not anchor.exists()


def test_after_revalidation_source_chmod_and_in_place_mutation_cannot_change_anchor(tmp_path):
    original = _executable(tmp_path / "adapter", "GOOD")
    original.chmod(0o500)  # this exact shape used to trigger the unsafe hardlink optimization
    prepared = runtime_identity.prepare_launch("fixture", [str(original)])
    try:
        runtime_identity.revalidate_launch(prepared)
        original.chmod(0o700)
        original.write_text("#!/bin/sh\nprintf '%s\\n' EVIL\n")

        read_fd, write_fd = os.pipe()
        try:
            pid = os.posix_spawn(
                prepared.argv[0], prepared.argv, prepared.environment,
                file_actions=((os.POSIX_SPAWN_DUP2, write_fd, 1),
                              (os.POSIX_SPAWN_CLOSE, read_fd),
                              (os.POSIX_SPAWN_CLOSE, write_fd)),
            )
            os.close(write_fd)
            write_fd = -1
            output = os.read(read_fd, 1024)
            _pid, status = os.waitpid(pid, 0)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)
        assert os.waitstatus_to_exitcode(status) == 0
        assert output.strip() == b"GOOD"
        assert prepared.anchor_root.stat().st_ino != original.parent.stat().st_ino
        assert Path(prepared.argv[0]).stat().st_ino != original.stat().st_ino
    finally:
        prepared.close()


def test_pipx_style_shebang_interpreter_and_script_are_both_private_identities(
        tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    tool = registry.Tool(
        bin="pipx-fixture", phase="fixture", role="pipx launch identity",
        runtime="pipx", pin="1.2.3", install="pipx install pipx-fixture",
    )
    root = registry._managed_root(tool)
    candidate = root / "versions" / ("a" * 32)
    app = candidate / "home" / ".local" / "bin" / tool.bin
    venv = candidate / "pipx" / "venvs" / "pipx-fixture"
    interpreter = venv / "bin" / "python"
    app.parent.mkdir(parents=True)
    interpreter.parent.mkdir(parents=True)
    base_python = Path(sys.executable).resolve(strict=True)
    interpreter.symlink_to(base_python)
    (venv / "pyvenv.cfg").write_text(
        f"home = {base_python.parent}\ninclude-system-site-packages = false\n"
        f"version = {sys.version_info.major}.{sys.version_info.minor}\n"
        f"executable = {base_python}\n"
    )
    app.write_text(f"#!{interpreter}\nprint('GOOD')\n")
    app.chmod(0o700)
    receipt = _publish_fixture_runtime(tool, candidate, app)
    external = next(row["external"] for row in receipt["files"]
                    if row["path"].endswith("/bin/python"))
    assert external["path"] == str(base_python)

    monkeypatch.setattr(
        registry, "tool_for_bin",
        lambda name: tool if Path(name).name == tool.bin else None,
    )
    prepared = runtime_identity.prepare_launch(tool.bin, [str(app)])
    try:
        runtime_identity.revalidate_launch(prepared)
        private_interpreter = Path(prepared.argv[0])
        private_script = Path(prepared.argv[1])
        assert private_interpreter.is_relative_to(prepared.anchor_root)
        assert private_script.is_relative_to(prepared.anchor_root)
        assert private_interpreter.stat().st_ino != base_python.stat().st_ino
        assert private_script.stat().st_ino != app.stat().st_ino

        # Exact after-revalidate/before-spawn attack: both the app bytes and interpreter name change.
        for directory in (candidate, *candidate.parents[:2], app.parent, interpreter.parent):
            if directory.exists():
                directory.chmod(0o700)
        app.chmod(0o700)
        app.write_text("#!/bin/sh\nprintf 'EVIL\\n'\n")
        interpreter.unlink()
        interpreter.symlink_to("/bin/false")

        read_fd, write_fd = os.pipe()
        try:
            pid = os.posix_spawn(
                prepared.argv[0], prepared.argv, prepared.environment,
                file_actions=((os.POSIX_SPAWN_DUP2, write_fd, 1),
                              (os.POSIX_SPAWN_CLOSE, read_fd),
                              (os.POSIX_SPAWN_CLOSE, write_fd)),
            )
            os.close(write_fd)
            write_fd = -1
            output = os.read(read_fd, 1024)
            _pid, status = os.waitpid(pid, 0)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)
        assert os.waitstatus_to_exitcode(status) == 0
        assert output.strip() == b"GOOD"
    finally:
        prepared.close()


def test_run_scoped_managed_payload_is_copied_once_and_cleaned_after_multiple_launches(
        tmp_path, monkeypatch):
    tool, _candidate, executable = _managed_script_runtime(tmp_path, monkeypatch)
    copied = []
    real_copy = runtime_identity._copy_receipt_payload

    def observed_copy(source, receipt, launch, index):
        copied.append(sum(row["bytes"] for row in receipt["files"]))
        return real_copy(source, receipt, launch, index)

    monkeypatch.setattr(runtime_identity, "_copy_receipt_payload", observed_copy)
    repository = type("Repository", (), {})()
    with runtime_identity.managed_payload_snapshot_scope() as scope:
        scope.bind(repository)
        assert repository._runtime_payload_scope is scope
        roots = []
        for _index in range(3):
            prepared = runtime_identity.prepare_launch(
                tool.bin, [str(executable)], payload_scope=scope,
            )
            roots.append(Path(prepared.record["payload_anchors"][0]["root"]))
            runtime_identity.revalidate_launch(prepared)
            prepared.close()
        assert len(set(roots)) == 1
        assert roots[0].exists(), "the per-run copy must outlive each individual launch"
        snapshot_container = roots[0].parent
    assert len(copied) == 1 and copied[0] > 0
    assert not hasattr(repository, "_runtime_payload_scope")
    assert not snapshot_container.exists()


def test_run_scoped_snapshot_never_reuses_a_stale_mutated_source(tmp_path, monkeypatch):
    tool, candidate, executable = _managed_script_runtime(tmp_path, monkeypatch)
    with runtime_identity.managed_payload_snapshot_scope() as scope:
        prepared = runtime_identity.prepare_launch(
            tool.bin, [str(executable)], payload_scope=scope,
        )
        snapshot = Path(prepared.record["payload_anchors"][0]["root"])
        runtime_identity.revalidate_launch(prepared)

        for directory in (candidate, *candidate.parents[:2], executable.parent):
            directory.chmod(0o700)
        executable.chmod(0o700)
        executable.write_text("#!/bin/sh\nprintf 'EVIL\\n'\n")

        read_fd, write_fd = os.pipe()
        try:
            pid = os.posix_spawn(
                prepared.argv[0], prepared.argv, prepared.environment,
                file_actions=((os.POSIX_SPAWN_DUP2, write_fd, 1),
                              (os.POSIX_SPAWN_CLOSE, read_fd),
                              (os.POSIX_SPAWN_CLOSE, write_fd)),
            )
            os.close(write_fd)
            write_fd = -1
            output = os.read(read_fd, 1024)
            _pid, status = os.waitpid(pid, 0)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)
        assert os.waitstatus_to_exitcode(status) == 0 and output.strip() == b"GOOD"
        prepared.close()
        with pytest.raises(runtime_identity.RuntimeIdentityError, match="receipt is invalid"):
            runtime_identity.prepare_launch(
                tool.bin, [str(executable)], payload_scope=scope,
            )
        assert snapshot.exists(), "the detached identity remains valid for its original run claim"
        snapshot_container = snapshot.parent
    assert not snapshot_container.exists()


def test_run_scoped_snapshot_cleanup_failure_is_loud_and_recoverable(tmp_path, monkeypatch):
    tool, _candidate, executable = _managed_script_runtime(tmp_path, monkeypatch)
    manager = runtime_identity.managed_payload_snapshot_scope()
    scope = manager.__enter__()
    prepared = runtime_identity.prepare_launch(
        tool.bin, [str(executable)], payload_scope=scope,
    )
    container = Path(prepared.record["payload_anchors"][0]["root"]).parent
    prepared.close()
    real_rmtree = runtime_identity.shutil.rmtree

    def fail_snapshot_cleanup(path, *args, **kwargs):
        if Path(path) == container:
            raise OSError("injected run-snapshot cleanup fault")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.shutil, "rmtree", fail_snapshot_cleanup)
    with pytest.raises(runtime_identity.RuntimeIdentityError, match="remains after cleanup"):
        manager.__exit__(None, None, None)
    assert container.exists()
    monkeypatch.setattr(runtime_identity.shutil, "rmtree", real_rmtree)
    scope.close()
    assert not container.exists()


def test_run_scoped_snapshot_cleanup_refuses_a_replaced_root_identity(tmp_path, monkeypatch):
    tool, _candidate, executable = _managed_script_runtime(tmp_path, monkeypatch)
    manager = runtime_identity.managed_payload_snapshot_scope()
    scope = manager.__enter__()
    prepared = runtime_identity.prepare_launch(
        tool.bin, [str(executable)], payload_scope=scope,
    )
    container = Path(prepared.record["payload_anchors"][0]["root"]).parent
    prepared.close()
    displaced = container.with_name(container.name + "-displaced")
    container.rename(displaced)
    container.mkdir(mode=0o700)

    with pytest.raises(runtime_identity.RuntimeIdentityError, match="root identity changed"):
        manager.__exit__(None, None, None)
    assert container.is_dir() and displaced.is_dir()
    runtime_identity.shutil.rmtree(container)
    runtime_identity._settle_launch_root(displaced)
    scope.close()


def test_run_scoped_snapshot_cleanup_cancellation_preempts_an_ordinary_body_fault(
        tmp_path, monkeypatch):
    tool, _candidate, executable = _managed_script_runtime(tmp_path, monkeypatch)
    real_rmtree = runtime_identity.shutil.rmtree
    captured = {}

    def remove_then_cancel(path, *args, **kwargs):
        result = real_rmtree(path, *args, **kwargs)
        if Path(path) == captured.get("container"):
            raise KeyboardInterrupt("snapshot cleanup cancellation")
        return result

    with pytest.raises(KeyboardInterrupt, match="snapshot cleanup cancellation"):
        with runtime_identity.managed_payload_snapshot_scope() as scope:
            prepared = runtime_identity.prepare_launch(
                tool.bin, [str(executable)], payload_scope=scope,
            )
            captured["container"] = Path(
                prepared.record["payload_anchors"][0]["root"],
            ).parent
            prepared.close()
            monkeypatch.setattr(runtime_identity.shutil, "rmtree", remove_then_cancel)
            raise RuntimeError("ordinary body fault")
    assert not captured["container"].exists()


def test_managed_wrapper_consumes_only_the_private_payload_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    payload_body = b"printf 'GOOD\\n'\n"
    tool = registry.Tool(
        bin="wrapper-fixture", phase="fixture", role="wrapper payload identity",
        runtime="source", ref="deadbeef", install="build wrapper-fixture",
        runtime_exec="sh", runtime_entry=".local/share/quarry/entry.sh",
        runtime_payloads=[{
            "path": ".local/share/quarry/entry.sh",
            "sha256": hashlib.sha256(payload_body).hexdigest(),
        }],
    )
    root = registry._managed_root(tool)
    candidate = root / "versions" / ("b" * 32)
    wrapper = candidate / "home" / ".local" / "bin" / tool.bin
    entry = candidate / "home" / tool.runtime_entry
    wrapper.parent.mkdir(parents=True)
    entry.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\nexit 99\n")
    wrapper.chmod(0o700)
    entry.write_bytes(payload_body)
    _publish_fixture_runtime(tool, candidate, wrapper)
    monkeypatch.setattr(
        registry, "tool_for_bin",
        lambda name: tool if Path(name).name == tool.bin else None,
    )

    prepared = runtime_identity.prepare_launch(tool.bin, [str(wrapper)])
    try:
        runtime_identity.revalidate_launch(prepared)
        assert Path(prepared.argv[1]).is_relative_to(prepared.anchor_root)
        for directory in (candidate, *candidate.parents[:2], entry.parent):
            directory.chmod(0o700)
        entry.chmod(0o600)
        entry.write_text("printf 'EVIL\\n'\n")

        read_fd, write_fd = os.pipe()
        try:
            pid = os.posix_spawn(
                prepared.argv[0], prepared.argv, prepared.environment,
                file_actions=((os.POSIX_SPAWN_DUP2, write_fd, 1),
                              (os.POSIX_SPAWN_CLOSE, read_fd),
                              (os.POSIX_SPAWN_CLOSE, write_fd)),
            )
            os.close(write_fd)
            write_fd = -1
            output = os.read(read_fd, 1024)
            _pid, status = os.waitpid(pid, 0)
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)
        assert os.waitstatus_to_exitcode(status) == 0 and output.strip() == b"GOOD"
    finally:
        prepared.close()


def test_absent_subfinder_config_appearance_and_relative_paths_fail_closed(tmp_path, monkeypatch):
    executable = _executable(tmp_path / "subfinder", "OK")
    tool = registry.Tool(
        bin="subfinder", phase="vertical", role="fixture", policy="distro",
        env_allow=["SUBFINDER_PROVIDER_CONFIG", "SUBFINDER_CONFIG"],
    )
    monkeypatch.setattr(
        registry, "tool_for_bin",
        lambda name: tool if Path(name).name == "subfinder" else None,
    )
    with pytest.raises(runtime_identity.RuntimeIdentityError, match="must be absolute"):
        runtime_identity.prepare_launch(
            "subfinder", [str(executable)], caller_env={"SUBFINDER_CONFIG": "relative.yaml"},
        )

    config = tmp_path / "config.yaml"
    provider = tmp_path / "provider.yaml"
    prepared = runtime_identity.prepare_launch(
        "subfinder", [str(executable)], caller_env={
            "SUBFINDER_CONFIG": str(config),
            "SUBFINDER_PROVIDER_CONFIG": str(provider),
        },
    )
    try:
        runtime_identity.revalidate_launch(prepared)
        config.write_text("appeared: true\n")
        with pytest.raises(runtime_identity.RuntimeIdentityError, match="absent runtime input appeared"):
            runtime_identity.revalidate_launch(prepared)
    finally:
        prepared.close()


def test_nuclei_template_snapshot_is_copied_once_per_lane_and_detached(tmp_path, monkeypatch):
    source = tmp_path / "nuclei-templates"
    source.mkdir()
    (source / "template.yaml").write_text("id: stable\n")
    real_copy = runtime_identity._copy_input_tree
    calls = []

    def observed_copy(*args, **kwargs):
        calls.append(args[0])
        return real_copy(*args, **kwargs)

    monkeypatch.setattr(runtime_identity, "_copy_input_tree", observed_copy)
    with runtime_identity.reusable_tree_snapshot(source, role="nuclei-templates"):
        first = runtime_identity._active_tree_snapshot(source)
        second = runtime_identity._active_tree_snapshot(source)
        assert first is second and len(calls) == 1
        anchored = Path(first["path"])
        assert anchored.is_dir()
        (source / "template.yaml").write_text("id: attacker\n")
        assert (anchored / "template.yaml").read_text() == "id: stable\n"
        snapshot_root = Path(first["root"])
    assert not snapshot_root.exists()


def test_non_root_owned_immutable_helper_is_rejected(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("fixture ownership cannot model an unprivileged owner while running as root")
    helper = _executable(tmp_path / "chromium", "OK")
    helper.chmod(0o555)
    with pytest.raises(runtime_identity.RuntimeIdentityError, match="root authority"):
        runtime_identity._immutable_system_file(helper)


@pytest.mark.parametrize(
    ("tool_name", "path_flag"),
    [("gowitness", "--chrome-path"), ("katana", "-system-chrome-path"),
     ("nuclei", None)],
)
def test_every_declared_chromium_consumer_gets_one_exact_admitted_browser_identity(
        tmp_path, monkeypatch, tool_name, path_flag):
    declared = {tool.bin for tool in registry.load_tools() if tool.needs_chromium}
    assert declared == {"gowitness", "katana", "nuclei"}
    tool = registry.Tool(
        bin=tool_name, phase="fixture", role="browser consumer", policy="distro",
        needs_chromium=True,
    )
    executable = _executable(tmp_path / tool_name, "OK")
    browser = _executable(tmp_path / "chromium", "BROWSER")
    browser_record, _browser = runtime_identity._host_identity(str(browser), role="browser")
    browser_record.update({"role": "browser", "runtime": "host-browser"})
    monkeypatch.setattr(
        registry, "tool_for_bin",
        lambda name: tool if Path(name).name == tool_name else None,
    )
    monkeypatch.setattr(
        runtime_identity, "_browser_identity", lambda: (browser_record, browser),
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    templates = tmp_path / "nuclei-templates"
    templates.mkdir()
    (templates / "fixture.yaml").write_text("id: fixture\n")

    prepared = runtime_identity.prepare_launch(tool_name, [str(executable)])
    try:
        browsers = [
            identity for identity in prepared.record["identities"]
            if identity.get("role") == "browser"
        ]
        assert len(browsers) == 1
        anchored_browser = prepared.anchor_root / "chromium"
        assert anchored_browser.is_file()
        if path_flag is not None:
            assert prepared.argv[prepared.argv.index(path_flag) + 1] == str(anchored_browser)
        else:
            assert "-system-chrome" in prepared.argv
            assert prepared.environment["PATH"].split(os.pathsep)[0] == str(prepared.anchor_root)
        runtime_identity.revalidate_launch(prepared)
    finally:
        prepared.close()


def test_receipted_internal_link_swap_and_restore_cannot_poison_private_payload(
        tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "good").write_text("GOOD")
    (source / "evil").write_text("EVIL")
    link = source / "selected"
    link.symlink_to("good")
    receipt = {"files": registry._tree_rows(source)}
    launch = tmp_path / "launch"
    launch.mkdir()
    real_readlink = runtime_identity.os.readlink
    reads = {"source": 0}

    def swap_restore(path, *args, **kwargs):
        if Path(path) == link:
            reads["source"] += 1
            if reads["source"] == 1:
                admitted = real_readlink(path)
                link.unlink()
                link.symlink_to("evil")
                return admitted
            if reads["source"] == 2:
                link.unlink()
                link.symlink_to("good")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.os, "readlink", swap_restore)
    with pytest.raises(runtime_identity.RuntimeIdentityError, match="changed while anchoring"):
        runtime_identity._copy_receipt_payload(source, receipt, launch, 0)


@pytest.mark.parametrize("fault", [KeyboardInterrupt("window cancellation"), SystemExit(71)])
def test_oob_managed_window_fault_still_settles_private_credential(
        tmp_path, monkeypatch, fault):
    token = "V310-OOB-CONSTRUCTOR-CANARY"
    captured = {"directories": []}
    real_mkdtemp = secrets.tempfile.mkdtemp

    def private_directory(*args, **kwargs):
        kwargs["dir"] = tmp_path
        name = real_mkdtemp(*args, **kwargs)
        captured["directories"].append(Path(name))
        return name

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", private_directory)
    monkeypatch.setattr(oob.secrets, "values", lambda: [token])
    monkeypatch.setattr(
        oob.runner, "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(fault),
    )

    with pytest.raises(type(fault)):
        oob._run_client_window(
            object(), log=tmp_path / "log", session_file=tmp_path / "session",
            server="oob.example", token=token,
            wait=1, seed_prior=False, managed_outputs=False,
        )

    assert captured["directories"] and all(not path.exists() for path in captured["directories"])


def test_launch_anchor_cleanup_failure_is_loud_until_absence_is_proven(tmp_path, monkeypatch):
    prepared = runtime_identity.prepare_launch("fixture", [str(_executable(tmp_path / "adapter", "OK"))])
    root = prepared.anchor_root
    real_rmtree = runtime_identity.shutil.rmtree
    monkeypatch.setattr(
        runtime_identity.shutil, "rmtree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected cleanup fault")),
    )
    with pytest.raises(runtime_identity.RuntimeIdentityError, match="remains after cleanup"):
        prepared.close()
    assert root.exists()
    monkeypatch.setattr(runtime_identity.shutil, "rmtree", real_rmtree)
    prepared.close()
    assert not root.exists()


def test_rejected_install_candidate_cleanup_is_explicit_and_recoverable(tmp_path, monkeypatch):
    candidate = tmp_path / "versions" / ("a" * 32)
    payload = candidate / "home" / "bin" / "tool"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"REJECTED")
    registry._freeze_candidate_payload(candidate)
    registry._seal_candidate_root(candidate)
    real_rmtree = registry.shutil.rmtree
    monkeypatch.setattr(
        registry.shutil, "rmtree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected cleanup fault")),
    )
    with pytest.raises(registry._RollbackError) as caught:
        registry._discard_candidate(candidate)
    assert caught.value.recovery == candidate and candidate.exists()
    monkeypatch.setattr(registry.shutil, "rmtree", real_rmtree)
    registry._discard_candidate(candidate)
    assert not candidate.exists()


def test_managed_launch_binds_compact_complete_receipt_closure(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    tool = registry.Tool(
        bin="qtool", phase="vertical", role="fixture", runtime="source",
        ref="deadbeef", install="build {ref} {bin}", capability="qtool --version",
    )
    destination = tmp_path / ".local" / "bin" / "qtool"

    def install(_command, _dry):
        home = Path(registry._install_context.environment["HOME"])
        staged = home / ".local" / "bin" / ".stage" / "qtool"
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(b"VERIFIED-RUNTIME")
        (home / "runtime-helper.dat").write_bytes(b"VERIFIED-HELPER")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", install)
    monkeypatch.setattr(registry, "_probe", lambda *_args, **_kwargs: (0, "qtool 1"))
    monkeypatch.setattr(registry.shutil, "which", lambda name: str(destination) if name == "qtool" else None)
    assert registry.install_one(tool, lambda _message: None)
    monkeypatch.setattr(registry, "tool_for_bin", lambda name: tool if name == "qtool" else None)

    prepared = runtime_identity.prepare_launch("qtool", ["qtool"])
    try:
        managed = prepared.record["identities"][0]
        assert managed["attestation"] == "managed-receipt"
        assert set(managed["closure"]) == {"bytes", "objects", "sha256"}
        assert managed["closure"]["objects"] >= 1
        runtime_identity.revalidate_launch(prepared)
        active, _receipt = registry.managed_runtime_receipt(tool)
        payload = active / "home" / "runtime-helper.dat"
        payload.chmod(0o600)
        payload.write_bytes(b"MUTATED")
        with pytest.raises(runtime_identity.RuntimeIdentityError, match="closure changed"):
            runtime_identity.revalidate_launch(prepared)
    finally:
        prepared.close()


def test_runtime_environment_is_allowlisted_and_record_contains_names_not_values(tmp_path, monkeypatch):
    executable = _executable(tmp_path / "adapter", "OK")
    canary = "V310_SECRET_CANARY_41f9378a"
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", canary)
    monkeypatch.setenv("PDCP_API_KEY", canary)
    monkeypatch.setenv("RANDOM_UNDECLARED", canary)

    prepared = runtime_identity.prepare_launch("fixture", [str(executable)])
    try:
        assert not ({"AWS_SECRET_ACCESS_KEY", "PDCP_API_KEY", "RANDOM_UNDECLARED"}
                    & set(prepared.environment))
        assert canary not in json.dumps(prepared.record, sort_keys=True)
        assert prepared.environment["PATH"].split(os.pathsep)[0] == str(prepared.anchor_root)
    finally:
        prepared.close()


def test_managed_launch_uses_private_home_and_xdg_state(tmp_path, monkeypatch):
    executable = _executable(tmp_path / "adapter", "OK")
    ambient = tmp_path / "ambient"
    monkeypatch.setenv("HOME", str(ambient / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(ambient / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(ambient / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(ambient / "data"))

    prepared = runtime_identity.prepare_launch("fixture", [str(executable)])
    try:
        for name, child in (("HOME", "home"), ("XDG_CONFIG_HOME", "xdg-config"),
                            ("XDG_CACHE_HOME", "xdg-cache"), ("XDG_DATA_HOME", "xdg-data")):
            value = Path(prepared.environment[name])
            assert value == prepared.anchor_root / child
            assert value.is_dir() and value != Path(os.environ[name])
        runtime_identity.revalidate_launch(prepared)
    finally:
        prepared.close()


def test_dynamic_adapter_config_is_reconciled_as_a_file_not_misparsed_as_a_tree(tmp_path):
    executable = _executable(tmp_path / "adapter", "OK")
    config = tmp_path / "provider-config.yaml"
    config.write_text("provider: stable\n")
    prepared = runtime_identity.prepare_launch("fixture", [str(executable)])
    try:
        prepared.record["dynamic_closure"] = [
            runtime_identity._file_record("adapter-config", config),
        ]
        runtime_identity.revalidate_launch(prepared)
        config.write_text("provider: changed\n")
        with pytest.raises(runtime_identity.RuntimeIdentityError, match="closure changed"):
            runtime_identity.revalidate_launch(prepared)
    finally:
        prepared.close()


def test_adapter_credentials_come_only_from_the_declared_framework_source(monkeypatch):
    monkeypatch.setenv("PDCP_API_KEY", "AMBIENT-MUST-NOT-WIN")
    monkeypatch.setattr(secrets, "chaos", lambda: "FRAMEWORK-CANARY")
    assert secrets.adapter_environment("subfinder", ["PDCP_API_KEY"]) == {
        "PDCP_API_KEY": "FRAMEWORK-CANARY",
    }
    assert secrets.adapter_environment("nuclei", []) == {}
    with pytest.raises(ValueError, match="unknown credential"):
        secrets.adapter_environment("fixture", ["AWS_SECRET_ACCESS_KEY"])


def test_secret_store_rejects_symlink_wrong_mode_hardlink_and_foreign_owner(tmp_path, monkeypatch):
    store_path = tmp_path / "secrets.yaml"
    store_path.write_text("projectdiscovery: V310-PRIVATE\n")
    store_path.chmod(0o600)
    assert secrets._read_store(store_path) == {"projectdiscovery": "V310-PRIVATE"}

    alias = tmp_path / "alias.yaml"
    alias.symlink_to(store_path)
    with pytest.raises(secrets.SecretStoreError, match="symlink|opened safely"):
        secrets._read_store(alias)

    store_path.chmod(0o640)
    with pytest.raises(secrets.SecretStoreError, match="owner-held 0600"):
        secrets._read_store(store_path)
    store_path.chmod(0o600)

    hardlink = tmp_path / "hardlink.yaml"
    os.link(store_path, hardlink)
    with pytest.raises(secrets.SecretStoreError, match="owner-held 0600"):
        secrets._read_store(store_path)
    hardlink.unlink()

    current_uid = os.geteuid()
    monkeypatch.setattr(secrets.os, "geteuid", lambda: current_uid + 1)
    with pytest.raises(secrets.SecretStoreError, match="owner-held 0600"):
        secrets._read_store(store_path)


def test_contract_telemetry_records_environment_names_never_values(tmp_path, monkeypatch):
    canary = "V310-TELEMETRY-CANARY-dc06f4"
    events.reset()
    events.configure(tmp_path)
    monkeypatch.setattr(
        contract, "_run",
        lambda tool, cmd, **_kwargs: RunResult(tool, cmd, Status.SUCCESS, 0, 0.1, None, 0),
    )
    try:
        contract.run_contract(
            "vertical.subfinder", ["subfinder"], env={"PDCP_API_KEY": canary},
        )
        body = (tmp_path / "events.jsonl").read_text()
    finally:
        events.reset()
    assert canary not in body
    start = next(row for row in map(json.loads, body.splitlines()) if row["event"] == "tool_start")
    assert start["env"] == {"PDCP_API_KEY": "<provided>"}


def test_runtime_admission_rejects_environment_subclasses_without_invoking_them():
    class HostileDict(dict):
        def _explode(self, *_args, **_kwargs):
            raise AssertionError("dict subclass method was invoked")

        __iter__ = items = keys = values = __len__ = __bool__ = __str__ = __repr__ = _explode

    class HostileStr(str):
        def __str__(self):
            raise AssertionError("str subclass method was invoked")

        def __repr__(self):
            raise AssertionError("str subclass method was invoked")

    for environment in (
        HostileDict({"PYTHONHASHSEED": "0"}),
        {HostileStr("PYTHONHASHSEED"): "0"},
        {"PYTHONHASHSEED": HostileStr("0")},
        {"PYTHONHASHSEED": object()},
    ):
        with pytest.raises(runtime_identity.RuntimeIdentityError, match="environment"):
            runtime_identity.prepare_launch("fixture", ["/bin/true"], caller_env=environment)


def test_private_config_cleanup_failure_is_loud_and_residue_is_never_reported_clean(
        tmp_path, monkeypatch):
    captured = {}
    real_mkdtemp = secrets.tempfile.mkdtemp
    real_unlink = secrets.os.unlink
    real_rmdir = secrets.os.rmdir
    real_rmtree = secrets.shutil.rmtree

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        value = real_mkdtemp(*args, **kwargs)
        captured["directory"] = Path(value)
        return value

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", make)
    monkeypatch.setattr(secrets.os, "unlink",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("unlink fault")))
    monkeypatch.setattr(secrets.os, "rmdir",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("rmdir fault")))

    with pytest.raises(secrets.SecretCleanupError, match="remains"):
        with secrets.private_tool_config("fault", {"token": "CANARY"}):
            pass
    directory = captured["directory"]
    assert directory.exists(), "fixture must demonstrate the residue that made cleanup fail closed"
    # Settle the test-owned injected residue without relying on the patched cleanup primitives.
    monkeypatch.setattr(secrets.os, "unlink", real_unlink)
    monkeypatch.setattr(secrets.os, "rmdir", real_rmdir)
    real_rmtree(directory)


def test_private_config_cleanup_refuses_a_replaced_directory_identity(tmp_path, monkeypatch):
    real_mkdtemp = secrets.tempfile.mkdtemp

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        return real_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", make)
    manager = secrets.private_tool_config("identity", {"token": "CANARY"})
    path = manager.__enter__()
    directory = path.parent
    displaced = directory.with_name(directory.name + "-displaced")
    directory.rename(displaced)
    directory.mkdir(mode=0o700)

    with pytest.raises(secrets.SecretCleanupError, match="identity changed"):
        manager.__exit__(None, None, None)
    assert directory.is_dir()
    assert not (displaced / path.name).exists(), "the held credential inode must still be erased/unlinked"
    directory.rmdir()
    secrets.shutil.rmtree(displaced)


def test_private_config_preserves_keyboard_interrupt_when_cleanup_also_faults(tmp_path, monkeypatch):
    captured = {}
    real_mkdtemp = secrets.tempfile.mkdtemp
    real_rmtree = secrets.shutil.rmtree

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        value = real_mkdtemp(*args, **kwargs)
        captured["directory"] = Path(value)
        return value

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", make)
    monkeypatch.setattr(secrets.os, "unlink",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("unlink fault")))
    monkeypatch.setattr(secrets.os, "rmdir",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("rmdir fault")))
    with pytest.raises(KeyboardInterrupt) as caught:
        with secrets.private_tool_config("interrupt", {"token": "CANARY"}):
            raise KeyboardInterrupt
    assert any("credential cleanup also failed" in note for note in getattr(caught.value, "__notes__", ()))
    monkeypatch.undo()
    real_rmtree(captured["directory"])


def test_private_config_cleanup_keyboard_interrupt_preempts_ordinary_body_failure(
        tmp_path, monkeypatch):
    captured = {}
    real_mkdtemp = secrets.tempfile.mkdtemp
    real_rmdir = secrets.os.rmdir

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        value = real_mkdtemp(*args, **kwargs)
        captured["directory"] = Path(value)
        return value

    def rmdir_then_interrupt(path, *args, **kwargs):
        real_rmdir(path, *args, **kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", make)
    monkeypatch.setattr(secrets.os, "rmdir", rmdir_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        with secrets.private_tool_config("cancel", {"token": "CANARY"}):
            raise RuntimeError("ordinary body fault")
    assert not captured["directory"].exists()


def test_private_config_close_after_write_fault_still_erases_bytes(tmp_path, monkeypatch):
    captured = {}
    real_mkdtemp = secrets.tempfile.mkdtemp
    real_close = secrets.os.close
    tripped = {"value": False}

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        value = real_mkdtemp(*args, **kwargs)
        captured["directory"] = Path(value)
        return value

    def close_then_fault(fd):
        real_close(fd)
        if not tripped["value"]:
            tripped["value"] = True
            raise OSError("close-after-effect")

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", make)
    monkeypatch.setattr(secrets.os, "close", close_then_fault)
    with pytest.raises(OSError, match="close-after-effect"):
        with secrets.private_tool_config("close", {"token": "CANARY"}):
            pytest.fail("a close fault before yield must not enter the body")
    assert not captured["directory"].exists()


@pytest.mark.parametrize("role,target_close", [("writer", 1), ("claim", 2), ("directory", 3)])
@pytest.mark.parametrize("effect", ["before", "after"])
@pytest.mark.parametrize("fault_type", [OSError, KeyboardInterrupt, SystemExit])
def test_private_config_settles_every_exact_fd_across_close_faults(
        tmp_path, monkeypatch, role, target_close, effect, fault_type):
    real_mkdtemp = secrets.tempfile.mkdtemp
    real_close = secrets.os.close
    state = {"calls": 0, "fd": None, "directory": None, "entered": False}

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        value = real_mkdtemp(*args, **kwargs)
        state["directory"] = Path(value)
        return value

    def close_fault(fd):
        state["calls"] += 1
        if state["calls"] == target_close:
            state["fd"] = fd
            if effect == "after":
                real_close(fd)
            raise fault_type(f"{role}-close-{effect}")
        real_close(fd)

    monkeypatch.setattr(secrets.tempfile, "mkdtemp", make)
    monkeypatch.setattr(secrets.os, "close", close_fault)
    with pytest.raises(fault_type, match=f"{role}-close-{effect}"):
        with secrets.private_tool_config("fd-settle", {"token": "V310-FD-CANARY"}):
            state["entered"] = True
    assert state["entered"] is (role != "writer")
    assert state["fd"] is not None and not state["directory"].exists()
    with pytest.raises(OSError) as invalid:
        os.fstat(state["fd"])
    assert invalid.value.errno == getattr(os, "EBADF", 9)


@pytest.mark.parametrize("role,target_close", [("writer", 1), ("claim", 2), ("parent", 3)])
@pytest.mark.parametrize("effect", ["before", "after"])
@pytest.mark.parametrize("fault_type", [OSError, KeyboardInterrupt, SystemExit])
def test_github_token_settles_every_exact_fd_across_close_faults(
        tmp_path, monkeypatch, role, target_close, effect, fault_type):
    token = "ghp_V310DescriptorSettlement000000000000"
    real_mkstemp = secrets.tempfile.mkstemp
    real_close = secrets.os.close
    state = {"calls": 0, "fd": None, "path": None, "entered": False}

    def make(**kwargs):
        fd, name = real_mkstemp(dir=tmp_path, **kwargs)
        state["path"] = Path(name)
        return fd, name

    def close_fault(fd):
        state["calls"] += 1
        if state["calls"] == target_close:
            state["fd"] = fd
            if effect == "after":
                real_close(fd)
            raise fault_type(f"{role}-close-{effect}")
        real_close(fd)

    monkeypatch.setattr(secrets, "github_tokens", lambda: [token])
    monkeypatch.setattr(secrets.tempfile, "mkstemp", make)
    monkeypatch.setattr(secrets.os, "close", close_fault)
    with pytest.raises(fault_type, match=f"{role}-close-{effect}"):
        with secrets.github_tokens_lifetime():
            state["entered"] = True
    assert state["entered"] is (role != "writer")
    assert state["fd"] is not None and not state["path"].exists()
    with pytest.raises(OSError) as invalid:
        os.fstat(state["fd"])
    assert invalid.value.errno == getattr(os, "EBADF", 9)


@pytest.mark.parametrize("effect", ["before", "after"])
@pytest.mark.parametrize("fault_type", [OSError, KeyboardInterrupt, SystemExit])
def test_secret_store_settles_its_exact_read_fd_across_close_faults(
        tmp_path, monkeypatch, effect, fault_type):
    path = tmp_path / "secrets.yaml"
    path.write_text("projectdiscovery: V310-STORE-FD-CANARY\n")
    path.chmod(0o600)
    real_close = secrets.os.close
    captured = {}

    def close_fault(fd):
        captured["fd"] = fd
        if effect == "after":
            real_close(fd)
        raise fault_type(f"store-close-{effect}")

    monkeypatch.setattr(secrets.os, "close", close_fault)
    with pytest.raises(fault_type, match=f"store-close-{effect}"):
        secrets._read_store(path)
    assert path.read_text() == "projectdiscovery: V310-STORE-FD-CANARY\n"
    with pytest.raises(OSError) as invalid:
        os.fstat(captured["fd"])
    assert invalid.value.errno == getattr(os, "EBADF", 9)


def test_exact_fd_settlement_never_closes_a_reused_descriptor(tmp_path, monkeypatch):
    original = tmp_path / "original"
    replacement = tmp_path / "replacement"
    original.write_text("ORIGINAL")
    replacement.write_text("REPLACEMENT")
    fd = os.open(original, os.O_RDONLY)
    identity = secrets._identity(os.fstat(fd))
    real_close = secrets.os.close
    state = {}

    def close_then_reuse(target):
        real_close(target)
        state["replacement_fd"] = os.open(replacement, os.O_RDONLY)
        assert state["replacement_fd"] == target
        raise OSError("close-after-effect-with-reuse")

    monkeypatch.setattr(secrets.os, "close", close_then_reuse)
    with pytest.raises(secrets.SecretCleanupError, match="reused"):
        secrets._close_exact_fd(fd, identity, label="reuse test")
    assert os.read(state["replacement_fd"], 32) == b"REPLACEMENT"
    real_close(state["replacement_fd"])


def test_private_config_is_owner_only_during_its_lifetime(tmp_path, monkeypatch):
    monkeypatch.setattr(
        secrets.tempfile, "mkdtemp",
        lambda **kwargs: str(tmp_path / "private") if not (tmp_path / "private").mkdir(mode=0o700)
        else "",
    )
    with secrets.private_tool_config("mode", {"token": "CANARY"}) as path:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert path.read_text() == "token: CANARY\n"
        directory = path.parent
    assert not directory.exists()


def test_github_token_transport_is_owner_only_and_settled(monkeypatch):
    token = "ghp_V310SyntheticCredential000000000000000"
    monkeypatch.setattr(secrets, "github_tokens", lambda: [token])
    with secrets.github_tokens_lifetime() as path:
        assert path is not None and stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_text() == token + "\n"
        kept = path
    assert not kept.exists()


def test_github_token_cleanup_refuses_a_replaced_file_identity(tmp_path, monkeypatch):
    token = "ghp_V310SyntheticCredential000000000000000"
    monkeypatch.setattr(secrets, "github_tokens", lambda: [token])
    real_mkstemp = secrets.tempfile.mkstemp
    monkeypatch.setattr(
        secrets.tempfile, "mkstemp",
        lambda **kwargs: real_mkstemp(dir=tmp_path, **kwargs),
    )
    manager = secrets.github_tokens_lifetime()
    path = manager.__enter__()
    displaced = path.with_name(path.name + "-displaced")
    path.rename(displaced)
    path.write_text("DECOY\n")
    path.chmod(0o600)

    with pytest.raises(secrets.SecretCleanupError, match="remains"):
        manager.__exit__(None, None, None)
    assert displaced.read_bytes() == b"", "the displaced held credential inode must be erased"
    assert path.read_text() == "DECOY\n"
    path.unlink()
    displaced.unlink()


def test_nuclei_oob_token_uses_only_a_private_config_and_is_settled(monkeypatch):
    token = "V310-NUCLEI-CANARY-2b745d"
    monkeypatch.setattr(
        secrets, "oob",
        lambda: {"callback_server": "https://oob.example", "auth_token": token},
    )
    with params._nuclei_oob_flags() as flags:
        assert flags[:2] == ("-iserver", "https://oob.example")
        assert "-itoken" not in flags and token not in flags
        config = Path(flags[flags.index("-config") + 1])
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        assert token in config.read_text()
        directory = config.parent
    assert not directory.exists()


def test_dalfox_cleanup_fault_is_loud_without_replacing_keyboard_interrupt(monkeypatch):
    cleanup = params.OobCredentialError("credential remains")
    monkeypatch.setattr(params, "_make_oob_credential", lambda _secret: (Path("/d"), Path("/d/cfg")))
    monkeypatch.setattr(params, "_drop_oob_credential", lambda *_args: (_ for _ in ()).throw(cleanup))
    with pytest.raises(KeyboardInterrupt) as caught:
        with params.blind_oob_credential("CANARY"):
            raise KeyboardInterrupt
    assert any("cleanup also failed" in note for note in getattr(caught.value, "__notes__", ()))

    with pytest.raises(params.OobCredentialError, match="credential remains"):
        with params.blind_oob_credential("CANARY"):
            pass


def test_dalfox_acquisition_keyboard_interrupt_settles_written_credential(tmp_path, monkeypatch):
    captured = {}
    real_mkdtemp = tempfile.mkdtemp

    def make(*args, **kwargs):
        kwargs["dir"] = tmp_path
        value = real_mkdtemp(*args, **kwargs)
        captured["directory"] = Path(value)
        return value

    def write_then_interrupt(value, stream):
        stream.write(json.dumps(value))
        stream.flush()
        raise KeyboardInterrupt

    monkeypatch.setattr(tempfile, "mkdtemp", make)
    monkeypatch.setattr(params.json, "dump", write_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        with params.blind_oob_credential("CANARY"):
            pytest.fail("credential acquisition cancellation must not enter the body")
    assert not captured["directory"].exists()


def test_registry_declares_only_the_two_pdcp_consumers_and_runtime_dependencies():
    tools = {tool.bin: tool for tool in registry.load_tools()}
    assert {name for name, tool in tools.items() if tool.credential_env} == {"asnmap", "subfinder"}
    assert tools["puredns"].runtime_bins == ["massdns"]
    assert tools["jxscout-chunks"].runtime_exec == "node"
    assert tools["jxscout-ast"].runtime_exec == "bun"
    for name in ("jxscout-chunks", "jxscout-ast"):
        assert tools[name].runtime_payloads
        assert all(len(item["sha256"]) == 64 for item in tools[name].runtime_payloads)


class _ShodanResponse:
    def __init__(self, document, status=200):
        self.status = status
        self._body = json.dumps(document).encode("utf-8")

    def read(self, amount=-1):
        if not self._body:
            return b""
        if amount is None or amount < 0:
            amount = len(self._body)
        chunk, self._body = self._body[:amount], self._body[amount:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _patch_provider(monkeypatch, responses, seen=None):
    def scoped(_ctx, url, **_kwargs):
        if seen is not None:
            seen.append((
                _kwargs.get("method", "GET"), url,
                dict(_kwargs.get("headers") or {}), _kwargs.get("timeout"),
            ))
        response = responses() if callable(responses) else responses.pop(0)
        return response.read(), url, getattr(response, "status", 200)
    monkeypatch.setattr(vertical.fetch, "scoped_public_provider_get", scoped)


def test_shodan_dns_adapter_is_in_process_strict_and_bounded(monkeypatch):
    canary = "V310SHODANKEY00000000000000000000"
    pages = [
        _ShodanResponse({"subdomains": ["www", "API"], "more": True}),
        _ShodanResponse({"subdomains": ["mail"], "more": False}),
    ]
    requests = []

    def responses():
        return pages.pop(0)

    _patch_provider(monkeypatch, responses, requests)
    result = vertical._shodan_domain("Acme.Example", canary, timeout=9, max_pages=5)

    assert result == {"www.acme.example", "api.acme.example", "mail.acme.example"}
    assert result.pages == 2 and not result.partial and result.cursor is None
    assert [url for _method, url, _headers, _timeout in requests] == [
        f"https://api.shodan.io/dns/domain/Acme.Example?key={canary}&page=1",
        f"https://api.shodan.io/dns/domain/Acme.Example?key={canary}&page=2",
    ]
    assert all(timeout == 9 for _method, _url, _headers, timeout in requests)


def test_shodan_dns_failures_never_serialize_the_query_credential(monkeypatch):
    canary = "V310SHODANKEY00000000000000000000"

    _patch_provider(monkeypatch, lambda: (_ for _ in ()).throw(
            OSError(f"request failed for ?key={canary}"),
        ))
    with pytest.raises(RuntimeError) as caught:
        vertical._shodan_domain("acme.example", canary)
    assert canary not in str(caught.value) and canary not in repr(caught.value)


def test_shosubgo_has_no_remaining_registry_or_subprocess_authority():
    from quarry_recon import policy

    tools = registry.load_tools()
    assert all(tool.bin != "shosubgo" for tool in tools)
    source = Path(vertical.__file__).read_text()
    assert "['shosubgo'" not in source and '["shosubgo"' not in source
    sources = (Path(vertical.__file__).parents[1] / "data" / "sources.yaml").read_text()
    assert "vertical.shosubgo:         {tool: internal" in sources
    assert policy.PROVIDER_DOORS["vertical.shosubgo"] == "run_provider"


@pytest.mark.synthetic_process
def test_configured_canary_is_removed_from_every_persisted_child_sink(
        tmp_path, monkeypatch, fake_direct_containment):
    isolated_install = any(
        any(path.glob("*quarry*"))
        for path in map(Path, site.getsitepackages()) if path.is_dir()
    )
    if not isolated_install:
        pytest.skip("real fixed-worker replay requires the project installed for Python -I")
    canary = "V310-CREDENTIAL-SINK-CANARY-607c83f1"
    tool = registry.Tool(
        bin="credential-fixture", phase="fixture", role="credential sink probe",
        policy="distro", credential_env=["PDCP_API_KEY"],
    )
    monkeypatch.setattr(registry, "tool_for_bin", lambda _name: tool)
    monkeypatch.setattr(secrets, "chaos", lambda: canary)
    monkeypatch.setattr(secrets, "values", lambda: [canary])
    real_capture = runner_supervisor.capture_process_identity
    captured_pids = []

    def delay_started_capture(pid):
        captured_pids.append(pid)
        if len(captured_pids) == 2:
            # The credential fixture exits immediately.  Before the STARTED EOF
            # barrier this delay let the worker reap it and made the parent lose
            # /proc identity.  The worker must now retain that identity until the
            # parent finishes this exact capture and containment verification.
            time.sleep(0.1)
        return real_capture(pid)

    monkeypatch.setattr(
        runner_supervisor, "capture_process_identity", delay_started_capture,
    )

    run = store.Run.create(tmp_path, "acme.example", run_id="v310-secret-sinks")
    run.write_state("running")
    stdout_path = run.raw_path("fixture", "credential", "stdout.bin")
    stderr_path = run.raw_path("fixture", "credential", "stderr.bin")
    native_path = run.raw_path("fixture", "credential", "native.bin")
    executable = tmp_path / "credential-fixture"
    executable.write_text(
        "#!/bin/sh\n"
        "printf 'out:%s\\n' \"$PDCP_API_KEY\"\n"
        "printf 'err:%s\\n' \"$PDCP_API_KEY\" >&2\n"
        "printf '%s\\n' \"${QUARRY_RUNNER_PRIVATE_REDACTIONS-absent}\"\n"
        "printf 'native:%s' \"$PDCP_API_KEY\" > \"$1\"\n"
    )
    executable.chmod(0o700)
    command = [str(executable), str(native_path)]
    result = runner.run(
        "credential-fixture", command, repository=run,
        stdout=RepositoryOutput.publish_path(run, stdout_path),
        stderr=RepositoryOutput.publish_path(run, stderr_path),
        native_outputs=(runner_native.RepositoryNativeOutput.file(
            1, "raw", "fixture", "credential", "native.bin",
        ),),
        timeout=20,
    )
    run.record("fixture", result)

    assert result.status is Status.FAILED
    assert "framework credential" in result.note
    assert result.meta["execution_reason"] == "complete"
    assert result.meta["repository_publication"] == "published"
    assert len(captured_pids) == 2 and captured_pids[0] != captured_pids[1]
    assert not native_path.exists(), "credential-bearing native output must never publish"
    assert canary.encode() not in stdout_path.read_bytes()
    assert canary.encode() not in stderr_path.read_bytes()
    assert b"QUARRY_RUNNER_PRIVATE_REDACTIONS" not in stdout_path.read_bytes()
    assert b"absent" in stdout_path.read_bytes()
    assert b"*" * len(canary) in stdout_path.read_bytes()
    assert list(run.dir.rglob(".quarry-*.stage")) == []
    for path in run.dir.rglob("*"):
        if path.is_file():
            assert canary.encode() not in path.read_bytes(), path
