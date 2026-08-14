"""QR39-008 — typed install results + atomic activation with last-good rollback + concurrency lock.

A post-swap failure must restore the previous healthy binary; a required bootstrap-step failure must make
`quarry install` exit nonzero; a staging failure must never report success.
"""
import fcntl
import os
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from quarry_recon import bootstrap, registry
from quarry_recon.bootstrap import InstallResult
from quarry_recon.registry import Tool, install_one

pytestmark = pytest.mark.offline


def _src_tool():
    return Tool(bin="qtool", phase="vertical", role="test", runtime="source",
                ref="deadbeef", install="stage {ref} {bin}", capability="qtool --version")


def _bindir(home: Path) -> Path:
    return home / ".local" / "bin"


def _candidate_stage() -> Path:
    """The private candidate HOME selected by install_one for the current installer thread."""
    environment = registry._install_context.environment
    return Path(environment["HOME"]) / ".local" / "bin" / ".stage" / "qtool"


def _sink(*a, **k):
    pass


def test_post_swap_failure_rolls_back_to_last_good(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")                                  # the previously healthy binary

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    def boom(*a, **k):
        raise OSError("receipt disk full")
    monkeypatch.setattr(registry, "_write_runtime_receipt", boom)

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # rolled back, not left as NEW
    assert not (_bindir(tmp_path) / ".stage" / ".qtool.last-good").exists()


def test_staging_failure_is_no_false_success(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    dest.chmod(0o500)
    monkeypatch.setattr(registry, "run_shell", lambda cmd, dry: (1, "build failed"))
    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # untouched — nothing was displaced


def test_healthy_install_activates_and_writes_receipt(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))

    assert install_one(_src_tool(), _sink) is True
    assert dest.read_bytes() == b"NEW"
    assert registry._receipt_path("qtool").exists()
    active, _receipt = registry.managed_runtime_receipt(_src_tool())
    assert stat.S_IMODE(active.stat().st_mode) == 0o500
    assert not (_bindir(tmp_path) / ".stage" / ".qtool.last-good").exists()


def test_concurrent_install_is_locked_out(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    stage_dir = _bindir(tmp_path) / ".stage"
    stage_dir.mkdir(parents=True)
    held = os.open(str(stage_dir / ".qtool.installing.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)          # another install holds the lock
    # run_shell must never run while the lock is held
    monkeypatch.setattr(registry, "run_shell",
                        lambda *a, **k: pytest.fail("ran install under a held lock"))
    try:
        assert install_one(_src_tool(), _sink) is False
        assert dest.read_bytes() == b"GOOD"
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)


def test_required_step_failure_makes_install_exit_nonzero(tmp_path, monkeypatch):
    monkeypatch.delenv("QUARRY_FROM_INSTALLER", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(bootstrap, "system_report", lambda ctx="install": {"level": "ok", "checks": []})
    monkeypatch.setattr(bootstrap, "install_system_packages",
                        lambda echo, dry: InstallResult("system-packages", True, True))
    monkeypatch.setattr(bootstrap, "ensure_golang",
                        lambda echo, dry: InstallResult("go", False, True, kind="required_tool_missing",
                                                        detail="pin missing"))
    monkeypatch.setattr(bootstrap, "install_data_files",
                        lambda echo, dry, update=False: InstallResult("data-files", True, True))
    monkeypatch.setattr(bootstrap, "run_extras",
                        lambda echo, dry: InstallResult("extras", True, False))
    monkeypatch.setattr(bootstrap, "cleanup", lambda echo, dry: None)
    monkeypatch.setattr("quarry_recon.cli.load_tools", lambda: [])

    from quarry_recon.cli import cli
    res = CliRunner().invoke(cli, ["install"])
    assert res.exit_code != 0, res.output
    assert "required step failed" in res.output and "go" in res.output


def test_install_result_blocks_only_when_required():
    assert InstallResult("x", False, True).blocks is True
    assert InstallResult("x", False, False).blocks is False
    assert InstallResult("x", True, True).blocks is False


def test_planted_symlink_stage_is_never_activated(tmp_path, monkeypatch):
    """A symlink planted at the stage path is refused (O_NOFOLLOW) — its target is never activated."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    secret = tmp_path / "attacker"
    secret.write_bytes(b"ATTACKER")

    def fake_shell(cmd, dry):
        stage_dir = _candidate_stage().parent
        stage_dir.mkdir(parents=True, exist_ok=True)
        link = stage_dir / "qtool"
        if link.is_symlink() or link.exists():
            link.unlink()
        os.symlink(str(secret), str(link))                     # stage path is a planted symlink
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # the symlink target was never followed/activated


def test_post_verification_swap_is_refused(tmp_path, monkeypatch):
    """A payload mutation between the two final closure reads activates nothing."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))

    real_tree = registry._tree_rows
    calls = {"count": 0}

    def swapping_tree(root):
        rows = real_tree(root)
        calls["count"] += 1
        if calls["count"] == 1:
            payload = Path(root) / "home" / ".local" / "bin" / "qtool"
            payload.chmod(0o700)
            payload.write_bytes(b"EVIL-UNVERIFIED")
        return rows

    monkeypatch.setattr(registry, "_tree_rows", swapping_tree)

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # unverified swapped-in object never activated


def test_rollback_restores_binary_and_its_receipt_as_a_pair(tmp_path, monkeypatch):
    """A post-swap failure restores the PREVIOUS healthy binary AND the receipt that describes it — the receipt
    never survives while its binary is rolled back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    dest.chmod(0o500)
    registry._write_receipt("qtool", "good-ref", "a" * 64)     # the receipt for the healthy binary
    assert registry._read_receipt("qtool")["ident"] == "good-ref"

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    # Inject after the current pointer and aliases were published, exercising pair rollback.
    monkeypatch.setattr(
        registry, "managed_runtime_receipt",
        lambda _tool: (_ for _ in ()).throw(registry._ActivationError("post-publish fault")),
    )

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # binary rolled back
    assert stat.S_IMODE(dest.stat().st_mode) == 0o500           # mode is part of last-good identity too
    assert registry._read_receipt("qtool")["ident"] == "good-ref"   # receipt rolled back WITH it
    assert not (_bindir(tmp_path) / ".stage" / ".qtool.last-good").exists()
    assert not (_bindir(tmp_path) / ".stage" / ".qtool.last-good.receipt").exists()


def test_curl_to_uses_fail_flag(tmp_path, monkeypatch):
    """`--fail` turns an HTTP 4xx/5xx into a nonzero exit instead of an error body written to disk."""
    captured = {}

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return Completed()

    monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
    bootstrap._curl_to("https://example.invalid/x", tmp_path / "x", False)
    assert "--fail" in captured["argv"]


def test_empty_required_data_file_is_a_failure(tmp_path, monkeypatch):
    """A 200 that writes an EMPTY required file (no fallback) is a typed failure, not a silent success."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(bootstrap, "load_bootstrap",
                        lambda: {"data_files": [{"name": "resolvers", "url": "https://x/r",
                                                 "dest": str(tmp_path / "r.txt")}]})

    def empty_curl(url, dest, dry, timeout=300):
        Path(dest).write_text("")                              # server answered, but with nothing
        return 0, ""

    monkeypatch.setattr(bootstrap, "_curl_to", empty_curl)
    res = bootstrap.install_data_files(_sink, False)
    assert res.blocks is True and "resolvers" in (res.detail or "")


def _go_tool():
    return Tool(bin="gtool", phase="vertical", role="test", runtime="go",
                ref="v1.2.3", install="go install example.com/gtool@{ref}")


def test_go_pipx_install_is_locked_out(tmp_path, monkeypatch):
    """The in-place go/pipx path honours the SAME per-bin lock as staged installs (QR39-008 finding 7)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    stage_dir = _bindir(tmp_path) / ".stage"
    stage_dir.mkdir(parents=True)
    held = os.open(str(stage_dir / ".gtool.installing.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setattr(registry, "run_shell",
                        lambda *a, **k: pytest.fail("ran a go/pipx install under a held lock"))
    try:
        assert install_one(_go_tool(), _sink) is False
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)


def test_publish_rejects_work_swapped_before_replace(tmp_path, monkeypatch):
    """A swapped current-pointer temporary is rejected and the legacy last-good pair is restored."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))

    real_replace = os.replace

    def swapping_replace(src, dst, *a, **k):
        source = Path(src)
        if source.name.startswith(".current-") and not source.name.endswith(".link"):
            source.unlink()
            source.symlink_to("versions/" + "0" * 32)
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(registry.os, "replace", swapping_replace)

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # swapped-in unverified inode never left active


def test_dangling_symlink_staging_target_creates_no_out_of_tree_file(tmp_path, monkeypatch):
    """A DANGLING symlink planted at the predictable stage path is cleared (exists() alone would miss it), so
    the install command writes a real in-tree file and nothing is created THROUGH the link out of tree."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    outside = tmp_path / "outside" / "planted"
    outside.parent.mkdir(parents=True)
    stage_dir = _bindir(tmp_path) / ".stage"
    stage_dir.mkdir(parents=True)
    os.symlink(str(outside), str(stage_dir / "qtool"))         # dangling: target does not exist yet

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        with open(stage, "w") as fh:
            fh.write("NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))

    assert install_one(_src_tool(), _sink) is True
    assert not outside.exists()                                # nothing written out of tree
    assert dest.read_bytes() == b"NEW"                         # the in-tree file was staged + activated


def test_rollback_deletes_receipt_when_it_cannot_be_restored(tmp_path, monkeypatch):
    """If the last-good receipt cannot be restored, it is DELETED — never left describing the rejected binary
    (a missing receipt forces re-verify; a stale one would lie)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")
    registry._write_receipt("qtool", "good-ref", "a" * 64)

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    monkeypatch.setattr(
        registry, "managed_runtime_receipt",
        lambda _tool: (_ for _ in ()).throw(registry._ActivationError("post-publish fault")),
    )

    real_replace = os.replace

    def failing_receipt_restore(src, dst, *a, **k):
        if Path(dst) == registry._receipt_path("qtool") and ".rollback" in Path(src).name:
            raise OSError("cannot restore receipt")
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(registry.os, "replace", failing_receipt_restore)

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # binary restored
    assert not registry._receipt_path("qtool").exists()        # stale receipt DELETED, never left as NEW


def test_rollback_binary_restore_failure_is_reported_loudly(tmp_path, monkeypatch):
    """A failure to restore the BINARY during rollback is reported LOUDLY, never suppressed into a false OK."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    monkeypatch.setattr(
        registry, "managed_runtime_receipt",
        lambda _tool: (_ for _ in ()).throw(registry._ActivationError("post-publish fault")),
    )

    real_replace = os.replace

    def failing_bin_restore(src, dst, *a, **k):
        if Path(dst) == dest and ".rollback" in Path(src).name:
            raise OSError("disk gone")
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(registry.os, "replace", failing_bin_restore)

    msgs = []
    assert install_one(_src_tool(), msgs.append) is False
    assert any("CRITICAL" in m for m in msgs)


def test_writable_staging_name_removed_after_activation(tmp_path, monkeypatch):
    """After a successful activation the writable staging name is gone — the active inode has only `dest`."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))
    monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))

    assert install_one(_src_tool(), _sink) is True
    assert dest.read_bytes() == b"NEW"
    assert not (_bindir(tmp_path) / ".stage" / "qtool").exists()   # writable staging name dropped


def test_active_bytes_changed_after_verify_is_refused(tmp_path, monkeypatch):
    """If the active file's bytes are altered after verification (so they no longer match the receipt digest),
    install refuses to report success and rolls back to last-good."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"GOOD")

    def fake_shell(cmd, dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"NEW")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry, "_probe", lambda *a, **k: (0, ""))

    real_managed = registry.managed_runtime_receipt
    calls = {"count": 0}

    def tampering_receipt(tool):
        result = real_managed(tool)
        calls["count"] += 1
        if calls["count"] == 1:
            active, receipt = result
            payload = active / receipt["tools"]["qtool"]["executable"]
            payload.chmod(0o700)
            payload.write_bytes(b"MUTATED-AFTER-VERIFY")
        return result

    monkeypatch.setattr(registry, "managed_runtime_receipt", tampering_receipt)

    assert install_one(_src_tool(), _sink) is False
    assert dest.read_bytes() == b"GOOD"                        # active digest != receipt -> refused, rolled back


def test_jxscout_consumers_declare_one_shared_lock_key():
    from quarry_recon.registry import load_tools
    ts = {t.bin: t for t in load_tools()}
    assert ts["jxscout-chunks"].lock_key == ts["jxscout-ast"].lock_key == "jxscout-tree"


def test_shared_lock_key_serializes_both_jxscout_consumers(tmp_path, monkeypatch):
    """A held lock on the SHARED resource key blocks the other consumer of the same tree (not just the same
    bin), so jxscout-chunks and jxscout-ast cannot race on ~/.local/share/quarry/jxscout."""
    monkeypatch.setenv("HOME", str(tmp_path))
    stage_dir = _bindir(tmp_path) / ".stage"
    stage_dir.mkdir(parents=True)
    held = os.open(str(stage_dir / ".jxscout-tree.installing.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setattr(registry, "run_shell",
                        lambda *a, **k: pytest.fail("ran a jxscout install under a held shared-resource lock"))
    t = Tool(bin="jxscout-ast", phase="crawl", role="ast", runtime="source", ref="deadbeef",
             install="stage {ref} {bin}", lock_key="jxscout-tree", capability="jxscout-ast --version")
    try:
        assert install_one(t, _sink) is False
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)


def test_shared_lock_reinstall_revalidates_every_retained_companion(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    one = Tool(bin="pair-one", phase="crawl", role="one", runtime="source", ref="one-ref",
               install="stage {ref} {bin}", lock_key="pair-tree")
    two = Tool(bin="pair-two", phase="crawl", role="two", runtime="source", ref="two-ref",
               install="stage {ref} {bin}", lock_key="pair-tree")
    expected = {"pair-one": b"ONE", "pair-two": b"TWO"}
    corrupt_companion = {"value": False}

    def shell(_cmd, _dry):
        tool = registry._install_context.tool
        home = Path(registry._install_context.environment["HOME"])
        stage = home / ".local" / "bin" / ".stage" / tool.bin
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(expected[tool.bin])
        if corrupt_companion["value"]:
            companion = home / ".local" / "bin" / "pair-two"
            companion.write_bytes(b"BROKEN")
        return 0, ""

    def probe(tool, executable, _environment):
        return executable.read_bytes() == expected[tool.bin]

    bindir = _bindir(tmp_path)
    monkeypatch.setattr(registry, "run_shell", shell)
    monkeypatch.setattr(registry, "_probe_candidate", probe)
    monkeypatch.setattr(registry, "load_tools", lambda: [one, two])
    monkeypatch.setattr(registry.shutil, "which", lambda name: str(bindir / name))

    assert install_one(one, _sink) is True
    assert install_one(two, _sink) is True
    prior_one, prior_two = (bindir / "pair-one").read_bytes(), (bindir / "pair-two").read_bytes()

    corrupt_companion["value"] = True
    assert install_one(one, _sink) is False
    assert (bindir / "pair-one").read_bytes() == prior_one
    assert (bindir / "pair-two").read_bytes() == prior_two


@pytest.mark.parametrize("fault", [OSError("after-effect"), KeyboardInterrupt("cancel")])
def test_current_pointer_replace_after_effect_restores_last_good(
        tmp_path, monkeypatch, fault):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    payload = {"value": b"GOOD"}

    def shell(_cmd, _dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(payload["value"])
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", shell)
    monkeypatch.setattr(registry, "_probe_candidate", lambda *_args: True)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: str(dest))
    assert install_one(_src_tool(), _sink) is True
    old_active = registry.managed_runtime_receipt(_src_tool())[0]
    payload["value"] = b"NEW"
    real_replace = registry.os.replace

    def land_then_raise(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if Path(destination).name == "current" and Path(source).name.startswith(".current-"):
            raise fault
        return result

    monkeypatch.setattr(registry.os, "replace", land_then_raise)
    if isinstance(fault, Exception):
        assert install_one(_src_tool(), _sink) is False
    else:
        with pytest.raises(type(fault)):
            install_one(_src_tool(), _sink)
    assert registry.managed_runtime_receipt(_src_tool())[0] == old_active
    assert dest.read_bytes() == b"GOOD"


def test_activation_return_boundary_cancellation_keeps_committed_candidate(
        tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"

    def shell(_cmd, _dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"COMMITTED")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", shell)
    monkeypatch.setattr(registry, "_probe_candidate", lambda *_args: True)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: str(dest))
    real_activate = registry._activate_candidate

    def activate_then_cancel(*args, **kwargs):
        real_activate(*args, **kwargs)
        raise KeyboardInterrupt("after activation returned")

    monkeypatch.setattr(registry, "_activate_candidate", activate_then_cancel)
    with pytest.raises(KeyboardInterrupt):
        install_one(_src_tool(), _sink)
    active, receipt = registry.managed_runtime_receipt(_src_tool())
    assert (active / receipt["tools"]["qtool"]["executable"]).read_bytes() == b"COMMITTED"
    assert dest.read_bytes() == b"COMMITTED"


def test_postcommit_backup_cleanup_fault_keeps_new_active_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"

    def shell(_cmd, _dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"COMMITTED")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", shell)
    monkeypatch.setattr(registry, "_probe_candidate", lambda *_args: True)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: str(dest))
    real_discard = registry._discard_candidate

    def cleanup_fault(path):
        if Path(path).name.startswith(".rollback-"):
            raise registry._RollbackError("injected postcommit cleanup fault", Path(path))
        return real_discard(path)

    monkeypatch.setattr(registry, "_discard_candidate", cleanup_fault)
    messages = []
    assert install_one(_src_tool(), messages.append) is False
    active, receipt = registry.managed_runtime_receipt(_src_tool())
    assert (active / receipt["tools"]["qtool"]["executable"]).read_bytes() == b"COMMITTED"
    assert dest.read_bytes() == b"COMMITTED"
    assert any("activation committed" in message for message in messages)


@pytest.mark.parametrize("fault", [OSError("echo fault"), KeyboardInterrupt("echo cancellation")])
def test_postcommit_reporting_fault_never_discards_active_candidate(
        tmp_path, monkeypatch, fault):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"

    def shell(_cmd, _dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(b"COMMITTED")
        return 0, ""

    calls = {"count": 0}

    def echo(_message):
        calls["count"] += 1
        if calls["count"] == 1:
            raise fault

    monkeypatch.setattr(registry, "run_shell", shell)
    monkeypatch.setattr(registry, "_probe_candidate", lambda *_args: True)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: str(dest))
    if isinstance(fault, Exception):
        assert install_one(_src_tool(), echo) is False
    else:
        with pytest.raises(type(fault)):
            install_one(_src_tool(), echo)
    assert dest.read_bytes() == b"COMMITTED"
    assert registry.managed_runtime_receipt(_src_tool()) is not None


@pytest.mark.parametrize("fault", [OSError("fsync fault"), KeyboardInterrupt("fsync cancellation")])
def test_payload_durability_fault_precedes_activation_and_preserves_last_good(
        tmp_path, monkeypatch, fault):
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = _bindir(tmp_path) / "qtool"
    payload = {"value": b"GOOD"}

    def shell(_cmd, _dry):
        stage = _candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_bytes(payload["value"])
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", shell)
    monkeypatch.setattr(registry, "_probe_candidate", lambda *_args: True)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: str(dest))
    assert install_one(_src_tool(), _sink) is True
    old_active = registry.managed_runtime_receipt(_src_tool())[0]
    payload["value"] = b"NEW"
    monkeypatch.setattr(
        registry, "_durably_settle_candidate_payload",
        lambda _candidate: (_ for _ in ()).throw(fault),
    )
    if isinstance(fault, Exception):
        assert install_one(_src_tool(), _sink) is False
    else:
        with pytest.raises(type(fault)):
            install_one(_src_tool(), _sink)
    assert registry.managed_runtime_receipt(_src_tool())[0] == old_active
    assert dest.read_bytes() == b"GOOD"


def test_probe_keeps_verified_fd_open_for_the_child(monkeypatch):
    """_probe(pass_fd=N) inherits fd N into the child via pass_fds (so /proc/self/fd/N resolves there); with
    no pass_fd it sets none. This is the plumbing the staged capability probe depends on."""
    captured = {}

    class R:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured.clear()
        captured.update(kwargs)
        return R()

    monkeypatch.setattr(registry.subprocess, "run", fake_run)
    registry._probe("some-cmd", pass_fd=7)
    assert captured.get("pass_fds") == (7,)
    registry._probe("some-cmd")
    assert "pass_fds" not in captured
