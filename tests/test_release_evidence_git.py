"""Real-Git boundary checks for the candidate identity collector."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from quarry_recon import release_evidence as evidence

pytestmark = [pytest.mark.integration, pytest.mark.requires_tool]


GIT = os.fspath(Path(shutil.which("git") or pytest.skip("Git is required", allow_module_level=True)).resolve())


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [GIT, "-C", os.fspath(repository), *arguments],
        capture_output=True,
        check=True,
        text=True,
    )
    return completed.stdout.strip()


def _candidate_repository(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[1]
    repository = tmp_path / "candidate"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Quarry Test")
    _git(repository, "config", "user.email", "quarry-test@example.invalid")
    for relative in sorted(set(evidence.DEFAULT_IDENTITY_INPUTS.values())):
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source / relative).read_bytes())
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "candidate")
    return repository


def test_real_git_candidate_is_repeatable_and_ignored_notes_stay_outside_evidence(tmp_path):
    repository = _candidate_repository(tmp_path)
    index = repository / _git(repository, "rev-parse", "--git-path", "index")
    index_before = (index.read_bytes(), index.stat().st_mtime_ns)
    first = evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)
    second = evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)
    assert (index.read_bytes(), index.stat().st_mtime_ns) == index_before
    assert first == second
    assert first["git_commit"] == _git(repository, "rev-parse", "HEAD")
    assert first["git_tree"] == _git(repository, "rev-parse", "HEAD^{tree}")
    assert first["dirty"] is False
    assert first["package_version"] == "0.3.9"
    assert os.fspath(repository).encode() not in evidence.canonical_json_bytes(first)

    with (repository / ".git" / "info" / "exclude").open("a", encoding="utf-8") as stream:
        stream.write("notes/\n")
    notes = repository / "notes" / "private.md"
    notes.parent.mkdir()
    notes.write_text("outside release evidence\n", encoding="utf-8")
    assert evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT) == first


def test_real_git_nonignored_change_refuses_collection(tmp_path):
    repository = _candidate_repository(tmp_path)
    (repository / "unexpected.txt").write_text("not part of the candidate\n", encoding="utf-8")
    with pytest.raises(evidence.EvidenceError, match="dirty"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_real_git_index_visibility_flags_cannot_hide_a_tracked_change(tmp_path, flag):
    repository = _candidate_repository(tmp_path)
    _git(repository, "update-index", flag, "pyproject.toml")
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "quarry-recon"\nversion = "9.9.9"\n',
        encoding="utf-8",
    )
    assert _git(repository, "status", "--porcelain=v1") == ""
    with pytest.raises(evidence.EvidenceError, match="visibility"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable-hook boundary")
def test_real_git_fsmonitor_cannot_hide_a_tracked_change(tmp_path):
    repository = _candidate_repository(tmp_path)
    hook = repository / ".git" / "hooks" / "release-evidence-fsmonitor"
    hook.write_text("#!/bin/sh\nprintf 'token\\0'\n", encoding="utf-8")
    hook.chmod(0o700)
    _git(repository, "config", "core.fsmonitor", os.fspath(hook))
    assert _git(repository, "status", "--porcelain=v1") == ""
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "quarry-recon"\nversion = "9.9.9"\n',
        encoding="utf-8",
    )
    assert _git(repository, "status", "--porcelain=v1") == ""
    with pytest.raises(evidence.EvidenceError, match="dirty"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode boundary")
def test_real_git_local_filemode_config_cannot_hide_a_mode_change(tmp_path):
    repository = _candidate_repository(tmp_path)
    _git(repository, "config", "core.filemode", "false")
    (repository / "pyproject.toml").chmod(0o755)
    assert _git(repository, "status", "--porcelain=v1") == ""
    with pytest.raises(evidence.EvidenceError, match="dirty"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink boundary")
def test_real_git_local_symlink_config_cannot_hide_a_type_change(tmp_path):
    repository = _candidate_repository(tmp_path)
    link = repository / "tracked-link"
    link.symlink_to("target")
    _git(repository, "add", "tracked-link")
    _git(repository, "commit", "-q", "-m", "add symlink")
    _git(repository, "config", "core.symlinks", "false")
    link.unlink()
    link.write_text("target", encoding="utf-8")
    assert _git(repository, "status", "--porcelain=v1") == ""
    with pytest.raises(evidence.EvidenceError, match="dirty"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink boundary")
def test_real_git_identity_input_must_be_a_regular_blob_not_a_symlink(tmp_path):
    repository = _candidate_repository(tmp_path)
    path = repository / "pyproject.toml"
    target = path.read_text(encoding="utf-8")
    path.unlink()
    path.symlink_to(target)
    _git(repository, "add", "pyproject.toml")
    _git(repository, "commit", "-q", "-m", "replace metadata with symlink")
    with pytest.raises(evidence.EvidenceError, match="regular tracked blob"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX stat-cache boundary")
def test_real_git_local_stat_cache_config_cannot_hide_same_size_content(tmp_path):
    repository = _candidate_repository(tmp_path)
    path = repository / "pyproject.toml"
    initial = path.stat()
    old_ns = initial.st_mtime_ns - 20_000_000_000
    os.utime(path, ns=(old_ns, old_ns))
    _git(repository, "update-index", "--refresh")
    before = path.stat()
    original = path.read_bytes()
    changed = bytes([original[0] ^ 1]) + original[1:]
    _git(repository, "config", "core.trustctime", "false")
    _git(repository, "config", "core.checkStat", "minimal")
    path.write_bytes(changed)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert _git(repository, "status", "--porcelain=v1") == ""
    with pytest.raises(evidence.EvidenceError, match="do not match"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


@pytest.mark.skipif(os.name != "posix", reason="POSIX Git filter boundary")
def test_real_git_clean_filter_cannot_rewrite_or_execute_during_raw_comparison(tmp_path):
    repository = _candidate_repository(tmp_path)
    marker = tmp_path / "filter-executed"
    filter_program = tmp_path / "mask-filter"
    path = repository / "pyproject.toml"
    original = path.read_bytes()
    committed_first = chr(original[0])
    filter_program.write_text(
        "#!/bin/sh\n"
        f": > {shlex.quote(os.fspath(marker))}\n"
        "first=1\n"
        "while IFS= read -r line || [ -n \"$line\" ]; do\n"
        "  if [ \"$first\" -eq 1 ]; then\n"
        f"    printf '%s%s\\n' {shlex.quote(committed_first)} \"${{line#?}}\"\n"
        "    first=0\n"
        "  else\n"
        "    printf '%s\\n' \"$line\"\n"
        "  fi\n"
        "done\n",
        encoding="utf-8",
    )
    filter_program.chmod(0o700)
    (repository / ".git" / "info" / "attributes").write_text(
        "pyproject.toml filter=mask\n",
        encoding="utf-8",
    )
    _git(repository, "config", "filter.mask.clean", shlex.quote(os.fspath(filter_program)))
    path.write_bytes(b"X" + original[1:])
    assert _git(repository, "status", "--porcelain=v1") == ""
    assert marker.exists()
    marker.unlink()
    with pytest.raises(evidence.EvidenceError, match="bytes do not match"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)
    assert not marker.exists()


def test_real_git_submodule_index_flag_cannot_hide_a_tracked_change(tmp_path):
    child_source = tmp_path / "child-source"
    child_source.mkdir()
    _git(child_source, "init", "-q")
    _git(child_source, "config", "user.name", "Quarry Test")
    _git(child_source, "config", "user.email", "quarry-test@example.invalid")
    (child_source / "f").write_text("committed\n", encoding="utf-8")
    _git(child_source, "add", "f")
    _git(child_source, "commit", "-q", "-m", "child")

    repository = _candidate_repository(tmp_path)
    _git(
        repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        os.fspath(child_source),
        "vendor/child",
    )
    _git(repository, "commit", "-q", "-am", "add child")
    child = repository / "vendor" / "child"
    _git(child, "update-index", "--assume-unchanged", "f")
    (child / "f").write_text("ambient change\n", encoding="utf-8")
    assert _git(child, "status", "--porcelain=v1") == ""
    assert _git(repository, "status", "--porcelain=v1", "--ignore-submodules=none") == ""
    with pytest.raises(evidence.EvidenceError, match="visibility"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


def test_real_git_submodule_cannot_redirect_its_worktree_outside_the_candidate(tmp_path):
    child_source = tmp_path / "redirect-child-source"
    child_source.mkdir()
    _git(child_source, "init", "-q")
    _git(child_source, "config", "user.name", "Quarry Test")
    _git(child_source, "config", "user.email", "quarry-test@example.invalid")
    (child_source / "f").write_text("committed\n", encoding="utf-8")
    _git(child_source, "add", "f")
    _git(child_source, "commit", "-q", "-m", "child")

    repository = _candidate_repository(tmp_path)
    _git(
        repository,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        os.fspath(child_source),
        "vendor/child",
    )
    _git(repository, "commit", "-q", "-am", "add child")
    child = repository / "vendor" / "child"
    external = tmp_path / "redirected-worktree"
    external.mkdir()
    (external / "f").write_text("committed\n", encoding="utf-8")
    _git(child, "config", "core.worktree", os.fspath(external))
    (child / "f").write_text("ambient change\n", encoding="utf-8")
    assert Path(_git(child, "rev-parse", "--show-toplevel")).resolve() == external.resolve()
    assert _git(child, "status", "--porcelain=v1") == ""
    with pytest.raises(evidence.EvidenceError, match="expected checkout"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


def test_real_git_superproject_cannot_redirect_the_requested_candidate(tmp_path):
    repository = _candidate_repository(tmp_path)
    external = tmp_path / "redirected-superproject"
    shutil.copytree(repository, external, ignore=shutil.ignore_patterns(".git"))
    _git(repository, "config", "core.worktree", os.fspath(external))
    assert Path(_git(repository, "rev-parse", "--show-toplevel")).resolve() == external.resolve()
    with pytest.raises(evidence.EvidenceError, match="requested candidate"):
        evidence.collect_candidate_identity(repository, "0.3.10", git_executable=GIT)


def test_real_git_nested_repository_cannot_redirect_to_an_ancestor_candidate(tmp_path):
    repository = _candidate_repository(tmp_path)
    with (repository / ".git" / "info" / "exclude").open("a", encoding="utf-8") as stream:
        stream.write("nested/\n")
    nested = repository / "nested"
    nested.mkdir()
    _git(nested, "init", "-q")
    _git(nested, "config", "core.worktree", os.fspath(repository))
    assert Path(_git(nested, "rev-parse", "--show-toplevel")).resolve() == repository.resolve()
    with pytest.raises(evidence.EvidenceError, match="different Git directory"):
        evidence.collect_candidate_identity(nested, "0.3.10", git_executable=GIT)
