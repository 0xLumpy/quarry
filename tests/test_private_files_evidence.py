from __future__ import annotations

import copy
import inspect
import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

from quarry_recon import private_files_evidence as private_files
from quarry_recon import privfs


pytestmark = pytest.mark.offline
_CANDIDATE = "sha256:" + "a" * 64


def _open_fds() -> set[int]:
    return {int(entry) for entry in os.listdir("/proc/self/fd") if entry.isdigit()}


def _secure(directory: Path) -> Path:
    os.chmod(directory, privfs.DIR_MODE)
    return directory


def _remembered_collection_authority(tmp_path: Path, roots: list[Path]):
    def allocate() -> private_files._CollectionRootAuthority:
        root = Path(tempfile.mkdtemp(prefix="quarry-private-files-test-", dir=tmp_path))
        os.chmod(root, privfs.DIR_MODE)
        roots.append(root)
        parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        parent = os.fstat(parent_fd)
        held = os.fstat(root_fd)
        return private_files._CollectionRootAuthority(
            name=root.name,
            parent_fd=parent_fd,
            root_fd=root_fd,
            parent_identity=private_files._collection_directory_identity(parent),
            identity=private_files._collection_directory_identity(held),
        )
    return allocate


def test_frozen_roster_matches_committed_bytes_and_measured_producer_recomputes_every_row():
    roster = Path("release/evidence/private-files-case-roster-v1.json").read_bytes()
    assert roster == private_files.canonical_json_bytes(private_files.case_roster())
    assert private_files.read_case_roster(roster) == private_files.case_roster()
    artifacts = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)
    assert set(artifacts) == {"filesystem-trace", "mode-owner-symlink-matrix"}
    for name, artifact in artifacts.items():
        assert private_files.verify_artifact(artifact, artifact_kind=name) is artifact
        assert all(row["post"] is not None for row in artifact["observations"])
        assert artifact["disposition"] == "source_substrate"


def test_case_roster_reader_requires_exact_canonical_named_specs():
    roster = private_files.case_roster()
    roster["cases"][0]["operation"] = "substituted_operation"
    with pytest.raises(private_files.PrivateFilesEvidenceError, match="frozen"):
        private_files.read_case_roster(private_files.canonical_json_bytes(roster))


def test_source_substrate_is_measured_but_cannot_launder_itself_into_acceptance():
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["mode-owner-symlink-matrix"]
    with pytest.raises(TypeError):
        private_files.verify_artifact(artifact, accepting=True)
    artifact["disposition"] = "pass"
    artifact["open_reasons"] = []
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)


def test_private_clock_brackets_collection_and_production_receipts_cover_every_frozen_umask(monkeypatch):
    ticks = iter(("2026-08-21T10:00:00Z", "2026-08-21T10:00:01Z"))
    monkeypatch.setattr(private_files, "_utc_now", lambda: next(ticks))
    artifacts = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)
    trace = artifacts["filesystem-trace"]
    assert trace["started_at"] == "2026-08-21T10:00:00Z"
    assert trace["finished_at"] == "2026-08-21T10:00:01Z"
    assert all(row["tested_umasks"] == [0, 2, 18, 63]
               for row in trace["observations"][:2])


def test_stale_private_clock_is_rejected_after_collection(monkeypatch):
    ticks = iter(("2026-08-21T10:00:01Z", "2026-08-21T10:00:00Z"))
    monkeypatch.setattr(private_files, "_utc_now", lambda: next(ticks))
    with pytest.raises(private_files.PrivateFilesEvidenceError, match="before it starts"):
        private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)


@pytest.mark.parametrize("mutate", [
    lambda artifact: artifact["observations"].pop(),
    lambda artifact: artifact["observations"][0].__setitem__("mutation", "created"),
    lambda artifact: artifact["observations"][0]["post"].__setitem__("kind", "file"),
])
def test_measured_rows_and_binding_cannot_be_forged(mutate):
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["mode-owner-symlink-matrix"]
    mutate(artifact)
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)


def test_public_creation_signatures_reject_mutable_receipt_injection(tmp_path):
    assert "_creation_receipt" not in str(inspect.signature(privfs.private_dir))
    assert "_creation_receipt" not in str(inspect.signature(privfs.open_private))
    before = _open_fds()
    with pytest.raises(TypeError):
        privfs.private_dir(tmp_path / "directory", _creation_receipt=[])
    with pytest.raises(TypeError):
        privfs.open_private(tmp_path / "file", _creation_receipt=[])
    assert _open_fds() == before


@pytest.mark.parametrize(("wrapper", "leaf_name"), [
    (privfs._private_dir_with_creation_receipt, "new-directory"),
    (privfs._open_private_with_creation_receipt, "new-file"),
])
def test_receipt_fstat_fault_quarantines_only_the_new_leaf(tmp_path, monkeypatch, wrapper, leaf_name):
    root, target = _secure(tmp_path), tmp_path / leaf_name
    real_fstat = privfs.os.fstat
    calls = 0

    def fail_receipt(fd):
        nonlocal calls
        calls += 1
        # Parent hardening is first; the second fstat is the actual just-created
        # descriptor receipt, before the evidence-only hardening check.
        if calls == 2:
            raise OSError("injected first-descriptor receipt failure")
        return real_fstat(fd)

    monkeypatch.setattr(privfs.os, "fstat", fail_receipt)
    with pytest.raises(OSError, match="receipt failure"):
        wrapper(target)
    assert not target.exists()
    assert any(item.name.startswith(".quarry-evidence-quarantine-") for item in root.iterdir())


@pytest.mark.parametrize(("wrapper", "leaf_name"), [
    (privfs._private_dir_with_creation_receipt, "harden-directory"),
    (privfs._open_private_with_creation_receipt, "harden-file"),
])
def test_post_create_hardening_fault_quarantines_only_the_new_leaf(tmp_path, monkeypatch, wrapper, leaf_name):
    root, target = _secure(tmp_path), tmp_path / leaf_name
    real_harden = privfs._harden_fd
    calls = 0

    def fail_leaf_hardening(fd, *, is_dir):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected post-create hardening failure")
        return real_harden(fd, is_dir=is_dir)

    monkeypatch.setattr(privfs, "_harden_fd", fail_leaf_hardening)
    with pytest.raises(OSError, match="post-create hardening"):
        wrapper(target)
    assert not target.exists()
    assert any(item.name.startswith(".quarry-evidence-quarantine-") for item in root.iterdir())


def test_fault_on_existing_leaf_never_rolls_back_or_truncates_preexisting_data(tmp_path, monkeypatch):
    root, target = _secure(tmp_path), tmp_path / "already-present"
    target.write_bytes(b"must survive")
    os.chmod(target, privfs.FILE_MODE)
    before = target.stat()
    real_harden = privfs._harden_fd
    calls = 0

    def fail_existing_leaf(fd, *, is_dir):
        nonlocal calls
        calls += 1
        if calls == 2:
            return False
        return real_harden(fd, is_dir=is_dir)

    monkeypatch.setattr(privfs, "_harden_fd", fail_existing_leaf)
    with pytest.raises(OSError, match="refusing a non-regular"):
        privfs._open_private_with_creation_receipt(target)
    after = target.stat()
    assert target.read_bytes() == b"must survive"
    assert (after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode)) == (
        before.st_dev, before.st_ino, stat.S_IMODE(before.st_mode),
    )
    assert not any(item.name.startswith(".quarry-evidence-quarantine-") for item in root.iterdir())


def test_unresolved_created_identity_has_typed_failure_and_cannot_yield_substrate(tmp_path, monkeypatch):
    root, target = _secure(tmp_path), tmp_path / "unresolved"
    real_fstat, real_stat = privfs.os.fstat, privfs.os.stat
    calls = 0

    def fail_receipt(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected receipt failure")
        return real_fstat(fd)

    def fail_fd_identity(path, *args, **kwargs):
        if isinstance(path, int):
            raise OSError("injected descriptor identity failure")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "fstat", fail_receipt)
    monkeypatch.setattr(privfs.os, "stat", fail_fd_identity)
    with pytest.raises(privfs.PrivatePathMutationUnresolved, match="mutation is unresolved"):
        privfs._open_private_with_creation_receipt(target)
    assert target.exists()  # uncertainty retains the leaf; no path is deleted on an unknown identity

    parent_pid = os.getpid()
    roots: list[Path] = []
    monkeypatch.setattr(private_files, "_new_collection_root_authority", _remembered_collection_authority(tmp_path, roots))
    child_calls = 0

    def fail_child_receipt(fd):
        nonlocal child_calls
        if os.getpid() != parent_pid:
            child_calls += 1
            # The child fchdirs to the pinned root, so its first evidence fstat
            # is the descriptor receipt itself rather than a pathname ancestor.
            if child_calls == 1:
                raise OSError("injected receipt failure")
        return real_fstat(fd)

    def fail_child_fd_identity(path, *args, **kwargs):
        if os.getpid() != parent_pid and isinstance(path, int):
            raise OSError("injected descriptor identity failure")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "fstat", fail_child_receipt)
    monkeypatch.setattr(privfs.os, "stat", fail_child_fd_identity)
    with pytest.raises(private_files.PrivateFilesEvidenceError, match="PrivatePathMutationUnresolved"):
        private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)
    assert roots and all(not item.exists() for item in roots)


def test_quarantine_uses_atomic_no_replace_and_preserves_a_planted_collision(tmp_path, monkeypatch):
    root, source = _secure(tmp_path), tmp_path / "created"
    source.write_bytes(b"owned evidence leaf")
    os.chmod(source, privfs.FILE_MODE)
    identity = privfs._evidence_leaf_identity(source.stat())
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    real_noreplace = privfs._renameat2_noreplace
    random_values = iter((b"\x11" * 16, b"\x22" * 16))
    planted: Path | None = None
    calls = 0

    def collide_before_atomic_move(source_parent, source_name, destination_parent, destination_name):
        nonlocal calls, planted
        calls += 1
        if calls == 1:
            planted = root / destination_name
            planted_fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                privfs.FILE_MODE,
                dir_fd=destination_parent,
            )
            try:
                os.write(planted_fd, b"planted collision")
            finally:
                os.close(planted_fd)
        return real_noreplace(source_parent, source_name, destination_parent, destination_name)

    monkeypatch.setattr(privfs.os, "urandom", lambda _size: next(random_values))
    monkeypatch.setattr(privfs, "_renameat2_noreplace", collide_before_atomic_move)
    monkeypatch.setattr(
        privfs.os, "rename", lambda *_args, **_kwargs: pytest.fail("replacing rename was used"),
    )
    try:
        privfs._evidence_quarantine_created_leaf(
            parent_fd, source.name, identity, components=(source.name,),
        )
    finally:
        os.close(parent_fd)

    first = root / f".quarry-evidence-quarantine-{(b'\x11' * 16).hex()}"
    second = root / f".quarry-evidence-quarantine-{(b'\x22' * 16).hex()}"
    assert calls == 2
    assert planted == first
    assert first.read_bytes() == b"planted collision"
    assert privfs._evidence_leaf_identity(second.stat()) == identity
    assert not source.exists()


def test_quarantine_without_atomic_no_replace_fails_typed_without_moving_source(tmp_path, monkeypatch):
    root, source = _secure(tmp_path), tmp_path / "created"
    source.write_bytes(b"owned evidence leaf")
    os.chmod(source, privfs.FILE_MODE)
    identity = privfs._evidence_leaf_identity(source.stat())
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def unavailable(*_args, **_kwargs):
        raise privfs.PrivatePathUnsupported("no atomic rename support")

    monkeypatch.setattr(privfs, "_renameat2_noreplace", unavailable)
    try:
        with pytest.raises(privfs.PrivatePathMutationUnresolved, match="could not reserve"):
            privfs._evidence_quarantine_created_leaf(
                parent_fd, source.name, identity, components=(source.name,),
            )
    finally:
        os.close(parent_fd)
    assert source.read_bytes() == b"owned evidence leaf"
    assert not list(root.glob(".quarry-evidence-quarantine-*"))


def test_collection_cleanup_uses_pinned_root_and_preserves_a_substituted_replacement(
    tmp_path, monkeypatch,
):
    roots: list[Path] = []
    monkeypatch.setattr(private_files, "_new_collection_root_authority", _remembered_collection_authority(tmp_path, roots))
    real_remove_tree = private_files._remove_private_tree_fd
    substituted = False
    replacement_identity: tuple[int, int] | None = None
    displaced = tmp_path / "displaced-owned-root"

    def clean_then_substitute(directory_fd):
        nonlocal substituted, replacement_identity
        real_remove_tree(directory_fd)
        if roots and not substituted:
            held = os.fstat(directory_fd)
            original = roots[0].stat()
            if (held.st_dev, held.st_ino) == (original.st_dev, original.st_ino):
                # The original is now empty but still pinned by the authority fd.
                # Replace its name with another same-UID directory exactly before
                # the final name-to-removal transition.
                os.rename(roots[0], displaced)
                roots[0].mkdir(mode=privfs.DIR_MODE)
                replacement = roots[0].stat()
                replacement_identity = replacement.st_dev, replacement.st_ino
                substituted = True

    monkeypatch.setattr(private_files, "_remove_private_tree_fd", clean_then_substitute)
    with pytest.raises(private_files.PrivateFilesEvidenceError, match="root cleanup failed"):
        private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)

    assert substituted and replacement_identity is not None
    replacement = roots[0].stat()
    assert (replacement.st_dev, replacement.st_ino) == replacement_identity
    # The collection cannot return an artifact after its name claim changed;
    # critically, it did not delete the replacement or strand the owned inode.
    assert roots[0].is_dir()
    assert not displaced.exists()


def test_collection_authority_claim_precedes_the_former_path_return_boundary(tmp_path, monkeypatch):
    assert not hasattr(private_files, "_new_collection_root")
    assert not hasattr(private_files, "_claim_collection_root")
    monkeypatch.setattr(private_files.tempfile, "gettempdir", lambda: os.fspath(tmp_path))
    real_allocate = private_files._new_collection_root_authority
    displaced = tmp_path / "displaced-owned-root"
    replacement_identity: tuple[int, int] | None = None
    replacement_name: str | None = None

    def allocate_then_substitute() -> private_files._CollectionRootAuthority:
        nonlocal replacement_identity, replacement_name
        authority = real_allocate()
        # This is the former handoff point: creation has completed but collection
        # has not started.  The allocator returns a descriptor claim, not a path.
        os.rename(
            authority.name, displaced,
            src_dir_fd=authority.parent_fd, dst_dir_fd=authority.parent_fd,
        )
        os.mkdir(authority.name, privfs.DIR_MODE, dir_fd=authority.parent_fd)
        replacement = os.stat(authority.name, dir_fd=authority.parent_fd, follow_symlinks=False)
        replacement_name = authority.name
        replacement_identity = replacement.st_dev, replacement.st_ino
        return authority

    monkeypatch.setattr(private_files, "_new_collection_root_authority", allocate_then_substitute)
    with pytest.raises(private_files.PrivateFilesEvidenceError, match="root cleanup failed"):
        private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)

    assert replacement_identity is not None and replacement_name is not None
    replacement = (tmp_path / replacement_name).stat()
    assert (replacement.st_dev, replacement.st_ino) == replacement_identity
    assert not displaced.exists()


@pytest.mark.parametrize("fault_mode", ["before", "after", "reuse"])
def test_child_confinement_settles_ambiguous_close_without_artifact_or_stranded_root(
    tmp_path, monkeypatch, fault_mode,
):
    roots: list[Path] = []
    monkeypatch.setattr(private_files, "_new_collection_root_authority", _remembered_collection_authority(tmp_path, roots))
    parent_pid = os.getpid()
    real_close = privfs.os.close
    attempts_path = tmp_path / f"close-{fault_mode}.log"
    before = _open_fds()
    log_fd = private_files._PARENT_OPEN(
        attempts_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, privfs.FILE_MODE,
    )
    seen_pids: list[int] = []
    real_waitpid = private_files._PARENT_WAITPID

    def record_waitpid(pid, options):
        result = real_waitpid(pid, options)
        if pid > 0:
            seen_pids.append(pid)
        return result

    monkeypatch.setattr(private_files, "_PARENT_WAITPID", record_waitpid)
    # Arm from the evidence-only receipt handoff itself, rather than from a
    # pathname-depth-dependent close count.  This remains exact when the child
    # enters the pinned collection descriptor and uses relative production paths.
    real_finish = privfs._evidence_finish_created_leaf
    armed_fd: int | None = None

    def arm_leaf_close(*args, **kwargs):
        nonlocal armed_fd
        if os.getpid() != parent_pid:
            armed_fd = kwargs["leaf_fd"]
        return real_finish(*args, **kwargs)

    monkeypatch.setattr(privfs, "_evidence_finish_created_leaf", arm_leaf_close)
    calls = 0
    faulted = False

    def ambiguous_close(fd):
        nonlocal calls, faulted
        if os.getpid() == parent_pid:
            return real_close(fd)
        calls += 1
        private_files._PARENT_WRITE(log_fd, f"attempt:{calls}:{fd}\n".encode())
        if fd == armed_fd and not faulted:
            faulted = True
            if fault_mode in {"after", "reuse"}:
                real_close(fd)
            if fault_mode == "reuse":
                reused = os.open("/dev/null", os.O_RDONLY)
                private_files._PARENT_WRITE(log_fd, f"reuse:{reused}\n".encode())
            raise OSError(f"injected ambiguous close ({fault_mode})")
        return real_close(fd)

    monkeypatch.setattr(privfs.os, "close", ambiguous_close)
    try:
        with pytest.raises(private_files.PrivateFilesEvidenceError, match="PrivatePathMutationUnresolved"):
            private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)
    finally:
        private_files._PARENT_CLOSE(log_fd)
    assert _open_fds() == before
    assert roots and all(not root.exists() for root in roots)
    assert seen_pids
    with pytest.raises(ChildProcessError):
        os.waitpid(seen_pids[0], os.WNOHANG)
    attempts = attempts_path.read_text().splitlines()
    assert any(line.startswith("attempt:") for line in attempts)
    if fault_mode == "reuse":
        reuse_index = next(index for index, line in enumerate(attempts) if line.startswith("reuse:"))
        reused = int(attempts[reuse_index].split(":", 1)[1])
        faulted_fd = int(attempts[reuse_index - 1].rsplit(":", 1)[1])
        assert reused == faulted_fd
        later_attempts = [int(line.rsplit(":", 1)[1]) for line in attempts[reuse_index + 1:]
                          if line.startswith("attempt:")]
        assert faulted_fd not in later_attempts


def test_existing_parent_and_missing_leaf_have_one_immutable_creation_receipt(tmp_path):
    root = _secure(tmp_path)
    parent = privfs.private_dir(root / "parent")
    receipt = privfs._private_dir_with_creation_receipt(parent / "leaf")
    assert receipt is not None
    with pytest.raises((AttributeError, TypeError)):
        receipt.stat = receipt.stat
    file_receipt = privfs._open_private_with_creation_receipt(parent / "file")
    assert file_receipt is not None
    assert stat.S_ISREG(file_receipt.stat.st_mode)
    nested_receipt = privfs._private_dir_with_creation_receipt(root / "missing-parent" / "leaf")
    assert nested_receipt is not None
    assert (root / "missing-parent").is_dir()
    assert stat.S_IMODE((root / "missing-parent" / "leaf").stat().st_mode) == privfs.DIR_MODE


def test_refusal_error_is_positive_except_foreign_unsupported_and_unsupported_pair_is_exact():
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["mode-owner-symlink-matrix"]
    for row in artifact["observations"][:2]:
        assert type(row["error"]) is int and row["error"] > 0
        assert row["error_detail"]["class"] == "PrivatePathUnsafe"
    artifact["observations"][0]["error"] = None
    artifact["observations"][0]["error_detail"] = {"class": "unsupported", "components": []}
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["mode-owner-symlink-matrix"]
    foreign = artifact["observations"][2]
    if foreign["error"] is None:
        assert foreign["error_detail"] == {"class": "unsupported", "components": []}
        foreign["error_detail"] = {"class": "unsupported", "components": ["forged"]}
        with pytest.raises(private_files.PrivateFilesEvidenceError):
            private_files.verify_artifact(artifact)


def test_huge_integer_and_created_post_substitution_are_rejected():
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["filesystem-trace"]
    artifact["collector_uid"] = 1 << 63
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["filesystem-trace"]
    artifact["observations"][0]["post"]["uid"] += 1
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)


def test_malformed_unsupported_and_roster_order_are_rejected():
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["mode-owner-symlink-matrix"]
    artifact["observations"][2]["error"] = 1
    artifact["observations"][2]["error_detail"] = {"class": "unsupported", "components": []}
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["mode-owner-symlink-matrix"]
    artifact["observations"] = list(reversed(artifact["observations"]))
    with pytest.raises(private_files.PrivateFilesEvidenceError):
        private_files.verify_artifact(artifact)


def test_json_schema_freezes_structure_and_manual_verifier_covers_dynamic_stat_equality():
    jsonschema = pytest.importorskip("jsonschema")
    roster_schema = json.loads(Path("release/evidence/schemas/private-files-case-roster-v1.schema.json").read_text())
    roster_validator = jsonschema.Draft202012Validator(roster_schema)
    roster = private_files.case_roster()
    roster_validator.validate(roster)
    roster_mutation = copy.deepcopy(roster)
    roster_mutation["cases"][3]["lane"] = "H0-hermetic"
    assert not roster_validator.is_valid(roster_mutation)

    for name in ("filesystem-trace", "mode-owner-symlink-matrix"):
        artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)[name]
        schema = json.loads(Path(f"release/evidence/schemas/private-files-{name}-v1.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(artifact)
        for mutate in (
            lambda value: value.__setitem__("lane", "H1-tool-integration" if name == "filesystem-trace" else "H0-hermetic"),
            lambda value: value["observations"][0].__setitem__("case_id", "substituted-case"),
            lambda value: value["observations"][0].__setitem__(
                "expected", "refused" if name == "filesystem-trace" else "created",
            ),
            lambda value: value["observations"][0]["post"].__setitem__("mode", 0o644),
        ):
            broken = copy.deepcopy(artifact)
            mutate(broken)
            assert not validator.is_valid(broken)
            with pytest.raises(private_files.PrivateFilesEvidenceError):
                private_files.verify_artifact(broken)
        # JSON Schema deliberately cannot say post.uid == collector_uid or
        # post == pre.  The manual semantic verifier makes that comparison.
        semantic_only = copy.deepcopy(artifact)
        semantic_only["observations"][0]["post"]["uid"] += 1
        assert validator.is_valid(semantic_only)
        with pytest.raises(private_files.PrivateFilesEvidenceError):
            private_files.verify_artifact(semantic_only)
        too_wide = copy.deepcopy(artifact)
        too_wide["observations"][0]["post"]["mode"] = 0o10000
        assert not validator.is_valid(too_wide)


def test_artifact_json_reader_requires_canonical_line():
    artifact = private_files.build_source_substrate(candidate_identity_digest=_CANDIDATE)["filesystem-trace"]
    body = private_files.canonical_json_bytes(artifact)
    assert private_files.read_artifact(body) == artifact
    with pytest.raises(private_files.PrivateFilesEvidenceError, match="canonical"):
        private_files.read_artifact(json.dumps(artifact).encode() + b"\n")
