"""Measured C-PRIVATE-FILES evidence with an explicitly open local producer."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import select
import signal
import stat
import tempfile
import time
from datetime import datetime, timezone
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from . import privfs

TRACE_SCHEMA = "quarry.private-files-filesystem-trace.v1"
MATRIX_SCHEMA = "quarry.private-files-mode-owner-symlink-matrix.v1"
ROSTER_SCHEMA = "quarry.private-files-case-roster.v1"
GATE_ID, RELEASE, MAX_BYTES = "C-PRIVATE-FILES", "0.3.10", 1024 * 1024
_DIGEST, _TOKEN = re.compile(r"sha256:[0-9a-f]{64}\Z"), re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_MAX_INT = (1 << 63) - 1
_OPEN_REASONS = ("unsigned_evidence_instance", "unaccepted_release_evidence")
_COLLECTION_TIMEOUT_SECONDS = 10.0

# The collector deliberately saves its parent-side controls before tests (or an
# embedding process) alter ``privfs.os.close``.  The child still calls the live
# privfs operations, so fault injection exercises the production descriptor path.
_PARENT_CLOSE = os.close
_PARENT_FCHDIR = os.fchdir
_PARENT_FCHMOD = os.fchmod
_PARENT_FSTAT = os.fstat
_PARENT_FORK = os.fork
_PARENT_GETEUID = os.geteuid
_PARENT_KILL = os.kill
_PARENT_KILLPG = os.killpg
_PARENT_LISTDIR = os.listdir
_PARENT_MKDIR = os.mkdir
_PARENT_OPEN = os.open
_PARENT_PIPE = os.pipe
_PARENT_PIPE2 = getattr(os, "pipe2", None)
_PARENT_READ = os.read
_PARENT_RMDIR = os.rmdir
_PARENT_SETSID = os.setsid
_PARENT_SET_INHERITABLE = os.set_inheritable
_PARENT_STAT = os.stat
_PARENT_UNLINK = os.unlink
_PARENT_URANDOM = os.urandom
_PARENT_WAITPID = os.waitpid
_PARENT_WRITE = os.write

# Named operation specifications; collectors never supply their own roster.
_CASES = (
    ("h0-create-directory-umask", "H0-hermetic", "filesystem-trace", "create_directory", "created"),
    ("h0-create-file-umask", "H0-hermetic", "filesystem-trace", "create_file", "created"),
    ("h0-existing-mode-refusal", "H0-hermetic", "filesystem-trace", "existing_unsafe_mode", "refused"),
    ("h1-directory-symlink-refusal", "H1-tool-integration", "mode-owner-symlink-matrix", "directory_symlink", "refused"),
    ("h1-file-symlink-refusal", "H1-tool-integration", "mode-owner-symlink-matrix", "file_symlink", "refused"),
    ("h1-foreign-owner-refusal", "H1-tool-integration", "mode-owner-symlink-matrix", "foreign_owner", "refused"),
)
_ARTIFACTS = (("filesystem-trace", TRACE_SCHEMA, "H0-hermetic"),
              ("mode-owner-symlink-matrix", MATRIX_SCHEMA, "H1-tool-integration"))


class PrivateFilesEvidenceError(ValueError):
    """An artifact is malformed, inconsistent, or overclaims acceptance."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise PrivateFilesEvidenceError("artifact is not canonical JSON") from exc


def raw_sha256(body: bytes) -> str:
    if type(body) is not bytes:
        raise PrivateFilesEvidenceError("digest input must be exact bytes")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def case_roster() -> dict:
    return {"cases": [{"artifact_kind": artifact, "expected": expected, "id": case_id,
                        "lane": lane, "operation": operation}
                       for case_id, lane, artifact, operation, expected in _CASES],
            "gate_id": GATE_ID, "release": RELEASE, "schema_version": ROSTER_SCHEMA}


def roster_digest() -> str:
    return raw_sha256(canonical_json_bytes(case_roster()))


def _stat(path: Path) -> dict | None:
    try:
        value = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return {"device": value.st_dev, "gid": value.st_gid, "inode": value.st_ino,
            "kind": "directory" if stat.S_ISDIR(value.st_mode) else "file" if stat.S_ISREG(value.st_mode) else "symlink" if stat.S_ISLNK(value.st_mode) else "other",
            "mode": stat.S_IMODE(value.st_mode), "nlink": value.st_nlink, "uid": value.st_uid}


def _refusal(operation, anchor: int, components: tuple[str, ...]) -> tuple[int, dict]:
    try:
        operation(anchor, components)
    except privfs.PrivatePathError as exc:
        return getattr(exc, "errno", errno.ELOOP), {"class": type(exc).__name__, "components": list(exc.components)}
    except OSError as exc:
        return exc.errno or errno.EIO, {"class": type(exc).__name__, "components": list(components)}
    raise PrivateFilesEvidenceError("adversarial private filesystem operation was unexpectedly accepted")


_TESTED_UMASKS = (0o000, 0o002, 0o022, 0o077)


def _collect_case(spec: tuple, root: Path) -> dict:
    case_id, _lane, _artifact, operation, expected = spec
    target, before, error, detail = root / case_id, None, None, None
    descriptor_stats: list[dict] = []
    if operation in {"create_directory", "create_file"}:
        for umask in _TESTED_UMASKS:
            old_umask = os.umask(umask)
            candidate = root / f"{case_id}-{umask:03o}"
            try:
                if operation == "create_directory":
                    receipt = privfs._private_dir_with_creation_receipt(candidate)
                else:
                    receipt = privfs._open_private_with_creation_receipt(candidate)
                if receipt is None:
                    raise PrivateFilesEvidenceError("production creation did not emit exactly one first-descriptor receipt")
                value = receipt.stat
                descriptor_stats.append({"kind": "directory" if stat.S_ISDIR(value.st_mode) else "file",
                                         "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid})
            finally:
                os.umask(old_umask)
        after = _stat(root / f"{case_id}-{_TESTED_UMASKS[-1]:03o}")
    else:
        old_umask = os.umask(0o077)
        try:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if operation == "existing_unsafe_mode":
                    target.write_bytes(b"x"); os.chmod(target, 0o644)
                    before = _stat(target)
                    error, detail = _refusal(privfs.open_strict_file_at, root_fd, (case_id,))
                elif operation == "directory_symlink":
                    outside = root / "outside-dir"; outside.mkdir(mode=0o700)
                    target.symlink_to(outside, target_is_directory=True)
                    before = _stat(target)
                    error, detail = _refusal(privfs.open_strict_dir_at, root_fd, (case_id,))
                elif operation == "file_symlink":
                    outside = root / "outside-file"; outside.write_bytes(b"x"); os.chmod(outside, 0o600)
                    target.symlink_to(outside)
                    before = _stat(target)
                    error, detail = _refusal(privfs.open_strict_file_at, root_fd, (case_id,))
                elif operation == "foreign_owner":
                    target.write_bytes(b"x"); os.chmod(target, 0o600)
                    try:
                        os.chown(target, 65534, -1)
                    except PermissionError:
                        detail = {"class": "unsupported", "components": []}
                    else:
                        before = _stat(target)
                        error, detail = _refusal(privfs.open_strict_file_at, root_fd, (case_id,))
                    if before is None:
                        before = _stat(target)
                else:  # pragma: no cover - immutable roster
                    raise AssertionError(operation)
            finally:
                os.close(root_fd)
        finally:
            os.umask(old_umask)
        after = _stat(target)
    return {"case_id": case_id, "error": error, "error_detail": detail, "expected": expected,
            "mutation": "created" if expected == "created" and after is not None else "none",
            "operation": operation, "post": after, "pre": before,
            "descriptor_stats": descriptor_stats, "tested_umasks": list(_TESTED_UMASKS) if descriptor_stats else []}


def _collection_directory_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    """The non-mutable identity facts used to keep collection cleanup on one inode."""
    return value.st_dev, value.st_ino, value.st_uid, stat.S_IFMT(value.st_mode)


@dataclass(frozen=True, slots=True)
class _CollectionRootAuthority:
    """Pinned parent/name and root descriptor claims for one disposable collection tree."""

    name: str
    parent_fd: int
    root_fd: int
    parent_identity: tuple[int, int, int, int]
    identity: tuple[int, int, int, int]


_COLLECTION_ROOT_PREFIX = "quarry-private-files-"
_COLLECTION_ROOT_ATTEMPTS = 32


def _new_collection_root_authority() -> _CollectionRootAuthority:
    """Create and pin one disposable root without exposing an unclaimed path.

    A collection remains source-only: POSIX offers no descriptor-returning mkdir,
    so an uncooperative same-UID process in the shared temporary parent can race
    the one mkdirat/openat transition.  This producer makes no claim to defeat
    that hostile allocation race.  Once the descriptor claim exists, collection
    and cleanup operate only through it and fail closed on every name mismatch.
    """
    parent_fd: int | None = None
    root_fd: int | None = None
    try:
        parent_fd = _PARENT_OPEN(
            tempfile.gettempdir(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        held_parent = _PARENT_FSTAT(parent_fd)
        if not stat.S_ISDIR(held_parent.st_mode):
            raise PrivateFilesEvidenceError("private filesystem collection parent is not a directory")
        parent_identity = _collection_directory_identity(held_parent)
        for _ in range(_COLLECTION_ROOT_ATTEMPTS):
            name = _COLLECTION_ROOT_PREFIX + _PARENT_URANDOM(16).hex()
            try:
                _PARENT_MKDIR(name, privfs.DIR_MODE, dir_fd=parent_fd)
            except FileExistsError:
                continue
            root_fd = _PARENT_OPEN(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd,
            )
            held = _PARENT_FSTAT(root_fd)
            named = _PARENT_STAT(name, dir_fd=parent_fd, follow_symlinks=False)
            identity = _collection_directory_identity(held)
            if (not stat.S_ISDIR(held.st_mode) or held.st_uid != _PARENT_GETEUID()
                    or _collection_directory_identity(named) != identity):
                raise PrivateFilesEvidenceError("private filesystem collection root was substituted")
            _PARENT_FCHMOD(root_fd, privfs.DIR_MODE)
            hardened = _PARENT_FSTAT(root_fd)
            named = _PARENT_STAT(name, dir_fd=parent_fd, follow_symlinks=False)
            if (stat.S_IMODE(hardened.st_mode) != privfs.DIR_MODE
                    or _collection_directory_identity(hardened) != identity
                    or _collection_directory_identity(named) != identity):
                raise PrivateFilesEvidenceError("private filesystem collection root was substituted")
            authority = _CollectionRootAuthority(
                name=name, parent_fd=parent_fd, root_fd=root_fd,
                parent_identity=parent_identity, identity=identity,
            )
            parent_fd = None
            root_fd = None
            return authority
        raise PrivateFilesEvidenceError("could not allocate a private filesystem collection root")
    except BaseException:
        if root_fd is not None:
            _PARENT_CLOSE(root_fd)
        if parent_fd is not None:
            _PARENT_CLOSE(parent_fd)
        raise


def _remove_private_tree_fd(directory_fd: int) -> None:
    """Remove a known disposable tree using saved descriptor-relative parent controls."""
    for name in _PARENT_LISTDIR(directory_fd):
        value = _PARENT_STAT(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(value.st_mode):
            child_fd = _PARENT_OPEN(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd,
            )
            try:
                _remove_private_tree_fd(child_fd)
            finally:
                _PARENT_CLOSE(child_fd)
            _PARENT_RMDIR(name, dir_fd=directory_fd)
        else:
            _PARENT_UNLINK(name, dir_fd=directory_fd)


def _owned_collection_root_name(root: _CollectionRootAuthority) -> str:
    """Locate the one parent entry that still names the pinned root inode.

    Directories cannot acquire a second hard link.  Looking through the retained
    parent descriptor therefore lets cleanup recover an owned root renamed within
    that parent while refusing an absent or substituted name without touching it.
    """
    names = []
    for candidate in _PARENT_LISTDIR(root.parent_fd):
        try:
            value = _PARENT_STAT(candidate, dir_fd=root.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            # Concurrent collectors may remove unrelated sibling entries after
            # this descriptor-relative directory snapshot.
            continue
        if (stat.S_ISDIR(value.st_mode)
                and _collection_directory_identity(value) == root.identity):
            names.append(candidate)
    if len(names) != 1 or type(names[0]) is not str:
        raise PrivateFilesEvidenceError("private filesystem collection root name was substituted")
    return names[0]


def _remove_collection_root(root: _CollectionRootAuthority) -> None:
    """Remove only the exact parent-created root after its child has definitely exited.

    The root descriptor is claimed before fork.  Cleanup consequently never
    re-opens ``path``: a same-UID path replacement is a collection failure and
    is left untouched rather than becoming a new deletion target.
    """
    cleanup_error: BaseException | None = None
    try:
        parent = _PARENT_FSTAT(root.parent_fd)
        held = _PARENT_FSTAT(root.root_fd)
        if (not stat.S_ISDIR(parent.st_mode)
                or _collection_directory_identity(parent) != root.parent_identity
                or not stat.S_ISDIR(held.st_mode)
                or _collection_directory_identity(held) != root.identity):
            raise PrivateFilesEvidenceError("private filesystem collection root authority changed")
        _remove_private_tree_fd(root.root_fd)
        owned_name = _owned_collection_root_name(root)
        _PARENT_RMDIR(owned_name, dir_fd=root.parent_fd)
        if _PARENT_FSTAT(root.root_fd).st_nlink != 0:
            raise PrivateFilesEvidenceError("private filesystem collection root removal is unresolved")
        if owned_name != root.name:
            raise PrivateFilesEvidenceError("private filesystem collection root name was substituted")
    except BaseException as exc:
        cleanup_error = exc
    close_error: BaseException | None = None
    for fd in (root.root_fd, root.parent_fd):
        try:
            _PARENT_CLOSE(fd)
        except BaseException as exc:
            if close_error is None:
                close_error = exc
    if cleanup_error is not None:
        if close_error is not None:
            raise cleanup_error from close_error
        raise cleanup_error
    if close_error is not None:
        raise PrivateFilesEvidenceError("private filesystem collection root close failed") from close_error


def _open_collection_report_pipe() -> tuple[int, int]:
    if _PARENT_PIPE2 is not None:
        return _PARENT_PIPE2(getattr(os, "O_CLOEXEC", 0))
    read_fd, write_fd = _PARENT_PIPE()
    _PARENT_SET_INHERITABLE(read_fd, False)
    _PARENT_SET_INHERITABLE(write_fd, False)
    return read_fd, write_fd


def _write_all(fd: int, body: bytes) -> None:
    offset = 0
    while offset < len(body):
        written = _PARENT_WRITE(fd, body[offset:])
        if written < 1:
            raise PrivateFilesEvidenceError("bounded child report write made no progress")
        offset += written


def _child_report(root_fd: int, write_fd: int) -> None:
    """Collect in a private process so an ambiguous close dies with its fd table."""
    exit_code = 1
    try:
        _PARENT_SETSID()
        # Work below the exact pre-fork root descriptor, not the mutable
        # pathname.  The production helpers still receive normal relative
        # paths; their initial cwd open is bound by the kernel to this inode.
        _PARENT_FCHDIR(root_fd)
        document = {
            "collector_uid": os.geteuid(),
            "observations": [_collect_case(spec, Path(".")) for spec in _CASES],
        }
        body = canonical_json_bytes(document)
        if len(body) > MAX_BYTES:
            raise PrivateFilesEvidenceError("bounded child report exceeds artifact limit")
        _write_all(write_fd, body)
        exit_code = 0
    except BaseException as exc:
        try:
            # The error type is enough to distinguish typed quarantine uncertainty;
            # never put paths or an arbitrary exception message in the report pipe.
            _write_all(write_fd, canonical_json_bytes({"error": type(exc).__name__}))
        except BaseException:
            pass
    finally:
        try:
            _PARENT_CLOSE(write_fd)
        finally:
            os._exit(exit_code)


def _kill_collection_group(pid: int) -> None:
    try:
        _PARENT_KILLPG(pid, signal.SIGKILL)
        return
    except ProcessLookupError:
        pass
    except OSError:
        pass
    try:
        _PARENT_KILL(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _reap_collection_child(pid: int) -> None:
    while True:
        try:
            _PARENT_WAITPID(pid, 0)
            return
        except InterruptedError:
            continue
        except ChildProcessError:
            return


def _read_collection_report(pid: int, read_fd: int) -> dict:
    """Require an EOF-terminated, bounded, successful child report before use."""
    body = bytearray()
    status: int | None = None
    eof = False
    deadline = time.monotonic() + _COLLECTION_TIMEOUT_SECONDS
    try:
        while not eof or status is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PrivateFilesEvidenceError("bounded private filesystem collection timed out")
            readable, _, _ = select.select((read_fd,), (), (), min(remaining, 0.05))
            if readable:
                chunk = _PARENT_READ(read_fd, min(65536, MAX_BYTES + 1 - len(body)))
                if chunk:
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        raise PrivateFilesEvidenceError("bounded child report exceeds artifact limit")
                else:
                    eof = True
            if status is None:
                waited, child_status = _PARENT_WAITPID(pid, os.WNOHANG)
                if waited:
                    status = child_status
                    if not eof:
                        # A post-exit writer can only be a descendant.  Kill its
                        # session before accepting any report or allowing a leak.
                        _kill_collection_group(pid)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            error = "child-exited-unsuccessfully"
            try:
                diagnostic = _strict_json(bytes(body))
                if set(diagnostic) == {"error"} and type(diagnostic["error"]) is str:
                    error = diagnostic["error"]
            except PrivateFilesEvidenceError:
                pass
            raise PrivateFilesEvidenceError(f"private filesystem collection failed: {error}")
        document = _strict_json(bytes(body))
        if (set(document) != {"collector_uid", "observations"}
                or type(document["collector_uid"]) is not int
                or document["collector_uid"] < 0
                or document["collector_uid"] > _MAX_INT
                or type(document["observations"]) is not list):
            raise PrivateFilesEvidenceError("bounded child report has wrong members")
        return document
    except BaseException:
        if status is None:
            _kill_collection_group(pid)
            _reap_collection_child(pid)
        else:
            _kill_collection_group(pid)
        raise


def _collect_local_report() -> dict:
    """Fork a bounded collector and remove its root before observations are released."""
    root = _new_collection_root_authority()
    read_fd: int | None = None
    write_fd: int | None = None
    pid: int | None = None
    result: dict | None = None
    failure: BaseException | None = None
    try:
        read_fd, write_fd = _open_collection_report_pipe()
        pid = _PARENT_FORK()
        if pid == 0:  # pragma: no cover - process exit makes this parent-unobservable
            _PARENT_CLOSE(read_fd)
            _child_report(root.root_fd, write_fd)
        _PARENT_CLOSE(write_fd)
        write_fd = None
        try:
            result = _read_collection_report(pid, read_fd)
        finally:
            # _read_collection_report either reaped the direct child itself or
            # observed its successful exit status.  Do not later signal a reused pid.
            pid = None
        _PARENT_CLOSE(read_fd)
        read_fd = None
    except BaseException as exc:
        failure = exc
    finally:
        if read_fd is not None:
            _PARENT_CLOSE(read_fd)
        if write_fd is not None:
            _PARENT_CLOSE(write_fd)
        if pid is not None and failure is not None:
            _kill_collection_group(pid)
            _reap_collection_child(pid)
        try:
            _remove_collection_root(root)
        except BaseException as exc:
            if failure is None:
                failure = PrivateFilesEvidenceError("private filesystem collection root cleanup failed")
                failure.__cause__ = exc
    if failure is not None:
        raise failure
    assert result is not None
    return result


def collect_local_observations() -> list[dict]:
    """Execute every frozen operation in a bounded child beneath one disposable root."""
    return _collect_local_report()["observations"]


def _expected_rows(observations: list[dict], *, kind: str, collector_uid: int,
                   allow_unavailable: bool = False) -> list[dict]:
    """Recompute semantic facts JSON Schema cannot express.

    The schemas freeze the ordered operation constants, array cardinalities, and
    static kind/mode facts.  Equality of two independently-recorded stat objects,
    dynamic uid ownership, and descriptor-to-post identity are deliberate manual
    checks here because Draft 2020-12 has no cross-instance equality operator.
    """
    if (type(observations) is not list or type(collector_uid) is not int
            or collector_uid < 0 or collector_uid > _MAX_INT):
        raise PrivateFilesEvidenceError("observations or collector_uid is invalid")
    kind_specs = [row for row in _CASES if row[2] == kind]
    kind_ids = [row[0] for row in kind_specs]
    all_ids = [row[0] for row in _CASES]
    observed_ids = [row.get("case_id") if type(row) is dict else None for row in observations]
    if observed_ids not in (kind_ids, all_ids):
        raise PrivateFilesEvidenceError("observations do not cover the exact frozen case roster")
    by_id = {row["case_id"]: row for row in observations}
    rows = []
    for case_id, _lane, artifact, operation, expected in kind_specs:
        row = by_id[case_id]
        required = {"case_id", "descriptor_stats", "error", "error_detail", "expected", "mutation", "operation", "post", "pre", "tested_umasks"}
        if (type(row) is not dict or set(row) != required or row["operation"] != operation
                or row["expected"] != expected):
            raise PrivateFilesEvidenceError("observation does not match named operation specification")
        pre, post, error = row["pre"], row["post"], row["error"]
        if pre is not None:
            _stat_fact(pre, f"{case_id}.pre")
        if post is not None:
            _stat_fact(post, f"{case_id}.post")
        if expected == "created":
            required_mode = 0o700 if operation == "create_directory" else 0o600
            required_kind = "directory" if operation == "create_directory" else "file"
            if (pre is not None or post is None or error is not None or row["error_detail"] is not None
                    or row["mutation"] != "created" or row["tested_umasks"] != list(_TESTED_UMASKS)
                    or type(row["tested_umasks"]) is not list or type(row["descriptor_stats"]) is not list
                    or len(row["descriptor_stats"]) != len(_TESTED_UMASKS)
                    or post["kind"] != required_kind or post["mode"] != required_mode
                    or post["uid"] != collector_uid
                    or any(type(item) is not dict or item != {"kind": required_kind, "mode": required_mode, "uid": collector_uid}
                           for item in row["descriptor_stats"])):
                raise PrivateFilesEvidenceError("creation facts do not prove first-descriptor privacy")
        else:
            expected_kind, expected_mode = (
                ("symlink", 0o777)
                if operation in {"directory_symlink", "file_symlink"}
                else ("file", 0o644 if operation == "existing_unsafe_mode" else 0o600)
            )
            detail = row["error_detail"]
            unavailable = detail == {"class": "unsupported", "components": []}
            expected_detail = {
                "existing_unsafe_mode": {"class": "LegacyModeMismatch", "components": [case_id]},
                "directory_symlink": {"class": "PrivatePathUnsafe", "components": [case_id]},
                "file_symlink": {"class": "PrivatePathUnsafe", "components": [case_id]},
                "foreign_owner": {"class": "PrivatePathUnsafe", "components": [case_id]},
            }[operation]
            if (row["tested_umasks"] != [] or row["descriptor_stats"] != [] or pre is None or post is None
                    or type(row["tested_umasks"]) is not list or type(row["descriptor_stats"]) is not list
                    or (unavailable and (not allow_unavailable or operation != "foreign_owner" or error is not None))
                    or (not unavailable and (type(error) is not int or error < 1 or error > _MAX_INT))
                    or row["mutation"] != "none" or type(detail) is not dict
                    or set(detail) != {"class", "components"}
                    or type(detail["components"]) is not list
                    or len(detail["components"]) > 64
                    or not all(type(item) is str for item in detail["components"])
                    or (unavailable and detail != {"class": "unsupported", "components": []})
                    or (not unavailable and detail != expected_detail)
                    or post != pre or post["kind"] != expected_kind or post["mode"] != expected_mode
                    or (operation == "foreign_owner" and not unavailable and post["uid"] == collector_uid)):
                raise PrivateFilesEvidenceError("unsafe-existing facts do not prove typed refusal without mutation")
        rows.append(row)
    return rows


def _digest(value: object, where: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise PrivateFilesEvidenceError(f"{where} must be a digest")
    return value


def _token(value: object, where: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise PrivateFilesEvidenceError(f"{where} must be a token")
    return value


def _stat_fact(value: object, where: str) -> dict:
    keys = {"device", "gid", "inode", "kind", "mode", "nlink", "uid"}
    if type(value) is not dict or set(value) != keys:
        raise PrivateFilesEvidenceError(f"{where} has wrong descriptor/stat fields")
    if value["kind"] not in {"directory", "file", "symlink", "other"}:
        raise PrivateFilesEvidenceError(f"{where} kind is invalid")
    for field in keys - {"kind"}:
        if (type(value[field]) is not int or value[field] < 0
                or value[field] > _MAX_INT):
            raise PrivateFilesEvidenceError(f"{where}.{field} is invalid")
    if value["mode"] > 0o7777:
        raise PrivateFilesEvidenceError(f"{where}.mode is invalid")
    return value


def _timestamp(value: object, where: str) -> str:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise PrivateFilesEvidenceError(f"{where} must be canonical UTC RFC3339")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PrivateFilesEvidenceError(f"{where} is not a real timestamp") from exc
    return value


def _utc_now() -> str:
    """Private clock seam used only to test the collection bracket."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_source_substrate(*, candidate_identity_digest: str, h0_evidence_instance_id: str = "instance-00",
                           h1_evidence_instance_id: str = "instance-01") -> dict[str, dict]:
    """Emit measured local artifacts, not hostile-same-UID isolation evidence or accepted proof."""
    _digest(candidate_identity_digest, "candidate_identity_digest")
    started_at = _utc_now()
    collection = _collect_local_report()
    observations = collection["observations"]
    finished_at = _utc_now()
    _timestamp(started_at, "started_at"); _timestamp(finished_at, "finished_at")
    if finished_at < started_at:
        raise PrivateFilesEvidenceError("source substrate finishes before it starts")
    collector_uid = collection["collector_uid"]
    ids = {"H0-hermetic": _token(h0_evidence_instance_id, "H0 evidence instance"),
           "H1-tool-integration": _token(h1_evidence_instance_id, "H1 evidence instance")}
    return {kind: {"artifact_kind": kind, "candidate_identity_digest": candidate_identity_digest,
                   "case_roster_digest": roster_digest(), "disposition": "source_substrate",
                   "collector_uid": collector_uid, "finished_at": finished_at, "started_at": started_at,
                   "evidence_instance_id": ids[lane], "gate_id": GATE_ID, "lane": lane,
                   "open_reasons": list(_OPEN_REASONS),
                   "observations": _expected_rows(observations, kind=kind, collector_uid=collector_uid, allow_unavailable=True), "release": RELEASE,
                   "schema_version": schema}
            for kind, schema, lane in _ARTIFACTS}


def _strict_json(body: bytes) -> dict:
    if type(body) is not bytes or len(body) > MAX_BYTES or not body.endswith(b"\n") or body.endswith(b"\n\n"):
        raise PrivateFilesEvidenceError("artifact violates bounded JSON-line contract")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PrivateFilesEvidenceError(f"duplicate JSON member {key!r}")
            result[key] = value
        return result
    try:
        document = json.loads(body[:-1].decode("utf-8", "strict"), object_pairs_hook=pairs,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PrivateFilesEvidenceError("artifact is not strict JSON") from exc
    if canonical_json_bytes(document) != body or type(document) is not dict:
        raise PrivateFilesEvidenceError("artifact is not canonical object JSON")
    return document


def read_case_roster(body: bytes) -> dict:
    """Accept only the canonical bytes generated from the named immutable case specs."""
    document = _strict_json(body)
    if body != canonical_json_bytes(case_roster()):
        raise PrivateFilesEvidenceError("case roster does not match the frozen named operation specs")
    return document


def verify_artifact(document: object, *, artifact_kind: str | None = None,
                    candidate_identity_digest: str | None = None) -> dict:
    required = {"artifact_kind", "candidate_identity_digest", "case_roster_digest", "collector_uid", "disposition", "evidence_instance_id", "finished_at", "gate_id", "lane", "open_reasons", "observations", "release", "schema_version", "started_at"}
    if type(document) is not dict or set(document) != required:
        raise PrivateFilesEvidenceError("artifact has wrong members")
    contract = next((row for row in _ARTIFACTS if row[0] == document["artifact_kind"]), None)
    if contract is None or document["schema_version"] != contract[1] or document["lane"] != contract[2] or document["gate_id"] != GATE_ID or document["release"] != RELEASE:
        raise PrivateFilesEvidenceError("artifact kind/schema/lane binding is wrong")
    if artifact_kind is not None and artifact_kind != document["artifact_kind"]:
        raise PrivateFilesEvidenceError("wrong artifact kind")
    candidate = _digest(document["candidate_identity_digest"], "candidate_identity_digest")
    if candidate_identity_digest is not None and candidate != candidate_identity_digest:
        raise PrivateFilesEvidenceError("artifact belongs to another candidate")
    _token(document["evidence_instance_id"], "evidence_instance_id")
    if (type(document["collector_uid"]) is not int or document["collector_uid"] < 0
            or document["collector_uid"] > _MAX_INT):
        raise PrivateFilesEvidenceError("collector_uid is invalid")
    started, finished = _timestamp(document["started_at"], "started_at"), _timestamp(document["finished_at"], "finished_at")
    if finished < started:
        raise PrivateFilesEvidenceError("artifact finishes before it starts")
    if document["case_roster_digest"] != roster_digest() or _expected_rows(document["observations"], kind=document["artifact_kind"], collector_uid=document["collector_uid"], allow_unavailable=document["disposition"] == "source_substrate") != document["observations"]:
        raise PrivateFilesEvidenceError("artifact does not bind/recompute exact observed roster")
    if document["disposition"] != "source_substrate":
        raise PrivateFilesEvidenceError("unsupported artifact disposition")
    if document["open_reasons"] != list(_OPEN_REASONS):
        raise PrivateFilesEvidenceError("source substrate must retain open acceptance distinction")
    return document


def read_artifact(body: bytes, *, artifact_kind: str | None = None,
                  candidate_identity_digest: str | None = None) -> dict:
    return verify_artifact(_strict_json(body), artifact_kind=artifact_kind,
                           candidate_identity_digest=candidate_identity_digest)


def verify_artifact_family(bodies: Mapping[str, bytes], *, candidate_identity_digest: str) -> dict[str, dict]:
    if not isinstance(bodies, Mapping) or set(bodies) != {row[0] for row in _ARTIFACTS}:
        raise PrivateFilesEvidenceError("C-PRIVATE-FILES requires exactly two artifacts")
    return {name: read_artifact(body, artifact_kind=name,
                                candidate_identity_digest=candidate_identity_digest) for name, body in bodies.items()}
