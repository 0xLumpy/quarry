"""Fail-closed runtime admission and credential-minimal child environments.

The installer receipt describes the complete immutable managed payload.  This module revalidates that
receipt immediately before a launch, resolves every executable to an absolute path, and emits a private
per-invocation record containing identities and environment *names* only.  Credential values never enter
the record, argv, telemetry, or a caller-provided environment.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path


class RuntimeIdentityError(RuntimeError):
    """An executable, payload, receipt, or environment could not be admitted."""


@dataclass(frozen=True)
class PreparedLaunch:
    argv: tuple[str, ...]
    environment: dict[str, str]
    record: dict
    anchor_root: Path
    private_checks: tuple[dict, ...] = field(default=(), repr=False)
    redactions: tuple[str, ...] = field(default=(), repr=False)
    payload_leases: tuple["_ManagedPayloadLease", ...] = field(default=(), repr=False)
    source_argv_indexes: tuple[int, ...] = field(default=(), repr=False)
    anchor_identity: "tuple[int, int] | None" = field(default=None, repr=False)

    def close(self) -> None:
        """Drop private executable/payload/config launch names and report any unsettled residue."""
        faults: list[BaseException] = []
        try:
            _settle_launch_root(self.anchor_root, expected_identity=self.anchor_identity)
        except BaseException as exc:
            faults.append(exc)
        for lease in reversed(self.payload_leases):
            try:
                lease.release()
            except BaseException as exc:
                faults.append(exc)
        cancellation = next((fault for fault in faults if not isinstance(fault, Exception)), None)
        if cancellation is not None:
            raise cancellation.with_traceback(cancellation.__traceback__)
        if faults:
            raise faults[0].with_traceback(faults[0].__traceback__)


_base_environment_names = (
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
)
_caller_environment_names = frozenset({"PYTHONHASHSEED"})
_system_path = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
_identity_schema = "quarry.runtime-launch.v1"
_max_dynamic_files = 200_000
_max_dynamic_bytes = 2 * 1024 * 1024 * 1024
_reusable_snapshots = threading.local()


def _settle_launch_root(root: Path, *, expected_identity: "tuple[int, int] | None" = None) -> None:
    """Remove one private launch authority and return only after proving its name absent."""
    if not root or not os.path.lexists(root):
        return
    errors: list[BaseException] = []
    root_fd = -1
    identity_valid = False
    try:
        root_fd = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        root_stat = os.fstat(root_fd)
        identity = (root_stat.st_dev, root_stat.st_ino)
        if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid()
                or (expected_identity is not None and identity != expected_identity)):
            raise RuntimeIdentityError(f"private runtime cleanup root identity changed: {root}")
        identity_valid = True
        os.fchmod(root_fd, 0o700)
        # Payload/config snapshots are sealed recursively. Restore deletion authority only on exact
        # owner-held directories; never chmod through a link into the admitted source or host runtime.
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
            observed = path.lstat()
            if observed.st_uid != os.geteuid():
                raise RuntimeIdentityError(
                    f"private runtime cleanup found a foreign-owned object: {path}"
                )
            if stat.S_ISDIR(observed.st_mode):
                os.chmod(path, 0o700)
            elif not (stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode)):
                raise RuntimeIdentityError(
                    f"private runtime cleanup found an unsupported object: {path}"
                )
    except BaseException as exc:
        errors.append(exc)
    if identity_valid:
        try:
            shutil.rmtree(root)
        except FileNotFoundError:
            pass
        except BaseException as exc:
            errors.append(exc)
    original_unlinked = False
    if root_fd >= 0:
        try:
            original_unlinked = os.fstat(root_fd).st_nlink == 0
        except BaseException as exc:
            errors.append(exc)
        try:
            os.close(root_fd)
        except BaseException as exc:
            errors.append(exc)
    cancellation = next((exc for exc in errors if not isinstance(exc, Exception)), None)
    if os.path.lexists(root) or (identity_valid and not original_unlinked):
        detail = (
            f"{type(errors[0]).__name__}: {errors[0]}"
            if errors else "unknown cleanup fault"
        )
        residue = RuntimeIdentityError(
            f"private runtime launch authority remains after cleanup ({detail}): {root}"
        )
        if cancellation is not None:
            cancellation.add_note(f"runtime launch residue also remains: {residue}")
            raise cancellation.with_traceback(cancellation.__traceback__)
        raise residue
    if cancellation is not None:
        raise cancellation.with_traceback(cancellation.__traceback__)


def _sha256_file(path: Path) -> tuple[str, int, int]:
    """Hash one exact no-follow regular inode and prove its name did not change during the read."""
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(resolved, flags)
    except OSError as exc:
        raise RuntimeIdentityError(f"runtime file cannot be opened safely: {resolved}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeIdentityError(f"runtime object is not a regular file: {resolved}")
        digest, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            raise RuntimeIdentityError(f"runtime file changed while it was hashed: {resolved}")
        if path.resolve(strict=True) != resolved:
            raise RuntimeIdentityError(f"runtime pathname changed while it was hashed: {path}")
        return digest.hexdigest(), total, stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def _resolve_executable(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeIdentityError("runtime executable name is invalid")
    selected = value if os.path.isabs(value) else shutil.which(value)
    if not selected:
        raise RuntimeIdentityError(f"runtime executable is unavailable: {value}")
    try:
        path = Path(selected).resolve(strict=True)
        observed = path.stat()
    except OSError as exc:
        raise RuntimeIdentityError(f"runtime executable cannot be resolved: {value}") from exc
    if not stat.S_ISREG(observed.st_mode) or not os.access(path, os.X_OK):
        raise RuntimeIdentityError(f"runtime executable is not executable: {path}")
    return path


def _file_record(role: str, path: Path) -> dict:
    digest, size, mode = _sha256_file(path)
    return {"bytes": size, "path": str(path), "role": role,
            "sha256": digest, "mode": mode}


def _closure_record(rows: list[dict]) -> dict:
    """Compactly bind the complete canonical receipt inventory without copying it per invocation."""
    if not isinstance(rows, list):
        raise RuntimeIdentityError("managed runtime closure is not a canonical inventory")
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8", "strict",
    )
    return {
        "bytes": sum(row.get("bytes", 0) for row in rows if isinstance(row, dict)),
        "objects": len(rows),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _copy_regular(source: Path, destination: Path, expected: dict, *, mode: int | None = None) -> dict:
    """Copy verified bytes through a held source descriptor into a distinct private inode."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeIdentityError(f"launch source is not regular: {source}")
        destination_fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
        )
        digest, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("launch authority write made no progress")
                view = view[written:]
        os.fsync(destination_fd)
        wanted_mode = ((before.st_mode if mode is None else mode) & 0o777) & ~0o222
        os.fchmod(destination_fd, wanted_mode or 0o400)
        if (digest.hexdigest(), total) != (expected["sha256"], expected["bytes"]):
            raise RuntimeIdentityError(f"launch source changed while anchoring: {source}")
        after = os.fstat(source_fd)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            raise RuntimeIdentityError(f"launch source changed while anchoring: {source}")
        named = source.lstat()
        if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeIdentityError(f"launch source name changed while anchoring: {source}")
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)
    return _file_record("launch-copy", destination)


def _copy_receipt_payload(source_root: Path, receipt: dict, launch_root: Path,
                          index: int) -> tuple[Path, dict]:
    """Materialize a complete receipt closure below the private per-launch authority."""
    from . import registry

    destination_root = launch_root / f"payload-{index}"
    destination_root.mkdir(mode=0o700)
    rows = receipt["files"]
    for row in rows:
        relative = Path(row["path"])
        source = source_root / relative
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        kind = row["kind"]
        if kind == "directory":
            destination.mkdir(exist_ok=True, mode=0o700)
        elif kind == "file":
            _copy_regular(source, destination, row, mode=row["mode"])
        elif kind == "symlink":
            link_fd = -1
            try:
                try:
                    link_fd = os.open(
                        source,
                        os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    )
                    link_before = os.fstat(link_fd)
                    source_target = os.readlink("", dir_fd=link_fd)
                except (AttributeError, OSError) as exc:
                    raise RuntimeIdentityError(
                        f"managed payload link is unavailable while anchoring: {relative}"
                    ) from exc
                encoded_target = source_target.encode("utf-8", "strict")
                if (not stat.S_ISLNK(link_before.st_mode)
                        or source_target != row.get("target")
                        or len(encoded_target) != row.get("bytes")
                        or hashlib.sha256(encoded_target).hexdigest() != row.get("sha256")):
                    raise RuntimeIdentityError(
                        f"managed payload link no longer matches its receipt: {relative}"
                    )
                declared = Path(source_target)
                declared_resolved = (
                    declared if declared.is_absolute() else source.parent / declared
                ).resolve(strict=True)
                external = row.get("external")
                if external is not None:
                    # A venv interpreter link becomes a private regular inode at the same lexical path.
                    # Python retains the mirrored venv prefix without consulting the mutable host link.
                    try:
                        expected_resolved = Path(external["path"]).resolve(strict=True)
                    except (KeyError, OSError, TypeError) as exc:
                        raise RuntimeIdentityError(
                            f"managed external payload link cannot be reconciled: {relative}"
                        )
                    if declared_resolved != expected_resolved:
                        raise RuntimeIdentityError(
                            f"managed external payload link changed while anchoring: {relative}"
                        )
                    _copy_regular(
                        expected_resolved, destination, external, mode=external["mode"],
                    )
                else:
                    try:
                        target_relative = declared_resolved.relative_to(
                            source_root.resolve(strict=True),
                        )
                    except (OSError, ValueError) as exc:
                        raise RuntimeIdentityError(
                            f"managed payload link cannot be privately anchored: {relative}"
                        ) from exc
                    translated = os.path.relpath(
                        destination_root / target_relative, destination.parent,
                    )
                    os.symlink(translated, destination)

                # The held O_PATH descriptor prevents the unlinked inode from being recycled. Even a
                # swap-then-restore using the same target string therefore cannot regain this identity.
                source_target_after = os.readlink(source)
                source_target_confirm = os.readlink(source)
                link_after = source.lstat()
                if ((link_before.st_dev, link_before.st_ino, link_before.st_mode,
                     link_before.st_mtime_ns, link_before.st_ctime_ns)
                        != (link_after.st_dev, link_after.st_ino, link_after.st_mode,
                            link_after.st_mtime_ns, link_after.st_ctime_ns)
                        or source_target_after != source_target
                        or source_target_confirm != source_target):
                    raise RuntimeIdentityError(
                        f"managed payload link changed while anchoring: {relative}"
                    )
            except OSError as exc:
                raise RuntimeIdentityError(
                    f"managed payload link changed while anchoring: {relative}"
                ) from exc
            finally:
                if link_fd >= 0:
                    os.close(link_fd)
        else:
            raise RuntimeIdentityError(f"managed payload has unknown receipt kind: {kind!r}")
    for directory in sorted(
            (path for path in destination_root.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts), reverse=True):
        os.chmod(directory, 0o500)
    os.chmod(destination_root, 0o500)
    anchored_rows = registry._tree_rows(destination_root)
    record = {
        "closure": _closure_record(anchored_rows),
        "root": str(destination_root),
        "source_root": str(source_root),
    }
    return destination_root, record


def _record_without_path(record: dict) -> dict:
    return {key: value for key, value in record.items() if key != "path"}


def _copy_input_file(source: Path, destination: Path, *, allow_absent: bool) -> dict:
    """Snapshot one invocation input and retain its source/anchor checks outside public evidence."""
    source = source.absolute()
    if not os.path.lexists(source):
        if not allow_absent:
            raise RuntimeIdentityError(f"required runtime input is absent: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        expected = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"source": str(source), "source_kind": "absent", "anchor": str(destination),
                "anchor_kind": "file", "expected": expected}
    source_record = _file_record("private-input", source)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _copy_regular(Path(source_record["path"]), destination, source_record, mode=0o400)
    return {
        "source": str(source), "source_kind": "file", "source_expected": source_record,
        "anchor": str(destination), "anchor_kind": "file",
        "expected": {"bytes": source_record["bytes"], "sha256": source_record["sha256"]},
    }


def _copy_input_tree(source: Path, destination: Path, *, allow_absent: bool) -> dict:
    """Snapshot one config/template tree without accepting alias authority."""
    source = source.absolute()
    destination.mkdir(parents=True, mode=0o700)
    if not os.path.lexists(source):
        if not allow_absent:
            raise RuntimeIdentityError(f"required runtime tree is absent: {source}")
        observed = _dynamic_tree(destination, "private-tree")
        return {"source": str(source), "source_kind": "absent", "anchor": str(destination),
                "anchor_kind": "tree", "expected": _record_without_path(observed)}
    before = _dynamic_tree(source, "private-tree")
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix().encode()):
        relative = path.relative_to(source)
        target = destination / relative
        observed = path.lstat()
        if stat.S_ISDIR(observed.st_mode):
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        elif stat.S_ISREG(observed.st_mode):
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            record = _file_record("private-tree-file", path)
            _copy_regular(Path(record["path"]), target, record, mode=record["mode"])
        else:
            raise RuntimeIdentityError(f"runtime tree contains an unsupported alias/object: {path}")
    after = _dynamic_tree(source, "private-tree")
    anchored = _dynamic_tree(destination, "private-tree")
    if _record_without_path(before) != _record_without_path(after):
        raise RuntimeIdentityError(f"runtime tree changed while it was privately anchored: {source}")
    if _record_without_path(before) != _record_without_path(anchored):
        raise RuntimeIdentityError(f"runtime tree copy differs from admitted source: {source}")
    return {
        "source": str(source), "source_kind": "tree",
        "source_expected": _record_without_path(before), "anchor": str(destination),
        "anchor_kind": "tree", "expected": _record_without_path(anchored),
    }


def _active_tree_snapshot(source: Path) -> "dict | None":
    snapshots = getattr(_reusable_snapshots, "trees", None)
    entry = None if snapshots is None else snapshots.get(str(source.absolute()))
    if entry is None or entry.get("check") is not None:
        return entry
    root = Path(tempfile.mkdtemp(prefix="quarry-runtime-snapshot-"))
    os.chmod(root, 0o700)
    entry["root"] = root
    root_stat = root.lstat()
    entry["identity"] = (root_stat.st_dev, root_stat.st_ino)
    try:
        check = _copy_input_tree(source, root / "tree", allow_absent=False)
        for directory in sorted(
                (path for path in (root / "tree").rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts), reverse=True):
            os.chmod(directory, 0o500)
        os.chmod(root / "tree", 0o500)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.chmod(root, 0o500)
        check["source_kind"] = "detached-tree"
        check["role"] = entry["role"]
        check["private"] = False
        entry["path"] = Path(check["anchor"])
        entry["check"] = check
        return entry
    except BaseException as primary:
        try:
            _settle_launch_root(root, expected_identity=entry["identity"])
        except BaseException as cleanup_fault:
            if not isinstance(primary, Exception):
                primary.add_note(
                    f"runtime tree snapshot cleanup also failed: "
                    f"{type(cleanup_fault).__name__}: {cleanup_fault}"
                )
            elif not isinstance(cleanup_fault, Exception):
                raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
            else:
                primary.add_note(
                    f"runtime tree snapshot cleanup also failed: "
                    f"{type(cleanup_fault).__name__}: {cleanup_fault}"
                )
        entry.update({"root": None, "path": None, "check": None, "identity": None})
        raise primary.with_traceback(primary.__traceback__)


@contextmanager
def reusable_tree_snapshot(source: Path, *, role: str):
    """Register one lazily-created detached tree authority reusable by sequential lane launches."""
    source = Path(source).absolute()
    trees = getattr(_reusable_snapshots, "trees", None)
    if trees is None:
        trees = {}
        _reusable_snapshots.trees = trees
    key = str(source)
    if key in trees:
        raise RuntimeIdentityError(f"runtime tree already has an active snapshot: {source}")
    entry = {
        "source": source, "role": role, "root": None, "path": None,
        "check": None, "identity": None,
    }
    trees[key] = entry
    primary = None
    try:
        try:
            yield source
        except BaseException as exc:
            primary = exc
    except BaseException as exc:
        if primary is None:
            primary = exc
    finally:
        trees.pop(key, None)
        cleanup_fault = None
        root = entry.get("root")
        if root is not None:
            try:
                _settle_launch_root(root, expected_identity=entry["identity"])
            except BaseException as exc:
                cleanup_fault = exc
        if not trees:
            try:
                del _reusable_snapshots.trees
            except AttributeError:
                pass
        if primary is not None:
            if cleanup_fault is not None:
                if not isinstance(primary, Exception):
                    primary.add_note(
                        f"runtime tree snapshot cleanup also failed: "
                        f"{type(cleanup_fault).__name__}: {cleanup_fault}"
                    )
                elif not isinstance(cleanup_fault, Exception):
                    raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
                else:
                    primary.add_note(
                        f"runtime tree snapshot cleanup also failed: "
                        f"{type(cleanup_fault).__name__}: {cleanup_fault}"
                    )
            raise primary.with_traceback(primary.__traceback__)
        if cleanup_fault is not None:
            raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)


def _private_snapshot_signature(root: Path) -> tuple[tuple, ...]:
    """Bind every private snapshot name to owner-held inode metadata without rereading payload bytes."""
    root = Path(root)
    paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
    signature = []
    for path in paths:
        observed = path.lstat()
        if observed.st_uid != os.geteuid():
            raise RuntimeIdentityError(f"managed payload snapshot has foreign ownership: {path}")
        if stat.S_ISDIR(observed.st_mode):
            kind, target = "directory", None
        elif stat.S_ISREG(observed.st_mode):
            kind, target = "file", None
        elif stat.S_ISLNK(observed.st_mode):
            kind, target = "symlink", os.readlink(path)
        else:
            raise RuntimeIdentityError(f"managed payload snapshot has an unsupported object: {path}")
        relative = "." if path == root else path.relative_to(root).as_posix()
        signature.append((
            relative, kind, observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_nlink, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns,
            target,
        ))
    return tuple(signature)


class _ManagedPayloadLease:
    """One launch's live claim on a run-scoped, detached managed payload."""

    def __init__(self, scope: "ManagedPayloadSnapshotScope", key: tuple, entry: dict):
        self._scope = scope
        self._key = key
        self._entry = entry
        self._released = False

    @property
    def root(self) -> Path:
        return self._entry["root"]

    @property
    def record(self) -> dict:
        return dict(self._entry["record"])

    def validate(self) -> None:
        self._scope._validate(self)

    def release(self) -> None:
        self._scope._release(self)


class ManagedPayloadSnapshotScope:
    """Per-run owner of identity-bound payload copies shared by that run's launches only."""

    def __init__(self):
        self._lock = threading.RLock()
        self._entries: dict[tuple, dict] = {}
        self._repositories: list[object] = []
        self._closed = False

    def bind(self, repository) -> None:
        """Attach this exact scope to one run object so worker threads receive it explicitly."""
        with self._lock:
            if self._closed:
                raise RuntimeIdentityError("managed payload snapshot scope is already closed")
            existing = getattr(repository, "_runtime_payload_scope", None)
            if existing not in (None, self):
                raise RuntimeIdentityError("repository already has another runtime payload scope")
            setattr(repository, "_runtime_payload_scope", self)
            if repository not in self._repositories:
                self._repositories.append(repository)

    @staticmethod
    def _key(source_root: Path, receipt: dict) -> tuple:
        try:
            source = source_root.resolve(strict=True)
            canonical = json.dumps(
                receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8", "strict")
            generation = receipt["generation"]
        except (KeyError, OSError, TypeError, UnicodeError, ValueError) as exc:
            raise RuntimeIdentityError("managed payload receipt cannot key a run snapshot") from exc
        return str(source), str(generation), hashlib.sha256(canonical).hexdigest()

    def acquire(self, source_root: Path, receipt: dict) -> _ManagedPayloadLease:
        key = self._key(source_root, receipt)
        with self._lock:
            if self._closed:
                raise RuntimeIdentityError("managed payload snapshot scope is already closed")
            entry = self._entries.get(key)
            if entry is None:
                container = Path(tempfile.mkdtemp(prefix="quarry-runtime-payload-"))
                os.chmod(container, 0o700)
                container_stat = container.lstat()
                container_identity = (container_stat.st_dev, container_stat.st_ino)
                try:
                    root, record = _copy_receipt_payload(Path(key[0]), receipt, container, 0)
                    directory_fd = os.open(
                        container, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    )
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                    os.chmod(container, 0o500)
                    entry = {
                        "container": container,
                        "container_identity": container_identity,
                        "root": root,
                        "record": record,
                        "signature": _private_snapshot_signature(root),
                        "leases": 0,
                    }
                    self._entries[key] = entry
                except BaseException as primary:
                    cleanup_fault = None
                    try:
                        _settle_launch_root(
                            container, expected_identity=container_identity,
                        )
                    except BaseException as exc:
                        cleanup_fault = exc
                    if cleanup_fault is not None:
                        if isinstance(primary, Exception) and not isinstance(cleanup_fault, Exception):
                            raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
                        primary.add_note(
                            "managed payload snapshot cleanup also failed: "
                            f"{type(cleanup_fault).__name__}: {cleanup_fault}"
                        )
                    raise primary.with_traceback(primary.__traceback__)
            entry["leases"] += 1
            return _ManagedPayloadLease(self, key, entry)

    def _validate(self, lease: _ManagedPayloadLease) -> None:
        with self._lock:
            if lease._released or self._closed or self._entries.get(lease._key) is not lease._entry:
                raise RuntimeIdentityError("managed payload snapshot lease is not live")
            if _private_snapshot_signature(lease.root) != lease._entry["signature"]:
                raise RuntimeIdentityError("managed payload snapshot changed before spawn")

    def _release(self, lease: _ManagedPayloadLease) -> None:
        with self._lock:
            if lease._released:
                return
            entry = self._entries.get(lease._key)
            if entry is not lease._entry or entry["leases"] <= 0:
                raise RuntimeIdentityError("managed payload snapshot lease accounting is invalid")
            lease._released = True
            entry["leases"] -= 1
            if self._closed and entry["leases"] == 0:
                fault = None
                try:
                    _settle_launch_root(
                        entry["container"], expected_identity=entry["container_identity"],
                    )
                except BaseException as exc:
                    fault = exc
                if not os.path.lexists(entry["container"]):
                    self._entries.pop(lease._key, None)
                if fault is not None:
                    raise fault.with_traceback(fault.__traceback__)

    def close(self) -> None:
        """Detach repositories, settle every idle snapshot, and fail loudly on residue/live claims."""
        faults: list[BaseException] = []
        with self._lock:
            self._closed = True
            for repository in self._repositories:
                try:
                    if getattr(repository, "_runtime_payload_scope", None) is self:
                        delattr(repository, "_runtime_payload_scope")
                except BaseException as exc:
                    faults.append(exc)
            self._repositories.clear()
            for key, entry in tuple(self._entries.items()):
                if entry["leases"]:
                    faults.append(RuntimeIdentityError(
                        f"managed payload snapshot has {entry['leases']} live launch lease(s)"
                    ))
                    continue
                try:
                    _settle_launch_root(
                        entry["container"], expected_identity=entry["container_identity"],
                    )
                except BaseException as exc:
                    faults.append(exc)
                if not os.path.lexists(entry["container"]):
                    self._entries.pop(key, None)
        cancellation = next((fault for fault in faults if not isinstance(fault, Exception)), None)
        if cancellation is not None:
            raise cancellation.with_traceback(cancellation.__traceback__)
        if faults:
            raise faults[0].with_traceback(faults[0].__traceback__)


@contextmanager
def managed_payload_snapshot_scope():
    """Yield one exact per-run payload authority and preserve body/cleanup cancellation precedence."""
    scope = ManagedPayloadSnapshotScope()
    primary = None
    try:
        yield scope
    except BaseException as exc:
        primary = exc
    finally:
        cleanup_fault = None
        try:
            scope.close()
        except BaseException as exc:
            cleanup_fault = exc
        if primary is not None:
            if cleanup_fault is not None:
                if isinstance(primary, Exception) and not isinstance(cleanup_fault, Exception):
                    raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
                primary.add_note(
                    "managed payload scope cleanup also failed: "
                    f"{type(cleanup_fault).__name__}: {cleanup_fault}"
                )
            raise primary.with_traceback(primary.__traceback__)
        if cleanup_fault is not None:
            raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)


def _launch_anchors(identities: list[dict], payloads=(), input_specs=(), *,
                    payload_scope: "ManagedPayloadSnapshotScope | None" = None) -> tuple[
        Path, dict[str, Path], list[dict], dict[str, Path], list[dict], dict[str, Path],
        tuple[dict, ...], tuple[_ManagedPayloadLease, ...], tuple[int, int]]:
    """Create private non-writable names for the exact executable inodes admitted above.

    Every source is copied through a held descriptor into a distinct private inode.  A hardlink is not an
    authority boundary: the source owner could make that shared inode writable after admission.  The
    resulting absolute name lives below a 0500 private directory, is re-hashed, and is the only executable
    pathname handed to the worker.
    """
    root = Path(tempfile.mkdtemp(prefix="quarry-runtime-launch-"))
    os.chmod(root, 0o700)
    root_stat = root.lstat()
    root_identity = (root_stat.st_dev, root_stat.st_ino)
    anchors: dict[str, Path] = {}
    records: list[dict] = []
    payload_leases: list[_ManagedPayloadLease] = []
    try:
        for identity in identities:
            executable = identity["executable"]
            source = Path(executable["path"])
            key = str(source)
            if key in anchors:
                continue
            if identity.get("attestation") == "immutable-system-name":
                admitted = _immutable_system_file(source)
                digest, size, mode = _sha256_file(admitted)
                if (digest, size, mode) != (
                        executable["sha256"], executable["bytes"], executable["mode"]):
                    raise RuntimeIdentityError(f"immutable helper changed during admission: {source}")
                anchors[key] = admitted
                for alias in (
                    "chrome", "google-chrome", "microsoft-edge", "chromium",
                    "chromium-browser", "google-chrome-stable",
                ):
                    alias_path = root / alias
                    if not os.path.lexists(alias_path):
                        os.symlink(str(admitted), alias_path)
                continue
            name = source.name
            if name in {path.name for path in anchors.values()}:
                name = f"{len(anchors)}-{name}"
            destination = root / name
            _copy_regular(source, destination, executable, mode=0o500)
            destination_mode = stat.S_IMODE(destination.lstat().st_mode)
            if destination_mode & 0o222 or not destination_mode & 0o111:
                raise RuntimeIdentityError(f"launch anchor is not immutable executable content: {destination}")
            anchored = _file_record(identity.get("role", "executable"), destination)
            if (anchored["sha256"], anchored["bytes"]) != (
                    executable["sha256"], executable["bytes"]):
                raise RuntimeIdentityError(f"launch anchor differs from admitted executable: {source}")
            anchors[key] = destination
            records.append({**anchored, "source_path": key})
        payload_roots, payload_records = {}, []
        for index, (source_root, receipt) in enumerate(payloads):
            if payload_scope is None:
                anchored_root, anchored_record = _copy_receipt_payload(
                    source_root, receipt, root, index,
                )
            else:
                lease = payload_scope.acquire(source_root, receipt)
                payload_leases.append(lease)
                anchored_root, anchored_record = lease.root, lease.record
            payload_roots[str(source_root)] = anchored_root
            payload_records.append(anchored_record)
        input_paths, private_checks = {}, []
        for index, spec in enumerate(input_specs):
            source = Path(spec["source"]).absolute()
            destination = root / f"input-{index}"
            if spec["kind"] == "file":
                check = _copy_input_file(source, destination, allow_absent=spec["allow_absent"])
            elif spec["kind"] == "tree":
                reusable = _active_tree_snapshot(source)
                if reusable is not None:
                    if reusable["role"] != spec["role"]:
                        raise RuntimeIdentityError("runtime tree snapshot role does not match its consumer")
                    check = dict(reusable["check"])
                    destination = reusable["path"]
                else:
                    check = _copy_input_tree(source, destination, allow_absent=spec["allow_absent"])
            else:
                raise RuntimeIdentityError("runtime input snapshot kind is unknown")
            check["role"] = spec["role"]
            check["private"] = bool(spec.get("private", False))
            input_paths[spec["key"]] = destination
            private_checks.append(check)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.chmod(root, 0o500)
        return (root, anchors, records, payload_roots, payload_records, input_paths,
                tuple(private_checks), tuple(payload_leases), root_identity)
    except BaseException as primary:
        cleanup_faults: list[BaseException] = []
        for lease in reversed(payload_leases):
            try:
                lease.release()
            except BaseException as exc:
                cleanup_faults.append(exc)
        try:
            _settle_launch_root(root, expected_identity=root_identity)
        except BaseException as exc:
            cleanup_faults.append(exc)
        cleanup_cancellation = next(
            (fault for fault in cleanup_faults if not isinstance(fault, Exception)), None,
        )
        if isinstance(primary, Exception) and cleanup_cancellation is not None:
            raise cleanup_cancellation.with_traceback(cleanup_cancellation.__traceback__)
        for cleanup_fault in cleanup_faults:
            primary.add_note(
                f"runtime launch cleanup also failed: {type(cleanup_fault).__name__}: "
                f"{cleanup_fault}"
            )
        raise primary.with_traceback(primary.__traceback__)


def _managed_identity(tool, executable: Path) -> tuple[dict, Path, dict]:
    from . import registry

    try:
        managed = registry.managed_runtime_receipt(tool)
    except Exception as exc:
        raise RuntimeIdentityError(
            f"managed runtime receipt is invalid for {tool.bin}: {type(exc).__name__}"
        ) from exc
    if managed is None:
        raise RuntimeIdentityError(
            f"{tool.bin} has no complete managed runtime receipt; reinstall it with Quarry"
        )
    root, receipt = managed
    identity = receipt["tools"].get(tool.bin)
    if not isinstance(identity, dict):
        raise RuntimeIdentityError(f"managed runtime receipt does not name {tool.bin}")
    expected = (root / identity["executable"]).resolve(strict=True)
    if executable != expected:
        raise RuntimeIdentityError(
            f"PATH substitution refused for {tool.bin}: {executable} != {expected}"
        )
    receipt_digest, receipt_bytes, _mode = _sha256_file(root / registry._RUNTIME_RECEIPT_NAME)
    record = {
        "attestation": "managed-receipt",
        "executable": _file_record("executable", executable),
        "identity": identity["content_identity"],
        "declared_identity": identity["identity"],
        "receipt": {"bytes": receipt_bytes, "path": str(root / registry._RUNTIME_RECEIPT_NAME),
                    "sha256": receipt_digest},
        "runtime": identity["runtime"],
        "runtime_root": str(root),
        "closure": _closure_record(receipt["files"]),
    }
    return record, root, receipt


def _host_identity(name: str, *, role: str) -> tuple[dict, Path]:
    executable = _resolve_executable(name)
    return ({"attestation": "host-digest", "executable": _file_record(role, executable),
             "identity": "sha256:" + _sha256_file(executable)[0], "runtime": "host",
             "runtime_root": str(executable.parent), "closure": None}, executable)


def _tool_identity(name: str) -> tuple[dict, Path, "object | None", "Path | None", "dict | None"]:
    from . import registry

    tool = registry.tool_for_bin(Path(name).name)
    executable = _resolve_executable(name)
    if tool is None or tool.policy == "distro":
        record, executable = _host_identity(str(executable), role="executable")
        if tool is not None:
            record["identity"] = "distro@sha256:" + record["executable"]["sha256"]
        return record, executable, tool, None, None
    record, root, receipt = _managed_identity(tool, executable)
    return record, executable, tool, root, receipt


def _dynamic_tree(root: Path, role: str) -> dict:
    """Hash an invocation-selected template/config tree without following links outside it."""
    try:
        root = root.resolve(strict=True)
        root_stat = root.stat()
    except OSError as exc:
        raise RuntimeIdentityError(f"required {role} tree is unavailable: {root}") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise RuntimeIdentityError(f"required {role} path is not a directory: {root}")
    rows, total = [], 0
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        observed = path.lstat()
        if stat.S_ISDIR(observed.st_mode):
            continue
        if stat.S_ISLNK(observed.st_mode):
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError) as exc:
                raise RuntimeIdentityError(f"{role} tree contains an escaping link: {relative}") from exc
            target = os.readlink(path).encode("utf-8", "strict")
            row = {"bytes": len(target), "kind": "symlink", "path": relative,
                   "sha256": hashlib.sha256(target).hexdigest()}
        elif stat.S_ISREG(observed.st_mode):
            digest, size, _mode = _sha256_file(path)
            row = {"bytes": size, "kind": "file", "path": relative, "sha256": digest}
        else:
            raise RuntimeIdentityError(f"{role} tree contains an unsupported object: {relative}")
        rows.append(row)
        total += row["bytes"]
        if len(rows) > _max_dynamic_files or total > _max_dynamic_bytes:
            raise RuntimeIdentityError(f"{role} tree exceeds its runtime-attestation bound")
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"bytes": total, "files": len(rows), "path": str(root), "role": role,
            "sha256": hashlib.sha256(canonical).hexdigest()}


def _nuclei_closure(environment: dict[str, str]) -> list[dict]:
    home = Path(environment.get("HOME") or Path.home())
    template_root = home / "nuclei-templates"
    return [_dynamic_tree(template_root, "nuclei-templates")]


def _subfinder_closure(environment: dict[str, str]) -> list[dict]:
    home = Path(environment.get("HOME") or Path.home())
    base = Path(environment.get("XDG_CONFIG_HOME") or home / ".config") / "subfinder"
    paths = (
        Path(environment.get("SUBFINDER_PROVIDER_CONFIG") or base / "provider-config.yaml"),
        Path(environment.get("SUBFINDER_CONFIG") or base / "config.yaml"),
    )
    return [_file_record("adapter-config", path) for path in paths if path.is_file()]


def _shebang(path: Path) -> "tuple[str, tuple[str, ...]] | None":
    """Return a safely parsed kernel interpreter request for a managed script."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        line = os.read(fd, 4096).split(b"\n", 1)[0]
    finally:
        os.close(fd)
    if not line.startswith(b"#!"):
        return None
    try:
        words = shlex.split(line[2:].decode("utf-8", "strict").strip())
    except (UnicodeError, ValueError) as exc:
        raise RuntimeIdentityError(f"managed script has an invalid shebang: {path}") from exc
    if not words or any("\x00" in word for word in words):
        raise RuntimeIdentityError(f"managed script has an empty/invalid shebang: {path}")
    if Path(words[0]).name == "env":
        tail = words[1:]
        if tail[:1] == ["-S"]:
            tail = tail[1:]
        if not tail or tail[0].startswith("-") or "=" in tail[0]:
            raise RuntimeIdentityError(f"managed script uses an ambiguous env shebang: {path}")
        return tail[0], tuple(tail[1:])
    return words[0], tuple(words[1:])


def _lexically_below(path: str, root: Path) -> "Path | None":
    candidate = Path(path)
    if not candidate.is_absolute():
        return None
    try:
        return candidate.relative_to(root)
    except ValueError:
        return None


def _immutable_system_file(path: Path) -> Path:
    """Prove a helper name and every ancestor are root-owned and non-writable."""
    resolved = path.resolve(strict=True)
    observed = resolved.stat()
    if (not stat.S_ISREG(observed.st_mode) or not os.access(resolved, os.X_OK)
            or observed.st_uid != 0 or observed.st_mode & 0o022):
        raise RuntimeIdentityError(f"system helper is not immutable root authority: {resolved}")
    cursor = resolved.parent
    while True:
        parent = cursor.stat()
        if parent.st_uid != 0 or parent.st_mode & 0o022:
            raise RuntimeIdentityError(f"system helper ancestry is not immutable root authority: {cursor}")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    return resolved


def _browser_identity() -> tuple[dict, Path]:
    candidates = (
        Path("/usr/lib/chromium/chromium"), Path("/opt/google/chrome/chrome"),
        Path("/usr/lib/chromium-browser/chromium-browser"),
    )
    for candidate in candidates:
        try:
            executable = _immutable_system_file(candidate)
        except (OSError, RuntimeIdentityError):
            continue
        record = {
            "attestation": "immutable-system-name",
            "executable": _file_record("browser", executable),
            "identity": "sha256:" + _sha256_file(executable)[0],
            "runtime": "host-browser",
            "runtime_root": str(executable.parent),
            "closure": None,
            "role": "browser",
        }
        return record, executable
    raise RuntimeIdentityError("no immutable exact Chromium runtime is available")


def _exact_caller_environment(caller: "dict | None") -> dict[str, str]:
    """Copy an exact builtin string mapping without invoking subclass behavior."""
    if caller is None:
        return {}
    if type(caller) is not dict:
        raise RuntimeIdentityError("caller environment must be an exact string mapping")
    result: dict[str, str] = {}
    for key, value in dict.items(caller):
        if type(key) is not str or type(value) is not str:
            raise RuntimeIdentityError("caller environment must be an exact string mapping")
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise RuntimeIdentityError("caller environment contains an invalid key or value")
        result[key] = value
    return result


def _minimal_environment(tool, executable_paths: list[Path], caller: "dict | None") -> dict[str, str]:
    from . import secrets

    caller = _exact_caller_environment(caller)
    ambient = os.environ
    allowed = set(_base_environment_names)
    if tool is not None:
        allowed.update(tool.env_allow or ())
        allowed.difference_update(tool.credential_env or ())
    environment = {name: ambient[name] for name in allowed if name in ambient}
    environment.setdefault("HOME", str(Path.home()))
    path_parts = []
    for path in (*executable_paths, *(Path(item) for item in _system_path)):
        directory = path if path.is_dir() else path.parent
        text = str(directory)
        if text not in path_parts:
            path_parts.append(text)
    environment["PATH"] = os.pathsep.join(path_parts)
    if caller:
        permitted = set(_caller_environment_names)
        if tool is not None:
            permitted.update(tool.env_allow or ())
            permitted.difference_update(tool.credential_env or ())
        unknown = set(caller) - permitted
        if unknown:
            raise RuntimeIdentityError(
                "caller environment contains non-allowlisted names: " + ", ".join(sorted(unknown))
            )
        environment.update(caller)
    if tool is not None:
        environment.update(secrets.adapter_environment(tool.bin, tool.credential_env or ()))
    return environment


def prepare_launch(tool_name: str, argv: list[str], *, caller_env: "dict | None" = None,
                   payload_scope: "ManagedPayloadSnapshotScope | None" = None) -> PreparedLaunch:
    """Resolve and attest one launch without executing it or exposing credential values."""
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise RuntimeIdentityError("runtime argv must be a non-empty string list")
    caller_env = _exact_caller_environment(caller_env)
    main, executable, tool, root, receipt = _tool_identity(argv[0])
    if tool is not None and tool.bin != tool_name:
        raise RuntimeIdentityError(
            f"runtime adapter {tool_name!r} attempted executable {tool.bin!r}"
        )
    identities = [dict(main, role="adapter")]
    executable_paths = [executable]
    for dependency_name in (tool.runtime_bins if tool is not None else ()) or ():
        identity, dependency, _decl, _root, _receipt = _tool_identity(dependency_name)
        identities.append(dict(identity, role="dependency"))
        executable_paths.append(dependency)

    browser_path = None
    if tool is not None and tool.needs_chromium:
        browser, browser_path = _browser_identity()
        identities.append(browser)
        executable_paths.append(browser_path)

    payloads: list[tuple[Path, dict]] = []
    command_args = list(argv[1:])
    input_specs: list[dict] = []
    input_arg_indexes: dict[int, str] = {}
    browser_arg_indexes: list[int] = []
    environment_inputs: dict[str, str] = {}

    # Every explicit -config file is snapshotted. These files can carry credentials, so their digests and
    # names remain in PreparedLaunch's private checks and never enter the public identity record.
    for index, item in enumerate(tuple(command_args[:-1])):
        if item in {"-config", "--config"}:
            value = command_args[index + 1]
            if not value or "\x00" in value or not Path(value).is_absolute():
                raise RuntimeIdentityError("runtime config path is invalid")
            key = f"argv-config-{index}"
            input_specs.append({"key": key, "role": "private-config", "kind": "file",
                                "source": value, "allow_absent": False,
                                "private": True})
            input_arg_indexes[index + 1] = key

    if tool_name == "github-subdomains":
        for index, item in enumerate(tuple(command_args[:-1])):
            if item in {"-t", "--token-file"}:
                value = command_args[index + 1]
                if not value or "\x00" in value or not Path(value).is_absolute():
                    raise RuntimeIdentityError("GitHub credential file path is invalid")
                key = f"github-token-file-{index}"
                input_specs.append({"key": key, "role": "github-token-file", "kind": "file",
                                    "source": value, "allow_absent": False, "private": True})
                input_arg_indexes[index + 1] = key

    ambient_plus_caller = dict(os.environ)
    ambient_plus_caller.update(caller_env)
    if tool_name == "subfinder":
        home = Path(ambient_plus_caller.get("HOME") or Path.home())
        xdg = Path(ambient_plus_caller.get("XDG_CONFIG_HOME") or home / ".config")
        provider_value = ambient_plus_caller.get("SUBFINDER_PROVIDER_CONFIG")
        config_value = ambient_plus_caller.get("SUBFINDER_CONFIG")
        if provider_value and not Path(provider_value).is_absolute():
            raise RuntimeIdentityError("SUBFINDER_PROVIDER_CONFIG must be absolute")
        if config_value and not Path(config_value).is_absolute():
            raise RuntimeIdentityError("SUBFINDER_CONFIG must be absolute")
        sources = {
            "SUBFINDER_PROVIDER_CONFIG": Path(
                provider_value or xdg / "subfinder" / "provider-config.yaml"
            ),
            "SUBFINDER_CONFIG": Path(config_value or xdg / "subfinder" / "config.yaml"),
        }
        flags = {"SUBFINDER_PROVIDER_CONFIG": "-pc", "SUBFINDER_CONFIG": "-config"}
        for name, source in sources.items():
            key = name.lower()
            input_specs.append({"key": key, "role": name.lower(), "kind": "file",
                                "source": str(source), "allow_absent": True, "private": True})
            environment_inputs[name] = key
            if flags[name] not in command_args:
                command_args.extend((flags[name], f"@input:{key}"))
                input_arg_indexes[len(command_args) - 1] = key

    if tool_name == "nuclei":
        home = Path(ambient_plus_caller.get("HOME") or Path.home())
        config_value = ambient_plus_caller.get("NUCLEI_CONFIG")
        if config_value and not Path(config_value).is_absolute():
            raise RuntimeIdentityError("NUCLEI_CONFIG must be absolute")
        config_source = Path(
            config_value
            or Path(ambient_plus_caller.get("XDG_CONFIG_HOME") or home / ".config") / "nuclei"
        )
        template_source = home / "nuclei-templates"
        input_specs.extend((
            {"key": "nuclei-config", "role": "nuclei-config", "kind": "tree",
             "source": str(config_source), "allow_absent": True, "private": True},
            {"key": "nuclei-templates", "role": "nuclei-templates", "kind": "tree",
             "source": str(template_source), "allow_absent": False, "private": False},
        ))
        environment_inputs["NUCLEI_CONFIG"] = "nuclei-config"
        if not any(item in {"-t", "-templates"} for item in command_args):
            command_args.extend(("-t", "@input:nuclei-templates"))
            input_arg_indexes[len(command_args) - 1] = "nuclei-templates"

    if browser_path is not None:
        path_flags = (
            ("--chrome-path",) if tool_name == "gowitness"
            else ("-scp", "-system-chrome-path") if tool_name == "katana"
            else ()
        )
        selected_flags = [index for index, item in enumerate(command_args) if item in path_flags]
        if len(selected_flags) > 1:
            raise RuntimeIdentityError(f"{tool_name} declares more than one browser authority")
        if selected_flags:
            value_index = selected_flags[0] + 1
            if value_index >= len(command_args):
                raise RuntimeIdentityError(f"{tool_name} browser path flag has no value")
            selected = command_args[value_index]
            try:
                selected_path = (
                    Path(selected).resolve(strict=True)
                    if selected and "\x00" not in selected and Path(selected).is_absolute()
                    else None
                )
            except OSError:
                selected_path = None
            if selected_path != browser_path:
                raise RuntimeIdentityError(f"{tool_name} browser path differs from its admitted identity")
            browser_arg_indexes.append(value_index)
        elif tool_name == "gowitness":
            command_args.extend(("--chrome-path", "@browser"))
            browser_arg_indexes.append(len(command_args) - 1)
        elif tool_name == "katana":
            command_args.extend(("-system-chrome-path", "@browser"))
            browser_arg_indexes.append(len(command_args) - 1)
        elif tool_name == "nuclei" and not any(
                item in {"-cdpe", "-cdp-endpoint"} for item in command_args):
            if not any(item in {"-sc", "-system-chrome"} for item in command_args):
                command_args.append("-system-chrome")

    launch_source = str(executable)
    entry_relative = None
    entry_environment_relative: dict[str, str] = {}
    shebang = None
    shebang_interpreter_source = None
    if tool is not None and tool.runtime_entry:
        if root is None or receipt is None:
            raise RuntimeIdentityError(f"{tool.bin} wrapper payload has no managed receipt")
        entry = (root / "home" / tool.runtime_entry).resolve(strict=True)
        try:
            entry.relative_to(root)
        except ValueError as exc:
            raise RuntimeIdentityError(f"{tool.bin} runtime entry escapes its receipt") from exc
        declared = next((item for item in tool.runtime_payloads or ()
                         if item["path"] == tool.runtime_entry), None)
        if declared is None or _sha256_file(entry)[0] != declared["sha256"]:
            raise RuntimeIdentityError(f"{tool.bin} runtime entry digest is not declared")
        runtime_identity, runtime_exec, _decl, _root, _receipt = _tool_identity(tool.runtime_exec)
        identities.append(dict(runtime_identity, role="interpreter"))
        executable_paths.append(runtime_exec)
        payloads.append((root, receipt))
        launch_source = str(runtime_exec)
        entry_relative = Path("home") / tool.runtime_entry
        for name, relative in (tool.runtime_entry_env or {}).items():
            payload = (root / "home" / relative).resolve(strict=True)
            try:
                payload.relative_to(root)
            except ValueError as exc:
                raise RuntimeIdentityError(f"{tool.bin} runtime environment payload escapes") from exc
            declared = next((item for item in tool.runtime_payloads or ()
                             if item["path"] == relative), None)
            if declared is None or _sha256_file(payload)[0] != declared["sha256"]:
                raise RuntimeIdentityError(f"{tool.bin} runtime environment payload is not declared")
            entry_environment_relative[name] = str(Path("home") / relative)
    else:
        shebang = _shebang(executable)
        if shebang is not None:
            interpreter_name, _interpreter_args = shebang
            lexical = _lexically_below(interpreter_name, root) if root is not None else None
            if root is not None and receipt is not None:
                payloads.append((root, receipt))
            if lexical is not None:
                shebang_interpreter_source = lexical
            else:
                interpreter_identity, interpreter, _decl, _root, _receipt = _tool_identity(
                    interpreter_name,
                )
                identities.append(dict(interpreter_identity, role="shebang-interpreter"))
                executable_paths.append(interpreter)
                shebang_interpreter_source = str(interpreter)

    # Preserve order while de-duplicating shared managed roots.
    payloads = list({str(item[0]): item for item in payloads}.values())
    (anchor_root, anchors, anchor_records, payload_roots, payload_records, input_paths,
     private_checks, payload_leases, anchor_identity) = _launch_anchors(
         identities, payloads, input_specs, payload_scope=payload_scope,
     )
    try:
        if launch_source not in anchors:
            raise RuntimeIdentityError("selected runtime executable has no private launch authority")
        for index, key in input_arg_indexes.items():
            command_args[index] = str(input_paths[key])
        for index in browser_arg_indexes:
            command_args[index] = str(anchors[str(browser_path)])

        entry_environment: dict[str, str] = {}
        if entry_relative is not None:
            payload_root = payload_roots[str(root)]
            entry_path = (payload_root / entry_relative).resolve(strict=True)
            actual = [str(anchors[launch_source]), *(tool.runtime_argv_prefix or ()),
                      str(entry_path), *command_args]
            source_argument_offset = 2 + len(tool.runtime_argv_prefix or ())
            entry_environment = {
                name: str((payload_root / relative).resolve(strict=True))
                for name, relative in entry_environment_relative.items()
            }
        elif shebang is not None:
            _interpreter_name, interpreter_args = shebang
            if isinstance(shebang_interpreter_source, Path):
                interpreter = (payload_roots[str(root)] / shebang_interpreter_source).resolve(strict=True)
            else:
                interpreter = anchors[str(shebang_interpreter_source)]
            if root is not None and str(root) in payload_roots:
                relative = Path(receipt["tools"][tool.bin]["executable"])
                script = (payload_roots[str(root)] / relative).resolve(strict=True)
            else:
                script = anchors[str(executable)]
            actual = [str(interpreter), *interpreter_args, str(script), *command_args]
            source_argument_offset = 2 + len(interpreter_args)
        else:
            actual = [str(anchors[launch_source]), *command_args]
            source_argument_offset = 1

        source_argv_indexes = (
            0, *(source_argument_offset + index for index in range(len(argv) - 1)),
        )

        environment = _minimal_environment(tool, list(anchors.values()), caller_env)
        environment.update(entry_environment)
        for name, key in environment_inputs.items():
            environment[name] = str(input_paths[key])
        dynamic = [
            _dynamic_tree(Path(check["anchor"]), check["role"])
            for check in private_checks
            if not check["private"] and check["anchor_kind"] == "tree"
        ]
        record = {
            "schema_version": _identity_schema,
            "tool": tool_name,
            "argv_items": len(actual),
            "environment_keys": sorted(environment),
            "credential_environment_keys": sorted(
                set(tool.credential_env or ()) & set(environment) if tool is not None else set()
            ),
            "identities": identities,
            "selected_executable": _file_record("selected-executable", Path(actual[0])),
            "launch_anchors": anchor_records,
            "payload_anchors": payload_records,
            "private_inputs": [
                {"kind": check["anchor_kind"], "role": check["role"],
                 "source_state": check["source_kind"]}
                for check in private_checks if check["private"]
            ],
            "dynamic_closure": dynamic,
        }
        from . import secrets
        redactions = set(secrets.values()) if any(
            check["private"] for check in private_checks
        ) or (tool is not None and bool(tool.credential_env)) else set()
        if tool is not None:
            redactions.update(
                environment[name] for name in (tool.credential_env or ()) if name in environment
            )
        exact_redactions = tuple(sorted(
            (value for value in redactions if isinstance(value, str) and len(value) >= 6),
            key=lambda value: (-len(value.encode("utf-8", "strict")), value),
        ))
        return PreparedLaunch(
            tuple(actual), environment, record, anchor_root,
            private_checks=private_checks, redactions=exact_redactions,
            payload_leases=payload_leases, source_argv_indexes=source_argv_indexes,
            anchor_identity=anchor_identity,
        )
    except BaseException as primary:
        try:
            PreparedLaunch(
                (), {}, {}, anchor_root, payload_leases=payload_leases,
                anchor_identity=anchor_identity,
            ).close()
        except BaseException as cleanup_fault:
            if not isinstance(primary, Exception):
                primary.add_note(
                    f"runtime launch cleanup also failed: {type(cleanup_fault).__name__}: "
                    f"{cleanup_fault}"
                )
                raise primary.with_traceback(primary.__traceback__)
            if not isinstance(cleanup_fault, Exception):
                raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
            primary.add_note(
                f"runtime launch cleanup also failed: {type(cleanup_fault).__name__}: {cleanup_fault}"
            )
        raise


def revalidate_launch(prepared: PreparedLaunch) -> None:
    """Reconcile every recorded executable/payload/template identity immediately before spawn."""
    if not isinstance(prepared, PreparedLaunch) or prepared.record.get("schema_version") != _identity_schema:
        raise RuntimeIdentityError("runtime launch record is not an admitted v1 identity")
    if (not isinstance(prepared.source_argv_indexes, tuple)
            or not prepared.source_argv_indexes
            or prepared.source_argv_indexes[0] != 0
            or any(type(index) is not int or index < 0 or index >= len(prepared.argv)
                   for index in prepared.source_argv_indexes)
            or tuple(sorted(set(prepared.source_argv_indexes))) != prepared.source_argv_indexes):
        raise RuntimeIdentityError("runtime source argv mapping is invalid")
    root = prepared.anchor_root
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise RuntimeIdentityError("private runtime launch directory is unavailable") from exc
    if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) != 0o500 or root.is_symlink()):
        raise RuntimeIdentityError("private runtime launch directory identity is unsafe")
    if prepared.anchor_identity != (root_stat.st_dev, root_stat.st_ino):
        raise RuntimeIdentityError("private runtime launch directory identity changed")
    anchors = prepared.record.get("launch_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise RuntimeIdentityError("runtime launch has no anchored executable identities")
    anchor_paths = set()
    for anchor in anchors:
        if not isinstance(anchor, dict) or not isinstance(anchor.get("source_path"), str):
            raise RuntimeIdentityError("runtime launch anchor record is malformed")
        path = Path(anchor.get("path", ""))
        try:
            if path.parent != root or path.resolve(strict=True).parent != root.resolve(strict=True):
                raise RuntimeIdentityError("runtime launch anchor escapes its private authority")
        except OSError as exc:
            raise RuntimeIdentityError("runtime launch anchor is unavailable") from exc
        digest, size, mode = _sha256_file(path)
        if (digest, size, mode) != (anchor.get("sha256"), anchor.get("bytes"), anchor.get("mode")):
            raise RuntimeIdentityError(f"runtime launch anchor changed before spawn: {path}")
        anchor_paths.add(str(path))
    selected = prepared.record.get("selected_executable")
    if not isinstance(selected, dict) or prepared.argv[0] != selected.get("path"):
        raise RuntimeIdentityError("runtime argv does not select its admitted executable")
    selected_observed = _file_record("selected-executable", Path(prepared.argv[0]))
    if selected_observed != selected:
        raise RuntimeIdentityError("selected runtime executable changed before spawn")
    for identity in prepared.record.get("identities") or ():
        executable = identity.get("executable") if isinstance(identity, dict) else None
        if not isinstance(executable, dict):
            raise RuntimeIdentityError("runtime executable identity is absent")
        path = Path(executable.get("path", ""))
        digest, size, mode = _sha256_file(path)
        if (digest, size, mode) != (
                executable.get("sha256"), executable.get("bytes"), executable.get("mode")):
            raise RuntimeIdentityError(f"runtime executable changed before spawn: {path}")
        if identity.get("attestation") == "managed-receipt":
            root = Path(identity.get("runtime_root", ""))
            from . import registry
            receipt_path = root / registry._RUNTIME_RECEIPT_NAME
            receipt_digest, receipt_size, _receipt_mode = _sha256_file(receipt_path)
            receipt = identity.get("receipt") or {}
            if (receipt_digest, receipt_size) != (receipt.get("sha256"), receipt.get("bytes")):
                raise RuntimeIdentityError("managed runtime receipt changed before spawn")
            if _closure_record(registry._tree_rows(root)) != identity.get("closure"):
                raise RuntimeIdentityError("managed runtime closure changed before spawn")
        elif identity.get("attestation") == "immutable-system-name":
            if _immutable_system_file(path) != path.resolve(strict=True):
                raise RuntimeIdentityError("immutable system helper name changed before spawn")
    from . import registry
    payload_leases = {str(lease.root): lease for lease in prepared.payload_leases}
    if len(payload_leases) != len(prepared.payload_leases):
        raise RuntimeIdentityError("runtime payload snapshot leases are duplicated")
    observed_payload_leases = set()
    for payload in prepared.record.get("payload_anchors") or ():
        if not isinstance(payload, dict) or set(payload) != {"closure", "root", "source_root"}:
            raise RuntimeIdentityError("runtime payload anchor record is malformed")
        lease = payload_leases.get(payload["root"])
        if lease is not None:
            if lease.record != payload:
                raise RuntimeIdentityError("managed payload snapshot record changed before spawn")
            lease.validate()
            observed_payload_leases.add(payload["root"])
        elif _closure_record(registry._tree_rows(Path(payload["root"]))) != payload["closure"]:
            raise RuntimeIdentityError("private managed payload closure changed before spawn")
    if observed_payload_leases != set(payload_leases):
        raise RuntimeIdentityError("runtime payload snapshot lease is absent from its identity record")
    for check in prepared.private_checks:
        source = Path(check["source"])
        if check["source_kind"] == "absent":
            if os.path.lexists(source):
                raise RuntimeIdentityError("an absent runtime input appeared before spawn")
        elif check["source_kind"] == "file":
            if _file_record("private-input", source) != check["source_expected"]:
                raise RuntimeIdentityError("private runtime input changed before spawn")
        elif check["source_kind"] == "tree":
            observed = _record_without_path(_dynamic_tree(source, "private-tree"))
            if observed != check["source_expected"]:
                raise RuntimeIdentityError("private runtime tree changed before spawn")
        elif check["source_kind"] == "detached-tree":
            # The source was reconciled before/after the lane snapshot. Launches consume only the detached
            # private authority, so later source mutation cannot alter executed bytes.
            pass
        else:
            raise RuntimeIdentityError("private runtime source state is malformed")
        anchor = Path(check["anchor"])
        if check["anchor_kind"] == "file":
            digest, size, _mode = _sha256_file(anchor)
            observed = {"bytes": size, "sha256": digest}
        elif check["anchor_kind"] == "tree":
            observed = _record_without_path(_dynamic_tree(anchor, "private-tree"))
        else:
            raise RuntimeIdentityError("private runtime anchor state is malformed")
        if observed != check["expected"]:
            raise RuntimeIdentityError("private runtime input anchor changed before spawn")
    for dynamic in prepared.record.get("dynamic_closure") or ():
        if not isinstance(dynamic, dict):
            raise RuntimeIdentityError("dynamic runtime closure is malformed")
        keys = set(dynamic)
        if keys == {"bytes", "files", "path", "role", "sha256"}:
            observed = _dynamic_tree(Path(dynamic["path"]), str(dynamic["role"]))
        elif keys == {"bytes", "mode", "path", "role", "sha256"}:
            observed = _file_record(str(dynamic["role"]), Path(dynamic["path"]))
        else:
            raise RuntimeIdentityError("dynamic runtime closure has an unknown shape")
        if observed != dynamic:
            raise RuntimeIdentityError("dynamic runtime closure changed before spawn")


def publish_launch_identity(repository, request_id: str, record: dict) -> str:
    """Durably bind one credential-free launch record into the run before execution."""
    if not isinstance(request_id, str) or len(request_id) != 32 or any(
            char not in "0123456789abcdef" for char in request_id):
        raise RuntimeIdentityError("runtime request identity is invalid")
    data = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8", "strict")
    components = ("raw", "runtime-identities", f"{request_id}.json")
    with repository.artifact_claim(*components) as claim:
        writer = claim.open_writer()
        view = memoryview(data)
        while view:
            written = os.write(writer, view)
            if written <= 0:
                raise RuntimeIdentityError("runtime identity write made no progress")
            view = view[written:]
        claim.publish()
    return "/".join(components)
