"""Descriptor-based private filesystem helpers: dirs 0700, files 0600 at creation, every component opened
O_NOFOLLOW through a directory fd so no symlinked level can redirect a write outside the tree."""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import signal
import stat
import threading
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600
_MAX_WORKER_PID = (1 << 31) - 1


def _harden_fd(fd: int, *, is_dir: bool) -> bool:
    """True iff `fd` ends up owned by us with no group/other bits, tightening it if loose; else False."""
    try:
        st = os.fstat(fd)
    except OSError:
        return False
    if st.st_uid != os.geteuid():
        return False
    if stat.S_IMODE(st.st_mode) & 0o077:
        try:
            os.fchmod(fd, DIR_MODE if is_dir else FILE_MODE)
        except OSError:
            return False
        return not (stat.S_IMODE(os.fstat(fd).st_mode) & 0o077)
    return True


def _walk_dirfd(directory) -> int:
    """A fd for `directory`, creating missing levels 0700 and refusing a symlinked component (O_NOFOLLOW);
    an existing loose leaf is tightened, ancestors left alone. Caller owns the fd."""
    directory = Path(directory)
    parts = directory.parts
    if directory.is_absolute():
        dfd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        rest = parts[1:]
    else:
        dfd = os.open(os.getcwd(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        rest = parts
    try:
        created = True
        for comp in rest:
            try:
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                created = False
            except FileNotFoundError:
                try:
                    os.mkdir(comp, DIR_MODE, dir_fd=dfd)
                    created = True
                except FileExistsError:
                    created = False          # a concurrent walker made it; adopt and harden it below
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
            os.close(dfd)
            dfd = nfd
        if not created and not _harden_fd(dfd, is_dir=True):
            raise OSError(f"cannot make {directory} private (foreign owner or fchmod failed)")
        return dfd
    except BaseException:
        os.close(dfd)
        raise


def private_dir(path) -> Path:
    """Create `path` and missing parents 0700, refusing a symlinked component; tighten the leaf if loose."""
    os.close(_walk_dirfd(path))
    return Path(path)


def open_private(path, *, append: bool = False) -> int:
    """A 0600 write fd owned by us or it raises; O_NOFOLLOW/O_NONBLOCK in a symlink-safe 0700 parent, truncates
    unless `append`."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    try:
        # no O_TRUNC yet: validate the target before destroying any existing content
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_APPEND if append else 0)
        fd = os.open(path.name, flags, FILE_MODE, dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or not _harden_fd(fd, is_dir=False):
            raise OSError(f"refusing a non-regular or non-private target: {path}")
        if not append:
            os.ftruncate(fd, 0)          # truncate only after ownership/mode/type are verified
    except BaseException:
        os.close(fd)
        raise
    return fd


def write_private(path, text: str, *, encoding: str = "utf-8") -> None:
    """Atomically replace `path` with 0600 content via an exclusive random-named same-dir temp (O_EXCL|O_NOFOLLOW
    refuses a planted symlink, hard link or reused name), then rename inside the parent dir fd."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    tmp = f".{path.name}.{os.urandom(8).hex()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=dfd)
        try:
            with os.fdopen(fd, "w", encoding=encoding) as fh:
                fh.write(text)
            os.replace(tmp, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(dfd)


def append_private(path, text: str, *, encoding: str = "utf-8") -> None:
    """Append to `path`, creating it 0600 (and tightening an existing loose file) in a symlink-safe parent."""
    with os.fdopen(open_private(path, append=True), "a", encoding=encoding) as fh:
        fh.write(text)


def touch_private(path) -> Path:
    """Ensure `path` exists as a 0600 regular file owned by us in a 0700 parent, or raise. Tightens a
    pre-existing loose file; refuses a symlink, FIFO/device, or another user's file."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    try:
        try:
            os.close(os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=dfd))
        except FileExistsError:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode) or not _harden_fd(fd, is_dir=False):
                    raise OSError(f"refusing a non-regular or non-private target: {path}")
            finally:
                os.close(fd)
    finally:
        os.close(dfd)
    return path


def open_ro_private(path) -> int:
    """A read fd for a regular file owned by us, opened through a symlink-safe parent dir-fd walk (O_NOFOLLOW at
    every level) so no swapped component can redirect the read; raises otherwise. Caller owns the fd."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or not _harden_fd(fd, is_dir=False):
            raise OSError(f"refusing a non-regular or non-private file: {path}")   # never accept a loose file
    except BaseException:
        os.close(fd)
        raise
    return fd


def is_private(path) -> bool:
    """Whether `path` is a regular file or directory owned by us with no group/other bits (never a symlink,
    FIFO, socket or device)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return False
    return st.st_uid == os.geteuid() and not (stat.S_IMODE(st.st_mode) & 0o077)


def harden(path) -> bool:
    """Tighten an owned, too-loose regular file or directory to the private mode; refuse a symlink, another
    user's path, or a non-regular non-directory (FIFO/socket/device). Returns whether it ends up private."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if st.st_uid != os.geteuid() or stat.S_ISLNK(st.st_mode):
        return False
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return False
    if stat.S_IMODE(st.st_mode) & 0o077:
        try:
            os.chmod(path, DIR_MODE if stat.S_ISDIR(st.st_mode) else FILE_MODE, follow_symlinks=False)
        except OSError:
            return False
    return True


def write_json_private(path, obj, *, indent=None) -> None:
    write_private(path, json.dumps(obj, ensure_ascii=False, indent=indent))


# The helpers above are the v0.3.9 compatibility surface.  They intentionally retain
# their historical create-and-tighten behaviour until callers move behind the Phase 1
# repository authority.  The descriptor-relative core below is strict by default: it
# never creates or repairs an object while opening it.

_MAX_COMPONENTS = 64
_MAX_COMPONENT_BYTES = 255
_MAX_RELATIVE_PATH_BYTES = 4096
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_OPEN_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_OPEN_FLAGS = os.O_RDONLY | _O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_STAGE_OPEN_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW |
                     os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))


def _detect_strict_capability_gaps() -> tuple[str, ...]:
    supports_dir_fd = getattr(os, "supports_dir_fd", frozenset())
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", frozenset())
    required = (
        (_O_DIRECTORY != 0, "O_DIRECTORY"),
        (_O_NOFOLLOW != 0, "O_NOFOLLOW"),
        (os.open in supports_dir_fd, "descriptor-relative open"),
        (os.stat in supports_dir_fd, "descriptor-relative stat"),
        (os.stat in supports_follow_symlinks, "no-follow stat"),
        (os.rename in supports_dir_fd, "descriptor-relative rename"),
        (os.unlink in supports_dir_fd, "descriptor-relative unlink"),
        (hasattr(os, "fchmod"), "descriptor chmod"),
        (hasattr(os, "fsync"), "descriptor fsync"),
        (hasattr(fcntl, "F_DUPFD_CLOEXEC"), "atomic close-on-exec descriptor duplicate"),
    )
    return tuple(name for available, name in required if not available)


_STRICT_CAPABILITY_GAPS = _detect_strict_capability_gaps()


class PrivatePathError(RuntimeError):
    """Base class for a strict managed-path failure."""

    def __init__(self, message: str, *, components: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.components = components


class PrivatePathMissing(PrivatePathError):
    """A validated managed path component does not exist."""


class PrivatePathUnsafe(PrivatePathError):
    """A managed path exists, but its structure or identity is unsafe."""


class PrivatePathUnsupported(PrivatePathError):
    """The host cannot provide Quarry's strict descriptor-relative contract."""


def _require_strict_capabilities() -> None:
    if _STRICT_CAPABILITY_GAPS:
        raise PrivatePathUnsupported(
            "strict private filesystem support is unavailable: "
            + ", ".join(_STRICT_CAPABILITY_GAPS),
        )


class LegacyModeMismatch(PrivatePathUnsafe):
    """An otherwise safe, owned object does not have the exact managed mode."""

    def __init__(self, *, components: tuple[str, ...], expected: int, actual: int) -> None:
        super().__init__(
            f"managed path has mode {actual:#05o}; expected {expected:#05o}",
            components=components,
        )
        self.expected = expected
        self.actual = actual


class PrivateReplaceUncertain(PrivatePathError):
    """The rename landed, but durability or final-path identity is uncertain."""


class PrivateReplaceCommittedWithFault(PrivatePathError):
    """A replacement committed durably, but settlement also observed a fault."""


_STAGE_OPERATIONS = frozenset({
    "prepare", "seal", "replace", "abort", "abort_handoff",
    "abort_spawn", "borrow_spawn", "mark_spawned", "bind_worker", "transfer", "fence",
})
_STAGE_STATES = frozenset({
    "open", "sealed", "handoff_prepared", "publishing", "committed",
    "replaced_uncertain", "aborted", "prepared", "spawn_prepared",
    "worker_spawned_unverified", "worker_claim_bound", "parent_writers_closed",
    "transfer_uncertain", "settled", "fenced",
})


class PrivateStageStateError(PrivatePathError):
    """A fixed, credential-safe private-stage lifecycle refusal."""

    def __init__(self, operation: str, state: str) -> None:
        if (type(operation) is not str or operation not in _STAGE_OPERATIONS
                or type(state) is not str or state not in _STAGE_STATES):
            raise TypeError("invalid private stage operation or state")
        self.operation = operation
        self.state = state
        super().__init__(
            f"private stage operation {operation} is invalid in state {state}",
        )


class PrivateStageHandoffError(PrivatePathError):
    """A fixed, credential-safe batch handoff or cleanup failure."""

    def __init__(self, operation: str) -> None:
        if type(operation) is not str or operation not in {
            "prepare", "abort_handoff", "abort_spawn", "mark_spawned",
            "borrow_spawn", "bind_worker", "transfer", "fence",
        }:
            raise TypeError("invalid private stage handoff operation")
        self.operation = operation
        self.cleanup_errors: tuple[BaseException, ...] = ()
        self.close_errors: tuple[BaseException, ...] = ()
        super().__init__(f"private stage handoff {operation} failed")


class PrivateStageTransferUncertain(PrivateStageHandoffError):
    """The registered parent writer-close boundary did not settle cleanly.

    The immutable inode facts are safe to use for later quarantine and audit, but
    this exception is deliberately not a successful transfer receipt and conveys
    no writable descriptor, path, request correlation value, process proof or
    content claim.
    """

    def __init__(
        self, *, claimed_worker_pid: int,
        file_identities: tuple[tuple[int, int], ...],
    ) -> None:
        super().__init__("transfer")
        self.claimed_worker_pid = claimed_worker_pid
        self.file_identities = file_identities

    def __repr__(self) -> str:
        return (
            "PrivateStageTransferUncertain("
            f"stages={len(self.file_identities)}, state='transfer_uncertain')"
        )


class PrivateStageBindUncertain(PrivateStageHandoffError):
    """A caller-attested worker-claim bind was interrupted at its boundary.

    ``authority`` is the sole opaque recovery capability.  It is intentionally
    omitted from rendering; a supervisor may use it only to complete transfer
    after independently validating process identity, containment and readiness.
    """

    def __init__(
        self,
        *,
        authority: object,
        claimed_worker_pid: int | None,
        file_identities: tuple[tuple[int, int], ...],
    ) -> None:
        super().__init__("bind_worker")
        self.authority = authority
        self.claimed_worker_pid = claimed_worker_pid
        self.file_identities = file_identities

    def __repr__(self) -> str:
        return (
            "PrivateStageBindUncertain("
            f"stages={len(self.file_identities)}, state='worker_claim_bound')"
        )


class PrivateStageSpawnUncertain(PrivateStageHandoffError):
    """A spawn callback ran, but recording its PID correlation was interrupted.

    When this exception escapes through the normal cooperative path, the callback
    wrapper has attempted to fence and consume ``authority``.  The field is opaque
    diagnostic correlation, not process or recovery authority.  An unrelated
    asynchronous escape follows the spawn wrapper's explicit supervisor-recovery
    contract instead.
    """

    def __init__(
        self,
        *,
        authority: object,
        claimed_worker_pid: int | None,
        file_identities: tuple[tuple[int, int], ...],
    ) -> None:
        super().__init__("mark_spawned")
        self.authority = authority
        self.claimed_worker_pid = claimed_worker_pid
        self.file_identities = file_identities

    def __repr__(self) -> str:
        return (
            "PrivateStageSpawnUncertain("
            f"stages={len(self.file_identities)}, state='worker_spawned_unverified')"
        )


def validate_relative_components(
    components: tuple[str, ...], *, allow_empty: bool = True,
) -> tuple[str, ...]:
    """Validate and return an exact relative-component tuple without filesystem I/O.

    The tuple form is deliberate: callers cannot smuggle an absolute path or rely on
    platform-specific separator parsing.  Printable Unicode is retained, while path
    syntax, controls, surrogates and unbounded names are rejected.
    """
    if type(components) is not tuple:
        raise PrivatePathUnsafe("managed path must be an exact tuple of components")
    if not components and not allow_empty:
        raise PrivatePathUnsafe("managed path must contain at least one component")
    if len(components) > _MAX_COMPONENTS:
        raise PrivatePathUnsafe("managed path has too many components")

    total = 0
    for component in components:
        if type(component) is not str:
            raise PrivatePathUnsafe("managed path components must be exact strings")
        if not component or component in {".", ".."}:
            raise PrivatePathUnsafe("managed path contains an empty or traversal component")
        if "/" in component or "\\" in component:
            raise PrivatePathUnsafe("managed path component contains a separator")
        if any(unicodedata.category(char).startswith("C") for char in component):
            raise PrivatePathUnsafe("managed path component contains a control or surrogate")
        try:
            encoded = component.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PrivatePathUnsafe("managed path component is not valid UTF-8") from exc
        if len(encoded) > _MAX_COMPONENT_BYTES:
            raise PrivatePathUnsafe("managed path component is too long")
        total += len(encoded) + 1
    if total > _MAX_RELATIVE_PATH_BYTES:
        raise PrivatePathUnsafe("managed relative path is too long")
    return components


def _validate_anchor_fd(anchor_fd: int) -> int:
    if type(anchor_fd) is not int or anchor_fd < 0:
        raise PrivatePathUnsafe("managed path anchor must be a non-negative file descriptor")
    return anchor_fd


def _identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _close_owned(fd: int) -> BaseException | None:
    if fd < 0:
        return None
    try:
        os.close(fd)
    except BaseException as exc:
        return exc
    return None


def _attach_close_errors(primary: BaseException, errors: list[BaseException]) -> None:
    if not errors:
        return
    try:
        primary.close_errors = tuple(errors)
    except BaseException:
        pass


def _close_fds(*fds: int) -> list[BaseException]:
    errors = []
    for fd in fds:
        error = _close_owned(fd)
        if error is not None:
            errors.append(error)
    return errors


def _close_fds_once(*fds: int) -> list[BaseException]:
    """Attempt every owned close once, including when an injected seam raises.

    A close that reports failure is ownership-ambiguous: retrying the integer can
    close an unrelated descriptor if the kernel already released and reused it.
    This helper therefore records the fault and advances exactly once per input.
    """
    errors = []
    for fd in fds:
        try:
            error = _close_owned(fd)
        except BaseException as exc:
            errors.append(exc)
        else:
            if error is not None:
                errors.append(error)
    return errors


def _close_exposed_stage_writers_once(
    claims: tuple[tuple[int, tuple[int, int]], ...],
    *,
    allow_unlinked: bool = False,
) -> list[BaseException]:
    """Authenticate and close each externally exposed stage writer at most once.

    ``pass_fds`` crosses into Popen and callers can accidentally close one of those
    integers before settlement.  File-descriptor reuse would otherwise let cleanup
    close an unrelated object.  Each claim is therefore checked immediately before
    close against its immutable stage inode plus the strict file contract.  A stale,
    reused or malformed integer is recorded and deliberately *not* closed.

    Same-process code racing a replacement between ``fstat`` and ``close`` remains
    outside Quarry's documented security boundary; canonical lifecycle locks prevent
    all supported repository operations from doing so.
    """
    errors: list[BaseException] = []
    for claim in claims:
        errors.extend(
            _close_one_exposed_stage_writer_once(
                claim, allow_unlinked=allow_unlinked,
            )
        )
    return errors


def _close_one_exposed_stage_writer_once(
    claim: tuple[int, tuple[int, int]], *, allow_unlinked: bool = False,
) -> list[BaseException]:
    """Identity-authenticate and attempt one exposed file descriptor close."""
    fd, expected_identity = claim
    errors: list[BaseException] = []
    try:
        observed = os.fstat(fd)
        if _identity(observed) != expected_identity:
            raise PrivatePathUnsafe("private stage writer identity changed")
    except BaseException as exc:
        # EBADF or a different inode means this integer is no longer our claim;
        # closing it could destroy an unrelated newly reused descriptor.
        errors.append(exc)
        return errors
    try:
        if allow_unlinked and observed.st_nlink == 0:
            if not stat.S_ISREG(observed.st_mode):
                raise PrivatePathUnsafe("managed file is not a regular file")
            if observed.st_uid != os.geteuid():
                raise PrivatePathUnsafe("managed file is not owned by the current user")
            if stat.S_IMODE(observed.st_mode) != FILE_MODE:
                raise LegacyModeMismatch(
                    components=(), expected=FILE_MODE,
                    actual=stat.S_IMODE(observed.st_mode),
                )
        else:
            _validate_strict_file_stat(observed, ())
    except BaseException as exc:
        # Exact inode identity is already proved.  A metadata anomaly makes the
        # result non-clean, but retaining this actual writer would leak mutable
        # authority, so it still receives its one close attempt below.
        errors.append(exc)
    try:
        close_error = _close_owned(fd)
    except BaseException as exc:
        errors.append(exc)
    else:
        if close_error is not None:
            errors.append(close_error)
    return errors


def _close_exposed_stage_dirs_once(
    claims: tuple[tuple[int, tuple[int, int], tuple[str, ...]], ...],
) -> list[BaseException]:
    """Authenticate and close public stage directory descriptors once.

    Identity is checked before metadata.  A stale or reused numeric descriptor is
    skipped so cleanup cannot close an unrelated directory.  When identity matches,
    a type/owner/mode anomaly is recorded but the authentic stage directory is still
    closed once to consume retained authority.
    """
    errors: list[BaseException] = []
    for claim in claims:
        errors.extend(_close_one_exposed_stage_dir_once(claim))
    return errors


def _close_one_exposed_stage_dir_once(
    claim: tuple[int, tuple[int, int], tuple[str, ...]],
) -> list[BaseException]:
    """Identity-authenticate and attempt one exposed directory close."""
    fd, expected_identity, components = claim
    errors: list[BaseException] = []
    try:
        observed = os.fstat(fd)
        if _identity(observed) != expected_identity:
            raise PrivatePathUnsafe(
                "private stage directory identity changed",
                components=components,
            )
    except BaseException as exc:
        errors.append(exc)
        return errors
    try:
        _validate_strict_dir_stat(observed, components)
    except BaseException as exc:
        errors.append(exc)
    try:
        close_error = _close_owned(fd)
    except BaseException as exc:
        errors.append(exc)
    else:
        if close_error is not None:
            errors.append(close_error)
    return errors


@contextmanager
def _owned_fd(fd: int):
    """Close one owned descriptor exactly once without masking a primary fault."""
    try:
        yield fd
    except BaseException as primary:
        close_errors = _close_fds(fd)
        _attach_close_errors(primary, close_errors)
        raise
    else:
        close_errors = _close_fds(fd)
        if close_errors:
            primary = close_errors[0]
            _attach_close_errors(primary, close_errors[1:])
            raise primary


def _file_signature(st: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        stat.S_IMODE(st.st_mode),
        st.st_nlink,
        st.st_size,
        st.st_ctime_ns,
    )


def _digest_fd(fd: int) -> tuple[int, str]:
    """Hash an exact regular-file snapshot while restoring the descriptor offset."""
    original = os.lseek(fd, 0, os.SEEK_CUR)
    digest = hashlib.sha256()
    size = 0
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.lseek(fd, original, os.SEEK_SET)
    return size, digest.hexdigest()


def _fsync_managed(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        unsupported = {
            code
            for code in (
                getattr(errno, "EINVAL", None),
                getattr(errno, "ENOTSUP", None),
                getattr(errno, "EOPNOTSUPP", None),
            )
            if code is not None
        }
        if exc.errno in unsupported:
            raise PrivatePathUnsupported(
                "the filesystem cannot provide required fsync durability",
            ) from exc
        raise


def _validate_strict_dir_stat(st: os.stat_result, components: tuple[str, ...]) -> None:
    if not stat.S_ISDIR(st.st_mode):
        raise PrivatePathUnsafe("managed directory is not a real directory", components=components)
    if st.st_uid != os.geteuid():
        raise PrivatePathUnsafe("managed directory is not owned by the current user", components=components)
    mode = stat.S_IMODE(st.st_mode)
    if mode != DIR_MODE:
        raise LegacyModeMismatch(components=components, expected=DIR_MODE, actual=mode)


def _validate_strict_file_stat(st: os.stat_result, components: tuple[str, ...]) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise PrivatePathUnsafe("managed file is not a regular file", components=components)
    if st.st_uid != os.geteuid():
        raise PrivatePathUnsafe("managed file is not owned by the current user", components=components)
    if st.st_nlink != 1:
        raise PrivatePathUnsafe("managed file has ambiguous hard links", components=components)
    mode = stat.S_IMODE(st.st_mode)
    if mode != FILE_MODE:
        raise LegacyModeMismatch(components=components, expected=FILE_MODE, actual=mode)


def _classify_open_error(
    exc: OSError, parent_fd: int, component: str, components: tuple[str, ...], *, expect_dir: bool,
) -> None:
    if exc.errno == errno.ENOENT:
        raise PrivatePathMissing("managed path does not exist", components=components) from exc
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise PrivatePathUnsafe("managed path contains a symlink or wrong object type", components=components) from exc

    structural_errnos = {
        code for code in (
            getattr(errno, "EACCES", None),
            getattr(errno, "EPERM", None),
            getattr(errno, "ENXIO", None),
            getattr(errno, "ENODEV", None),
            getattr(errno, "EISDIR", None),
        ) if code is not None
    }
    if exc.errno not in structural_errnos:
        raise exc

    # Opening a socket (and some devices), or an inaccessible legacy object, can
    # fail before fstat.  A no-follow stat is used only for those narrow structural
    # errors.  Resource exhaustion and I/O failures always propagate unchanged.
    try:
        observed = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise PrivatePathMissing("managed path does not exist", components=components) from exc
    except OSError:
        raise exc
    if expect_dir:
        _validate_strict_dir_stat(observed, components)
    else:
        _validate_strict_file_stat(observed, components)
    raise exc


def open_strict_dir_at(anchor_fd: int, components: tuple[str, ...] = ()) -> int:
    """Open an existing exact-0700 owned directory below ``anchor_fd``.

    Every supplied component is opened relative to the descriptor for its parent with
    ``O_NOFOLLOW``.  The returned descriptor is owned by the caller.  The anchor is
    validated just like every descendant; this function has no filesystem side effect.
    """
    _require_strict_capabilities()
    components = validate_relative_components(components)
    anchor_fd = _validate_anchor_fd(anchor_fd)

    current = os.dup(anchor_fd)
    walked: tuple[str, ...] = ()
    try:
        _validate_strict_dir_stat(os.fstat(current), walked)
        for component in components:
            walked += (component,)
            child = -1
            try:
                child = os.open(component, _DIR_OPEN_FLAGS, dir_fd=current)
            except OSError as exc:
                _classify_open_error(exc, current, component, walked, expect_dir=True)
                raise AssertionError("unreachable")
            try:
                _validate_strict_dir_stat(os.fstat(child), walked)
            except BaseException as primary:
                close_errors = _close_fds(child)
                _attach_close_errors(primary, close_errors)
                raise
            previous = current
            current = -1
            close_errors = _close_fds(previous)
            if close_errors:
                close_errors.extend(_close_fds(child))
                primary = close_errors[0]
                _attach_close_errors(primary, close_errors[1:])
                raise primary
            current = child
        return current
    except BaseException as primary:
        close_errors = _close_fds(current)
        _attach_close_errors(primary, close_errors)
        raise


def open_strict_root_at(anchor_fd: int, component: str) -> int:
    """Open one strict managed root below a safe owned, but not necessarily 0700, anchor.

    This is the explicit project-directory boundary.  The external anchor must be a
    real directory owned by the current user and may not be group/other-writable.  The
    managed child itself still must satisfy the exact strict directory contract.
    """
    _require_strict_capabilities()
    components = validate_relative_components((component,), allow_empty=False)
    anchor_fd = _validate_anchor_fd(anchor_fd)
    boundary = os.dup(anchor_fd)
    child = -1
    try:
        boundary_stat = os.fstat(boundary)
        if not stat.S_ISDIR(boundary_stat.st_mode):
            raise PrivatePathUnsafe("managed root anchor is not a real directory")
        if boundary_stat.st_uid != os.geteuid():
            raise PrivatePathUnsafe("managed root anchor is not owned by the current user")
        if stat.S_IMODE(boundary_stat.st_mode) & 0o022:
            raise PrivatePathUnsafe("managed root anchor is group/other-writable")
        try:
            child = os.open(component, _DIR_OPEN_FLAGS, dir_fd=boundary)
        except OSError as exc:
            _classify_open_error(exc, boundary, component, components, expect_dir=True)
            raise AssertionError("unreachable")
        try:
            _validate_strict_dir_stat(os.fstat(child), components)
        except BaseException as primary:
            close_errors = _close_fds(child)
            _attach_close_errors(primary, close_errors)
            child = -1
            raise
        owned_boundary = boundary
        boundary = -1
        close_errors = _close_fds(owned_boundary)
        if close_errors:
            close_errors.extend(_close_fds(child))
            child = -1
            primary = close_errors[0]
            _attach_close_errors(primary, close_errors[1:])
            raise primary
        result = child
        child = -1
        return result
    except BaseException as primary:
        close_errors = _close_fds(child, boundary)
        _attach_close_errors(primary, close_errors)
        raise


def _open_strict_file_in(
    parent_fd: int,
    component: str,
    components: tuple[str, ...],
    *,
    _claim=None,
) -> int:
    """Open a strict file, optionally populating a pre-registered claim slot.

    The internal claim form assigns the syscall result directly into its retained
    slot before Python reaches another source line.  Validation faults deliberately
    leave that private descriptor in the cleanup ledger instead of attempting an
    untracked best-effort close.
    """
    fd = -1
    try:
        if _claim is None:
            fd = os.open(component, _FILE_OPEN_FLAGS, dir_fd=parent_fd)
        else:
            object.__setattr__(_claim, "_fd", os.open(component, _FILE_OPEN_FLAGS, dir_fd=parent_fd))
            object.__setattr__(_claim, "_disposition", "pending")
            fd = _claim._fd
    except OSError as exc:
        if _claim is not None and _claim._fd < 0:
            object.__setattr__(_claim, "_disposition", "unallocated")
        _classify_open_error(exc, parent_fd, component, components, expect_dir=False)
        raise AssertionError("unreachable")
    try:
        observed = os.fstat(fd)
        if _claim is not None:
            object.__setattr__(_claim, "_owned_identity", _identity(observed))
        _validate_strict_file_stat(observed, components)
    except BaseException as primary:
        if _claim is not None:
            _record_descriptor_claim_error(_claim, primary)
            raise
        close_errors = _close_fds(fd)
        _attach_close_errors(primary, close_errors)
        raise
    return fd


def open_strict_file_at(anchor_fd: int, components: tuple[str, ...]) -> int:
    """Open an existing exact-0600, single-link owned regular file below an anchor."""
    _require_strict_capabilities()
    components = validate_relative_components(components, allow_empty=False)
    anchor_fd = _validate_anchor_fd(anchor_fd)
    parent = open_strict_dir_at(anchor_fd, components[:-1])
    result = -1
    try:
        result = _open_strict_file_in(parent, components[-1], components)
        owned_parent = parent
        parent = -1
        close_errors = _close_fds(owned_parent)
        if close_errors:
            close_errors.extend(_close_fds(result))
            result = -1
            primary = close_errors[0]
            _attach_close_errors(primary, close_errors[1:])
            raise primary
        returned = result
        result = -1
        return returned
    except BaseException as primary:
        close_errors = _close_fds(result, parent)
        _attach_close_errors(primary, close_errors)
        raise


@dataclass(frozen=True)
class LegacyModeRepairReceipt:
    """Identity-bound facts a repository can place in its compatibility record."""

    components: tuple[str, ...]
    object_kind: str
    uid: int
    device: int
    inode: int
    before_mode: int
    after_mode: int


class LegacyRepairUncertain(PrivatePathError):
    """A permission change landed, but its durable settlement was not confirmed."""

    def __init__(
        self, message: str, *, components: tuple[str, ...], receipt: LegacyModeRepairReceipt | None,
    ) -> None:
        super().__init__(message, components=components)
        self.receipt = receipt


class LegacyRepairCommittedWithFault(PrivatePathError):
    """A mode repair committed, but descriptor settlement also reported a fault."""

    def __init__(
        self, message: str, *, components: tuple[str, ...], receipt: LegacyModeRepairReceipt | None,
    ) -> None:
        super().__init__(message, components=components)
        self.receipt = receipt


def _observe_repair_target(
    parent_fd: int, component: str, components: tuple[str, ...], *, is_dir: bool,
) -> os.stat_result:
    try:
        observed = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise PrivatePathMissing("legacy repair target does not exist", components=components) from exc
    except OSError:
        raise
    if is_dir:
        if not stat.S_ISDIR(observed.st_mode):
            raise PrivatePathUnsafe("legacy repair target is not a directory", components=components)
    elif not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
        raise PrivatePathUnsafe(
            "legacy repair target is not a single-link regular file", components=components,
        )
    if observed.st_uid != os.geteuid():
        raise PrivatePathUnsafe("legacy repair target is not owned by the current user", components=components)
    return observed


def _validate_repairable_mode(
    observed: os.stat_result, components: tuple[str, ...], *, expected: int,
) -> int:
    actual = stat.S_IMODE(observed.st_mode)
    if actual & 0o7000:
        raise PrivatePathUnsafe(
            "legacy repair refuses set-id or sticky permission bits", components=components,
        )
    if actual & expected != expected:
        raise PrivatePathUnsafe(
            "legacy repair would have to add missing owner permissions", components=components,
        )
    return actual


def repair_legacy_mode_at(
    anchor_fd: int, components: tuple[str, ...], *, is_dir: bool,
) -> LegacyModeRepairReceipt | None:
    """Explicitly remove excess permission bits from one otherwise safe owned object.

    This narrow compatibility operation never adds a missing owner permission, changes
    ownership, accepts a hard-linked file, or follows a symlink.  A changed object
    returns an identity-bound receipt; an already exact object returns ``None``.
    Repository callers are responsible for durably recording a returned receipt.

    An empty component tuple is accepted only for a directory anchor.  This is the
    explicit boundary for repairing an externally opened legacy root; ordinary strict
    traversal still requires the anchor itself to be exact.
    """
    _require_strict_capabilities()
    components = validate_relative_components(components)
    anchor_fd = _validate_anchor_fd(anchor_fd)
    if type(is_dir) is not bool:
        raise PrivatePathUnsafe("legacy repair object kind must be explicit")
    if not components and not is_dir:
        raise PrivatePathUnsafe("a file repair requires a relative component")

    parent = os.dup(anchor_fd) if not components else open_strict_dir_at(anchor_fd, components[:-1])
    fd = -1
    result: LegacyModeRepairReceipt | None = None
    failure: BaseException | None = None
    try:
        if not components:
            observed = os.fstat(parent)
            if not stat.S_ISDIR(observed.st_mode):
                raise PrivatePathUnsafe("legacy repair anchor is not a directory")
            if observed.st_uid != os.geteuid():
                raise PrivatePathUnsafe("legacy repair anchor is not owned by the current user")
            component = None
        else:
            component = components[-1]
            observed = _observe_repair_target(parent, component, components, is_dir=is_dir)

        expected = DIR_MODE if is_dir else FILE_MODE
        actual = _validate_repairable_mode(observed, components, expected=expected)
        if actual == expected:
            result = None
        else:
            if component is None:
                fd = os.dup(parent)
            else:
                flags = _DIR_OPEN_FLAGS if is_dir else _FILE_OPEN_FLAGS
                try:
                    fd = os.open(component, flags, dir_fd=parent)
                except OSError as exc:
                    _classify_open_error(exc, parent, component, components, expect_dir=is_dir)
                    raise AssertionError("unreachable")

            before = os.fstat(fd)
            if _identity(before) != _identity(observed):
                raise PrivatePathUnsafe("legacy repair target was substituted", components=components)
            # Re-evaluate every eligibility condition on the held descriptor.
            if is_dir:
                if not stat.S_ISDIR(before.st_mode):
                    raise PrivatePathUnsafe("legacy repair target is not a directory", components=components)
            elif not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise PrivatePathUnsafe(
                    "legacy repair target is not a single-link regular file", components=components,
                )
            if before.st_uid != os.geteuid():
                raise PrivatePathUnsafe(
                    "legacy repair target is not owned by the current user", components=components,
                )
            before_mode = _validate_repairable_mode(before, components, expected=expected)
            if before_mode == expected:
                result = None
            else:
                try:
                    os.fchmod(fd, expected)
                    after = os.fstat(fd)
                    if _identity(after) != _identity(before):
                        raise PrivatePathUnsafe(
                            "legacy repair target identity changed", components=components,
                        )
                    if is_dir:
                        _validate_strict_dir_stat(after, components)
                    else:
                        _validate_strict_file_stat(after, components)
                    receipt = LegacyModeRepairReceipt(
                        components=components,
                        object_kind="directory" if is_dir else "file",
                        uid=after.st_uid,
                        device=after.st_dev,
                        inode=after.st_ino,
                        before_mode=before_mode,
                        after_mode=stat.S_IMODE(after.st_mode),
                    )
                    _fsync_managed(fd)
                    settled = os.fstat(fd)
                    if _identity(settled) != _identity(before):
                        raise PrivatePathUnsafe(
                            "legacy repair target identity changed", components=components,
                        )
                    if is_dir:
                        _validate_strict_dir_stat(settled, components)
                    else:
                        _validate_strict_file_stat(settled, components)
                    result = receipt
                except BaseException as exc:
                    if isinstance(exc, LegacyRepairUncertain):
                        raise
                    landed_receipt = None
                    proved_unchanged = False
                    reconciliation_error = None
                    try:
                        current = os.fstat(fd)
                        if _identity(current) == _identity(before):
                            current_mode = stat.S_IMODE(current.st_mode)
                            if current_mode == expected:
                                if is_dir:
                                    _validate_strict_dir_stat(current, components)
                                else:
                                    _validate_strict_file_stat(current, components)
                                landed_receipt = LegacyModeRepairReceipt(
                                    components=components,
                                    object_kind="directory" if is_dir else "file",
                                    uid=current.st_uid,
                                    device=current.st_dev,
                                    inode=current.st_ino,
                                    before_mode=before_mode,
                                    after_mode=current_mode,
                                )
                            elif current_mode == before_mode:
                                proved_unchanged = True
                    except BaseException as reconcile_exc:
                        reconciliation_error = reconcile_exc
                    if proved_unchanged:
                        raise
                    error = LegacyRepairUncertain(
                        "legacy mode change landed but settlement is uncertain",
                        components=components,
                        receipt=landed_receipt,
                    )
                    error.reconciliation_error = reconciliation_error
                    raise error from exc
    except BaseException as exc:
        failure = exc

    close_errors = _close_fds(fd, parent)
    if failure is not None:
        try:
            failure.close_errors = tuple(close_errors)
        except BaseException:
            pass
        raise failure
    if close_errors:
        error = LegacyRepairCommittedWithFault(
            "legacy repair completed but descriptor close failed",
            components=components,
            receipt=result,
        )
        error.close_errors = tuple(close_errors)
        raise error from close_errors[0]
    return result


_PRIVATE_STAGE_CONSTRUCTOR = object()
_PRIVATE_STAGE_BATCH_CONSTRUCTOR = object()
_PRIVATE_STAGE_TRANSFER_AUTHORITY_CONSTRUCTOR = object()
_PRIVATE_STAGE_PARENT_CLOSE_RECEIPT_CONSTRUCTOR = object()
_PRIVATE_DESCRIPTOR_CLAIM_CONSTRUCTOR = object()
_PRIVATE_STAGE_BATCH_CLAIM_CONSTRUCTOR = object()
_PRIVATE_STAGE_CLEANUP_LEDGER_CONSTRUCTOR = object()


_DESCRIPTOR_CLAIM_KINDS = frozenset({
    "writer", "pin", "parent", "anchor",
    "source_writer", "source_parent", "source_anchor",
})
_DESCRIPTOR_CLAIM_TERMINAL = frozenset({
    "closed_clean", "closed_after_fault", "close_ambiguous", "gone",
    "identity_rejected", "unallocated",
})
_MAX_DESCRIPTOR_CLAIM_ERRORS = 2
_MAX_DESCRIPTOR_CLAIM_DROPPED = (1 << 63) - 1


class _PrivateDescriptorClaim:
    """One exact, privately retained descriptor with monotonic close progress."""

    __slots__ = (
        "_fd", "_identity", "_owned_identity", "_fresh_owned", "_kind",
        "_components", "_disposition",
        "_close_attempts", "_errors", "_dropped_error_count", "_metadata_fault",
        "_lock",
    )

    def __init__(
        self,
        *,
        fd: int,
        identity: tuple[int, int],
        kind: str,
        components: tuple[str, ...],
        _constructor_token: object,
    ) -> None:
        if (_constructor_token is not _PRIVATE_DESCRIPTOR_CLAIM_CONSTRUCTOR
                or type(fd) is not int or fd < -1
                or type(identity) is not tuple or len(identity) != 2
                or any(type(value) is not int or value < 0 for value in identity)
                or type(kind) is not str or kind not in _DESCRIPTOR_CLAIM_KINDS
                or type(components) is not tuple):
            raise PrivateStageHandoffError("prepare")
        object.__setattr__(self, "_fd", fd)
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "_owned_identity", None)
        object.__setattr__(self, "_fresh_owned", fd == -1)
        object.__setattr__(self, "_kind", kind)
        object.__setattr__(self, "_components", components)
        object.__setattr__(
            self, "_disposition", "allocating" if fd == -1 else "pending",
        )
        object.__setattr__(self, "_close_attempts", 0)
        object.__setattr__(self, "_errors", ())
        object.__setattr__(self, "_dropped_error_count", 0)
        object.__setattr__(self, "_metadata_fault", False)
        object.__setattr__(self, "_lock", threading.RLock())

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private descriptor claims are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private descriptor claims are read-only")

    @property
    def fd(self) -> int:
        with self._lock:
            return self._fd

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def disposition(self) -> str:
        with self._lock:
            return self._disposition

    @property
    def errors(self) -> tuple[BaseException, ...]:
        with self._lock:
            return self._errors

    def __repr__(self) -> str:
        return (
            "PrivateDescriptorClaim("
            f"kind={self._kind!r}, disposition={self._disposition!r})"
        )


@dataclass(frozen=True, slots=True, repr=False, init=False)
class PrivateStageParentCloseReceipt:
    """Proof that registered parent writer FDs matched and close returned cleanly.

    This receipt does not prove the absence of aliases, child inheritance, process
    identity, containment, content stability, GO release or publication.  The PID
    is only an untrusted correlation claim for a supervisor to compose with its own
    Popen handle, transcript and containment evidence.  ``repr`` omits correlation
    and filesystem identity values so logs cannot expose ambient authority facts.
    """

    request_id: str
    claimed_worker_pid: int
    file_identities: tuple[tuple[int, int], ...]
    state: str = "parent_writers_closed"

    def __init__(
        self,
        *,
        request_id: str,
        claimed_worker_pid: int,
        file_identities: tuple[tuple[int, int], ...],
        _constructor_token: object,
    ) -> None:
        if (_constructor_token is not _PRIVATE_STAGE_PARENT_CLOSE_RECEIPT_CONSTRUCTOR
                or type(request_id) is not str or len(request_id) != 32
                or any(char not in "0123456789abcdef" for char in request_id)
                or type(claimed_worker_pid) is not int
                or not 1 <= claimed_worker_pid <= _MAX_WORKER_PID
                or type(file_identities) is not tuple
                or not 1 <= len(file_identities) <= 3
                or any(type(identity) is not tuple or len(identity) != 2
                       or any(type(value) is not int or value < 0 for value in identity)
                       for identity in file_identities)
                or len(set(file_identities)) != len(file_identities)):
            raise PrivateStageHandoffError("transfer")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "claimed_worker_pid", claimed_worker_pid)
        object.__setattr__(self, "file_identities", file_identities)
        object.__setattr__(self, "state", "parent_writers_closed")

    def __repr__(self) -> str:
        return (
            "PrivateStageParentCloseReceipt("
            f"stages={len(self.file_identities)}, state={self.state!r})"
        )


class PrivateFileStage:
    """Opaque handle for an unpublished same-directory file stage.

    Public attributes are read-only views.  The claim itself lives in slots so a
    caller cannot redirect publication by mutating an instance ``__dict__``.
    Quarry does not treat Python code executing in this process as a hostile
    security boundary; the opacity prevents accidental authority drift.
    """

    __slots__ = (
        "_anchor_fd",
        "_anchor_identity",
        "_parent_fd",
        "_file_fd",
        "_temporary_name",
        "_destination_name",
        "_components",
        "_parent_identity",
        "_file_identity",
        "_expected_digest",
        "_sealed_signature",
        "_sealed_digest",
        "_state",
        "_lifecycle_lock",
        "_cleanup_ledger",
    )

    def __init__(
        self,
        *,
        anchor_fd: int,
        parent_fd: int,
        file_fd: int,
        temporary_name: str,
        destination_name: str,
        components: tuple[str, ...],
        anchor_identity: tuple[int, int] | None = None,
        parent_identity: tuple[int, int],
        file_identity: tuple[int, int],
        _constructor_token: object,
    ) -> None:
        if _constructor_token is not _PRIVATE_STAGE_CONSTRUCTOR:
            raise PrivatePathUnsafe("private stages must be created by the strict staging API")
        if (type(anchor_identity) is not tuple or len(anchor_identity) != 2
                or any(type(value) is not int or value < 0 for value in anchor_identity)):
            raise PrivatePathUnsafe("private stage anchor identity is invalid")
        object.__setattr__(self, "_anchor_fd", anchor_fd)
        object.__setattr__(self, "_anchor_identity", anchor_identity)
        object.__setattr__(self, "_parent_fd", parent_fd)
        object.__setattr__(self, "_file_fd", file_fd)
        object.__setattr__(self, "_temporary_name", temporary_name)
        object.__setattr__(self, "_destination_name", destination_name)
        object.__setattr__(self, "_components", components)
        object.__setattr__(self, "_parent_identity", parent_identity)
        object.__setattr__(self, "_file_identity", file_identity)
        object.__setattr__(self, "_expected_digest", None)
        object.__setattr__(self, "_sealed_signature", None)
        object.__setattr__(self, "_sealed_digest", None)
        object.__setattr__(self, "_state", "open")
        object.__setattr__(self, "_lifecycle_lock", threading.RLock())
        object.__setattr__(self, "_cleanup_ledger", None)

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private stage claims are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private stage claims are read-only")

    @property
    def anchor_fd(self) -> int:
        return self._anchor_fd

    @property
    def anchor_identity(self) -> tuple[int, int]:
        return self._anchor_identity

    @property
    def parent_fd(self) -> int:
        return self._parent_fd

    @property
    def file_fd(self) -> int:
        return self._file_fd

    @property
    def temporary_name(self) -> str:
        return self._temporary_name

    @property
    def destination_name(self) -> str:
        return self._destination_name

    @property
    def components(self) -> tuple[str, ...]:
        return self._components

    @property
    def parent_identity(self) -> tuple[int, int]:
        return self._parent_identity

    @property
    def file_identity(self) -> tuple[int, int]:
        return self._file_identity

    @property
    def sealed_signature(self) -> tuple[int, int, int, int, int, int, int] | None:
        return self._sealed_signature

    @property
    def expected_digest(self) -> tuple[int, str] | None:
        return self._expected_digest

    @property
    def sealed_digest(self) -> tuple[int, str] | None:
        return self._sealed_digest

    @property
    def state(self) -> str:
        return self._state

    def abort(self) -> None:
        abort_private_stage(self)

    def __enter__(self) -> "PrivateFileStage":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        # Once handoff preparation succeeds the batch, not this per-file handle,
        # owns every writer and pin.  Letting the stage context manager attempt a
        # second cleanup would both violate that ownership boundary and turn a
        # successful prepare into a lifecycle error.
        with self._lifecycle_lock:
            if self.state in {"open", "sealed", "aborted"}:
                try:
                    self.abort()
                except BaseException as cleanup_error:
                    if exc is None:
                        raise
                    try:
                        exc.private_cleanup_error = cleanup_error
                    except BaseException:
                        pass


class _PrivateStageBatchClaim:
    """Private descriptor claims belonging to one immutable stage identity."""

    __slots__ = ("_stage", "_writer", "_pin", "_parent", "_anchor")

    def __init__(
        self,
        *,
        stage: PrivateFileStage,
        writer: _PrivateDescriptorClaim,
        pin: _PrivateDescriptorClaim,
        parent: _PrivateDescriptorClaim,
        anchor: _PrivateDescriptorClaim,
        _constructor_token: object,
    ) -> None:
        if (_constructor_token is not _PRIVATE_STAGE_BATCH_CLAIM_CONSTRUCTOR
                or type(stage) is not PrivateFileStage
                or any(type(claim) is not _PrivateDescriptorClaim for claim in (
                    writer, pin, parent, anchor,
                ))
                or (writer._kind, pin._kind, parent._kind, anchor._kind)
                != ("writer", "pin", "parent", "anchor")):
            raise PrivateStageHandoffError("prepare")
        object.__setattr__(self, "_stage", stage)
        object.__setattr__(self, "_writer", writer)
        object.__setattr__(self, "_pin", pin)
        object.__setattr__(self, "_parent", parent)
        object.__setattr__(self, "_anchor", anchor)

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private stage batch claims are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private stage batch claims are read-only")

    @property
    def writer(self) -> _PrivateDescriptorClaim:
        return self._writer

    @property
    def pin(self) -> _PrivateDescriptorClaim:
        return self._pin

    @property
    def parent(self) -> _PrivateDescriptorClaim:
        return self._parent

    @property
    def anchor(self) -> _PrivateDescriptorClaim:
        return self._anchor

    def __repr__(self) -> str:
        return "PrivateStageBatchClaim(descriptors=4)"


class _PrivateStageCleanupLedger:
    """Retained cleanup authority; terminal state never erases pending claims."""

    __slots__ = ("_stage_claims", "_extra_claims", "_lock")

    def __init__(
        self,
        *,
        stage_claims: tuple[_PrivateStageBatchClaim, ...] = (),
        extra_claims: tuple[_PrivateDescriptorClaim, ...] = (),
        _constructor_token: object,
    ) -> None:
        if (_constructor_token is not _PRIVATE_STAGE_CLEANUP_LEDGER_CONSTRUCTOR
                or type(stage_claims) is not tuple
                or type(extra_claims) is not tuple
                or any(type(claim) is not _PrivateStageBatchClaim
                       for claim in stage_claims)
                or any(type(claim) is not _PrivateDescriptorClaim
                       for claim in extra_claims)):
            raise PrivateStageHandoffError("prepare")
        object.__setattr__(self, "_stage_claims", stage_claims)
        object.__setattr__(self, "_extra_claims", extra_claims)
        object.__setattr__(self, "_lock", threading.RLock())

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private cleanup ledgers are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private cleanup ledgers are read-only")

    @property
    def stage_claims(self) -> tuple[_PrivateStageBatchClaim, ...]:
        return self._stage_claims

    @property
    def claims(self) -> tuple[_PrivateDescriptorClaim, ...]:
        grouped = tuple(
            claim
            for stage_claim in self._stage_claims
            for claim in (
                stage_claim._writer, stage_claim._pin,
                stage_claim._parent, stage_claim._anchor,
            )
        )
        return grouped + self._extra_claims

    @property
    def pending(self) -> bool:
        with self._lock:
            return any(
                claim.disposition not in _DESCRIPTOR_CLAIM_TERMINAL
                for claim in self.claims
            )

    def __repr__(self) -> str:
        pending = sum(
            claim._disposition not in _DESCRIPTOR_CLAIM_TERMINAL
            for claim in self.claims
        )
        return f"PrivateStageCleanupLedger(claims={len(self.claims)}, pending={pending})"


class PrivateStageHandoffBatch:
    """Opaque parent-owned writers prepared for one not-yet-spawned worker.

    Writers are never exposed through this general lifecycle handle.  The internal
    spawn callback receives their ordered tuple only while canonical lifecycle locks
    remain held, and no raw tuple-returning API exists.  Neither object renders
    descriptors, paths nor request identity.
    """

    __slots__ = (
        "_stages", "_request_id", "_state",
        "_transfer_authority", "_transfer_receipt", "_cleanup_ledger",
    )

    def __init__(
        self,
        *,
        stages: tuple[PrivateFileStage, ...],
        cleanup_ledger: _PrivateStageCleanupLedger,
        request_id: str,
        _constructor_token: object,
    ) -> None:
        if (_constructor_token is not _PRIVATE_STAGE_BATCH_CONSTRUCTOR
                or type(cleanup_ledger) is not _PrivateStageCleanupLedger):
            raise PrivatePathUnsafe(
                "private stage handoffs must be created by the strict staging API",
            )
        object.__setattr__(self, "_stages", stages)
        object.__setattr__(self, "_request_id", request_id)
        object.__setattr__(self, "_state", "prepared")
        object.__setattr__(self, "_transfer_authority", None)
        object.__setattr__(self, "_transfer_receipt", None)
        object.__setattr__(self, "_cleanup_ledger", cleanup_ledger)

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private stage handoff claims are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private stage handoff claims are read-only")

    @property
    def pass_fds(self) -> tuple[int, ...]:
        # Compatibility tombstone: exposing writers before reservation lets an
        # accidental close/reuse make generic abort target an unrelated descriptor.
        return ()

    @property
    def state(self) -> str:
        return self._state

    def abort(self) -> None:
        abort_unspawned_private_stage_handoff(self)

    def __enter__(self) -> "PrivateStageHandoffBatch":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        # Join any in-flight batch lifecycle operation before deciding whether
        # cleanup remains ours.  Otherwise an already-invalidated abort could still
        # be physically closing its writers while this context returns.
        with _hold_stage_lifecycle(self._stages):
            operation = None
            if self.state == "prepared":
                operation = self.abort
            elif self.state == "aborted" and self._cleanup_ledger.pending:
                operation = self.abort
            elif self.state in {
                "spawn_prepared", "worker_spawned_unverified", "worker_claim_bound",
                "parent_writers_closed", "transfer_uncertain",
            }:
                # This fences evidence authority only; it neither asserts nor waits
                # for process settlement.
                operation = lambda: fence_private_stage_handoff(self)
            elif self.state == "fenced" and self._cleanup_ledger.pending:
                operation = lambda: fence_private_stage_handoff(self)
            if operation is not None:
                try:
                    operation()
                except BaseException as cleanup_error:
                    if exc is None:
                        raise
                    try:
                        exc.private_cleanup_error = cleanup_error
                    except BaseException:
                        pass

    def __repr__(self) -> str:
        return f"PrivateStageHandoffBatch(stages={len(self._stages)}, state={self._state!r})"


class _PrivateStageTransferAuthority:
    """Opaque one-shot spawn and transfer permission for one exact batch."""

    __slots__ = (
        "_batch", "_request_id", "_file_identities", "_claimed_worker_pid",
        "_borrowed", "_bound", "_consumed",
    )

    def __init__(
        self,
        *,
        batch: PrivateStageHandoffBatch,
        request_id: str,
        file_identities: tuple[tuple[int, int], ...],
        _constructor_token: object,
    ) -> None:
        if _constructor_token is not _PRIVATE_STAGE_TRANSFER_AUTHORITY_CONSTRUCTOR:
            raise PrivateStageHandoffError("bind_worker")
        object.__setattr__(self, "_batch", batch)
        object.__setattr__(self, "_request_id", request_id)
        object.__setattr__(self, "_file_identities", file_identities)
        object.__setattr__(self, "_claimed_worker_pid", None)
        object.__setattr__(self, "_borrowed", False)
        object.__setattr__(self, "_bound", False)
        object.__setattr__(self, "_consumed", False)

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private stage transfer authorities are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private stage transfer authorities are read-only")

    @property
    def pass_fds(self) -> tuple[int, ...]:
        """Compatibility tombstone; spawning is callback-owned and lock-scoped."""
        return ()

    def __repr__(self) -> str:
        state = (
            "consumed" if self._consumed
            else "bound" if self._bound
            else "spawn_prepared"
        )
        return f"PrivateStageTransferAuthority(state={state!r})"


def _inspect_stage_directory_claims_at(
    stage: PrivateFileStage, *, parent_fd: int, anchor_fd: int,
) -> tuple[BaseException, ...]:
    """Prove directory identities and return non-identity metadata anomalies.

    An identity failure raises immediately: no descriptor-relative operation may use
    that numeric descriptor.  Once exact identity is proved, a mode/type/owner fault
    is returned instead so fail-closed cleanup can still operate through and close
    the authentic directory while reporting the policy anomaly.
    """
    metadata_errors: list[BaseException] = []
    for fd, expected_identity, components, label in (
        (anchor_fd, stage.anchor_identity, (), "anchor"),
        (parent_fd, stage.parent_identity, stage.components[:-1], "parent"),
    ):
        observed = os.fstat(fd)
        if _identity(observed) != expected_identity:
            raise PrivatePathUnsafe(
                f"private stage {label} identity changed",
                components=stage.components,
            )
        try:
            _validate_strict_dir_stat(observed, components)
        except BaseException as exc:
            metadata_errors.append(exc)
    return tuple(metadata_errors)


def _validate_stage_directory_claims_at(
    stage: PrivateFileStage, *, parent_fd: int, anchor_fd: int,
) -> None:
    metadata_errors = _inspect_stage_directory_claims_at(
        stage, parent_fd=parent_fd, anchor_fd=anchor_fd,
    )
    if metadata_errors:
        raise metadata_errors[0]


def _validate_stage_directory_claims(stage: PrivateFileStage) -> None:
    """Authenticate both public directory descriptors before strict relative I/O."""
    _validate_stage_directory_claims_at(
        stage, parent_fd=stage.parent_fd, anchor_fd=stage.anchor_fd,
    )


def _stage_directory_close_claims(
    stage: PrivateFileStage,
    *,
    parent_fd: int | None = None,
    anchor_fd: int | None = None,
) -> tuple[tuple[int, tuple[int, int], tuple[str, ...]], ...]:
    return (
        (
            stage.parent_fd if parent_fd is None else parent_fd,
            stage.parent_identity,
            stage.components[:-1],
        ),
        (
            stage.anchor_fd if anchor_fd is None else anchor_fd,
            stage.anchor_identity,
            (),
        ),
    )


def _validate_live_stage(stage: PrivateFileStage, operation: str) -> None:
    if type(stage) is not PrivateFileStage:
        raise PrivatePathUnsafe("private stage handle has the wrong type")
    if stage.state not in {"open", "sealed"}:
        raise PrivateStageStateError(operation, stage.state)
    if stage._cleanup_ledger is not None:
        raise PrivateStageStateError(operation, stage.state)
    _validate_stage_directory_claims(stage)


def _set_stage(stage: PrivateFileStage, field: str, value) -> None:
    object.__setattr__(stage, f"_{field}", value)


def _record_descriptor_claim_error(
    claim: _PrivateDescriptorClaim, error: BaseException,
) -> None:
    with claim._lock:
        if len(claim._errors) < _MAX_DESCRIPTOR_CLAIM_ERRORS:
            object.__setattr__(claim, "_errors", claim._errors + (error,))
        else:
            object.__setattr__(
                claim,
                "_dropped_error_count",
                min(claim._dropped_error_count + 1, _MAX_DESCRIPTOR_CLAIM_DROPPED),
            )


def _validate_descriptor_claim_metadata(
    claim: _PrivateDescriptorClaim, observed: os.stat_result, *, allow_unlinked: bool,
) -> None:
    if claim._kind in {"parent", "anchor", "source_parent", "source_anchor"}:
        _validate_strict_dir_stat(observed, claim._components)
        return
    if allow_unlinked and observed.st_nlink == 0:
        if not stat.S_ISREG(observed.st_mode):
            raise PrivatePathUnsafe(
                "managed file is not a regular file", components=claim._components,
            )
        if observed.st_uid != os.geteuid():
            raise PrivatePathUnsafe(
                "managed file is not owned by the current user",
                components=claim._components,
            )
        if stat.S_IMODE(observed.st_mode) != FILE_MODE:
            raise LegacyModeMismatch(
                components=claim._components,
                expected=FILE_MODE,
                actual=stat.S_IMODE(observed.st_mode),
            )
    else:
        _validate_strict_file_stat(observed, claim._components)
    if claim._kind == "writer":
        flags = fcntl.fcntl(claim._fd, fcntl.F_GETFL)
        if flags & os.O_ACCMODE not in {os.O_WRONLY, os.O_RDWR}:
            raise PrivatePathUnsafe(
                "private stage writer is not writable", components=claim._components,
            )


def _new_descriptor_claim(
    fd: int,
    identity: tuple[int, int],
    kind: str,
    components: tuple[str, ...],
) -> _PrivateDescriptorClaim:
    return _PrivateDescriptorClaim(
        fd=fd,
        identity=identity,
        kind=kind,
        components=components,
        _constructor_token=_PRIVATE_DESCRIPTOR_CLAIM_CONSTRUCTOR,
    )


def _duplicate_private_claim(
    claim: _PrivateDescriptorClaim,
    source_fd: int,
    *,
    allow_unlinked: bool = False,
) -> _PrivateDescriptorClaim:
    """Populate one transaction-registered claim before validating its duplicate."""
    if (type(claim) is not _PrivateDescriptorClaim
            or claim._fd != -1 or claim._disposition != "allocating"):
        raise PrivateStageHandoffError("prepare")
    try:
        object.__setattr__(claim, "_fd", fcntl.fcntl(source_fd, fcntl.F_DUPFD_CLOEXEC, 0))
        object.__setattr__(claim, "_disposition", "pending")
        observed = os.fstat(claim._fd)
        object.__setattr__(claim, "_owned_identity", _identity(observed))
        if _identity(observed) != claim._identity:
            raise PrivatePathUnsafe(
                "private descriptor identity changed", components=claim._components,
            )
        _validate_descriptor_claim_metadata(
            claim, observed, allow_unlinked=allow_unlinked,
        )
        return claim
    except BaseException as primary:
        if claim._fd < 0:
            object.__setattr__(claim, "_disposition", "unallocated")
        else:
            _record_descriptor_claim_error(claim, primary)
        raise


def _inspect_descriptor_claim(
    claim: _PrivateDescriptorClaim, *, allow_unlinked: bool,
) -> os.stat_result | None:
    """Authenticate a pending claim, terminalizing only proved gone/foreign FDs."""
    try:
        observed = os.fstat(claim._fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        _record_descriptor_claim_error(claim, exc)
        object.__setattr__(claim, "_fd", -1)
        object.__setattr__(claim, "_disposition", "gone")
        return None
    if claim._fresh_owned and claim._owned_identity is None:
        # The descriptor was allocated directly into this unexposed claim slot.
        # An interruption before allocation validation cannot turn it into an
        # ambient numeric authority; adopt the observed inode solely for cleanup.
        object.__setattr__(claim, "_owned_identity", _identity(observed))
    cleanup_identity = (
        claim._identity
        if claim._owned_identity is None
        else claim._owned_identity
    )
    if _identity(observed) != cleanup_identity:
        error = PrivatePathUnsafe(
            "private descriptor identity changed", components=claim._components,
        )
        _record_descriptor_claim_error(claim, error)
        object.__setattr__(claim, "_fd", -1)
        object.__setattr__(claim, "_disposition", "identity_rejected")
        return None
    try:
        _validate_descriptor_claim_metadata(
            claim, observed, allow_unlinked=allow_unlinked,
        )
    except PrivatePathError as exc:
        _record_descriptor_claim_error(claim, exc)
        object.__setattr__(claim, "_metadata_fault", True)
    return observed


def _drain_private_descriptor_claim(
    claim: _PrivateDescriptorClaim, *, allow_unlinked: bool = True,
) -> tuple[BaseException, ...]:
    """Settle one descriptor with bounded, identity-checked close recovery."""
    with claim._lock:
        if claim._disposition in _DESCRIPTOR_CLAIM_TERMINAL:
            return ()
        before_errors = len(claim._errors)
        observed = _inspect_descriptor_claim(claim, allow_unlinked=allow_unlinked)
        if observed is None:
            return claim._errors[before_errors:]

        while claim._close_attempts < 2:
            object.__setattr__(claim, "_disposition", "close_started")
            object.__setattr__(claim, "_close_attempts", claim._close_attempts + 1)
            close_fault: BaseException | None = None
            try:
                close_fault = _close_owned(claim._fd)
            except BaseException as exc:
                close_fault = exc
            if close_fault is None:
                object.__setattr__(claim, "_fd", -1)
                object.__setattr__(
                    claim,
                    "_disposition",
                    "closed_clean" if not claim._errors else "closed_after_fault",
                )
                return claim._errors[before_errors:]

            _record_descriptor_claim_error(claim, close_fault)
            try:
                current = os.fstat(claim._fd)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    object.__setattr__(claim, "_fd", -1)
                    object.__setattr__(claim, "_disposition", "close_ambiguous")
                    return claim._errors[before_errors:]
                _record_descriptor_claim_error(claim, exc)
                object.__setattr__(claim, "_disposition", "close_started")
                return claim._errors[before_errors:]
            except BaseException as exc:
                _record_descriptor_claim_error(claim, exc)
                object.__setattr__(claim, "_disposition", "close_started")
                return claim._errors[before_errors:]
            cleanup_identity = (
                claim._identity
                if claim._owned_identity is None
                else claim._owned_identity
            )
            if _identity(current) != cleanup_identity:
                error = PrivatePathUnsafe(
                    "private descriptor identity changed during close",
                    components=claim._components,
                )
                _record_descriptor_claim_error(claim, error)
                object.__setattr__(claim, "_fd", -1)
                object.__setattr__(claim, "_disposition", "identity_rejected")
                return claim._errors[before_errors:]

        # The exact private descriptor remains live after its lifetime close budget.
        # Keep the claim pending for external/process-level recovery; never erase it
        # or manufacture a clean parent-close receipt.
        object.__setattr__(claim, "_disposition", "close_started")
        return claim._errors[before_errors:]


def _drain_private_stage_ledger(
    ledger: _PrivateStageCleanupLedger,
    *,
    kinds: frozenset[str] | None = None,
) -> tuple[BaseException, ...]:
    """Drain selected claims; one control fault cannot strand a suffix."""
    if type(ledger) is not _PrivateStageCleanupLedger:
        raise PrivateStageHandoffError("fence")
    errors: list[BaseException] = []

    def drain_pass() -> None:
        for claim in ledger.claims:
            if (kinds is not None and claim._kind not in kinds) or (
                claim._disposition in _DESCRIPTOR_CLAIM_TERMINAL
            ):
                continue
            try:
                errors.extend(_drain_private_descriptor_claim(claim))
            except BaseException as exc:
                _record_descriptor_claim_error(claim, exc)
                errors.append(exc)

    with ledger._lock:
        try:
            drain_pass()
        except BaseException as exc:
            errors.append(exc)
        finally:
            try:
                drain_pass()
            except BaseException as exc:
                errors.append(exc)
    return tuple(errors)


@contextmanager
def _hold_stage_lifecycle(stages: tuple[PrivateFileStage, ...]):
    """Serialize a small stage set in process-stable canonical order."""
    ordered = tuple(sorted(stages, key=id))
    if len(ordered) == 1:
        with ordered[0]._lifecycle_lock:
            yield
    elif len(ordered) == 2:
        with ordered[0]._lifecycle_lock:
            with ordered[1]._lifecycle_lock:
                yield
    elif len(ordered) == 3:
        with ordered[0]._lifecycle_lock:
            with ordered[1]._lifecycle_lock:
                with ordered[2]._lifecycle_lock:
                    yield
    else:
        raise PrivateStageHandoffError("prepare")


@contextmanager
def _defer_stage_transition_signals():
    """Best-effort per-thread signal deferral around ownership transitions.

    Production cancellation is cooperative supervisor state, never an asynchronous
    exception injected into these primitives.  POSIX masks are per thread, so this
    helper cannot promise process-wide SIGINT/SIGTERM atomicity once other threads
    exist; the surrounding reconciliation remains the fail-closed backstop.
    """
    pthread_sigmask = getattr(signal, "pthread_sigmask", None)
    if pthread_sigmask is None:
        yield
        return
    blocked = {signal.SIGINT, signal.SIGTERM}
    previous = pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        yield
    finally:
        # A pending Python signal may raise here.  Callers deliberately place this
        # restoration inside their outer reconciliation fence.
        pthread_sigmask(signal.SIG_SETMASK, previous)


def _serialized_stage_lifecycle(function):
    @wraps(function)
    def serialized(stage, *args, **kwargs):
        if type(stage) is not PrivateFileStage:
            return function(stage, *args, **kwargs)
        with stage._lifecycle_lock:
            return function(stage, *args, **kwargs)
    return serialized


def _serialized_batch_lifecycle(function):
    @wraps(function)
    def serialized(batch, *args, **kwargs):
        if type(batch) is not PrivateStageHandoffBatch:
            return function(batch, *args, **kwargs)
        with _hold_stage_lifecycle(batch._stages):
            # State is deliberately checked by the wrapped operation only after
            # every member lock is held.  The stage locks are the sole lifecycle
            # hierarchy, avoiding a batch-vs-stage lock inversion.
            return function(batch, *args, **kwargs)
    return serialized


def _release_stage_fds(stage: PrivateFileStage, state: str) -> list[BaseException]:
    file_fd = stage.file_fd
    file_identity = stage.file_identity
    parent_fd = stage.parent_fd
    anchor_fd = stage.anchor_fd
    directory_claims = _stage_directory_close_claims(
        stage, parent_fd=parent_fd, anchor_fd=anchor_fd,
    )
    _set_stage(stage, "file_fd", -1)
    _set_stage(stage, "parent_fd", -1)
    _set_stage(stage, "anchor_fd", -1)
    _set_stage(stage, "state", state)
    errors: list[BaseException] = []
    try:
        errors.extend(
            _close_exposed_stage_writers_once(((file_fd, file_identity),))
        )
    except BaseException as exc:
        errors.append(exc)
    try:
        errors.extend(_close_exposed_stage_dirs_once(directory_claims))
    except BaseException as exc:
        errors.append(exc)
    return errors


def _same_private_inode(left_fd: int, right_fd: int) -> bool:
    left = os.fstat(left_fd)
    right = os.fstat(right_fd)
    return (
        _identity(left) == _identity(right)
        and left.st_uid == right.st_uid == os.geteuid()
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode) == FILE_MODE
        and left.st_nlink == right.st_nlink == 1
        and left.st_size == right.st_size
    )


def _validate_handoff_request_id(request_id, operation: str = "prepare") -> str:
    if (type(request_id) is not str or len(request_id) != 32
            or any(char not in "0123456789abcdef" for char in request_id)):
        raise PrivateStageHandoffError(operation)
    return request_id


def _validate_handoff_worker_pid(worker_pid, operation: str) -> int:
    if type(worker_pid) is not int or not 1 <= worker_pid <= _MAX_WORKER_PID:
        raise PrivateStageHandoffError(operation)
    return worker_pid


def _reconcile_stages_aborted_direct(
    stages: tuple[PrivateFileStage, ...],
    ledger: _PrivateStageCleanupLedger,
) -> None:
    """Make every member abort-only while retaining the canonical cleanup graph."""
    for stage in stages:
        object.__setattr__(stage, "_cleanup_ledger", ledger)
        object.__setattr__(stage, "_state", "aborted")
        object.__setattr__(stage, "_file_fd", -1)
        object.__setattr__(stage, "_parent_fd", -1)
        object.__setattr__(stage, "_anchor_fd", -1)


def _reconcile_batch_aborted_direct(
    batch: PrivateStageHandoffBatch,
    authority: object,
    stages: tuple[PrivateFileStage, ...],
    ledger: _PrivateStageCleanupLedger,
) -> None:
    """Consume batch lifecycle authority and retain all cleanup claims."""
    if type(authority) is _PrivateStageTransferAuthority:
        object.__setattr__(authority, "_consumed", True)
    object.__setattr__(batch, "_transfer_authority", None)
    object.__setattr__(batch, "_transfer_receipt", None)
    object.__setattr__(batch, "_state", "aborted")
    object.__setattr__(batch, "_cleanup_ledger", ledger)
    _reconcile_stages_aborted_direct(stages, ledger)


def _reconcile_failed_prepare_cleanup(
    stages: tuple[PrivateFileStage, ...],
    ledger: _PrivateStageCleanupLedger,
    batch: PrivateStageHandoffBatch | None,
) -> tuple[BaseException, ...]:
    """Terminalize a failed prepare and drain even after one control interruption."""
    errors: list[BaseException] = []
    authority = None if batch is None else batch._transfer_authority

    def reconcile() -> None:
        if batch is None:
            _reconcile_stages_aborted_direct(stages, ledger)
        else:
            _reconcile_batch_aborted_direct(
                batch, authority, stages, ledger,
            )

    try:
        with _defer_stage_transition_signals():
            reconcile()
    except BaseException as exc:
        errors.append(exc)
    finally:
        # The direct second reconciliation bypasses no injectable helper and is the
        # backstop for a one-shot cooperative interruption between member updates.
        reconcile()
        try:
            errors.extend(_drain_private_stage_ledger(ledger))
        except BaseException as exc:
            errors.append(exc)
        finally:
            try:
                errors.extend(_drain_private_stage_ledger(ledger))
            except BaseException as exc:
                errors.append(exc)
    return tuple(errors)


def _settle_failed_prepare_cleanup(
    stages: tuple[PrivateFileStage, ...],
    ledger: _PrivateStageCleanupLedger,
    batch: PrivateStageHandoffBatch | None,
) -> tuple[BaseException, ...]:
    """One outer catch around reconciliation-handler entry and cleanup."""
    errors: list[BaseException] = []
    try:
        errors.extend(_reconcile_failed_prepare_cleanup(stages, ledger, batch))
    except BaseException as exc:
        errors.append(exc)
    finally:
        # Handler-entry interruption may have skipped the inner helper entirely.
        authority = None if batch is None else batch._transfer_authority
        if batch is None:
            _reconcile_stages_aborted_direct(stages, ledger)
        else:
            _reconcile_batch_aborted_direct(batch, authority, stages, ledger)
        try:
            errors.extend(_drain_private_stage_ledger(ledger))
        except BaseException as exc:
            errors.append(exc)
    return tuple(errors)


def _validate_open_stage_for_handoff(stage) -> None:
    if type(stage) is not PrivateFileStage:
        raise PrivateStageHandoffError("prepare")
    if stage.state != "open":
        raise PrivateStageStateError("prepare", stage.state)
    if stage._cleanup_ledger is not None:
        raise PrivateStageHandoffError("prepare")
    _validate_live_stage(stage, "prepare")
    if stage.expected_digest is not None:
        # A stage carrying an exact-byte publication claim cannot also be a mutable
        # sink handed to a worker.  Callers must create a fresh unclaimed stage for
        # streamed capture and authenticate its bytes only after worker settlement.
        raise PrivateStageHandoffError("prepare")
    observed = os.fstat(stage.file_fd)
    if observed.st_nlink == 0:
        raise PrivatePathUnsafe(
            "private stage name was substituted", components=stage.components,
        )
    _validate_strict_file_stat(observed, stage.components)
    if _identity(observed) != stage.file_identity:
        raise PrivatePathUnsafe(
            "private stage file identity changed", components=stage.components,
        )


def prepare_private_stage_handoff(
    stages: tuple[PrivateFileStage, ...], request_id: str,
) -> PrivateStageHandoffBatch:
    """Atomically move one to three OPEN stage writers into an unspawned batch.

    No child exists at this boundary.  Original descriptors are first captured in a
    retained cleanup ledger while caller-visible stage fields are tombstoned.  Writer,
    read-pin, parent and anchor authority is then duplicated into private CLOEXEC
    claims and the retained originals are settled.  A successful batch therefore owns
    no numeric descriptor that was previously exposed through a stage object.
    """
    _require_strict_capabilities()
    request_id = _validate_handoff_request_id(request_id)
    if type(stages) is not tuple or not 1 <= len(stages) <= 3:
        raise PrivateStageHandoffError("prepare")
    if any(type(stage) is not PrivateFileStage for stage in stages):
        raise PrivateStageHandoffError("prepare")
    if len({id(stage) for stage in stages}) != len(stages):
        raise PrivateStageHandoffError("prepare")
    with _hold_stage_lifecycle(stages):
        # Complete validation before allocating any private descriptor so an
        # ordinary refusal preserves every original stage and exception type.
        identities = set()
        for stage in stages:
            _validate_open_stage_for_handoff(stage)
            if stage.file_identity in identities:
                raise PrivateStageHandoffError("prepare")
            identities.add(stage.file_identity)
        try:
            return _prepare_private_stage_handoff_locked(stages, request_id)
        except PrivateStageHandoffError:
            raise
        except BaseException as primary:
            cleanup_errors: list[BaseException] = []
            ledgers = {
                id(stage._cleanup_ledger): stage._cleanup_ledger
                for stage in stages
                if type(stage._cleanup_ledger) is _PrivateStageCleanupLedger
            }
            if len(ledgers) == 1:
                ledger = next(iter(ledgers.values()))
                cleanup_errors.extend(
                    _settle_failed_prepare_cleanup(stages, ledger, None)
                )
            error = PrivateStageHandoffError("prepare")
            error.cleanup_errors = tuple(cleanup_errors)
            error.close_errors = tuple(cleanup_errors)
            raise error from primary


def _prepare_private_stage_handoff_locked(
    stages: tuple[PrivateFileStage, ...], request_id: str,
) -> PrivateStageHandoffBatch:
    """Outer typed-error boundary for the private prepare transaction."""
    try:
        return _prepare_private_stage_handoff_transaction_locked(stages, request_id)
    except PrivateStageHandoffError:
        raise
    except BaseException as primary:
        cleanup_errors: list[BaseException] = []
        ledgers = {
            id(stage._cleanup_ledger): stage._cleanup_ledger
            for stage in stages
            if type(stage._cleanup_ledger) is _PrivateStageCleanupLedger
        }
        if len(ledgers) == 1:
            ledger = next(iter(ledgers.values()))
            cleanup_errors.extend(
                _settle_failed_prepare_cleanup(stages, ledger, None)
            )
        error = PrivateStageHandoffError("prepare")
        error.cleanup_errors = tuple(cleanup_errors)
        error.close_errors = tuple(cleanup_errors)
        raise error from primary


def _prepare_private_stage_handoff_transaction_locked(
    stages: tuple[PrivateFileStage, ...], request_id: str,
) -> PrivateStageHandoffBatch:
    private_stage_claims: list[_PrivateStageBatchClaim] = []
    source_by_stage: list[tuple[
        _PrivateDescriptorClaim,
        _PrivateDescriptorClaim,
        _PrivateDescriptorClaim,
    ]] = []
    ledger: _PrivateStageCleanupLedger | None = None
    batch: PrivateStageHandoffBatch | None = None
    completed = False
    primary: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    try:
        for stage in stages:
            writer = _new_descriptor_claim(
                -1, stage.file_identity, "writer", stage.components,
            )
            parent = _new_descriptor_claim(
                -1, stage.parent_identity, "parent", stage.components[:-1],
            )
            anchor = _new_descriptor_claim(
                -1, stage.anchor_identity, "anchor", (),
            )
            pin = _new_descriptor_claim(
                -1, stage.file_identity, "pin", stage.components,
            )
            private_stage_claims.append(_PrivateStageBatchClaim(
                stage=stage,
                writer=writer,
                pin=pin,
                parent=parent,
                anchor=anchor,
                _constructor_token=_PRIVATE_STAGE_BATCH_CLAIM_CONSTRUCTOR,
            ))
            source_by_stage.append((
                _new_descriptor_claim(
                    stage.file_fd, stage.file_identity,
                    "source_writer", stage.components,
                ),
                _new_descriptor_claim(
                    stage.parent_fd, stage.parent_identity,
                    "source_parent", stage.components[:-1],
                ),
                _new_descriptor_claim(
                    stage.anchor_fd, stage.anchor_identity,
                    "source_anchor", (),
                ),
            ))

        ledger = _PrivateStageCleanupLedger(
            stage_claims=tuple(private_stage_claims),
            extra_claims=tuple(
                claim for stage_sources in source_by_stage for claim in stage_sources
            ),
            _constructor_token=_PRIVATE_STAGE_CLEANUP_LEDGER_CONSTRUCTOR,
        )
        batch = PrivateStageHandoffBatch(
            stages=stages,
            cleanup_ledger=ledger,
            request_id=request_id,
            _constructor_token=_PRIVATE_STAGE_BATCH_CONSTRUCTOR,
        )

        # The complete ownership graph is reachable and every stage is abort-only
        # before the first private FD allocation.  Allocation helpers populate only
        # pre-registered slots, while the original public integers live in retained
        # source claims after their stage properties are tombstoned.
        with _defer_stage_transition_signals():
            _reconcile_stages_aborted_direct(stages, ledger)

        for stage, stage_claim, sources in zip(
            stages, private_stage_claims, source_by_stage,
        ):
            source_writer, source_parent, source_anchor = sources
            _duplicate_private_claim(stage_claim.writer, source_writer.fd)
            _duplicate_private_claim(stage_claim.parent, source_parent.fd)
            _duplicate_private_claim(stage_claim.anchor, source_anchor.fd)
            _open_strict_file_in(
                stage_claim.parent.fd,
                stage.temporary_name,
                stage.components,
                _claim=stage_claim.pin,
            )
            pin_observed = os.fstat(stage_claim.pin.fd)
            _validate_descriptor_claim_metadata(
                stage_claim.pin, pin_observed, allow_unlinked=False,
            )
            if not _same_private_inode(stage_claim.writer.fd, stage_claim.pin.fd):
                raise PrivatePathUnsafe(
                    "private stage name was substituted", components=stage.components,
                )

        source_errors = _drain_private_stage_ledger(
            ledger,
            kinds=frozenset({
                "source_writer", "source_parent", "source_anchor",
            }),
        )
        source_clean = all(
            claim._disposition == "closed_clean" and not claim._errors
            for stage_sources in source_by_stage
            for claim in stage_sources
        )
        if source_errors or not source_clean:
            raise PrivateStageHandoffError("prepare")

        with _defer_stage_transition_signals():
            for stage in stages:
                _set_stage(stage, "state", "handoff_prepared")
        completed = True
    except BaseException as exc:
        completed = False
        primary = exc
    finally:
        if not completed and ledger is not None:
            cleanup_errors.extend(
                _settle_failed_prepare_cleanup(stages, ledger, batch)
            )

    if (not completed and ledger is not None and not ledger.pending
            and not cleanup_errors
            and all(not claim.errors for claim in ledger.claims)):
        # A semantic prepare refusal with wholly clean descriptor settlement needs no
        # retained recovery authority.  Fault-bearing terminal ledgers remain attached
        # as the bounded audit record; pending ledgers remain the only cleanup handle.
        for stage in stages:
            if stage._cleanup_ledger is ledger:
                object.__setattr__(stage, "_cleanup_ledger", None)

    if completed and batch is not None:
        return batch
    if primary is None:
        primary = PrivateStageHandoffError("prepare")
    error = PrivateStageHandoffError("prepare")
    error.cleanup_errors = tuple(cleanup_errors)
    error.close_errors = tuple(cleanup_errors)
    raise error from primary


@_serialized_batch_lifecycle
def abort_unspawned_private_stage_handoff(batch: PrivateStageHandoffBatch) -> None:
    """Consume an unspawned batch and drain its entirely private descriptor ledger.

    The caller must have synchronous proof that no child was created.  This slice
    cannot be used after spawn.  Unique temporary names remain unpublished orphan
    candidates for a future authority-locked GC; this operation performs no rename,
    unlink or publication.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("abort_handoff")
    if batch.state not in {"prepared", "aborted"}:
        raise PrivateStageStateError("abort_handoff", batch.state)
    stages = batch._stages
    ledger = batch._cleanup_ledger
    if type(ledger) is not _PrivateStageCleanupLedger:
        raise PrivateStageHandoffError("abort_handoff")
    if batch.state == "aborted" and not ledger.pending:
        return
    authority = batch._transfer_authority
    transition_errors: list[BaseException] = []
    cleanup_errors: list[BaseException] = []
    try:
        with _defer_stage_transition_signals():
            _reconcile_batch_aborted_direct(batch, authority, stages, ledger)
    except BaseException as exc:
        transition_errors.append(exc)
    finally:
        # This direct retry is reconciliation after authority was captured.  A
        # cooperative one-shot cancellation cannot leave a partially aborted set.
        _reconcile_batch_aborted_direct(batch, authority, stages, ledger)
        cleanup_errors.extend(_drain_private_stage_ledger(ledger))
    if transition_errors or cleanup_errors or ledger.pending:
        error = PrivateStageHandoffError("abort_handoff")
        error.cleanup_errors = tuple(transition_errors + cleanup_errors)
        error.close_errors = tuple(cleanup_errors)
        cause = (
            transition_errors[0] if transition_errors
            else cleanup_errors[0] if cleanup_errors
            else error
        )
        raise error from cause


def _validate_prepared_handoff_shape(
    batch: PrivateStageHandoffBatch, operation: str, *, stage_state: str,
) -> tuple[PrivateFileStage, ...]:
    stages = batch._stages
    ledger = batch._cleanup_ledger
    if (type(stages) is not tuple or not 1 <= len(stages) <= 3
            or any(type(stage) is not PrivateFileStage for stage in stages)
            or len({id(stage) for stage in stages}) != len(stages)
            or type(ledger) is not _PrivateStageCleanupLedger
            or len(ledger.stage_claims) != len(stages)
            or any(stage_claim._stage is not stage
                   for stage_claim, stage in zip(ledger.stage_claims, stages))
            or any(
                (
                    stage_claim.writer.kind,
                    stage_claim.pin.kind,
                    stage_claim.parent.kind,
                    stage_claim.anchor.kind,
                ) != ("writer", "pin", "parent", "anchor")
                or stage_claim.writer._identity != stage.file_identity
                or stage_claim.pin._identity != stage.file_identity
                or stage_claim.parent._identity != stage.parent_identity
                or stage_claim.anchor._identity != stage.anchor_identity
                for stage_claim, stage in zip(ledger.stage_claims, stages)
            )
            or any(
                claim.disposition != "pending"
                or claim.fd < 0
                for stage_claim in ledger.stage_claims
                for claim in (
                    stage_claim.writer, stage_claim.pin,
                    stage_claim.parent, stage_claim.anchor,
                )
            )
            or len({
                claim.fd
                for stage_claim in ledger.stage_claims
                for claim in (
                    stage_claim.writer, stage_claim.pin,
                    stage_claim.parent, stage_claim.anchor,
                )
            }) != 4 * len(stages)
            or any(stage.state != stage_state or stage.file_fd != -1
                   for stage in stages)):
        raise PrivateStageHandoffError(operation)
    return stages


@_serialized_batch_lifecycle
def _prepare_private_stage_transfer_authority(
    batch: PrivateStageHandoffBatch, *, request_id: str,
) -> _PrivateStageTransferAuthority:
    """Reserve an exact-batch transfer authority before any child exists.

    This step performs every validation and allocation needed by post-spawn bind,
    then moves the batch to ``spawn_prepared`` under its canonical locks.  The batch
    no longer permits generic abort.  The returned authority can be used only by the
    callback-owned spawn boundary or the exact no-child recovery path; it never
    exposes a raw ``pass_fds`` tuple.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("bind_worker")
    request_id = _validate_handoff_request_id(request_id, "bind_worker")
    if batch.state != "prepared":
        raise PrivateStageStateError("bind_worker", batch.state)
    stages = _validate_prepared_handoff_shape(
        batch, "bind_worker", stage_state="handoff_prepared",
    )
    if request_id != batch._request_id or batch._transfer_authority is not None:
        raise PrivateStageHandoffError("bind_worker")

    authority = _PrivateStageTransferAuthority(
        batch=batch,
        request_id=request_id,
        file_identities=tuple(stage.file_identity for stage in stages),
        _constructor_token=_PRIVATE_STAGE_TRANSFER_AUTHORITY_CONSTRUCTOR,
    )
    try:
        with _defer_stage_transition_signals():
            object.__setattr__(batch, "_transfer_authority", authority)
            object.__setattr__(batch, "_state", "spawn_prepared")
            for stage in stages:
                object.__setattr__(stage, "_state", "spawn_prepared")
        return authority
    except BaseException as primary:
        # No child exists yet, so restoration to the exact pre-reservation state is
        # both safe and preferable to stranding a capability the caller never saw.
        object.__setattr__(authority, "_consumed", True)
        object.__setattr__(batch, "_transfer_authority", None)
        object.__setattr__(batch, "_state", "prepared")
        for stage in stages:
            object.__setattr__(stage, "_state", "handoff_prepared")
        error = PrivateStageHandoffError("bind_worker")
        raise error from primary


def _validate_spawn_transfer_authority(
    batch: PrivateStageHandoffBatch, authority, operation: str,
) -> _PrivateStageTransferAuthority:
    if (type(authority) is not _PrivateStageTransferAuthority
            or authority._consumed is not False
            or authority._bound is not False
            or authority._batch is not batch
            or batch._transfer_authority is not authority
            or authority._request_id != batch._request_id):
        raise PrivateStageHandoffError(operation)
    return authority


def _borrow_private_stage_spawn_fds(
    batch: PrivateStageHandoffBatch, authority,
) -> tuple[int, ...]:
    """Compatibility refusal: a writer tuple may not escape a locked attempt."""
    raise PrivateStageHandoffError("borrow_spawn")


def _spawn_with_private_stage_handoff(
    batch: PrivateStageHandoffBatch, authority, spawn_callable,
) -> tuple[object, _PrivateStageTransferAuthority]:
    """Invoke one trusted Popen callback inside the locked inheritance boundary.

    ``spawn_callable`` receives the ordered ``pass_fds`` tuple only while every
    canonical stage lock is held.  It must invoke Popen synchronously, return that
    child object, and never retain the tuple.  The returned object's exact integer
    ``pid`` is recorded only as an untrusted correlation claim; neither the object
    nor its PID proves process identity, containment, readiness or parking.

    The caller MUST establish and retain independently killable containment before
    invoking this helper.  Natural callback/validation faults and cooperative
    cancellation enter a best-effort fence while the lifecycle locks remain held.
    Python cannot make cleanup-handler entry atomic against arbitrary asynchronous
    exception injection: such an escape may leave a reachable ``spawn_prepared`` or
    ``worker_spawned_unverified`` batch with borrowed, unconsumed authority and a
    pending private ledger.  It creates no close receipt, GO or publication claim.
    On every abnormal escape the supervisor MUST treat the child outcome as unknown,
    kill/reap its containment, then replay ``fence_private_stage_handoff`` from a
    cooperative cleanup path.  This wrapper never returns the raw writer tuple, and
    the trusted callback must neither retain nor duplicate it.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch or not callable(spawn_callable):
        raise PrivateStageHandoffError("borrow_spawn")
    stages = batch._stages
    if (type(stages) is not tuple or not 1 <= len(stages) <= 3
            or any(type(stage) is not PrivateFileStage for stage in stages)):
        raise PrivateStageHandoffError("borrow_spawn")

    with _hold_stage_lifecycle(stages):
        if batch.state != "spawn_prepared":
            raise PrivateStageStateError("borrow_spawn", batch.state)
        authority = _validate_spawn_transfer_authority(
            batch, authority, "borrow_spawn",
        )
        if authority._borrowed is not False:
            raise PrivateStageHandoffError("borrow_spawn")
        _validate_prepared_handoff_shape(
            batch, "borrow_spawn", stage_state="spawn_prepared",
        )
        ledger = batch._cleanup_ledger
        if type(ledger) is not _PrivateStageCleanupLedger:
            raise PrivateStageHandoffError("borrow_spawn")
        writer_claims = tuple(
            stage_claim._writer for stage_claim in ledger.stage_claims
        )
        writers = tuple(claim.fd for claim in writer_claims)
        if len(authority._file_identities) != len(writers):
            raise PrivateStageHandoffError("borrow_spawn")
        try:
            for claim, expected_identity in zip(
                writer_claims, authority._file_identities,
            ):
                if (claim._disposition != "pending"
                        or claim._identity != expected_identity):
                    raise PrivateStageHandoffError("borrow_spawn")
                observed = os.fstat(claim.fd)
                if _identity(observed) != expected_identity:
                    raise PrivatePathUnsafe("private stage writer identity changed")
                _validate_descriptor_claim_metadata(
                    claim, observed, allow_unlinked=False,
                )
        except BaseException as primary:
            error = PrivateStageHandoffError("borrow_spawn")
            raise error from primary

        child = None
        result = None
        primary: BaseException | None = None
        try:
            # This mutation leaves an exact, reachable recovery graph before callback
            # entry.  Ordinary faults enter the best-effort fence below; the docstring
            # defines the supervisor obligation for arbitrary async handler interruption.
            object.__setattr__(authority, "_borrowed", True)
            child = spawn_callable(writers)
            worker_pid = _validate_handoff_worker_pid(
                child.pid, "mark_spawned",
            )
            _mark_private_stage_worker_spawned_locked(
                batch, authority, worker_pid=worker_pid,
            )
            result = (child, authority)
        except BaseException as exc:
            primary = exc
        finally:
            # This backstop covers ordinary callback/validation faults and cooperative
            # cancellation, including an interruption handled by the inner body.  It
            # is deliberately not described as atomic against arbitrary async injection
            # at this cleanup handler's own entry; the retained ledger remains replayable.
            unresolved = (
                authority._borrowed is True
                and batch.state not in {
                    "worker_spawned_unverified", "worker_claim_bound",
                    "parent_writers_closed", "transfer_uncertain", "fenced",
                    "aborted",
                }
            )
            if primary is not None or unresolved:
                cleanup_errors: list[BaseException] = []
                try:
                    fence_private_stage_handoff(batch)
                except BaseException as exc:
                    cleanup_errors.append(exc)
                finally:
                    if batch.state != "fenced" or batch._cleanup_ledger.pending:
                        try:
                            fence_private_stage_handoff(batch)
                        except BaseException as exc:
                            cleanup_errors.append(exc)
                if primary is None:
                    primary = (
                        cleanup_errors[0]
                        if cleanup_errors
                        else PrivateStageHandoffError("borrow_spawn")
                    )
                elif cleanup_errors:
                    try:
                        primary.private_cleanup_error = cleanup_errors[0]
                    except BaseException:
                        pass

        if primary is not None:
            # The callback may have created a child even if it never returned.
            # Supervisor integration must kill/reap containment on this failure.
            raise primary
        if result is None:
            error = PrivateStageHandoffError("borrow_spawn")
            try:
                fence_private_stage_handoff(batch)
            except BaseException as cleanup_error:
                error.private_cleanup_error = cleanup_error
            raise error
        return result


def _validate_unverified_transfer_authority(
    batch: PrivateStageHandoffBatch, authority,
) -> _PrivateStageTransferAuthority:
    if (type(authority) is not _PrivateStageTransferAuthority
            or authority._consumed is not False
            or authority._bound is not False
            or authority._batch is not batch
            or batch._transfer_authority is not authority
            or authority._request_id != batch._request_id
            or type(authority._claimed_worker_pid) is not int
            or not 1 <= authority._claimed_worker_pid <= _MAX_WORKER_PID):
        raise PrivateStageHandoffError("bind_worker")
    return authority


def _force_aborted_spawn_state(
    batch: PrivateStageHandoffBatch,
    authority: _PrivateStageTransferAuthority,
    stages: tuple[PrivateFileStage, ...],
) -> None:
    """Consume every logical capability before failed-spawn cleanup begins."""
    object.__setattr__(authority, "_consumed", True)
    object.__setattr__(batch, "_transfer_authority", None)
    object.__setattr__(batch, "_transfer_receipt", None)
    object.__setattr__(batch, "_state", "aborted")
    for stage in stages:
        object.__setattr__(stage, "_file_fd", -1)
        object.__setattr__(stage, "_parent_fd", -1)
        object.__setattr__(stage, "_anchor_fd", -1)
        object.__setattr__(stage, "_cleanup_ledger", batch._cleanup_ledger)
        object.__setattr__(stage, "_state", "aborted")


@_serialized_batch_lifecycle
def _abort_private_stage_spawn(batch: PrivateStageHandoffBatch, authority) -> None:
    """Resolve one reserved authority after Popen proves no child was created.

    Only the exact unbound authority can consume a ``spawn_prepared`` batch.  The
    private descriptor ledger is drained while unique unpublished names remain for
    future authority-locked GC.  A replay of the same consumed authority is harmless;
    no other lifecycle may use this recovery path.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("abort_spawn")
    ledger = batch._cleanup_ledger
    if type(ledger) is not _PrivateStageCleanupLedger:
        raise PrivateStageHandoffError("abort_spawn")
    if batch.state == "aborted":
        if (type(authority) is _PrivateStageTransferAuthority
                and authority._batch is batch
                and authority._bound is False
                and authority._consumed is True):
            cleanup_errors = list(_drain_private_stage_ledger(ledger))
            if not cleanup_errors and not ledger.pending:
                return
            error = PrivateStageHandoffError("abort_spawn")
            error.cleanup_errors = tuple(cleanup_errors)
            error.close_errors = tuple(cleanup_errors)
            raise error from (cleanup_errors[0] if cleanup_errors else error)
        raise PrivateStageHandoffError("abort_spawn")
    if batch.state != "spawn_prepared":
        raise PrivateStageStateError("abort_spawn", batch.state)

    stages = _validate_prepared_handoff_shape(
        batch, "abort_spawn", stage_state="spawn_prepared",
    )
    authority = _validate_spawn_transfer_authority(batch, authority, "abort_spawn")
    transition_errors: list[BaseException] = []

    try:
        with _defer_stage_transition_signals():
            _force_aborted_spawn_state(batch, authority, stages)
    except BaseException as exc:
        transition_errors.append(exc)
        # Reconcile through primitive assignments, bypassing the injectable helper.
        object.__setattr__(authority, "_consumed", True)
        object.__setattr__(batch, "_transfer_authority", None)
        object.__setattr__(batch, "_transfer_receipt", None)
        object.__setattr__(batch, "_state", "aborted")
        for stage in stages:
            object.__setattr__(stage, "_file_fd", -1)
            object.__setattr__(stage, "_parent_fd", -1)
            object.__setattr__(stage, "_anchor_fd", -1)
            object.__setattr__(stage, "_cleanup_ledger", ledger)
            object.__setattr__(stage, "_state", "aborted")
    cleanup_errors = list(_drain_private_stage_ledger(ledger))
    if transition_errors or cleanup_errors or ledger.pending:
        error = PrivateStageHandoffError("abort_spawn")
        error.cleanup_errors = tuple(transition_errors + cleanup_errors)
        error.close_errors = tuple(cleanup_errors)
        cause = (transition_errors + cleanup_errors)[0] if (
            transition_errors or cleanup_errors
        ) else error
        raise error from cause


def _force_worker_spawned_unverified_state(
    batch: PrivateStageHandoffBatch,
    authority: _PrivateStageTransferAuthority,
    stages: tuple[PrivateFileStage, ...],
    claimed_worker_pid: int | None,
) -> None:
    object.__setattr__(batch, "_transfer_authority", authority)
    object.__setattr__(batch, "_state", "worker_spawned_unverified")
    if claimed_worker_pid is not None:
        object.__setattr__(authority, "_claimed_worker_pid", claimed_worker_pid)
    for stage in stages:
        object.__setattr__(stage, "_state", "worker_spawned_unverified")


def _mark_private_stage_worker_spawned_locked(
    batch: PrivateStageHandoffBatch, authority, *, worker_pid: int,
) -> _PrivateStageTransferAuthority:
    """Record a spawn callback's untrusted PID claim while all locks are held.

    Exact authority validation is the declaration boundary: after it passes, the
    batch can never return to a no-child state.  The integer is retained only as an
    unverified correlation fact.  No identity, containment, readiness, GO or
    publication claim is made.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("mark_spawned")
    if batch.state != "spawn_prepared":
        raise PrivateStageStateError("mark_spawned", batch.state)
    authority = _validate_spawn_transfer_authority(batch, authority, "mark_spawned")
    if authority._borrowed is not True:
        raise PrivateStageHandoffError("mark_spawned")
    stages = batch._stages
    valid_pid: int | None = None
    try:
        _validate_prepared_handoff_shape(
            batch, "mark_spawned", stage_state="spawn_prepared",
        )
        valid_pid = _validate_handoff_worker_pid(worker_pid, "mark_spawned")
        with _defer_stage_transition_signals():
            _force_worker_spawned_unverified_state(
                batch, authority, stages, valid_pid,
            )
        return authority
    except BaseException as primary:
        # Bypass the injectable transition seam during reconciliation.
        object.__setattr__(batch, "_transfer_authority", authority)
        object.__setattr__(batch, "_state", "worker_spawned_unverified")
        if valid_pid is not None:
            object.__setattr__(authority, "_claimed_worker_pid", valid_pid)
        for stage in stages:
            object.__setattr__(stage, "_state", "worker_spawned_unverified")
        error = PrivateStageSpawnUncertain(
            authority=authority,
            claimed_worker_pid=valid_pid,
            file_identities=authority._file_identities,
        )
        raise error from primary


def _mark_private_stage_worker_spawned(
    batch: PrivateStageHandoffBatch, authority, *, worker_pid: int,
) -> _PrivateStageTransferAuthority:
    """Compatibility refusal: marking is valid only on a locked attempt object."""
    raise PrivateStageHandoffError("mark_spawned")


@_serialized_batch_lifecycle
def _bind_private_stage_transfer_authority(
    batch: PrivateStageHandoffBatch, authority, *, worker_pid: int,
) -> _PrivateStageTransferAuthority:
    """Bind a caller-attested worker correlation claim to the exact batch.

    The caller is responsible for independently proving process identity,
    containment and readiness.  A repeated integer PID is not authentication.
    Once the exact batch/authority and correlation value pass, every later fault
    reconciles to ``worker_claim_bound``.  This function does not release GO.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("bind_worker")
    if batch.state != "worker_spawned_unverified":
        raise PrivateStageStateError("bind_worker", batch.state)
    authority = _validate_unverified_transfer_authority(batch, authority)
    stages = batch._stages

    # Refuse a malformed or mismatched correlation claim without upgrading state.
    proved_pid = _validate_handoff_worker_pid(worker_pid, "bind_worker")
    if proved_pid != authority._claimed_worker_pid:
        raise PrivateStageHandoffError("bind_worker")
    _validate_prepared_handoff_shape(
        batch, "bind_worker", stage_state="worker_spawned_unverified",
    )

    # The exact caller-attested value now matches.  A transition fault reconciles
    # to claim-bound and returns the opaque recovery capability in a typed error.
    try:
        with _defer_stage_transition_signals():
            _force_worker_claim_bound_state(batch, authority, stages)
            object.__setattr__(authority, "_bound", True)
    except BaseException as primary:
        object.__setattr__(batch, "_transfer_authority", authority)
        object.__setattr__(batch, "_state", "worker_claim_bound")
        object.__setattr__(authority, "_claimed_worker_pid", proved_pid)
        object.__setattr__(authority, "_bound", True)
        for stage in stages:
            object.__setattr__(stage, "_state", "worker_claim_bound")
        error = PrivateStageBindUncertain(
            authority=authority,
            claimed_worker_pid=proved_pid,
            file_identities=authority._file_identities,
        )
        raise error from primary
    return authority


def _validate_stage_transfer_authority(
    batch: PrivateStageHandoffBatch, authority,
) -> _PrivateStageTransferAuthority:
    if (type(authority) is not _PrivateStageTransferAuthority
            or authority._consumed is not False
            or authority._bound is not True
            or authority._batch is not batch
            or batch._transfer_authority is not authority
            or authority._request_id != batch._request_id
            or type(authority._claimed_worker_pid) is not int
            or not 1 <= authority._claimed_worker_pid <= _MAX_WORKER_PID):
        raise PrivateStageHandoffError("transfer")
    return authority


def _force_worker_claim_bound_state(
    batch: PrivateStageHandoffBatch,
    authority: _PrivateStageTransferAuthority,
    stages: tuple[PrivateFileStage, ...],
) -> None:
    object.__setattr__(batch, "_transfer_authority", authority)
    object.__setattr__(batch, "_state", "worker_claim_bound")
    for stage in stages:
        object.__setattr__(stage, "_state", "worker_claim_bound")


def _force_transfer_state(
    batch: PrivateStageHandoffBatch,
    authority: _PrivateStageTransferAuthority,
    stages: tuple[PrivateFileStage, ...],
    state: str,
    receipt: PrivateStageParentCloseReceipt | None,
) -> None:
    """Primitive reconciliation after the operation captured every authority."""
    object.__setattr__(authority, "_consumed", True)
    object.__setattr__(authority, "_borrowed", False)
    object.__setattr__(batch, "_transfer_authority", None)
    object.__setattr__(batch, "_transfer_receipt", receipt)
    object.__setattr__(batch, "_state", state)
    for stage in stages:
        object.__setattr__(stage, "_file_fd", -1)
        object.__setattr__(stage, "_state", state)


def _reconcile_transfer_state_direct(
    batch: PrivateStageHandoffBatch,
    authority: _PrivateStageTransferAuthority,
    stages: tuple[PrivateFileStage, ...],
    state: str,
    receipt: PrivateStageParentCloseReceipt | None,
) -> None:
    """Non-seam fallback used after the operation has captured all claims."""
    object.__setattr__(authority, "_consumed", True)
    object.__setattr__(authority, "_borrowed", False)
    object.__setattr__(batch, "_transfer_authority", None)
    object.__setattr__(batch, "_transfer_receipt", receipt)
    object.__setattr__(batch, "_state", state)
    for stage in stages:
        object.__setattr__(stage, "_file_fd", -1)
        object.__setattr__(stage, "_state", state)


@_serialized_batch_lifecycle
def transfer_private_stage_handoff(
    batch: PrivateStageHandoffBatch, authority,
) -> PrivateStageParentCloseReceipt:
    """Authenticate and close every registered parent-side stage writer.

    Clean completion proves only that each registered numeric descriptor still
    named its expected stage inode and that close returned successfully.  It does
    not prove absence of aliases, child inheritance, process identity, containment,
    content stability, GO release or publication.  A close fault consumes the
    authority and permanently marks the batch ``transfer_uncertain``.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("transfer")
    if batch.state != "worker_claim_bound":
        raise PrivateStageStateError("transfer", batch.state)
    stages = _validate_prepared_handoff_shape(
        batch, "transfer", stage_state="worker_claim_bound",
    )
    authority = _validate_stage_transfer_authority(batch, authority)

    file_identities = authority._file_identities
    ledger = batch._cleanup_ledger
    if type(ledger) is not _PrivateStageCleanupLedger:
        raise PrivateStageHandoffError("transfer")
    writer_claims = tuple(
        stage_claim._writer for stage_claim in ledger.stage_claims
    )
    if (len(writer_claims) != len(file_identities)
            or any(claim._identity != identity
                   for claim, identity in zip(writer_claims, file_identities))):
        raise PrivateStageHandoffError("transfer")
    receipt = PrivateStageParentCloseReceipt(
        request_id=batch._request_id,
        claimed_worker_pid=authority._claimed_worker_pid,
        file_identities=file_identities,
        _constructor_token=_PRIVATE_STAGE_PARENT_CLOSE_RECEIPT_CONSTRUCTOR,
    )
    uncertain = PrivateStageTransferUncertain(
        claimed_worker_pid=authority._claimed_worker_pid,
        file_identities=file_identities,
    )
    transition_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    try:
        with _defer_stage_transition_signals():
            _force_transfer_state(
                batch, authority, stages, "transfer_uncertain", None,
            )
    except BaseException as exc:
        transition_errors.append(exc)
    finally:
        _reconcile_transfer_state_direct(
            batch, authority, stages, "transfer_uncertain", None,
        )
        close_errors.extend(
            _drain_private_stage_ledger(
                ledger, kinds=frozenset({"writer"}),
            )
        )

    writers_clean = all(
        claim._disposition == "closed_clean" and not claim._errors
        for claim in writer_claims
    )
    if not transition_errors and not close_errors and writers_clean:
        try:
            with _defer_stage_transition_signals():
                _force_transfer_state(
                    batch, authority, stages, "parent_writers_closed", receipt,
                )
            return receipt
        except BaseException as exc:
            transition_errors.append(exc)
            _reconcile_transfer_state_direct(
                batch, authority, stages, "transfer_uncertain", None,
            )

    uncertain.cleanup_errors = tuple(transition_errors)
    uncertain.close_errors = tuple(close_errors)
    cause = (
        transition_errors[0] if transition_errors
        else close_errors[0] if close_errors
        else PrivateStageHandoffError("transfer")
    )
    raise uncertain from cause


def _force_fenced_state(
    batch: PrivateStageHandoffBatch, stages: tuple[PrivateFileStage, ...],
) -> None:
    authority = batch._transfer_authority
    if type(authority) is _PrivateStageTransferAuthority:
        object.__setattr__(authority, "_consumed", True)
        object.__setattr__(authority, "_borrowed", False)
    object.__setattr__(batch, "_transfer_authority", None)
    object.__setattr__(batch, "_transfer_receipt", None)
    object.__setattr__(batch, "_state", "fenced")
    for stage in stages:
        object.__setattr__(stage, "_file_fd", -1)
        object.__setattr__(stage, "_parent_fd", -1)
        object.__setattr__(stage, "_anchor_fd", -1)
        object.__setattr__(stage, "_cleanup_ledger", batch._cleanup_ledger)
        object.__setattr__(stage, "_state", "fenced")


def _reconcile_fenced_state_direct(
    batch: PrivateStageHandoffBatch,
    authority: object,
    stages: tuple[PrivateFileStage, ...],
) -> None:
    """Non-seam terminal reconciliation after all fence claims are captured."""
    if type(authority) is _PrivateStageTransferAuthority:
        object.__setattr__(authority, "_consumed", True)
        object.__setattr__(authority, "_borrowed", False)
    object.__setattr__(batch, "_transfer_authority", None)
    object.__setattr__(batch, "_transfer_receipt", None)
    object.__setattr__(batch, "_state", "fenced")
    for stage in stages:
        object.__setattr__(stage, "_file_fd", -1)
        object.__setattr__(stage, "_parent_fd", -1)
        object.__setattr__(stage, "_anchor_fd", -1)
        object.__setattr__(stage, "_cleanup_ledger", batch._cleanup_ledger)
        object.__setattr__(stage, "_state", "fenced")


@_serialized_batch_lifecycle
def fence_private_stage_handoff(batch: PrivateStageHandoffBatch) -> None:
    """Fail closed by draining a nonpublishable batch's private descriptor ledger.

    ``spawn_prepared`` is accepted only as ambiguous-attempt recovery when Popen's
    outcome was lost; it does not assert whether a child existed.  Unverified and
    caller-attested workers may likewise be live or unreapable.  Unique temporary
    names remain unpublished orphan candidates for later authority-locked GC.  This
    primitive records no process-settlement fact, never signals/releases a worker,
    and never renames, publishes or unlinks.
    """
    _require_strict_capabilities()
    if type(batch) is not PrivateStageHandoffBatch:
        raise PrivateStageHandoffError("fence")
    ledger = batch._cleanup_ledger
    if type(ledger) is not _PrivateStageCleanupLedger:
        raise PrivateStageHandoffError("fence")
    if batch.state == "fenced":
        cleanup_errors = list(_drain_private_stage_ledger(ledger))
        if not cleanup_errors and not ledger.pending:
            return
        error = PrivateStageHandoffError("fence")
        error.cleanup_errors = tuple(cleanup_errors)
        error.close_errors = tuple(cleanup_errors)
        raise error from (cleanup_errors[0] if cleanup_errors else error)
    writer_states = {
        "spawn_prepared", "worker_spawned_unverified", "worker_claim_bound",
    }
    if batch.state not in writer_states | {
        "parent_writers_closed", "transfer_uncertain",
    }:
        raise PrivateStageStateError("fence", batch.state)

    stages = batch._stages
    expected_state = batch.state
    if (type(stages) is not tuple or not 1 <= len(stages) <= 3
            or any(type(stage) is not PrivateFileStage for stage in stages)
            or any(stage.state != expected_state or stage.file_fd != -1
                   for stage in stages)):
        raise PrivateStageHandoffError("fence")
    if expected_state in writer_states:
        authority = batch._transfer_authority
        if (type(authority) is not _PrivateStageTransferAuthority
                or authority._batch is not batch
                or authority._consumed is not False
                or len(authority._file_identities) != len(ledger.stage_claims)):
            raise PrivateStageHandoffError("fence")

    transition_errors: list[BaseException] = []
    fence_authority = batch._transfer_authority
    try:
        with _defer_stage_transition_signals():
            _force_fenced_state(batch, stages)
    except BaseException as exc:
        transition_errors.append(exc)
    finally:
        _reconcile_fenced_state_direct(batch, fence_authority, stages)
        cleanup_errors = list(_drain_private_stage_ledger(ledger))

    if transition_errors or cleanup_errors or ledger.pending:
        error = PrivateStageHandoffError("fence")
        error.cleanup_errors = tuple(transition_errors + cleanup_errors)
        error.close_errors = tuple(cleanup_errors)
        cause = (transition_errors + cleanup_errors)[0] if (
            transition_errors or cleanup_errors
        ) else error
        raise error from cause


def _discard_named_claim(
    parent_fd: int,
    name: str,
    retained_fd: int,
    components: tuple[str, ...],
    *,
    _verification_claim: _PrivateDescriptorClaim | None = None,
) -> None:
    """Quarantine a name, then prove whether it names ``retained_fd``.

    POSIX has no descriptor-bound unlink.  Moving the current name to a random
    quarantine name first closes the validate-then-unlink window for ordinary
    repository concurrency: a substituted source is retained for inspection rather
    than deleted.  Code running as this same UID remains outside the trust boundary.
    """
    quarantine = ""
    for _ in range(32):
        candidate = f".quarry-discard-{os.urandom(16).hex()}.stage"
        try:
            os.stat(candidate, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            quarantine = candidate
            break
    if not quarantine:
        raise PrivatePathError("could not reserve a private discard name", components=components)

    try:
        os.rename(name, quarantine, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except FileNotFoundError:
        retained = os.fstat(retained_fd)
        if retained.st_nlink == 0:
            return
        raise PrivatePathUnsafe(
            "private stage claim disappeared before cleanup", components=components,
        )

    if _verification_claim is None:
        quarantined_fd = _open_strict_file_in(parent_fd, quarantine, components)
        with _owned_fd(quarantined_fd):
            if not _same_private_inode(quarantined_fd, retained_fd):
                raise PrivatePathUnsafe(
                    "private stage cleanup quarantined a substituted name",
                    components=components,
                )
    else:
        _open_strict_file_in(
            parent_fd,
            quarantine,
            components,
            _claim=_verification_claim,
        )
        if not _same_private_inode(_verification_claim.fd, retained_fd):
            raise PrivatePathUnsafe(
                "private stage cleanup quarantined a substituted name",
                components=components,
            )
    # Do not unlink here: POSIX has no descriptor-bound unlink, so a second
    # validate-then-unlink window would let a substituted name be deleted.  The
    # quarantined file is harmless and remains available for authority-locked GC.


def _validate_declared_stage_parent(stage: PrivateFileStage) -> None:
    """Refuse publication when the pinned parent no longer has its declared name."""
    _validate_stage_directory_claims(stage)
    declared = open_strict_dir_at(stage.anchor_fd, stage.components[:-1])
    with _owned_fd(declared):
        if _identity(os.fstat(declared)) != stage.parent_identity:
            raise PrivatePathUnsafe(
                "private stage parent no longer matches its declared path",
                components=stage.components,
            )


def create_private_stage(anchor_fd: int, components: tuple[str, ...]) -> PrivateFileStage:
    """Claim a unique 0600 stage in the destination directory without publishing it."""
    _require_strict_capabilities()
    components = validate_relative_components(components, allow_empty=False)
    anchor_fd = _validate_anchor_fd(anchor_fd)
    owned_anchor = open_strict_dir_at(anchor_fd, ())
    parent = -1
    fd = -1
    temporary_name = ""
    try:
        parent = open_strict_dir_at(owned_anchor, components[:-1])
        anchor_stat = os.fstat(owned_anchor)
        parent_stat = os.fstat(parent)
        for _ in range(32):
            temporary_name = f".quarry-{os.urandom(16).hex()}.stage"
            if temporary_name == components[-1]:
                continue
            try:
                fd = os.open(temporary_name, _STAGE_OPEN_FLAGS, FILE_MODE, dir_fd=parent)
                break
            except FileExistsError:
                continue
        else:
            raise PrivatePathError("could not claim a unique private stage", components=components)

        # This inode was exclusively created by this call.  Setting its creation mode
        # exactly is not compatibility repair and prevents an unusual umask from
        # removing required owner bits.
        os.fchmod(fd, FILE_MODE)
        file_stat = os.fstat(fd)
        _validate_strict_file_stat(file_stat, components)
        return PrivateFileStage(
            anchor_fd=owned_anchor,
            parent_fd=parent,
            file_fd=fd,
            temporary_name=temporary_name,
            destination_name=components[-1],
            components=components,
            anchor_identity=_identity(anchor_stat),
            parent_identity=_identity(parent_stat),
            file_identity=_identity(file_stat),
            _constructor_token=_PRIVATE_STAGE_CONSTRUCTOR,
        )
    except BaseException as primary:
        cleanup_error = None
        if temporary_name and parent >= 0 and fd >= 0:
            try:
                _discard_named_claim(parent, temporary_name, fd, components)
            except BaseException as exc:
                cleanup_error = exc
        close_errors = _close_fds(fd, parent, owned_anchor)
        try:
            primary.private_cleanup_error = cleanup_error
            primary.close_errors = tuple(close_errors)
        except BaseException:
            pass
        raise


def stage_private_bytes(
    anchor_fd: int, components: tuple[str, ...], data: bytes,
) -> PrivateFileStage:
    """Create a stage and write exact bytes; publication remains a separate operation."""
    _require_strict_capabilities()
    components = validate_relative_components(components, allow_empty=False)
    anchor_fd = _validate_anchor_fd(anchor_fd)
    if type(data) is not bytes:
        raise PrivatePathUnsafe("private stage data must be exact bytes", components=components)

    stage = create_private_stage(anchor_fd, components)
    _set_stage(stage, "expected_digest", (len(data), hashlib.sha256(data).hexdigest()))
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            try:
                count = os.write(stage.file_fd, view[written:])
            except InterruptedError:
                continue
            if count <= 0:
                raise OSError("private stage write made no progress")
            written += count
        return stage
    except BaseException as primary:
        try:
            abort_private_stage(stage)
        except BaseException as cleanup_error:
            try:
                primary.private_cleanup_error = cleanup_error
            except BaseException:
                pass
        raise


def _open_settled_stage(
    stage: PrivateFileStage,
    sealed_signature: tuple[int, int, int, int, int, int, int],
) -> tuple[int, tuple[int, str]]:
    _validate_stage_directory_claims(stage)
    read_fd = _open_strict_file_in(stage.parent_fd, stage.temporary_name, stage.components)
    try:
        if _file_signature(os.fstat(read_fd)) != sealed_signature:
            raise PrivatePathUnsafe(
                "private stage name changed while sealing",
                components=stage.components,
            )
        sealed_digest = _digest_fd(read_fd)
        if sealed_digest[0] != sealed_signature[5]:
            raise PrivatePathUnsafe(
                "private stage size changed while sealing",
                components=stage.components,
            )
        return read_fd, sealed_digest
    except BaseException as primary:
        close_errors = _close_fds(read_fd)
        _attach_close_errors(primary, close_errors)
        raise


@_serialized_stage_lifecycle
def seal_private_stage(stage: PrivateFileStage) -> None:
    """Flush and close a stage's write descriptor, freezing it for publication."""
    _require_strict_capabilities()
    _validate_live_stage(stage, "seal")
    if stage.state == "sealed":
        return
    before = os.fstat(stage.file_fd)
    _validate_strict_file_stat(before, stage.components)
    if _identity(before) != stage.file_identity:
        raise PrivatePathUnsafe("private stage file identity changed", components=stage.components)
    _fsync_managed(stage.file_fd)
    after = os.fstat(stage.file_fd)
    _validate_strict_file_stat(after, stage.components)
    if _identity(after) != stage.file_identity:
        raise PrivatePathUnsafe("private stage file identity changed", components=stage.components)
    sealed_signature = _file_signature(after)
    write_fd = stage.file_fd
    _set_stage(stage, "file_fd", -1)
    _set_stage(stage, "sealed_signature", sealed_signature)
    close_errors = _close_fds(write_fd)
    if close_errors:
        # Reopen the named inode so abort can still settle the claim.
        try:
            read_fd, sealed_digest = _open_settled_stage(stage, sealed_signature)
            if stage.expected_digest is not None and sealed_digest != stage.expected_digest:
                _set_stage(stage, "file_fd", read_fd)
                _set_stage(stage, "sealed_digest", sealed_digest)
                _set_stage(stage, "state", "sealed")
                raise PrivatePathUnsafe(
                    "private stage content does not match the declared bytes",
                    components=stage.components,
                )
            _set_stage(stage, "file_fd", read_fd)
            _set_stage(stage, "sealed_digest", sealed_digest)
            _set_stage(stage, "state", "sealed")
        except BaseException as reconciliation_error:
            error = PrivatePathError(
                "private stage data synced but descriptor settlement is uncertain",
                components=stage.components,
            )
            error.close_errors = tuple(close_errors)
            raise error from reconciliation_error
        error = PrivatePathError(
            "private stage data synced but its write descriptor did not close cleanly",
            components=stage.components,
        )
        error.close_errors = tuple(close_errors)
        raise error from close_errors[0]

    # Retain a read-only descriptor after closing the writer.  It pins the settled
    # inode so an unlinked replacement cannot be mistaken for it through inode reuse.
    read_fd, sealed_digest = _open_settled_stage(stage, sealed_signature)
    if stage.expected_digest is not None and sealed_digest != stage.expected_digest:
        _set_stage(stage, "file_fd", read_fd)
        _set_stage(stage, "sealed_digest", sealed_digest)
        _set_stage(stage, "state", "sealed")
        error = PrivatePathUnsafe(
            "private stage content does not match the declared bytes",
            components=stage.components,
        )
        raise error
    _set_stage(stage, "file_fd", read_fd)
    _set_stage(stage, "sealed_digest", sealed_digest)
    _set_stage(stage, "state", "sealed")


def _validate_named_stage(stage: PrivateFileStage) -> None:
    _validate_stage_directory_claims(stage)
    named_fd = _open_strict_file_in(stage.parent_fd, stage.temporary_name, stage.components)
    with _owned_fd(named_fd):
        observed = os.fstat(named_fd)
        expected = stage.sealed_signature
        matches = (
            _file_signature(observed) == expected
            if expected is not None
            else _identity(observed) == stage.file_identity
        )
        if not matches:
            raise PrivatePathUnsafe("private stage name was substituted", components=stage.components)
        if stage.sealed_digest is not None and _digest_fd(named_fd) != stage.sealed_digest:
            raise PrivatePathUnsafe("private stage content changed after sealing", components=stage.components)


def _validate_replace_destination(stage: PrivateFileStage) -> None:
    _validate_stage_directory_claims(stage)
    try:
        destination_fd = _open_strict_file_in(
            stage.parent_fd, stage.destination_name, stage.components,
        )
    except PrivatePathMissing:
        return
    with _owned_fd(destination_fd):
        os.fstat(destination_fd)  # keep the validated inode pinned until immediately before replace


def _destination_matches_stage(stage: PrivateFileStage) -> bool:
    _validate_stage_directory_claims(stage)
    try:
        destination_fd = _open_strict_file_in(
            stage.parent_fd, stage.destination_name, stage.components,
        )
    except PrivatePathMissing:
        return False
    with _owned_fd(destination_fd):
        landed = os.fstat(destination_fd)
        retained = os.fstat(stage.file_fd)
        metadata_matches = (
            _identity(landed) == stage.file_identity == _identity(retained)
            and landed.st_uid == retained.st_uid
            and stat.S_IMODE(landed.st_mode) == stat.S_IMODE(retained.st_mode) == FILE_MODE
            and landed.st_nlink == retained.st_nlink == 1
            and landed.st_size == retained.st_size
        )
        if not metadata_matches:
            return False
        expected_digest = stage.sealed_digest
        return (
            expected_digest is not None
            and _digest_fd(stage.file_fd) == expected_digest
            and _digest_fd(destination_fd) == expected_digest
        )


@_serialized_stage_lifecycle
def replace_private_stage(stage: PrivateFileStage) -> None:
    """Durably replace the destination with a settled same-directory stage.

    The file is ``fsync``ed before rename and the pinned containing directory is
    ``fsync``ed afterwards.  If the latter fails, the rename is reported as uncertain:
    callers must not claim either rollback or durable success.  Callers must hold the
    repository's exclusive mutation authority; Python objects are not a sandbox from
    other code executing as this same process and UID.
    """
    _require_strict_capabilities()
    _validate_live_stage(stage, "replace")
    seal_private_stage(stage)
    _validate_live_stage(stage, "replace")
    _validate_declared_stage_parent(stage)
    _validate_named_stage(stage)
    _validate_replace_destination(stage)
    rename_error: BaseException | None = None
    clean_rename_error: BaseException | None = None
    try:
        # This state is set before entering the syscall boundary.  Any asynchronous
        # interruption until a proven clean failure or committed settlement is
        # conservatively treated as a possibly-landed replacement.
        _set_stage(stage, "state", "publishing")
        try:
            _validate_stage_directory_claims(stage)
            os.rename(
                stage.temporary_name,
                stage.destination_name,
                src_dir_fd=stage.parent_fd,
                dst_dir_fd=stage.parent_fd,
            )
        except BaseException as exc:
            rename_error = exc

        landed_matches = _destination_matches_stage(stage)
        if not landed_matches and rename_error is not None:
            # The valid named stage proves the failed rename did not consume our
            # claim.  Reset to sealed only after that proof, so ordinary cleanup is
            # again safe.
            _validate_named_stage(stage)
            _set_stage(stage, "state", "sealed")
            clean_rename_error = rename_error
        elif not landed_matches:
            raise PrivatePathUnsafe(
                "private replacement landed but its identity could not be confirmed",
                components=stage.components,
            )
        else:
            _set_stage(stage, "state", "replaced_uncertain")
            _validate_stage_directory_claims(stage)
            _fsync_managed(stage.parent_fd)

            # Keep the settled inode pinned through directory fsync, then re-check
            # the published name and authenticated bytes.
            if not _destination_matches_stage(stage):
                raise PrivatePathUnsafe(
                    "durable replacement no longer occupies its declared path",
                    components=stage.components,
                )

            close_errors = _release_stage_fds(stage, "committed")
            if close_errors:
                error = PrivateReplaceCommittedWithFault(
                    "durable private replacement completed but descriptor close failed",
                    components=stage.components,
                )
                error.close_errors = tuple(close_errors)
                raise error from close_errors[0]
            if rename_error is not None:
                error = PrivateReplaceCommittedWithFault(
                    "private replacement was durably reconciled after the rename reported failure",
                    components=stage.components,
                )
                error.rename_error = rename_error
                raise error from rename_error
    except BaseException as cause:
        if stage.state == "sealed":
            raise
        if stage.state == "committed":
            if isinstance(cause, PrivateReplaceCommittedWithFault):
                raise
            close_errors = _release_stage_fds(stage, "committed")
            error = PrivateReplaceCommittedWithFault(
                "durable private replacement completed with a settlement fault",
                components=stage.components,
            )
            error.rename_error = rename_error
            error.close_errors = tuple(close_errors)
            raise error from cause

        close_errors = _release_stage_fds(stage, "replaced_uncertain")
        if isinstance(cause, PrivateReplaceUncertain):
            cause.close_errors = tuple(getattr(cause, "close_errors", ())) + tuple(close_errors)
            raise
        error = PrivateReplaceUncertain(
            "private replacement may have landed but did not settle",
            components=stage.components,
        )
        error.rename_error = rename_error
        error.close_errors = tuple(close_errors)
        raise error from cause

    if clean_rename_error is not None:
        raise clean_rename_error


def _abort_private_stage_locked(stage: PrivateFileStage) -> None:
    """Quarantine and close an unpublished stage; never remove a landed replacement.

    Unlike a worker batch fence, this ordinary unspawned-stage path owns the name and
    moves it once to a random non-authoritative discard name.  Relative I/O uses a
    private authenticated parent duplicate, and the quarantined inode is compared to
    a private retained duplicate.  Descriptor cleanup is ledger-backed.  Replay can
    resolve pre-authentication or re-authentication interruptions while close budget
    remains; two reported exact-live close faults require external recovery.
    """
    _require_strict_capabilities()
    if type(stage) is not PrivateFileStage:
        raise PrivatePathUnsafe("private stage handle has the wrong type")
    if stage.state == "handoff_prepared":
        raise PrivateStageStateError("abort", stage.state)
    if stage.state in {"publishing", "committed", "replaced_uncertain"}:
        return
    if stage.state == "aborted":
        ledger = stage._cleanup_ledger
        if type(ledger) is not _PrivateStageCleanupLedger or not ledger.pending:
            return
        cleanup_errors = list(_drain_private_stage_ledger(ledger))
        if not ledger.pending:
            object.__setattr__(stage, "_cleanup_ledger", None)
        if cleanup_errors or ledger.pending:
            error = PrivatePathError(
                "private stage cleanup remains uncertain",
                components=stage.components,
            )
            error.close_errors = tuple(cleanup_errors)
            raise error from (cleanup_errors[0] if cleanup_errors else error)
        return
    if stage.state not in {"open", "sealed"}:
        raise PrivateStageStateError("abort", stage.state)
    retained_ledger = stage._cleanup_ledger
    retained_claims = () if retained_ledger is None else retained_ledger.claims
    cleanup_parent = _new_descriptor_claim(
        -1, stage.parent_identity, "parent", stage.components[:-1],
    )
    cleanup_retained = _new_descriptor_claim(
        -1, stage.file_identity, "pin", stage.components,
    )
    quarantine_verifier = _new_descriptor_claim(
        -1, stage.file_identity, "pin", stage.components,
    )
    source_claims = (
            _new_descriptor_claim(
                stage.file_fd, stage.file_identity,
                "source_writer", stage.components,
            ),
            _new_descriptor_claim(
                stage.parent_fd, stage.parent_identity,
                "source_parent", stage.components[:-1],
            ),
            _new_descriptor_claim(
                stage.anchor_fd, stage.anchor_identity,
                "source_anchor", (),
            ),
    )
    ledger = _PrivateStageCleanupLedger(
        extra_claims=retained_claims + source_claims + (
            cleanup_parent, cleanup_retained, quarantine_verifier,
        ),
        _constructor_token=_PRIVATE_STAGE_CLEANUP_LEDGER_CONSTRUCTOR,
    )
    source_file_fd = stage.file_fd
    source_parent_fd = stage.parent_fd
    quarantine_error: BaseException | None = None
    transition_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    try:
        # Attach the complete recovery graph and become abort-only before the first
        # private allocation or name mutation.  Every later syscall result is stored
        # directly in one of these pre-registered slots.
        with _defer_stage_transition_signals():
            _reconcile_stages_aborted_direct((stage,), ledger)
        try:
            _duplicate_private_claim(cleanup_parent, source_parent_fd)
            _duplicate_private_claim(
                cleanup_retained, source_file_fd, allow_unlinked=True,
            )
            _discard_named_claim(
                cleanup_parent.fd,
                stage.temporary_name,
                cleanup_retained.fd,
                stage.components,
                _verification_claim=quarantine_verifier,
            )
        except BaseException as exc:
            quarantine_error = exc
    except BaseException as exc:
        transition_errors.append(exc)
    finally:
        _reconcile_stages_aborted_direct((stage,), ledger)
        close_errors.extend(_drain_private_stage_ledger(ledger))
    if not ledger.pending:
        object.__setattr__(stage, "_cleanup_ledger", None)
    if quarantine_error is not None:
        error = PrivatePathUnsafe(
            "private stage cleanup refused an absent or substituted claim",
            components=stage.components,
        )
        error.cleanup_errors = tuple(transition_errors)
        error.close_errors = tuple(close_errors)
        raise error from quarantine_error
    if transition_errors or close_errors or ledger.pending:
        error = PrivatePathError(
            "private stage cleanup completed with descriptor faults",
            components=stage.components,
        )
        error.cleanup_errors = tuple(transition_errors)
        error.close_errors = tuple(close_errors)
        cause = (
            transition_errors[0] if transition_errors
            else close_errors[0] if close_errors
            else error
        )
        raise error from cause


@_serialized_stage_lifecycle
def abort_private_stage(stage: PrivateFileStage) -> None:
    """Run ordinary stage cleanup behind a final typed reconciliation boundary."""
    try:
        # Keep handler entry inside a second boundary.  A one-shot interruption after
        # the locked transaction returns or raises is therefore translated only after
        # its retained descriptor graph has been reconciled below.
        try:
            result = _abort_private_stage_locked(stage)
        except BaseException:
            raise
        return result
    except PrivatePathError:
        raise
    except BaseException as primary:
        cleanup_errors: list[BaseException] = []
        ledger = (
            stage._cleanup_ledger
            if type(stage) is PrivateFileStage
            and type(stage._cleanup_ledger) is _PrivateStageCleanupLedger
            else None
        )
        if ledger is not None:
            cleanup_errors.extend(
                _settle_failed_prepare_cleanup((stage,), ledger, None)
            )
            if not ledger.pending:
                object.__setattr__(stage, "_cleanup_ledger", None)
        error = PrivatePathError(
            "private stage cleanup completed with descriptor faults",
            components=stage.components if type(stage) is PrivateFileStage else (),
        )
        error.cleanup_errors = tuple(cleanup_errors)
        error.close_errors = tuple(cleanup_errors)
        raise error from primary


def durable_replace_private(
    anchor_fd: int, components: tuple[str, ...], data: bytes,
) -> None:
    """Stage exact bytes and publish them with file-then-directory durability."""
    _require_strict_capabilities()
    components = validate_relative_components(components, allow_empty=False)
    anchor_fd = _validate_anchor_fd(anchor_fd)
    if type(data) is not bytes:
        raise PrivatePathUnsafe("private replacement data must be exact bytes", components=components)

    stage = stage_private_bytes(anchor_fd, components, data)
    try:
        replace_private_stage(stage)
    except BaseException as primary:
        try:
            abort_private_stage(stage)
        except BaseException as cleanup_error:
            try:
                primary.private_cleanup_error = cleanup_error
            except BaseException:
                pass
        raise
