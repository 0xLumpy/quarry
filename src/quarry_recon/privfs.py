"""Descriptor-based private filesystem helpers: dirs 0700, files 0600 at creation, every component opened
O_NOFOLLOW through a directory fd so no symlinked level can redirect a write outside the tree."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


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


def _open_strict_file_in(parent_fd: int, component: str, components: tuple[str, ...]) -> int:
    try:
        fd = os.open(component, _FILE_OPEN_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        _classify_open_error(exc, parent_fd, component, components, expect_dir=False)
        raise AssertionError("unreachable")
    try:
        _validate_strict_file_stat(os.fstat(fd), components)
    except BaseException as primary:
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


class PrivateFileStage:
    """Opaque handle for an unpublished same-directory file stage.

    Public attributes are read-only views.  The claim itself lives in slots so a
    caller cannot redirect publication by mutating an instance ``__dict__``.
    Quarry does not treat Python code executing in this process as a hostile
    security boundary; the opacity prevents accidental authority drift.
    """

    __slots__ = (
        "_anchor_fd",
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
        parent_identity: tuple[int, int],
        file_identity: tuple[int, int],
        _constructor_token: object,
    ) -> None:
        if _constructor_token is not _PRIVATE_STAGE_CONSTRUCTOR:
            raise PrivatePathUnsafe("private stages must be created by the strict staging API")
        object.__setattr__(self, "_anchor_fd", anchor_fd)
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

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private stage claims are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private stage claims are read-only")

    @property
    def anchor_fd(self) -> int:
        return self._anchor_fd

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
        if self.state not in {"committed", "replaced_uncertain", "aborted"}:
            try:
                self.abort()
            except BaseException as cleanup_error:
                if exc is None:
                    raise
                try:
                    exc.private_cleanup_error = cleanup_error
                except BaseException:
                    pass


def _validate_live_stage(stage: PrivateFileStage) -> None:
    if type(stage) is not PrivateFileStage:
        raise PrivatePathUnsafe("private stage handle has the wrong type")
    if stage.state not in {"open", "sealed"}:
        raise PrivatePathUnsafe("private stage is no longer live", components=stage.components)
    parent = os.fstat(stage.parent_fd)
    _validate_strict_dir_stat(parent, stage.components[:-1])
    if _identity(parent) != stage.parent_identity:
        raise PrivatePathUnsafe("private stage parent identity changed", components=stage.components)


def _set_stage(stage: PrivateFileStage, field: str, value) -> None:
    object.__setattr__(stage, f"_{field}", value)


def _release_stage_fds(stage: PrivateFileStage, state: str) -> list[BaseException]:
    file_fd = stage.file_fd
    parent_fd = stage.parent_fd
    anchor_fd = stage.anchor_fd
    _set_stage(stage, "file_fd", -1)
    _set_stage(stage, "parent_fd", -1)
    _set_stage(stage, "anchor_fd", -1)
    _set_stage(stage, "state", state)
    return _close_fds(file_fd, parent_fd, anchor_fd)


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


def _discard_named_claim(
    parent_fd: int,
    name: str,
    retained_fd: int,
    components: tuple[str, ...],
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

    quarantined_fd = _open_strict_file_in(parent_fd, quarantine, components)
    with _owned_fd(quarantined_fd):
        if not _same_private_inode(quarantined_fd, retained_fd):
            raise PrivatePathUnsafe(
                "private stage cleanup quarantined a substituted name",
                components=components,
            )
        # Do not unlink here: POSIX has no descriptor-bound unlink, so a second
        # validate-then-unlink window would let a substituted name be deleted.  The
        # quarantined file is harmless and remains available for authority-locked GC.


def _validate_declared_stage_parent(stage: PrivateFileStage) -> None:
    """Refuse publication when the pinned parent no longer has its declared name."""
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


def seal_private_stage(stage: PrivateFileStage) -> None:
    """Flush and close a stage's write descriptor, freezing it for publication."""
    _require_strict_capabilities()
    _validate_live_stage(stage)
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
    try:
        destination_fd = _open_strict_file_in(
            stage.parent_fd, stage.destination_name, stage.components,
        )
    except PrivatePathMissing:
        return
    with _owned_fd(destination_fd):
        os.fstat(destination_fd)  # keep the validated inode pinned until immediately before replace


def _destination_matches_stage(stage: PrivateFileStage) -> bool:
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


def replace_private_stage(stage: PrivateFileStage) -> None:
    """Durably replace the destination with a settled same-directory stage.

    The file is ``fsync``ed before rename and the pinned containing directory is
    ``fsync``ed afterwards.  If the latter fails, the rename is reported as uncertain:
    callers must not claim either rollback or durable success.  Callers must hold the
    repository's exclusive mutation authority; Python objects are not a sandbox from
    other code executing as this same process and UID.
    """
    _require_strict_capabilities()
    _validate_live_stage(stage)
    seal_private_stage(stage)
    _validate_live_stage(stage)
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


def abort_private_stage(stage: PrivateFileStage) -> None:
    """Quarantine and close an unpublished stage.  A landed replacement is never removed."""
    _require_strict_capabilities()
    if type(stage) is not PrivateFileStage:
        raise PrivatePathUnsafe("private stage handle has the wrong type")
    if stage.state in {"publishing", "committed", "replaced_uncertain", "aborted"}:
        return
    cleanup_error: BaseException | None = None
    try:
        _discard_named_claim(
            stage.parent_fd,
            stage.temporary_name,
            stage.file_fd,
            stage.components,
        )
    except BaseException as exc:
        cleanup_error = exc
    finally:
        file_fd = stage.file_fd
        parent_fd = stage.parent_fd
        anchor_fd = stage.anchor_fd
        _set_stage(stage, "file_fd", -1)
        _set_stage(stage, "parent_fd", -1)
        _set_stage(stage, "anchor_fd", -1)
        _set_stage(stage, "state", "aborted")
        close_errors = _close_fds(file_fd, parent_fd, anchor_fd)
    if cleanup_error is not None:
        error = PrivatePathUnsafe(
            "private stage cleanup refused an absent or substituted claim",
            components=stage.components,
        )
        error.close_errors = tuple(close_errors)
        raise error from cleanup_error
    if close_errors:
        error = PrivatePathError(
            "private stage cleanup completed but descriptor close failed",
            components=stage.components,
        )
        error.close_errors = tuple(close_errors)
        raise error from close_errors[0]


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
