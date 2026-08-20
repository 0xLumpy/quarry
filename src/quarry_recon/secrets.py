"""Framework-managed secrets — single store at ~/.config/quarry/secrets.yaml (chmod 600).

Holds only the keys the framework passes to tools itself (github, shodan, whoxy, projectdiscovery/chaos,
certspotter, openintel, censys) plus the notify and OOB-callback secrets.
Tool-native configs (subfinder provider-config.yaml, waymore config.yml) keep their own files —
this never touches them. Secret values are stripped from manifests and logs via redact(), and are
never written to target.yaml, run manifests, reports, or AI prompts.

Missing/unset keys are not an error: the consuming step is skipped gracefully.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import errno
from contextlib import contextmanager
from pathlib import Path

import yaml

PATH = Path.home() / ".config" / "quarry" / "secrets.yaml"
_cache: dict | None = None


class SecretCleanupError(RuntimeError):
    """A credential-bearing temporary object could not be proven absent."""


class SecretStoreError(RuntimeError):
    """The configured credential store is not an exact owner-private regular file."""


def _add_exception_note(error: BaseException, message: str) -> None:
    """Use Python 3.11 notes while preserving the same evidence on Python 3.10."""
    add_note = getattr(error, "add_note", None)
    if add_note is not None:
        add_note(message)
        return
    notes = getattr(error, "__notes__", None)
    if notes is None:
        error.__notes__ = [message]
    else:
        notes.append(message)


def _identity(observed: os.stat_result) -> tuple[int, int]:
    return observed.st_dev, observed.st_ino


def _fd_state(fd: int, identity: tuple[int, int]) -> str:
    """Return ``exact``, ``closed``, or ``reused`` without closing a possibly reused descriptor."""
    try:
        observed = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return "closed"
        raise SecretCleanupError(
            f"private descriptor state cannot be proven: {type(exc).__name__}"
        ) from exc
    return "exact" if _identity(observed) == identity else "reused"


def _close_exact_fd(fd: int, identity: tuple[int, int], *, label: str) -> None:
    """Close one identity-bound fd and prove its number invalid without closing a reused descriptor.

    A close syscall can report a fault before or after taking effect.  We probe first: an after-effect
    ``EBADF`` is already settled, while a still-open descriptor is closed through ``closerange`` (which
    bypasses an injected ``os.close`` fault) only while it still names the expected inode.  A different
    inode is never touched.
    """
    state = _fd_state(fd, identity)
    if state != "exact":
        raise SecretCleanupError(f"{label} descriptor is unexpectedly {state}")
    close_fault: BaseException | None = None
    try:
        os.close(fd)
    except BaseException as exc:
        close_fault = exc

    try:
        state = _fd_state(fd, identity)
    except BaseException as proof_fault:
        if close_fault is not None and not isinstance(close_fault, Exception):
            close_fault.add_note(
                f"{label} descriptor settlement also failed: "
                f"{type(proof_fault).__name__}: {proof_fault}"
            )
            raise close_fault.with_traceback(close_fault.__traceback__)
        raise
    settlement_fault: BaseException | None = None
    if state == "exact":
        try:
            os.closerange(fd, fd + 1)
            state = _fd_state(fd, identity)
        except BaseException as exc:
            settlement_fault = exc
    if state == "reused":
        settlement_fault = SecretCleanupError(
            f"{label} descriptor number was reused before close settlement"
        )
    elif state != "closed" and settlement_fault is None:
        settlement_fault = SecretCleanupError(f"{label} descriptor remains open after cleanup")

    if settlement_fault is not None:
        if close_fault is not None and not isinstance(close_fault, Exception):
            close_fault.add_note(
                f"{label} descriptor settlement also failed: "
                f"{type(settlement_fault).__name__}: {settlement_fault}"
            )
            raise close_fault.with_traceback(close_fault.__traceback__)
        if settlement_fault is close_fault:
            raise settlement_fault.with_traceback(settlement_fault.__traceback__)
        raise SecretCleanupError(
            f"{label} descriptor could not be settled: {settlement_fault}"
        ) from settlement_fault
    if close_fault is not None:
        raise close_fault.with_traceback(close_fault.__traceback__)


def _erase_exact_file(fd: int, identity: tuple[int, int], *, label: str) -> None:
    """Erase credential bytes through the held inode, fsync, and prove the exact inode empty."""
    before = os.fstat(fd)
    if _identity(before) != identity or not stat.S_ISREG(before.st_mode):
        raise SecretCleanupError(f"{label} credential descriptor identity changed")
    os.ftruncate(fd, 0)
    os.fsync(fd)
    after = os.fstat(fd)
    if _identity(after) != identity or after.st_size != 0:
        raise SecretCleanupError(f"{label} credential bytes could not be proven erased")


def _raise_primary_or_cleanup(primary: "BaseException | None",
                              cleanup: "BaseException | None", *, label: str) -> None:
    """Preserve control-flow precedence after exact cleanup has been attempted."""
    if primary is not None:
        if not isinstance(primary, Exception):
            if cleanup is not None:
                _add_exception_note(
                    primary,
                    f"{label} cleanup also failed: {type(cleanup).__name__}: {cleanup}"
                )
            raise primary.with_traceback(primary.__traceback__)
        if cleanup is not None and not isinstance(cleanup, Exception):
            raise cleanup.with_traceback(cleanup.__traceback__)
        if cleanup is not None:
            _add_exception_note(
                primary,
                f"{label} cleanup also failed: {type(cleanup).__name__}: {cleanup}",
            )
        raise primary.with_traceback(primary.__traceback__)
    if cleanup is not None:
        raise cleanup.with_traceback(cleanup.__traceback__)


def _read_store(path: Path) -> dict:
    """Read one exact 0600, single-link, owner-held store through a no-follow descriptor."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SecretStoreError("secrets.yaml must not be a symlink") from exc
        raise SecretStoreError(f"secrets.yaml cannot be opened safely: {type(exc).__name__}") from exc
    identity = None
    value = None
    primary: BaseException | None = None
    try:
        observed = os.fstat(fd)
        identity = _identity(observed)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) != 0o600):
            raise SecretStoreError("secrets.yaml must be one owner-held 0600 regular file")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                raise SecretStoreError("secrets.yaml exceeds its private-store byte bound")
            chunks.append(chunk)
        try:
            value = yaml.safe_load(b"".join(chunks).decode("utf-8", "strict")) or {}
        except (UnicodeError, yaml.YAMLError) as exc:
            raise SecretStoreError("secrets.yaml is not strict UTF-8 YAML") from exc
        after = os.fstat(fd)
        try:
            named = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise SecretStoreError("secrets.yaml identity changed while it was read") from exc
        if ((observed.st_dev, observed.st_ino, observed.st_mode, observed.st_nlink,
             observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino)):
            raise SecretStoreError("secrets.yaml identity changed while it was read")
        if not isinstance(value, dict):
            raise SecretStoreError("secrets.yaml root must be a mapping")
    except BaseException as exc:
        primary = exc
    close_fault = None
    try:
        if identity is None:
            observed = os.fstat(fd)
            identity = _identity(observed)
        _close_exact_fd(fd, identity, label="credential store")
    except BaseException as exc:
        close_fault = exc
    _raise_primary_or_cleanup(primary, close_fault, label="credential store descriptor")
    return value


def validate_store_path(path: Path = PATH) -> None:
    """Validate an existing store without caching or exposing any value."""
    _read_store(path)


def _settle_private_tool_config(directory: Path, path: Path, *, directory_fd: int,
                                directory_identity: tuple[int, int], claim_fd: int = -1,
                                file_identity: "tuple[int, int] | None" = None) -> None:
    """Erase/unlink the exact credential inode, remove its directory, and settle every held fd."""
    errors: list[BaseException] = []
    directory_exact = False
    named_directory_exact = False
    file_exact = claim_fd < 0
    named_file_exact = claim_fd < 0
    file_erased = claim_fd < 0
    file_unlinked = claim_fd < 0
    directory_unlinked = False
    claim_closed = claim_fd < 0
    directory_closed = False

    try:
        held_directory = os.fstat(directory_fd)
        directory_exact = (
            stat.S_ISDIR(held_directory.st_mode)
            and _identity(held_directory) == directory_identity
        )
        if not directory_exact:
            raise SecretCleanupError("private credential cleanup identity changed")
    except BaseException as exc:
        errors.append(exc)
    try:
        named_directory = directory.lstat()
        named_directory_exact = _identity(named_directory) == directory_identity
        if not named_directory_exact:
            raise SecretCleanupError("private credential cleanup identity changed")
    except BaseException as exc:
        errors.append(exc)

    if claim_fd >= 0 and file_identity is not None:
        try:
            held_file = os.fstat(claim_fd)
            file_exact = stat.S_ISREG(held_file.st_mode) and _identity(held_file) == file_identity
            if not file_exact:
                raise SecretCleanupError("private credential cleanup identity changed")
        except BaseException as exc:
            errors.append(exc)
        if file_exact:
            try:
                _erase_exact_file(claim_fd, file_identity, label="private config")
                file_erased = True
            except BaseException as exc:
                errors.append(exc)
        try:
            named_file = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            named_file_exact = _identity(named_file) == file_identity
            if not named_file_exact:
                raise SecretCleanupError("private credential cleanup identity changed")
        except BaseException as exc:
            errors.append(exc)
        if directory_exact and file_exact and named_file_exact:
            try:
                os.unlink(path.name, dir_fd=directory_fd)
            except BaseException as exc:
                errors.append(exc)
        try:
            current = os.fstat(claim_fd)
            file_erased = file_erased and current.st_size == 0
            file_unlinked = current.st_nlink == 0
        except BaseException as exc:
            errors.append(exc)
    elif claim_fd >= 0:
        errors.append(SecretCleanupError("private credential cleanup has no file identity"))

    if directory_exact and named_directory_exact:
        try:
            if os.listdir(directory_fd):
                raise SecretCleanupError("private credential directory contains unexpected residue")
            os.rmdir(directory)
        except BaseException as exc:
            errors.append(exc)
    try:
        directory_unlinked = os.fstat(directory_fd).st_nlink == 0
    except BaseException as exc:
        errors.append(exc)

    if claim_fd >= 0 and file_identity is not None:
        try:
            _close_exact_fd(claim_fd, file_identity, label="private config claim")
            claim_closed = True
        except BaseException as exc:
            errors.append(exc)
            try:
                claim_closed = _fd_state(claim_fd, file_identity) == "closed"
            except BaseException as proof_fault:
                errors.append(proof_fault)
    try:
        _close_exact_fd(directory_fd, directory_identity, label="private config directory")
        directory_closed = True
    except BaseException as exc:
        errors.append(exc)
        try:
            directory_closed = _fd_state(directory_fd, directory_identity) == "closed"
        except BaseException as proof_fault:
            errors.append(proof_fault)

    cancellation = next((exc for exc in errors if not isinstance(exc, Exception)), None)
    residue_present = (
        os.path.lexists(directory) or not directory_unlinked or not file_unlinked
        or not file_erased or not claim_closed or not directory_closed
    )
    if residue_present:
        detail = f"{type(errors[0]).__name__}: {errors[0]}" if errors else "unknown cleanup fault"
        residue = SecretCleanupError(
            f"private credential directory remains after cleanup ({detail}): {directory}"
        )
        if cancellation is not None:
            cancellation.add_note(f"credential residue also remains: {residue}")
            raise cancellation.with_traceback(cancellation.__traceback__)
        raise residue
    if cancellation is not None:
        raise cancellation.with_traceback(cancellation.__traceback__)
    if errors:
        raise errors[0].with_traceback(errors[0].__traceback__)


def load() -> dict:
    global _cache
    if _cache is None:
        _cache = _read_store(PATH)
    return _cache


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v.strip()] if v.strip() else []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return []


def _scalar(v) -> str | None:
    items = _as_list(v)
    return items[0] if items else None


#: local shape checks, never a network call — a pattern is declared only where the provider's format is
#: known. `doctor` reports the shape; nothing here gates a lane, since the provider is the authority.
_KEY_SHAPES = {
    # classic PAT `ghp_` + 36, fine-grained `github_pat_` + 82, and the pre-2021 40-hex tokens
    "github": re.compile(r"\A(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|[a-f0-9]{40})\Z"),
    "shodan": re.compile(r"\A[A-Za-z0-9]{32}\Z"),
}
#: what a key is never: an unedited template placeholder, or a value with whitespace/quotes in it.
_PLACEHOLDER = re.compile(r"(?i)\A(<.*>|your[-_ ]?|changeme|xxx+|todo|none|null|example)")


def key_shape(kind: str, value: str) -> str:
    """"ok" | "malformed" | "unknown" — a local verdict on one key's shape. "unknown" means no documented
    format is held for that provider, so the key is reported as set with nothing claimed about it."""
    v = (value or "").strip()
    if not v:
        return "unknown"
    if v != value or _PLACEHOLDER.match(v) or any(c.isspace() or c in "\"'" for c in v):
        return "malformed"
    rx = _KEY_SHAPES.get(kind)
    if rx is None:
        return "unknown"
    return "ok" if rx.match(v) else "malformed"


def github_tokens() -> list[str]:
    return _as_list(load().get("github"))


def shodan() -> str | None:
    return _scalar(load().get("shodan"))


def whoxy() -> str | None:
    return _scalar(load().get("whoxy"))


def chaos() -> str | None:
    """ProjectDiscovery / Chaos (PDCP) key — used by subfinder, asnmap, etc. via env."""
    return _scalar(load().get("projectdiscovery"))


def certspotter() -> str | None:
    """SSLMate certspotter API token (optional — the free tier works keyless at a low rate)."""
    return _scalar(load().get("certspotter"))


def openintel() -> dict:
    """Optional passive source (openintel-subs binary + local subs.db), {} unless an `openintel:` block
    is set. Not a registered tool: install/update/doctor ignore it, and it is silently unused unless
    both `binary` and `db` are configured."""
    o = load().get("openintel")
    return o if isinstance(o, dict) else {}


def censys() -> dict:
    """Optional Censys Platform creds `{token: <PAT>, org: <organization-id>}`, {} unless a `censys:`
    block is set. Silent opt-in: install/update/doctor ignore it and the vertical Censys source is
    skipped without noise unless both `token` and `org` are configured."""
    c = load().get("censys")
    return c if isinstance(c, dict) else {}


def oob() -> dict:
    """Optional out-of-band config for Quarry's one owned OOB layer. `callback_server` (plus optional
    `auth_token`) overrides the callback backend, for both Quarry's own interactsh-client session
    (-server, a bare host) and nuclei (-iserver, the full URL). Empty means the public backend."""
    o = load().get("oob")
    if not isinstance(o, dict):
        return {}
    # drop an auth_token with no callback host to authenticate to (the `-server` flag's own normalizer).
    from .oob import _server_hosts
    if o.get("auth_token") and not _server_hosts(o.get("callback_server")):
        o = {k: v for k, v in o.items() if k != "auth_token"}
    return o


def github_tokens_file(*, _hold_identity: bool = False):
    """Materialize a 0600 temp file of the GitHub tokens for tools that take `-t <file>`
    (github-subdomains). Returns None if no tokens; production callers use ``github_tokens_lifetime``."""
    toks = github_tokens()
    if not toks:
        return None
    fd, name = tempfile.mkstemp(prefix="quarry-gh-", suffix=".txt")
    p = Path(name)
    writer_identity = _identity(os.fstat(fd))
    claim_fd = -1
    claim_identity = None
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        view = memoryview(("\n".join(toks) + "\n").encode("utf-8", "strict"))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("GitHub credential write made no progress")
            view = view[written:]
        os.fsync(fd)
        if _hold_identity:
            claim_fd = os.dup(fd)
            claim_stat = os.fstat(claim_fd)
            claim_identity = _identity(claim_stat)
        try:
            _close_exact_fd(fd, writer_identity, label="GitHub token writer")
        except BaseException:
            if _fd_state(fd, writer_identity) == "closed":
                fd = -1
            raise
        else:
            fd = -1
        return (p, claim_fd, claim_identity) if _hold_identity else p
    except BaseException as primary:
        cleanup_faults: list[BaseException] = []
        if fd >= 0:
            try:
                _erase_exact_file(fd, writer_identity, label="GitHub token writer")
            except BaseException as exc:
                cleanup_faults.append(exc)
            try:
                _close_exact_fd(fd, writer_identity, label="GitHub token writer")
            except BaseException as exc:
                cleanup_faults.append(exc)
        try:
            _settle_private_file(
                p, claim_fd=claim_fd,
                file_identity=claim_identity,
            )
        except BaseException as exc:
            cleanup_faults.append(exc)
        cleanup_fault = next(
            (fault for fault in cleanup_faults if not isinstance(fault, Exception)),
            cleanup_faults[0] if cleanup_faults else None,
        )
        if cleanup_fault is not None:
            for extra in cleanup_faults:
                if extra is not cleanup_fault:
                    cleanup_fault.add_note(
                        f"additional cleanup fault: {type(extra).__name__}: {extra}"
                    )
        _raise_primary_or_cleanup(primary, cleanup_fault, label="GitHub credential")
        raise AssertionError("unreachable")


def _settle_private_file(path: Path, *, claim_fd: int = -1,
                         file_identity: "tuple[int, int] | None" = None) -> None:
    """Erase/unlink one exact credential file and settle every descriptor before returning."""
    faults: list[BaseException] = []
    parent_fd = -1
    parent_identity = None
    exact = claim_fd >= 0 and file_identity is not None
    original_erased = not exact
    original_unlinked = not exact
    claim_closed = not exact
    parent_closed = True
    try:
        if exact:
            held = os.fstat(claim_fd)
            if _identity(held) != file_identity or not stat.S_ISREG(held.st_mode):
                raise SecretCleanupError("private credential file identity changed")
            _erase_exact_file(claim_fd, file_identity, label="GitHub token")
            original_erased = True
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
            parent_identity = _identity(os.fstat(parent_fd))
            parent_closed = False
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(named) != file_identity:
                raise SecretCleanupError("private credential file identity changed")
            os.unlink(path.name, dir_fd=parent_fd)
        else:
            path.unlink(missing_ok=True)
    except BaseException as exc:
        faults.append(exc)
    if claim_fd >= 0:
        try:
            held = os.fstat(claim_fd)
            original_erased = original_erased and held.st_size == 0
            original_unlinked = held.st_nlink == 0
        except BaseException as exc:
            faults.append(exc)
    if exact:
        try:
            _close_exact_fd(claim_fd, file_identity, label="GitHub token claim")
            claim_closed = True
        except BaseException as exc:
            faults.append(exc)
            try:
                claim_closed = _fd_state(claim_fd, file_identity) == "closed"
            except BaseException as proof_fault:
                faults.append(proof_fault)
    if parent_fd >= 0 and parent_identity is not None:
        try:
            _close_exact_fd(parent_fd, parent_identity, label="GitHub token parent")
            parent_closed = True
        except BaseException as exc:
            faults.append(exc)
            try:
                parent_closed = _fd_state(parent_fd, parent_identity) == "closed"
            except BaseException as proof_fault:
                faults.append(proof_fault)
    cancellation = next((fault for fault in faults if not isinstance(fault, Exception)), None)
    if (os.path.lexists(path) or not original_unlinked or not original_erased
            or not claim_closed or not parent_closed):
        residue = SecretCleanupError(f"private credential file remains after cleanup: {path}")
        if cancellation is not None:
            cancellation.add_note(f"credential residue also remains: {residue}")
            raise cancellation.with_traceback(cancellation.__traceback__)
        raise residue
    if cancellation is not None:
        raise cancellation.with_traceback(cancellation.__traceback__)
    if faults:
        raise faults[0].with_traceback(faults[0].__traceback__)


@contextmanager
def github_tokens_lifetime():
    """Yield the private GitHub token file and settle it on every exit without masking cancellation."""
    claimed = github_tokens_file(_hold_identity=True)
    if claimed is None:
        yield None
        return
    path, claim_fd, file_identity = claimed
    primary = None
    try:
        yield path
    except BaseException as exc:
        primary = exc
    finally:
        cleanup_fault = None
        try:
            _settle_private_file(path, claim_fd=claim_fd, file_identity=file_identity)
        except BaseException as exc:
            cleanup_fault = exc
        if primary is not None:
            if not isinstance(primary, Exception):
                if cleanup_fault is not None:
                    primary.add_note(
                        f"GitHub credential cleanup also failed: {type(cleanup_fault).__name__}: "
                        f"{cleanup_fault}"
                    )
                raise primary.with_traceback(primary.__traceback__)
            if cleanup_fault is not None and not isinstance(cleanup_fault, Exception):
                raise cleanup_fault.with_traceback(cleanup_fault.__traceback__)
            if cleanup_fault is not None:
                primary.add_note(
                    f"GitHub credential cleanup also failed: {type(cleanup_fault).__name__}: "
                    f"{cleanup_fault}"
                )
            raise primary.with_traceback(primary.__traceback__)
        if cleanup_fault is not None:
            raise cleanup_fault


@contextmanager
def private_tool_config(prefix: str, values: dict[str, str]):
    """Yield one owner-private YAML config and erase its private directory on every normal exit."""
    if (not isinstance(prefix, str) or not re.fullmatch(r"[a-z0-9-]+", prefix)
            or not isinstance(values, dict) or not values
            or not all(isinstance(k, str) and k and isinstance(v, str) and v
                       for k, v in values.items())):
        raise ValueError("private tool config request is invalid")
    directory = Path(tempfile.mkdtemp(prefix=f"quarry-{prefix}-"))
    path = directory / "config.yaml"
    directory_fd = -1
    directory_identity = None
    claim_fd = -1
    file_identity = None
    writer_fd = -1
    primary: BaseException | None = None
    try:
        os.chmod(directory, 0o700)
        directory_fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        directory_stat = os.fstat(directory_fd)
        directory_identity = (directory_stat.st_dev, directory_stat.st_ino)
        writer_fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            file_stat = os.fstat(writer_fd)
            file_identity = _identity(file_stat)
            try:
                claim_fd = os.dup(writer_fd)
            except BaseException:
                claim_fd, writer_fd = writer_fd, -1
                raise
            body = yaml.safe_dump(values, default_flow_style=False, sort_keys=True).encode("utf-8")
            view = memoryview(body)
            while view:
                written = os.write(writer_fd, view)
                if written <= 0:
                    raise OSError("private config write made no progress")
                view = view[written:]
            os.fsync(writer_fd)
        finally:
            if writer_fd >= 0 and file_identity is not None:
                try:
                    _close_exact_fd(writer_fd, file_identity, label="private config writer")
                except BaseException:
                    if _fd_state(writer_fd, file_identity) == "closed":
                        writer_fd = -1
                    raise
                else:
                    writer_fd = -1
        yield path
    except BaseException as exc:
        primary = exc
    finally:
        cleanup_faults: list[BaseException] = []
        if writer_fd >= 0 and file_identity is not None:
            try:
                _erase_exact_file(writer_fd, file_identity, label="private config writer")
            except BaseException as exc:
                cleanup_faults.append(exc)
            try:
                _close_exact_fd(writer_fd, file_identity, label="private config writer")
            except BaseException as exc:
                cleanup_faults.append(exc)
        try:
            if directory_fd >= 0 and directory_identity is not None:
                _settle_private_tool_config(
                    directory, path, directory_fd=directory_fd,
                    directory_identity=directory_identity, claim_fd=claim_fd,
                    file_identity=file_identity,
                )
                directory_fd = claim_fd = -1
            else:
                try:
                    os.rmdir(directory)
                except FileNotFoundError:
                    pass
                if os.path.lexists(directory):
                    raise SecretCleanupError(
                        f"unclaimed private credential directory remains after cleanup: {directory}"
                    )
        except BaseException as exc:
            cleanup_faults.append(exc)
        cleanup_fault = next(
            (fault for fault in cleanup_faults if not isinstance(fault, Exception)),
            cleanup_faults[0] if cleanup_faults else None,
        )
        if cleanup_fault is not None:
            for extra in cleanup_faults:
                if extra is not cleanup_fault:
                    cleanup_fault.add_note(
                        f"additional cleanup fault: {type(extra).__name__}: {extra}"
                    )
        _raise_primary_or_cleanup(primary, cleanup_fault, label="credential")


def values() -> list[str]:
    """Every secret value, for redaction. Only values long enough to be real keys."""
    vals = list(github_tokens())
    for getter in (shodan, whoxy, chaos, certspotter):
        v = getter()
        if v:
            vals.append(v)
    nc = load().get("notify")                      # notify webhook URLs / telegram token are secret
    if isinstance(nc, dict):
        for k in ("slack", "discord", "webhook"):
            if isinstance(nc.get(k), str):
                vals.append(nc[k])
        tg = nc.get("telegram")
        if isinstance(tg, dict) and tg.get("token"):
            vals.append(str(tg["token"]))
    ob = load().get("oob")                          # the callback server's auth token is secret
    if isinstance(ob, dict) and isinstance(ob.get("auth_token"), str):
        vals.append(ob["auth_token"])
    cy = load().get("censys")                        # censys Platform PAT is secret (org id is not)
    if isinstance(cy, dict) and isinstance(cy.get("token"), str):
        vals.append(cy["token"])
    ai = load().get("ai")                            # reserved integration; never let a configured key leak
    if isinstance(ai, dict) and isinstance(ai.get("api_key"), str):
        vals.append(ai["api_key"])
    return [v for v in vals if v and len(v) >= 6]


def redact(text: str | None) -> str | None:
    """Replace every known secret value in `text` with ***. Safe on None/empty."""
    if not text:
        return text
    for v in values():
        text = text.replace(v, "***")
    return text


def redact_deep(value):
    """`redact` over a whole structure — every string leaf, at any depth.

    Containers are rebuilt, never mutated: the caller's object is evidence. Only configured credentials
    are replaced; discovered secrets and verbatim provider evidence are untouched."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        # keys too: a dict built from provider data can key on anything.
        return {redact_deep(k): redact_deep(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return type(value)(redact_deep(v) for v in value)
    return value


def _coerce(value) -> str:
    if isinstance(value, str):
        return value
    import json as _json
    return _json.dumps(value, sort_keys=True, default=str)


def mask(value) -> str:
    """Short, non-usable preview of a discovered secret (a scanner finding, not our own key) — enough to
    recognize, not enough to use. The complete value is retained whole on its entity and shown by local
    artifacts (HOTLIST, digest, exports); this preview only sits beside it."""
    s = _coerce(value).strip()
    if not s:
        return ""
    if len(s) <= 12:
        return f"…({len(s)} chars)"          # too short to show any char without leaking
    return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"


def fingerprint(value) -> str:
    """Stable short hash of a secret value — used as a dedup id without storing the raw."""
    import hashlib
    return hashlib.sha256(_coerce(value).encode("utf-8", "replace")).hexdigest()[:12]


def adapter_environment(tool: str, declared_names=()) -> dict[str, str]:
    """Credential values for exactly one registry-declared adapter environment.

    Ambient values are deliberately ignored: only the framework credential store can populate this map,
    and an unknown declaration fails closed instead of becoming a generic environment pass-through.
    """
    providers = {"PDCP_API_KEY": chaos}
    result = {}
    for name in declared_names:
        getter = providers.get(name)
        if getter is None:
            raise ValueError(f"{tool}: unknown credential environment declaration {name!r}")
        value = getter()
        if value:
            result[name] = value
    return result


def apply_env() -> None:
    """Compatibility no-op: credentials are injected only into declared adapter environments."""
    return None


def reset_cache() -> None:
    global _cache
    _cache = None
