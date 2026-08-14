"""Candidate-bound Linux H0 collection diagnostic.

This is a deliberately non-promotable development runner.  It proves that an
exact committed candidate can be collected behind a concrete bubblewrap
boundary, but it mounts an untrusted host ``/usr`` runtime closure and executes
no tests.  It emits no release-gate record: ``A-TAXONOMY`` remains open for the
non-nominated 0.3.9 package, and the final summary explicitly has no authority.

The standalone profile and its schema are future runner inputs.  They do not
alter candidate-identity.v1, its schema registry, or its default identity
inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import FrameType

from . import release_evidence as evidence

H0_DEVELOPMENT_PROFILE_SCHEMA = "quarry.h0-development-profile.v1"
H0_ISOLATION_REPORT_SCHEMA = "quarry.h0-isolation-report.v1"
H0_RUNTIME_RECORD_SCHEMA = "quarry.h0-development-runtime.v1"
H0_TOOLCHAIN_RECORD_SCHEMA = "quarry.h0-development-toolchain.v1"
H0_ISOLATION_RECORD_SCHEMA = "quarry.h0-development-isolation.v1"
H0_BWRAP_STATUS_SCHEMA = "quarry.h0-bwrap-status.v1"
H0_NON_RELEASE_SUMMARY_SCHEMA = "quarry.h0-non-release-diagnostic.v1"
H0_REASON = "non-nominated 0.3.9/development host runtime"
H0_PACKAGE_VERSION = "0.3.9"
H0_DIAGNOSTIC_ID = "A-TAXONOMY"
H0_LANE = "H0-hermetic"
H0_PROFILE_DEADLINE_SECONDS = 900

_MAX_COMMAND_OUTPUT = 1024 * 1024
_MAX_LOG_BYTES = 2 * 1024 * 1024
_MAX_ISOLATION_REPORT_BYTES = 64 * 1024
_MAX_BWRAP_STATUS_BYTES = 64 * 1024
_TERMINATION_GRACE_SECONDS = 2.0
_SELECT_SLICE_SECONDS = 0.1
_TOOL_VERSION_SECONDS = 15.0
_EXPECTED_ROOT_ENTRIES = ["bin", "candidate", "dev", "lib", "lib64", "proc", "usr", "work"]
_NAMESPACE_NAMES = ("cgroup", "ipc", "mnt", "net", "pid", "user", "uts")
_BWRAP_STATUS_NAMES = ("cgroup", "ipc", "mnt", "net", "pid", "uts")
_ARTIFACT_MEDIA_TYPES = {
    "bwrap-status": "application/json",
    "candidate-identity": "application/json",
    "development-profile": "application/json",
    "development-profile-schema": "application/schema+json",
    "isolation": "application/json",
    "pytest-stderr": "text/plain",
    "pytest-stdout": "text/plain",
    "pytest-taxonomy": "application/json",
    "pytest-taxonomy-schema": "application/schema+json",
    "runtime": "application/json",
    "toolchain": "application/json",
    "verification-job-map": "application/json",
    "verification-job-map-schema": "application/schema+json",
    "verification-workflow": "application/yaml",
}

_EXPECTED_PROFILE = {
    "bwrap_options": [
        "--unshare-user",
        "--unshare-all",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
    ],
    "candidate_mount": "/candidate",
    "candidate_package_version": H0_PACKAGE_VERSION,
    "deadline_seconds": H0_PROFILE_DEADLINE_SECONDS,
    "environment": [
        {"name": "HOME", "value": "/work/home"},
        {"name": "LANG", "value": "C.UTF-8"},
        {"name": "LC_ALL", "value": "C.UTF-8"},
        {"name": "PATH", "value": ""},
        {"name": "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "value": "1"},
        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
        {"name": "PYTHONHASHSEED", "value": "0"},
        {"name": "QUARRY_OFFLINE_CI", "value": "1"},
        {"name": "TMPDIR", "value": "/work/tmp"},
        {"name": "XDG_CACHE_HOME", "value": "/work/xdg-cache"},
        {"name": "XDG_CONFIG_HOME", "value": "/work/xdg-config"},
        {"name": "XDG_DATA_HOME", "value": "/work/xdg-data"},
    ],
    "fallback": "none",
    "hostname": "quarry-h0-development",
    "isolation": {
        "candidate_mount": "read-only-bind-fd",
        "candidate_tree": "regular-utf8-blobs-only-no-gitlinks-no-symlinks",
        "dev": "new-isolated-dev",
        "network": "unshared",
        "proc": "new-read-only-procfs",
        "report_channel": "parent-owned-canonical-json-pipe-closed-before-pytest",
        "root": "blank-tmpfs",
        "seccomp": "none-development-diagnostic",
        "work_mount": "read-write-bind-fd",
    },
    "lane": H0_LANE,
    "limits": {
        "bwrap_status_bytes": _MAX_BWRAP_STATUS_BYTES,
        "command_output_bytes": _MAX_COMMAND_OUTPUT,
        "isolation_report_bytes": _MAX_ISOLATION_REPORT_BYTES,
        "log_bytes_per_stream": _MAX_LOG_BYTES,
    },
    "mode": "collect-only-development-host-runtime",
    "publication": (
        "external-disjoint-create-only-0600-fsync-nonauthoritative-summary-last"
    ),
    "pytest_arguments": [
        "-p",
        "no:cacheprovider",
        "--collect-only",
        "-q",
        "-m",
        "offline",
        "--strict-markers",
        "--quarry-taxonomy-manifest",
        "/work/taxonomy.json",
        "/candidate/tests",
    ],
    "python_arguments": [
        "-I",
        "-B",
        "/candidate/src/quarry_recon/release_h0_inner.py",
    ],
    "reason": H0_REASON,
    "release": evidence.RELEASE_SCOPE,
    "runtime_mounts": [
        {
            "destination": "/usr",
            "source": "/usr",
            "trust": "untrusted-host-runtime-exec-closure",
        }
    ],
    "runtime_symlinks": [
        {"destination": "/bin", "target": "usr/bin"},
        {"destination": "/lib", "target": "usr/lib"},
        {"destination": "/lib64", "target": "usr/lib64"},
    ],
    "scratch": {
        "disjoint_from": ["output", "source"],
        "parent": "/tmp",
        "parent_mode": "01777-root-owned-sticky",
        "private_mode": "0700",
    },
    "schema_version": H0_DEVELOPMENT_PROFILE_SCHEMA,
    "status": "open",
    "work_mount": "/work",
}


class H0RunnerError(evidence.EvidenceError):
    """The development H0 diagnostic cannot produce a valid artifact bundle."""


class H0DeadlineError(H0RunnerError):
    """The single profile deadline expired before settlement."""


class PublicationSettlementError(H0RunnerError):
    """A private diagnostic artifact or its cleanup could not be settled."""


@dataclass
class _ToolPin:
    name: str
    path: str
    descriptor: int
    signature: tuple[int, ...]
    digest: str
    version: str = ""


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    streams: Mapping[str, bytes]


@dataclass
class _DeadlineControl:
    deadline: float
    previous_handler: object
    previous_timer: tuple[float, float]
    previous_mask: set[signal.Signals]
    settled: bool = False
    restored: bool = False

    def settle(self) -> None:
        if self.settled:
            raise H0RunnerError("profile deadline was already settled")
        self._restore_signal_contract()
        self.settled = True
        if time.monotonic() > self.deadline:
            raise H0DeadlineError("H0 development profile deadline expired during publication")

    def abort(self) -> None:
        if not self.restored:
            self._restore_signal_contract()

    def _restore_signal_contract(self) -> None:
        if self.restored:
            return
        if not all(
            hasattr(signal, name)
            for name in ("pthread_sigmask", "sigpending", "sigwait")
        ):
            raise H0RunnerError("deadline settlement requires Linux signal masking")
        primary: BaseException | None = None
        expired = False
        mask_restored = False
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        except BaseException as exc:
            primary = exc
        try:
            signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
        except BaseException as exc:
            if primary is None:
                primary = exc
        try:
            expired = signal.SIGALRM in signal.sigpending()
            if expired:
                signal.sigwait({signal.SIGALRM})
        except BaseException as exc:
            if primary is None:
                primary = exc
        try:
            signal.signal(signal.SIGALRM, self.previous_handler)
        except BaseException as exc:
            if primary is None:
                primary = exc
        try:
            signal.setitimer(signal.ITIMER_REAL, *self.previous_timer)
        except BaseException as exc:
            if primary is None:
                primary = exc
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
            mask_restored = True
        except BaseException as exc:
            if primary is None:
                primary = exc
        if primary is None and mask_restored:
            self.restored = True
        if primary is not None:
            raise primary
        if not self.restored:
            raise H0RunnerError("deadline signal contract could not be restored")
        if expired:
            raise H0DeadlineError("H0 development profile deadline expired during publication")


def _raw_digest(body: bytes) -> str:
    if type(body) is not bytes:
        raise H0RunnerError("artifact digest input must be exact bytes")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _canonical_line(document: object) -> bytes:
    return evidence.canonical_json_bytes(document) + b"\n"


def _read_canonical_line(body: bytes, name: str, *, maximum: int = evidence.MAX_RECORD_BYTES) -> dict:
    if type(body) is not bytes or len(body) > maximum:
        raise H0RunnerError(f"{name} exceeds its exact byte contract")
    if not body.endswith(b"\n") or body.endswith(b"\n\n"):
        raise H0RunnerError(f"{name} must end in exactly one LF")
    document = evidence.load_json_bytes(body[:-1], maximum=maximum)
    if type(document) is not dict or body != _canonical_line(document):
        raise H0RunnerError(f"{name} is not one canonical JSON line")
    return document


def read_development_profile(body: bytes) -> dict:
    """Validate the one development profile; no caller-controlled variants exist."""
    document = _read_canonical_line(body, "H0 development profile")
    if document != _EXPECTED_PROFILE:
        raise H0RunnerError("H0 development profile differs from the exact open-only contract")
    return document


def _read_development_profile_schema(body: bytes, profile: dict) -> dict:
    document = _read_canonical_line(body, "H0 development profile schema")
    evidence._validate_registered_schema(
        document,
        name="h0-development-profile",
        record_version=H0_DEVELOPMENT_PROFILE_SCHEMA,
    )
    expected = {
        "$id": "urn:quarry:schema:h0-development-profile:v1",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {name: {"const": value} for name, value in profile.items()},
        "required": sorted(profile),
        "type": "object",
    }
    if document != expected:
        raise H0RunnerError("H0 profile schema does not freeze every exact profile value")
    return document


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _normalized_absolute(value: str | os.PathLike[str], name: str) -> str:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise H0RunnerError(f"{name} must be a filesystem path") from exc
    if type(text) is not str:
        raise H0RunnerError(f"{name} must be a text filesystem path")
    try:
        normalized = evidence._absolute_tool_path(text, name)
    except evidence.EvidenceError as exc:
        raise H0RunnerError(str(exc)) from exc
    if os.name != "posix" or not PurePosixPath(normalized).is_absolute():
        raise H0RunnerError(f"{name} requires a normalized Linux absolute path")
    return normalized


def _open_tool(value: str | os.PathLike[str], name: str) -> _ToolPin:
    path = _normalized_absolute(value, f"{name} executable")
    try:
        if os.geteuid() == 0:
            raise H0RunnerError("development H0 runner refuses root execution")
        current = Path("/")
        for component in (None, *PurePosixPath(path).parts[1:-1]):
            if component is not None:
                current /= component
            ancestor = os.lstat(current)
            if (
                not stat.S_ISDIR(ancestor.st_mode)
                or ancestor.st_uid != 0
                or ancestor.st_mode & 0o022
                or os.access(current, os.W_OK, effective_ids=True, follow_symlinks=False)
            ):
                raise H0RunnerError(
                    f"{name} executable ancestry is not immutable to the unprivileged runner"
                )
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or not before.st_mode & 0o111
            or before.st_uid != 0
            or before.st_mode & 0o022
            or os.access(path, os.W_OK, effective_ids=True, follow_symlinks=False)
        ):
            raise H0RunnerError(
                f"{name} executable must be a root-owned, immutable executable regular file"
            )
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except H0RunnerError:
        raise
    except OSError as exc:
        raise H0RunnerError(f"cannot open pinned {name} executable {path!r}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if _stat_signature(opened) != _stat_signature(before):
            raise H0RunnerError(f"pinned {name} executable changed while opening")
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
        after = os.fstat(descriptor)
        if _stat_signature(after) != _stat_signature(opened):
            raise H0RunnerError(f"pinned {name} executable changed while hashing")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _ToolPin(
            name=name,
            path=path,
            descriptor=descriptor,
            signature=_stat_signature(opened),
            digest="sha256:" + hasher.hexdigest(),
        )
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _assert_tool_pin(pin: _ToolPin) -> None:
    try:
        by_descriptor = os.fstat(pin.descriptor)
        by_path = os.lstat(pin.path)
    except OSError as exc:
        raise H0RunnerError(f"cannot revalidate pinned {pin.name} executable: {exc}") from exc
    if _stat_signature(by_descriptor) != pin.signature or _stat_signature(by_path) != pin.signature:
        raise H0RunnerError(f"pinned {pin.name} executable changed during the diagnostic")


def _close_tool_pins(pins: Sequence[_ToolPin]) -> None:
    fault: BaseException | None = None
    cancellation: BaseException | None = None
    for pin in reversed(pins):
        try:
            os.close(pin.descriptor)
        except (OSError, KeyboardInterrupt, SystemExit) as exc:
            if fault is None:
                fault = exc
            if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
                cancellation = exc
    if cancellation is not None:
        raise cancellation
    if fault is not None:
        raise H0RunnerError(f"cannot close pinned tool descriptor: {fault}") from fault


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise H0DeadlineError("H0 development profile deadline expired")
    return remaining


def _signal_process_group(process: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return


def _leader_exited_unreaped(process: subprocess.Popen) -> bool:
    if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        raise H0RunnerError("bounded process settlement requires Linux waitid/WNOWAIT")
    try:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as exc:
        raise H0RunnerError("bounded process leader was reaped outside its owner") from exc
    return result is not None


def _terminate_and_reap(process: subprocess.Popen) -> None:
    """Settle one spawned process; never return while it can still be waited."""
    # Never poll()/wait() during the grace window: an exited leader remains a
    # zombie and reserves its PID/PGID until the whole group has received KILL.
    primary: BaseException | None = None
    cancellation: BaseException | None = None

    def remember(exc: BaseException) -> None:
        nonlocal primary, cancellation
        if primary is None:
            primary = exc
        if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
            cancellation = exc

    try:
        _signal_process_group(process, signal.SIGTERM)
    except BaseException as exc:
        remember(exc)
    grace_deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while time.monotonic() < grace_deadline:
        try:
            time.sleep(min(0.05, max(0.0, grace_deadline - time.monotonic())))
        except BaseException as exc:
            remember(exc)

    # Cancellation can arrive before or after the kernel side effect.  Keep
    # the unreaped group leader reserving its numeric PID/PGID and retry until
    # KILL is known to have been issued (or the group is already absent).
    kill_sent = False
    while not kill_sent:
        try:
            _signal_process_group(process, signal.SIGKILL)
            kill_sent = True
        except BaseException as exc:
            remember(exc)

    # Once wait/reap begins, never address the numeric PGID again.  A
    # cancellation after kernel waitpid but before Popen bookkeeping is retried
    # as reap-only settlement; ChildProcessError means no child remains
    # waitable and is therefore terminal for ownership purposes.
    try:
        _reap_without_signalling(
            process,
        )
    except BaseException as exc:
        remember(exc)
    if cancellation is not None:
        raise cancellation
    if primary is not None:
        if isinstance(primary, OSError):
            raise H0RunnerError(f"process settlement failed: {primary}") from primary
        raise primary


def _reap_without_signalling(process: subprocess.Popen) -> None:
    primary: BaseException | None = None
    cancellation: BaseException | None = None
    while process.returncode is None:
        try:
            process.wait(timeout=_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired as exc:
            if primary is None:
                primary = H0RunnerError("isolated process exceeded its SIGKILL reap bound")
                primary.__cause__ = exc
        except ChildProcessError:
            # The underlying waitpid already consumed this exact child before
            # Popen could publish returncode.  It is no longer waitable and its
            # numeric PID must not be signalled.
            process.returncode = 255
        except BaseException as exc:
            if primary is None:
                primary = exc
            if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
                cancellation = exc
    if cancellation is not None:
        raise cancellation
    if primary is not None:
        raise primary


def _close_descriptors(descriptors: list[int]) -> None:
    first: OSError | None = None
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except OSError as exc:
            if first is None:
                first = exc
    if first is not None:
        raise H0RunnerError(f"cannot close process channel exactly: {first}") from first


def _spawn_bounded(
    argv: Sequence[str],
    *,
    deadline: float,
    pass_fds: Sequence[int] = (),
    extra_readers: Mapping[str, tuple[int, int]] | None = None,
    close_after_spawn: Sequence[int] = (),
    environment: Mapping[str, str] | None = None,
) -> _ProcessResult:
    """Run an exact argv with bounded parent-owned byte streams."""
    # Establish ownership before argv/SIGCHLD validation or selector setup so
    # every early refusal closes channels transferred by the caller.
    readers = dict(extra_readers or {})
    process: subprocess.Popen | None = None
    process_streams: list[object] = []
    parent_close_pending = list(close_after_spawn)
    selector: selectors.BaseSelector | None = None
    owned_extra_descriptors = {descriptor for descriptor, _limit in readers.values()}
    buffers: dict[str, bytearray] = {name: bytearray() for name in readers}
    buffers.update({"stderr": bytearray(), "stdout": bytearray()})
    limits = {name: limit for name, (_descriptor, limit) in readers.items()}
    limits.update({"stderr": _MAX_LOG_BYTES, "stdout": _MAX_LOG_BYTES})
    primary: BaseException | None = None
    leader_release_started = False
    try:
        if not argv or any(type(argument) is not str for argument in argv):
            raise H0RunnerError("bounded process argv must be a non-empty exact string sequence")
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise H0RunnerError("bounded process owner refuses non-default SIGCHLD handling")
        selector = selectors.DefaultSelector()
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=tuple(pass_fds),
            env=dict(environment or {}),
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        process_streams = [process.stdout, process.stderr]
        _close_descriptors(parent_close_pending)
        stream_records = {
            "stdout": process.stdout.fileno(),
            "stderr": process.stderr.fileno(),
            **{name: descriptor for name, (descriptor, _limit) in readers.items()},
        }
        for name, descriptor in stream_records.items():
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, name)

        while selector.get_map() or not _leader_exited_unreaped(process):
            wait = min(_SELECT_SLICE_SECONDS, _remaining(deadline))
            if selector.get_map():
                events = selector.select(wait)
            else:
                time.sleep(wait)
                events = ()
            for key, _events in events:
                descriptor = key.fd
                name = key.data
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                buffer = buffers[name]
                buffer.extend(chunk)
                if len(buffer) > limits[name]:
                    raise H0RunnerError(f"{name} exceeded its {limits[name]}-byte limit")

        # Settle any daemonized same-group descendant before reserving leader
        # status is reaped and its numeric PGID can be reused.
        _signal_process_group(process, signal.SIGKILL)
        leader_release_started = True
        returncode = process.wait()
        return _ProcessResult(
            returncode=returncode,
            streams={name: bytes(body) for name, body in buffers.items()},
        )
    except BaseException as exc:
        primary = exc
        if process is not None:
            try:
                if leader_release_started:
                    _reap_without_signalling(
                        process,
                    )
                elif process.returncode is None:
                    _terminate_and_reap(process)
            except BaseException as settlement:
                if type(primary) not in {KeyboardInterrupt, SystemExit} and type(settlement) in {
                    KeyboardInterrupt,
                    SystemExit,
                }:
                    primary = settlement
                elif isinstance(primary, H0RunnerError):
                    primary = H0RunnerError(f"{primary}; process settlement also failed: {settlement}")
        raise primary
    finally:
        settlement: BaseException | None = None
        settlement_cancellation: BaseException | None = None
        if selector is not None:
            try:
                selector.close()
            except BaseException as exc:
                settlement = exc
                if type(exc) in {KeyboardInterrupt, SystemExit}:
                    settlement_cancellation = exc
        if parent_close_pending:
            try:
                _close_descriptors(parent_close_pending)
            except BaseException as exc:
                if settlement is None:
                    settlement = exc
                if type(exc) in {KeyboardInterrupt, SystemExit} and settlement_cancellation is None:
                    settlement_cancellation = exc
        for stream in process_streams:
            try:
                stream.close()
            except BaseException as exc:
                if settlement is None:
                    settlement = exc
                if type(exc) in {KeyboardInterrupt, SystemExit} and settlement_cancellation is None:
                    settlement_cancellation = exc
        while owned_extra_descriptors:
            descriptor = owned_extra_descriptors.pop()
            try:
                os.close(descriptor)
            except BaseException as exc:
                if isinstance(exc, OSError) and exc.errno == getattr(os, "EBADF", 9):
                    continue
                if settlement is None:
                    settlement = exc
                if type(exc) in {KeyboardInterrupt, SystemExit} and settlement_cancellation is None:
                    settlement_cancellation = exc
        if primary is None and settlement is not None:
            if isinstance(settlement, OSError):
                raise H0RunnerError(f"cannot close process channels exactly: {settlement}") \
                    from settlement
            raise settlement
        if (
            primary is not None
            and type(primary) not in {KeyboardInterrupt, SystemExit}
            and settlement_cancellation is not None
        ):
            raise settlement_cancellation


def _checked_process(
    argv: Sequence[str],
    *,
    deadline: float,
    label: str,
    maximum: int = _MAX_COMMAND_OUTPUT,
    environment: Mapping[str, str] | None = None,
) -> bytes:
    result = _spawn_bounded(argv, deadline=deadline, environment=environment)
    stdout = result.streams["stdout"]
    stderr = result.streams["stderr"]
    if len(stdout) > maximum or len(stderr) > maximum:
        raise H0RunnerError(f"{label} output exceeds {maximum} bytes")
    if result.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        raise H0RunnerError(f"{label} failed: {detail or result.returncode}")
    return stdout


def _one_version_line(stdout: bytes, stderr: bytes, name: str) -> str:
    raw = stdout if stdout.strip() else stderr
    try:
        text = raw.decode("utf-8", "strict").strip()
    except UnicodeError as exc:
        raise H0RunnerError(f"{name} version output is not strict UTF-8") from exc
    if not text or "\n" in text or "\r" in text or len(text.encode("utf-8")) > 512:
        raise H0RunnerError(f"{name} version output is not one bounded line")
    if any(ord(character) < 0x20 for character in text):
        raise H0RunnerError(f"{name} version output contains control characters")
    return text


def _probe_tool_versions(pins: Sequence[_ToolPin], *, deadline: float) -> None:
    arguments = {
        "bwrap": ("--version",),
        "git": ("--version",),
        "python": ("--version",),
    }
    for pin in pins:
        _assert_tool_pin(pin)
        result = _spawn_bounded(
            [pin.path, *arguments[pin.name]],
            deadline=min(deadline, time.monotonic() + _TOOL_VERSION_SECONDS),
        )
        if result.returncode != 0:
            raise H0RunnerError(f"cannot query pinned {pin.name} version")
        pin.version = _one_version_line(
            result.streams["stdout"], result.streams["stderr"], pin.name
        )
        _assert_tool_pin(pin)


@contextmanager
def _wall_deadline(seconds: int):
    """Install the one Linux wall deadline around even nested Git queries."""
    if type(seconds) is not int or seconds <= 0:
        raise H0RunnerError("profile deadline must be an exact positive integer")
    if not all(
        hasattr(signal, name)
        for name in (
            "ITIMER_REAL",
            "pthread_sigmask",
            "setitimer",
            "sigpending",
            "sigwait",
        )
    ):
        raise H0RunnerError("H0 development runner requires Linux interval timers")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if (
        previous_handler is not signal.SIG_DFL
        or previous_timer != (0.0, 0.0)
        or signal.SIGALRM in previous_mask
    ):
        raise H0RunnerError("H0 development runner refuses a pre-existing SIGALRM contract")

    def expired(_signum: int, _frame: FrameType | None) -> None:
        raise H0DeadlineError("H0 development profile deadline expired")

    control = _DeadlineControl(
        time.monotonic() + seconds,
        previous_handler,
        previous_timer,
        previous_mask,
    )
    setup_primary: BaseException | None = None
    setup_cleanup: BaseException | None = None
    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, seconds)
    except BaseException as exc:
        setup_primary = exc
        try:
            control.abort()
        except BaseException as cleanup_exc:
            setup_cleanup = cleanup_exc
    if setup_primary is not None:
        if setup_cleanup is not None:
            raise H0RunnerError(
                f"cannot install profile deadline ({setup_primary}); "
                f"signal rollback failed: {setup_cleanup}"
            ) from setup_cleanup
        raise setup_primary
    try:
        yield control
    finally:
        # Successful publication restores the deadline contract before the
        # normal context exit, which is therefore a strict no-op.
        control.abort()


def _git_base(pin: _ToolPin, repository: str | None = None) -> list[str]:
    argv = [pin.path]
    if repository is not None:
        argv.extend(("-C", repository))
    argv.extend((
        "-c", "core.checkStat=default",
        "-c", "core.fsmonitor=false",
        "-c", "core.ignoreStat=false",
        "-c", "core.trustctime=true",
        "-c", "core.untrackedCache=false",
        "-c", "core.fileMode=true",
        "-c", "core.symlinks=true",
    ))
    return argv


def _git_query(
    pin: _ToolPin,
    repository: str,
    arguments: Sequence[str],
    *,
    deadline: float,
    label: str,
) -> bytes:
    _assert_tool_pin(pin)
    body = _checked_process(
        [*_git_base(pin, repository), *arguments],
        deadline=deadline,
        label=label,
        environment=evidence._git_environment(),
    )
    _assert_tool_pin(pin)
    return body


def _one_ascii_line(body: bytes, name: str) -> str:
    try:
        value = body.decode("ascii", "strict").strip()
    except UnicodeError as exc:
        raise H0RunnerError(f"Git returned a non-ASCII {name}") from exc
    if not value or "\n" in value or "\r" in value:
        raise H0RunnerError(f"Git returned an invalid {name}")
    return value


def _resolve_source_repository(
    repository: str | os.PathLike[str],
    git: _ToolPin,
    *,
    deadline: float,
) -> str:
    requested = _normalized_absolute(repository, "source repository")
    try:
        requested_path = Path(requested).resolve(strict=True)
    except OSError as exc:
        raise H0RunnerError(f"cannot resolve source repository: {exc}") from exc
    if os.fspath(requested_path) != requested or not requested_path.is_dir():
        raise H0RunnerError("source repository must be a symlink-free absolute directory")
    root_text = _one_ascii_line(
        _git_query(
            git,
            requested,
            ("rev-parse", "--show-toplevel"),
            deadline=deadline,
            label="source repository root query",
        ),
        "source repository root",
    )
    try:
        root = Path(root_text).resolve(strict=True)
    except OSError as exc:
        raise H0RunnerError(f"cannot resolve Git source root: {exc}") from exc
    if os.fspath(root) != root_text or requested_path != root:
        raise H0RunnerError("source repository must exactly equal its symlink-free Git root")
    return os.fspath(root)


def _capture_source_identity(
    source_root: str,
    git: _ToolPin,
    *,
    deadline: float,
) -> tuple[str, str]:
    commit = _one_ascii_line(
        _git_query(
            git,
            source_root,
            ("rev-parse", "--verify", "HEAD^{commit}"),
            deadline=deadline,
            label="source commit capture",
        ),
        "source commit",
    )
    tree = _one_ascii_line(
        _git_query(
            git,
            source_root,
            ("rev-parse", "--verify", f"{commit}^{{tree}}"),
            deadline=deadline,
            label="source tree capture",
        ),
        "source tree",
    )
    try:
        evidence._object_id(commit, "captured source commit")
        evidence._object_id(tree, "captured source tree")
    except evidence.EvidenceError as exc:
        raise H0RunnerError(str(exc)) from exc
    return commit, tree


def _private_clone(
    source_root: str,
    target: Path,
    commit: str,
    tree: str,
    git: _ToolPin,
    *,
    deadline: float,
) -> list[evidence._TreeEntry]:
    helper, helper_signature = _git_upload_pack(git)
    _assert_tool_pin(git)
    if _git_upload_pack(git) != (helper, helper_signature):
        raise H0RunnerError("Git upload-pack helper changed during private clone")
    clone_argv = [
        *_git_base(git),
        "clone",
        "--quiet",
        "--no-checkout",
        "--no-hardlinks",
        "--no-local",
        "--no-tags",
        "--no-recurse-submodules",
        "--upload-pack",
        helper,
        "--",
        source_root,
        os.fspath(target),
    ]
    _checked_process(
        clone_argv,
        deadline=deadline,
        label="private Git clone",
        environment=evidence._git_environment(),
    )
    _assert_tool_pin(git)
    if _git_upload_pack(git) != (helper, helper_signature):
        raise H0RunnerError("Git upload-pack helper changed during private clone")
    _checked_process(
        [*_git_base(git, os.fspath(target)), "checkout", "--quiet", "--detach", "--force", commit],
        deadline=deadline,
        label="private Git checkout",
        environment=evidence._git_environment(),
    )
    _checked_process(
        [*_git_base(git, os.fspath(target)), "remote", "remove", "origin"],
        deadline=deadline,
        label="private Git remote removal",
        environment=evidence._git_environment(),
    )
    private_commit = _one_ascii_line(
        _git_query(
            git,
            os.fspath(target),
            ("rev-parse", "--verify", "HEAD^{commit}"),
            deadline=deadline,
            label="private commit verification",
        ),
        "private commit",
    )
    private_tree = _one_ascii_line(
        _git_query(
            git,
            os.fspath(target),
            ("rev-parse", "--verify", "HEAD^{tree}"),
            deadline=deadline,
            label="private tree verification",
        ),
        "private tree",
    )
    if private_commit != commit or private_tree != tree:
        raise H0RunnerError("private Git materialization does not match captured commit/tree")
    entries = _bounded_tree_entries(target, commit, git, deadline=deadline)
    if any(entry.kind == b"commit" or entry.mode == b"160000" for entry in entries):
        raise H0RunnerError("development H0 materialization refuses Gitlinks")
    if any(entry.mode == b"120000" for entry in entries):
        raise H0RunnerError("development H0 materialization refuses candidate symlinks")
    return entries


def _git_upload_pack(git: _ToolPin) -> tuple[str, tuple[int, ...]]:
    helper = os.path.join(os.path.dirname(git.path), "git-upload-pack")
    try:
        helper_stat = os.lstat(helper)
        helper_link = os.readlink(helper)
        helper_target = os.path.realpath(helper)
    except OSError as exc:
        raise H0RunnerError(f"cannot resolve immutable Git upload-pack helper: {exc}") from exc
    if (
        not stat.S_ISLNK(helper_stat.st_mode)
        or helper_stat.st_uid != 0
        or helper_link != os.path.basename(git.path)
        or helper_target != git.path
    ):
        raise H0RunnerError(
            "no-local clone requires a root-owned direct git-upload-pack symlink to pinned Git"
        )
    _assert_tool_pin(git)
    return helper, _stat_signature(helper_stat)


def _bounded_tree_entries(
    repository: Path,
    commit: str,
    git: _ToolPin,
    *,
    deadline: float,
) -> list[evidence._TreeEntry]:
    raw = _git_query(
        git,
        os.fspath(repository),
        ("ls-tree", "-r", "-z", "--full-tree", commit),
        deadline=deadline,
        label="private tree enumeration",
    )
    entries: list[evidence._TreeEntry] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            metadata, path = item.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            oid_text = object_id.decode("ascii", "strict")
        except (UnicodeError, ValueError) as exc:
            raise H0RunnerError("Git returned a malformed private tree entry") from exc
        if not evidence._valid_tree_shape(mode, kind, path):
            raise H0RunnerError("Git returned an unsupported private tree entry")
        try:
            evidence._object_id(oid_text, "private tree object id")
        except evidence.EvidenceError as exc:
            raise H0RunnerError(str(exc)) from exc
        entries.append(evidence._TreeEntry(mode, kind, object_id, path))
    entries.sort(key=lambda entry: entry.path)
    if len({entry.path for entry in entries}) != len(entries):
        raise H0RunnerError("private candidate tree contains duplicate paths")
    return entries


def _write_all(descriptor: int, body: bytes) -> None:
    offset = 0
    while offset < len(body):
        written = os.write(descriptor, body[offset:])
        if written <= 0:
            raise OSError("short file write")
        offset += written


def _export_candidate(
    private_repository: Path,
    destination: Path,
    entries: Sequence[evidence._TreeEntry],
    git: _ToolPin,
    *,
    deadline: float,
) -> Callable[[str], bytes]:
    destination.mkdir(mode=0o700)
    blob_cache: dict[str, bytes] = {}

    def read_blob(object_id: str) -> bytes:
        body = blob_cache.get(object_id)
        if body is None:
            body = _git_query(
                git,
                os.fspath(private_repository),
                ("cat-file", "blob", object_id),
                deadline=deadline,
                label="private candidate blob read",
            )
            blob_cache[object_id] = body
        return body

    for entry in entries:
        try:
            relative = entry.path.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise H0RunnerError("candidate paths must be strict UTF-8 for H0 taxonomy evidence") from exc
        normalized = evidence._safe_relative_path(relative, "candidate export path")
        target = destination.joinpath(*PurePosixPath(normalized).parts)
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        body = read_blob(entry.object_id.decode("ascii"))
        mode = 0o755 if entry.mode == b"100755" else 0o644
        descriptor = -1
        primary: BaseException | None = None
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode,
            )
            _write_all(descriptor, body)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        except BaseException as exc:
            primary = exc
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as close_fault:
                    if primary is None or (
                        type(primary) not in {KeyboardInterrupt, SystemExit}
                        and type(close_fault) in {KeyboardInterrupt, SystemExit}
                    ):
                        primary = close_fault
        if primary is not None:
            if isinstance(primary, OSError):
                raise H0RunnerError(
                    f"cannot export exact candidate file {relative!r}: {primary}"
                ) from primary
            raise primary
    try:
        evidence._refuse_raw_worktree_mismatch(
            destination,
            entries,
            blob_reader=read_blob,
            label="exported candidate",
        )
    except evidence.EvidenceError as exc:
        raise H0RunnerError(f"exported candidate verification failed: {exc}") from exc
    if (destination / ".git").exists() or (destination / ".git").is_symlink():
        raise H0RunnerError("private candidate export unexpectedly exposes .git")
    os.chmod(destination, 0o555)
    return read_blob


def _collect_private_identity(
    private_repository: Path,
    python: _ToolPin,
    git: _ToolPin,
    *,
    deadline: float,
) -> dict:
    worker = private_repository / "src" / "quarry_recon" / "release_h0_identity.py"
    if not worker.is_file() or worker.is_symlink():
        raise H0RunnerError("private candidate omits the regular identity worker")
    _assert_tool_pin(python)
    _assert_tool_pin(git)
    result = _spawn_bounded(
        [
            f"/proc/self/fd/{python.descriptor}",
            "-I",
            "-B",
            os.fspath(worker),
            "--repository",
            os.fspath(private_repository),
            "--git",
            git.path,
        ],
        deadline=deadline,
        pass_fds=(python.descriptor,),
        environment={},
    )
    _assert_tool_pin(python)
    _assert_tool_pin(git)
    if result.returncode != 0:
        detail = result.streams["stderr"].decode("utf-8", "replace").strip()
        raise H0RunnerError(f"private candidate identity worker failed: {detail or result.returncode}")
    if result.streams["stderr"]:
        raise H0RunnerError("private candidate identity worker emitted unexpected stderr")
    body = result.streams["stdout"]
    if len(body) > evidence.MAX_RECORD_BYTES:
        raise H0RunnerError("private candidate identity exceeds its byte limit")
    document = evidence.load_json_bytes(body)
    if type(document) is not dict or body != evidence.canonical_json_bytes(document):
        raise H0RunnerError("private candidate identity worker output is not canonical JSON")
    try:
        evidence.validate_candidate_identity(document)
    except evidence.EvidenceError as exc:
        raise H0RunnerError(f"private candidate identity is invalid: {exc}") from exc
    if document["package_version"] != H0_PACKAGE_VERSION:
        raise H0RunnerError(
            f"development H0 runner accepts only package {H0_PACKAGE_VERSION}, not "
            f"{document['package_version']!r}"
        )
    return document


def _read_regular_nofollow(root: Path, relative: str, *, maximum: int) -> bytes:
    parts = PurePosixPath(evidence._safe_relative_path(relative, "candidate input path")).parts
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptors: list[int] = []
    primary: BaseException | None = None
    body: bytes | None = None
    try:
        descriptors.append(os.open(root, directory_flags))
        for component in parts[:-1]:
            descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
        descriptors.append(os.open(parts[-1], file_flags, dir_fd=descriptors[-1]))
        descriptor = descriptors[-1]
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise H0RunnerError(f"candidate input {relative!r} must be a singly-linked regular file")
        if before.st_size > maximum:
            raise H0RunnerError(f"candidate input {relative!r} exceeds {maximum} bytes")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise H0RunnerError(f"candidate input {relative!r} exceeds {maximum} bytes")
        after = os.fstat(descriptor)
        if _stat_signature(before) != _stat_signature(after) or total != after.st_size:
            raise H0RunnerError(f"candidate input {relative!r} changed while being read")
        body = b"".join(chunks)
    except BaseException as exc:
        primary = exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as close_fault:
                if primary is None or (
                    type(primary) not in {KeyboardInterrupt, SystemExit}
                    and type(close_fault) in {KeyboardInterrupt, SystemExit}
                ):
                    primary = close_fault
    if primary is not None:
        if isinstance(primary, OSError):
            raise H0RunnerError(f"cannot read candidate input {relative!r}: {primary}") from primary
        raise primary
    if body is None:
        raise H0RunnerError("candidate input read reached an impossible state")
    return body


def _candidate_contracts(candidate: Path, identity: dict) -> dict[str, bytes | dict]:
    bodies: dict[str, bytes] = {}
    maxima = {
        evidence.PYTEST_TAXONOMY_SCHEMA_PATH: evidence.MAX_RECORD_BYTES,
        evidence.VERIFICATION_JOB_MAP_PATH: evidence.MAX_RECORD_BYTES,
        evidence.VERIFICATION_JOB_MAP_SCHEMA_PATH: evidence.MAX_RECORD_BYTES,
        evidence.H0_DEVELOPMENT_PROFILE_PATH: evidence.MAX_RECORD_BYTES,
        evidence.H0_DEVELOPMENT_PROFILE_SCHEMA_PATH: evidence.MAX_RECORD_BYTES,
        ".github/workflows/ci.yml": evidence.MAX_RECORD_BYTES,
        "src/quarry_recon/release_h0.py": evidence.MAX_RECORD_BYTES,
        "src/quarry_recon/release_h0_inner.py": evidence.MAX_RECORD_BYTES,
        "src/quarry_recon/release_h0_identity.py": evidence.MAX_RECORD_BYTES,
        "src/quarry_recon/release_evidence.py": evidence.MAX_RECORD_BYTES,
    }
    for path, maximum in maxima.items():
        bodies[path] = _read_regular_nofollow(candidate, path, maximum=maximum)

    input_records = {record["name"]: record for record in identity["inputs"]}
    for name, path in evidence.FUTURE_RUNNER_INPUTS.items():
        record = input_records.get(name)
        if record is None or record["path"] != path:
            raise H0RunnerError(f"private identity omits future runner input {name!r}")
        body = bodies.get(path)
        if body is None:
            body = _read_regular_nofollow(candidate, path, maximum=evidence.MAX_RECORD_BYTES)
            bodies[path] = body
        if record["digest"] != _raw_digest(body):
            raise H0RunnerError(f"private identity digest disagrees for future input {name!r}")

    profile = read_development_profile(bodies[evidence.H0_DEVELOPMENT_PROFILE_PATH])
    _read_development_profile_schema(
        bodies[evidence.H0_DEVELOPMENT_PROFILE_SCHEMA_PATH],
        profile,
    )

    taxonomy_schema = evidence.load_json_bytes(bodies[evidence.PYTEST_TAXONOMY_SCHEMA_PATH])
    evidence._validate_registered_schema(
        taxonomy_schema,
        name="pytest-taxonomy",
        record_version=evidence.PYTEST_TAXONOMY_SCHEMA,
    )
    job_map_schema = evidence.load_json_bytes(bodies[evidence.VERIFICATION_JOB_MAP_SCHEMA_PATH])
    evidence._validate_registered_schema(
        job_map_schema,
        name="verification-job-map",
        record_version=evidence.VERIFICATION_JOB_MAP_SCHEMA,
    )
    provisional_job_map = _read_canonical_line(
        bodies[evidence.VERIFICATION_JOB_MAP_PATH],
        "verification job map",
    )
    _provisional, workflow_records = evidence._verification_job_map_shape(provisional_job_map)
    workflow_directory = candidate / ".github" / "workflows"
    try:
        observed_workflows = sorted(
            f".github/workflows/{entry.name}"
            for entry in os.scandir(workflow_directory)
            if entry.is_file(follow_symlinks=False) and entry.name.endswith((".yml", ".yaml"))
        )
    except OSError as exc:
        raise H0RunnerError(f"cannot inventory candidate verification workflows: {exc}") from exc
    declared_workflows = [record["path"] for record in workflow_records]
    if observed_workflows != declared_workflows:
        raise H0RunnerError("verification job map does not cover the exact workflow inventory")
    workflow_bodies = {}
    for path in declared_workflows:
        body = bodies.get(path)
        if body is None:
            body = _read_regular_nofollow(candidate, path, maximum=evidence.MAX_RECORD_BYTES)
            bodies[path] = body
        workflow_bodies[path] = body
    job_map = evidence.read_verification_job_map(
        bodies[evidence.VERIFICATION_JOB_MAP_PATH],
        workflow_bodies=workflow_bodies,
    )

    local_sources = {
        "src/quarry_recon/release_h0.py": Path(__file__),
        "src/quarry_recon/release_evidence.py": Path(evidence.__file__),
    }
    for relative, local in local_sources.items():
        try:
            local_body = local.read_bytes()
        except OSError as exc:
            raise H0RunnerError(f"cannot verify loaded source authority for {relative!r}: {exc}") from exc
        if local_body != bodies[relative]:
            raise H0RunnerError(f"loaded source authority differs from candidate input {relative!r}")

    return {
        "bodies": bodies,
        "job_map": job_map,
        "profile": profile,
    }


_RUNTIME_PROBE = r"""
import hashlib, importlib.metadata, json, os, platform, sys
import click, idna, pytest, yaml
modules = {
    "click": (click, "click"),
    "idna": (idna, "idna"),
    "pytest": (pytest, "pytest"),
    "yaml": (yaml, "PyYAML"),
}
components = []
for name in sorted(modules):
    module, distribution = modules[name]
    path = os.path.realpath(module.__file__)
    with open(path, "rb") as stream:
        digest = "sha256:" + hashlib.sha256(stream.read()).hexdigest()
    components.append({
        "digest": digest,
        "name": name,
        "path": path,
        "version": importlib.metadata.version(distribution),
    })
document = {
    "base_prefix": os.path.realpath(sys.base_prefix),
    "components": components,
    "implementation": platform.python_implementation(),
    "prefix": os.path.realpath(sys.prefix),
    "python_executable": os.path.realpath(sys.executable),
    "python_version": platform.python_version(),
    "sys_path": [os.path.realpath(path) for path in sys.path],
}
print(json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")))
""".strip()


def _runtime_record(python: _ToolPin, profile: dict, *, deadline: float) -> dict:
    if not Path(python.path).is_relative_to(Path("/usr")):
        raise H0RunnerError("development host-runtime Python must be inside the /usr closure")
    _assert_tool_pin(python)
    result = _spawn_bounded(
        [f"/proc/self/fd/{python.descriptor}", "-I", "-B", "-c", _RUNTIME_PROBE],
        deadline=deadline,
        pass_fds=(python.descriptor,),
        environment={},
    )
    _assert_tool_pin(python)
    if result.returncode != 0 or result.streams["stderr"]:
        detail = result.streams["stderr"].decode("utf-8", "replace").strip()
        raise H0RunnerError(f"isolated Python runtime probe failed: {detail or result.returncode}")
    probe = _read_canonical_line(result.streams["stdout"], "Python runtime probe")
    required = {
        "base_prefix", "components", "implementation", "prefix",
        "python_executable", "python_version", "sys_path",
    }
    try:
        evidence._object(probe, "Python runtime probe", required)
        evidence._nonempty_string(probe["implementation"], "Python runtime implementation")
        evidence._nonempty_string(probe["python_version"], "Python runtime version")
    except evidence.EvidenceError as exc:
        raise H0RunnerError(str(exc)) from exc
    if probe["python_executable"] != python.path:
        raise H0RunnerError("Python runtime probe did not execute the pinned interpreter")
    for name in ("base_prefix", "prefix"):
        if probe[name] != "/usr":
            raise H0RunnerError(f"development Python {name} must be exactly /usr")
    if type(probe["sys_path"]) is not list or not probe["sys_path"]:
        raise H0RunnerError("Python runtime probe returned an invalid sys.path")
    for path in probe["sys_path"]:
        if type(path) is not str or not Path(path).is_relative_to(Path("/usr")):
            raise H0RunnerError("Python isolated sys.path escapes the recorded /usr closure")
    components = probe["components"]
    if type(components) is not list or [item.get("name") for item in components] != [
        "click", "idna", "pytest", "yaml"
    ]:
        raise H0RunnerError("Python runtime probe dependency inventory is incomplete")
    for item in components:
        try:
            evidence._object(item, "Python runtime module", {"digest", "name", "path", "version"})
            evidence._digest(item["digest"], "Python runtime module digest")
            evidence._nonempty_string(item["version"], "Python runtime module version")
        except evidence.EvidenceError as exc:
            raise H0RunnerError(str(exc)) from exc
        if not Path(item["path"]).is_relative_to(Path("/usr")):
            raise H0RunnerError("Python runtime dependency escapes the recorded /usr closure")
    return {
        "architecture": platform.machine(),
        "executable_closure_trusted": False,
        "host_kernel": platform.release(),
        "host_os": platform.system(),
        "mode": profile["mode"],
        "probe": probe,
        "runtime_kind": "development-host-runtime-not-an-image",
        "runtime_mounts": profile["runtime_mounts"],
        "runtime_symlinks": profile["runtime_symlinks"],
        "schema_version": H0_RUNTIME_RECORD_SCHEMA,
    }


def _toolchain_record(pins: Sequence[_ToolPin], runtime: dict) -> dict:
    records = []
    for pin in pins:
        _assert_tool_pin(pin)
        value = os.fstat(pin.descriptor)
        records.append({
            "authority": "local-root-owned-non-writable-ancestry-plus-open-hash-descriptor",
            "device": value.st_dev,
            "digest": pin.digest,
            "inode": value.st_ino,
            "mode": stat.S_IMODE(value.st_mode),
            "name": pin.name,
            "path": pin.path,
            "size": value.st_size,
            "version": pin.version,
        })
    git = next(pin for pin in pins if pin.name == "git")
    helper, helper_signature = _git_upload_pack(git)
    helper_stat = os.lstat(helper)
    if _stat_signature(helper_stat) != helper_signature:
        raise H0RunnerError("Git upload-pack helper changed while recording toolchain")
    records.append({
        "authority": "root-owned-immutable-symlink-to-pinned-git",
        "device": helper_stat.st_dev,
        "digest": git.digest,
        "inode": helper_stat.st_ino,
        "mode": stat.S_IMODE(helper_stat.st_mode),
        "name": "git-upload-pack",
        "path": helper,
        "size": helper_stat.st_size,
        "version": git.version,
    })
    records.sort(key=lambda record: record["name"])
    return {
        "dependency_closure_complete": False,
        "python_components": runtime["probe"]["components"],
        "schema_version": H0_TOOLCHAIN_RECORD_SCHEMA,
        "tools": records,
    }


def _open_mount_directory(path: Path, name: str) -> int:
    if not hasattr(os, "O_PATH") or not os.O_PATH:
        raise H0RunnerError("H0 development runner requires Linux O_PATH")
    descriptor = -1
    primary: BaseException | None = None
    try:
        descriptor = os.open(
            path,
            os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        value = os.fstat(descriptor)
        if not stat.S_ISDIR(value.st_mode):
            raise H0RunnerError(f"{name} mount descriptor is not a directory")
        return descriptor
    except BaseException as exc:
        primary = exc
    close_fault: BaseException | None = None
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except BaseException as exc:
            close_fault = exc
    if type(primary) in {KeyboardInterrupt, SystemExit}:
        raise primary
    if type(close_fault) in {KeyboardInterrupt, SystemExit}:
        raise close_fault
    if close_fault is not None:
        raise H0RunnerError(
            f"cannot settle failed {name} mount open ({primary}); close failed: {close_fault}"
        ) from close_fault
    if isinstance(primary, OSError):
        raise H0RunnerError(f"cannot open {name} mount by O_PATH/O_NOFOLLOW: {primary}") from primary
    raise primary


def _open_runtime_mount(profile: dict) -> tuple[int, tuple[int, ...]]:
    mounts = profile["runtime_mounts"]
    if mounts != [{
        "destination": "/usr",
        "source": "/usr",
        "trust": "untrusted-host-runtime-exec-closure",
    }]:
        raise H0RunnerError("development runtime mount must be the exact untrusted /usr closure")
    root = os.lstat("/")
    if (
        not stat.S_ISDIR(root.st_mode)
        or root.st_uid != 0
        or root.st_mode & 0o022
        or os.access("/", os.W_OK, effective_ids=True, follow_symlinks=False)
    ):
        raise H0RunnerError("filesystem root is mutable to the unprivileged runner")
    value = os.lstat("/usr")
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or value.st_mode & 0o022
        or os.access("/usr", os.W_OK, effective_ids=True, follow_symlinks=False)
    ):
        raise H0RunnerError("/usr runtime closure is mutable to the unprivileged runner")
    descriptor = _open_mount_directory(Path("/usr"), "host runtime")
    try:
        opened = os.fstat(descriptor)
        if _stat_signature(opened) != _stat_signature(value):
            raise H0RunnerError("/usr runtime closure changed while opening")
        return descriptor, _stat_signature(opened)
    except BaseException as primary:
        close_fault: BaseException | None = None
        try:
            os.close(descriptor)
        except BaseException as exc:
            close_fault = exc
        if type(primary) in {KeyboardInterrupt, SystemExit}:
            raise primary
        if type(close_fault) in {KeyboardInterrupt, SystemExit}:
            raise close_fault
        if close_fault is not None:
            raise H0RunnerError(
                f"cannot settle failed /usr runtime mount ({primary}); close failed: {close_fault}"
            ) from close_fault
        if isinstance(primary, OSError):
            raise H0RunnerError(f"cannot verify opened /usr runtime closure: {primary}") from primary
        raise


def _assert_runtime_mount(descriptor: int, signature: tuple[int, ...]) -> None:
    try:
        by_descriptor = os.fstat(descriptor)
        by_path = os.lstat("/usr")
    except OSError as exc:
        raise H0RunnerError(f"cannot revalidate /usr runtime closure: {exc}") from exc
    if _stat_signature(by_descriptor) != signature or _stat_signature(by_path) != signature:
        raise H0RunnerError("/usr runtime closure changed during the diagnostic")


def _prepare_work(path: Path) -> None:
    path.mkdir(mode=0o700)
    for name in ("home", "tmp", "xdg-cache", "xdg-config", "xdg-data"):
        (path / name).mkdir(mode=0o700)


def _host_namespaces() -> list[dict]:
    records = []
    for name in _NAMESPACE_NAMES:
        try:
            value = os.readlink(f"/proc/self/ns/{name}")
        except OSError as exc:
            raise H0RunnerError(f"cannot capture host {name} namespace: {exc}") from exc
        records.append({"name": name, "value": value})
    return records


def _build_bwrap_argv(
    profile: dict,
    *,
    bwrap: _ToolPin,
    python: _ToolPin,
    candidate_fd: int,
    work_fd: int,
    runtime_fd: int,
    status_fd: int,
    isolation_fd: int,
) -> list[str]:
    argv = [bwrap.path, *profile["bwrap_options"]]
    argv.extend(("--hostname", profile["hostname"], "--json-status-fd", str(status_fd)))
    argv.extend(("--tmpfs", "/"))
    argv.extend(("--dir", profile["candidate_mount"]))
    argv.extend(("--ro-bind-fd", str(candidate_fd), profile["candidate_mount"]))
    argv.extend(("--dir", profile["work_mount"]))
    argv.extend(("--bind-fd", str(work_fd), profile["work_mount"]))
    for mount in profile["runtime_mounts"]:
        argv.extend(("--dir", mount["destination"]))
        argv.extend(("--ro-bind-fd", str(runtime_fd), mount["destination"]))
    # Pin the actual interpreter bytes over the host-runtime mount before exec.
    argv.extend(("--ro-bind-fd", str(python.descriptor), python.path))
    for link in profile["runtime_symlinks"]:
        argv.extend(("--symlink", link["target"], link["destination"]))
    argv.extend(("--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev"))
    for item in profile["environment"]:
        argv.extend(("--setenv", item["name"], item["value"]))
    argv.extend(("--chdir", profile["candidate_mount"], "--", python.path))
    argv.extend(profile["python_arguments"])
    argv.extend(("--isolation-fd", str(isolation_fd)))
    return argv


def _parse_bwrap_status(body: bytes) -> tuple[dict, bytes]:
    if not body or len(body) > _MAX_BWRAP_STATUS_BYTES or not body.endswith(b"\n"):
        raise H0RunnerError("bubblewrap status channel has invalid framing")
    lines = body.splitlines()
    if len(lines) != 2:
        raise H0RunnerError("bubblewrap status channel must contain exactly two JSON documents")
    documents = []
    for line in lines:
        document = evidence.load_json_bytes(line, maximum=_MAX_BWRAP_STATUS_BYTES)
        if type(document) is not dict:
            raise H0RunnerError("bubblewrap status document must be an object")
        documents.append(document)
    first_required = {
        "child-pid",
        "cgroup-namespace",
        "ipc-namespace",
        "mnt-namespace",
        "net-namespace",
        "pid-namespace",
        "uts-namespace",
    }
    try:
        evidence._object(documents[0], "bubblewrap start status", first_required)
        evidence._object(documents[1], "bubblewrap exit status", {"exit-code"})
    except evidence.EvidenceError as exc:
        raise H0RunnerError(str(exc)) from exc
    for name, value in documents[0].items():
        if type(value) is not int or value <= 0:
            raise H0RunnerError(f"bubblewrap status {name!r} must be an exact positive integer")
    if documents[1]["exit-code"] != 0 or type(documents[1]["exit-code"]) is not int:
        raise H0RunnerError("bubblewrap status does not report one successful child exit")
    record = {
        "documents": documents,
        "schema_version": H0_BWRAP_STATUS_SCHEMA,
    }
    return record, _canonical_line(record)


def _namespace_inode(value: object, name: str) -> int:
    if type(value) is not str or not value.startswith(name + ":[") or not value.endswith("]"):
        raise H0RunnerError(f"isolation report has invalid {name} namespace identity")
    digits = value[len(name) + 2:-1]
    if not digits.isascii() or not digits.isdecimal():
        raise H0RunnerError(f"isolation report has invalid {name} namespace inode")
    return int(digits, 10)


def _validate_isolation_report(
    body: bytes,
    *,
    profile: dict,
    host_namespaces: Sequence[dict],
    candidate_stat: os.stat_result,
    work_stat: os.stat_result,
    runtime_stat: os.stat_result,
    bwrap_status: dict,
    expected_report_fd: int,
) -> dict:
    report = _read_canonical_line(
        body,
        "inner isolation report",
        maximum=_MAX_ISOLATION_REPORT_BYTES,
    )
    required = {
        "checks", "effective_capabilities", "environment", "gid", "hostname",
        "mounts", "namespaces", "open_descriptors", "root_entries", "schema_version", "uid",
    }
    try:
        evidence._object(report, "inner isolation report", required)
    except evidence.EvidenceError as exc:
        raise H0RunnerError(str(exc)) from exc
    if report["schema_version"] != H0_ISOLATION_REPORT_SCHEMA:
        raise H0RunnerError("inner isolation report schema is unsupported")
    check_names = {
        "candidate_read_only",
        "candidate_source_exact",
        "cwd_exact",
        "dev_isolated",
        "effective_capabilities_empty",
        "environment_exact",
        "fd_inventory_exact",
        "forbidden_roots_absent",
        "hostname_exact",
        "no_git_visible",
        "proc_read_only",
        "report_fd_is_pipe",
        "runtime_read_only",
        "work_read_write",
    }
    try:
        checks = evidence._object(report["checks"], "inner isolation checks", check_names)
    except evidence.EvidenceError as exc:
        raise H0RunnerError(str(exc)) from exc
    if any(value is not True for value in checks.values()):
        raise H0RunnerError("inner isolation report contains a failed check")
    if report["effective_capabilities"] != "0000000000000000":
        raise H0RunnerError("inner process retained effective capabilities")
    if report["hostname"] != profile["hostname"]:
        raise H0RunnerError("inner isolation hostname differs from the profile")
    if report["root_entries"] != _EXPECTED_ROOT_ENTRIES:
        raise H0RunnerError("inner root is not the exact blank-root mount inventory")
    for name in ("uid", "gid"):
        if type(report[name]) is not int or report[name] < 0:
            raise H0RunnerError(f"inner isolation {name} is invalid")
    if report["environment"] != profile["environment"]:
        raise H0RunnerError("inner isolation environment differs from the profile")
    if report["open_descriptors"] != [0, 1, 2, expected_report_fd]:
        raise H0RunnerError("inner isolation report contains an unexpected descriptor inventory")

    mounts = report["mounts"]
    expected_mounts = ["/candidate", "/dev", "/proc", "/usr", "/work"]
    if type(mounts) is not list or [item.get("path") for item in mounts] != expected_mounts:
        raise H0RunnerError("inner isolation mount inventory is incomplete or reordered")
    normalized_mounts = {}
    for index, item in enumerate(mounts):
        try:
            member = evidence._object(
                item,
                f"inner isolation mounts[{index}]",
                {"device", "inode", "path", "read_only"},
            )
        except evidence.EvidenceError as exc:
            raise H0RunnerError(str(exc)) from exc
        if (
            type(member["device"]) is not int
            or member["device"] < 0
            or type(member["inode"]) is not int
            or member["inode"] <= 0
            or type(member["read_only"]) is not bool
        ):
            raise H0RunnerError("inner isolation mount identity is invalid")
        normalized_mounts[member["path"]] = member
    if not all(normalized_mounts[path]["read_only"] for path in ("/candidate", "/proc", "/usr")):
        raise H0RunnerError("inner candidate/proc/runtime mount is not read-only")
    if normalized_mounts["/work"]["read_only"]:
        raise H0RunnerError("inner work mount is not read-write")
    if (
        normalized_mounts["/candidate"]["device"] != candidate_stat.st_dev
        or normalized_mounts["/candidate"]["inode"] != candidate_stat.st_ino
        or normalized_mounts["/work"]["device"] != work_stat.st_dev
        or normalized_mounts["/work"]["inode"] != work_stat.st_ino
        or normalized_mounts["/usr"]["device"] != runtime_stat.st_dev
        or normalized_mounts["/usr"]["inode"] != runtime_stat.st_ino
    ):
        raise H0RunnerError("inner bind mounts do not match the parent-opened descriptors")

    namespaces = report["namespaces"]
    if type(namespaces) is not list or [item.get("name") for item in namespaces] != list(
        _NAMESPACE_NAMES
    ):
        raise H0RunnerError("inner namespace inventory is incomplete or reordered")
    host_by_name = {item["name"]: item["value"] for item in host_namespaces}
    inner_by_name = {}
    for index, item in enumerate(namespaces):
        try:
            member = evidence._object(
                item,
                f"inner isolation namespaces[{index}]",
                {"name", "value"},
            )
        except evidence.EvidenceError as exc:
            raise H0RunnerError(str(exc)) from exc
        name = member["name"]
        inode = _namespace_inode(member["value"], name)
        if member["value"] == host_by_name.get(name):
            raise H0RunnerError(f"inner {name} namespace was not isolated from the host")
        inner_by_name[name] = inode
    start = bwrap_status["documents"][0]
    for name in _BWRAP_STATUS_NAMES:
        if inner_by_name[name] != start[f"{name}-namespace"]:
            raise H0RunnerError(f"inner {name} namespace disagrees with bubblewrap status")
    return report


def _execute_bwrap(
    profile: dict,
    *,
    bwrap: _ToolPin,
    python: _ToolPin,
    candidate_fd: int,
    work_fd: int,
    runtime_fd: int,
    runtime_signature: tuple[int, ...],
    host_namespaces: Sequence[dict],
    deadline: float,
) -> dict[str, bytes | dict]:
    owned_channels: list[int] = []
    status_read = status_write = isolation_read = isolation_write = -1
    try:
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        owned_channels.extend((status_read, status_write))
        isolation_read, isolation_write = os.pipe2(os.O_CLOEXEC)
        owned_channels.extend((isolation_read, isolation_write))
        argv = _build_bwrap_argv(
            profile,
            bwrap=bwrap,
            python=python,
            candidate_fd=candidate_fd,
            work_fd=work_fd,
            runtime_fd=runtime_fd,
            status_fd=status_write,
            isolation_fd=isolation_write,
        )
        _assert_tool_pin(bwrap)
        _assert_tool_pin(python)
        _assert_runtime_mount(runtime_fd, runtime_signature)
        # _spawn_bounded takes ownership of all four parent channel ends on
        # entry, including every Popen failure path.
        owned_channels.clear()
        result = _spawn_bounded(
            argv,
            deadline=deadline,
            pass_fds=(
                python.descriptor,
                candidate_fd,
                work_fd,
                runtime_fd,
                status_write,
                isolation_write,
            ),
            extra_readers={
                "bwrap_status": (status_read, _MAX_BWRAP_STATUS_BYTES),
                "isolation_report": (isolation_read, _MAX_ISOLATION_REPORT_BYTES),
            },
            close_after_spawn=(status_write, isolation_write),
            environment={},
        )
        _assert_tool_pin(bwrap)
        _assert_tool_pin(python)
        _assert_runtime_mount(runtime_fd, runtime_signature)
    finally:
        for descriptor in owned_channels:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if result.returncode != 0:
        detail = result.streams["stderr"].decode("utf-8", "replace").strip()
        raise H0RunnerError(f"bubblewrap H0 collection failed: {detail or result.returncode}")
    bwrap_status, bwrap_status_body = _parse_bwrap_status(result.streams["bwrap_status"])
    candidate_stat = os.fstat(candidate_fd)
    work_stat = os.fstat(work_fd)
    runtime_stat = os.fstat(runtime_fd)
    isolation_report = _validate_isolation_report(
        result.streams["isolation_report"],
        profile=profile,
        host_namespaces=host_namespaces,
        candidate_stat=candidate_stat,
        work_stat=work_stat,
        runtime_stat=runtime_stat,
        bwrap_status=bwrap_status,
        expected_report_fd=isolation_write,
    )
    isolation_record = {
        "bwrap_status_digest": _raw_digest(bwrap_status_body),
        "candidate_mount": {
            "device": candidate_stat.st_dev,
            "inode": candidate_stat.st_ino,
            "mode": "read-only-bind-fd",
        },
        "host_namespaces": list(host_namespaces),
        "host_runtime_exec_closure_trusted": False,
        "inner_report": isolation_report,
        "profile_digest": _raw_digest(_canonical_line(profile)),
        "schema_version": H0_ISOLATION_RECORD_SCHEMA,
        "work_mount": {
            "device": work_stat.st_dev,
            "inode": work_stat.st_ino,
            "mode": "read-write-bind-fd",
        },
    }
    return {
        "bwrap_status": bwrap_status_body,
        "isolation": _canonical_line(isolation_record),
        "stderr": result.streams["stderr"],
        "stdout": result.streams["stdout"],
    }


def _read_taxonomy_artifact(work: Path) -> tuple[dict, bytes]:
    target = work / "taxonomy.json"
    descriptor = -1
    primary: BaseException | None = None
    body: bytes | None = None
    try:
        before_path = os.lstat(target)
        descriptor = os.open(
            target,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        before = os.fstat(descriptor)
        if (
            _stat_signature(before_path) != _stat_signature(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > evidence.MAX_TAXONOMY_RECORD_BYTES
        ):
            raise H0RunnerError("taxonomy artifact is not one parent-owned private regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, evidence.MAX_TAXONOMY_RECORD_BYTES - total + 1),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > evidence.MAX_TAXONOMY_RECORD_BYTES:
                raise H0RunnerError("taxonomy artifact exceeds its byte limit")
        after = os.fstat(descriptor)
        if _stat_signature(before) != _stat_signature(after) or total != after.st_size:
            raise H0RunnerError("taxonomy artifact changed while being read")
        body = b"".join(chunks)
    except BaseException as exc:
        primary = exc
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except BaseException as close_fault:
            if primary is None or (
                type(primary) not in {KeyboardInterrupt, SystemExit}
                and type(close_fault) in {KeyboardInterrupt, SystemExit}
            ):
                primary = close_fault
    if primary is not None:
        if isinstance(primary, OSError):
            raise H0RunnerError(f"cannot read taxonomy artifact exactly: {primary}") from primary
        raise primary
    if body is None:
        raise H0RunnerError("taxonomy artifact read reached an impossible state")
    try:
        document = evidence.read_pytest_taxonomy(body)
    except evidence.EvidenceError as exc:
        raise H0RunnerError(f"taxonomy artifact is invalid: {exc}") from exc
    selection = document["selection"]
    lane_counts = {record["lane"]: record["selected"] for record in selection["selected_by_lane"]}
    if (
        selection["mark_expression"] != "offline"
        or selection["keyword_expression"] != ""
        or selection["selected"] <= 0
        or lane_counts[H0_LANE] != selection["selected"]
        or any(count for lane, count in lane_counts.items() if lane != H0_LANE)
    ):
        raise H0RunnerError("taxonomy artifact is not the exact positive H0 collection selection")
    return document, body


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_nonauthoritative_summary(
    record: object,
    *,
    artifact_bodies: Mapping[str, bytes],
) -> dict:
    required = {
        "a_taxonomy",
        "artifact_digests",
        "authority",
        "candidate",
        "candidate_identity_artifact_digest",
        "finished_at",
        "promotion_eligible",
        "purpose",
        "runner_inputs",
        "schema_version",
        "started_at",
    }
    if type(record) is not dict or set(record) != required:
        raise H0RunnerError("non-release summary has a non-exact top-level shape")
    if set(artifact_bodies) != set(_ARTIFACT_MEDIA_TYPES):
        raise H0RunnerError("non-release summary artifact inventory is incomplete")
    identity = _read_canonical_line(
        artifact_bodies["candidate-identity"],
        "summary candidate identity artifact",
    )
    try:
        evidence.validate_candidate_identity(identity)
        evidence._timestamp(record["started_at"], "non-release summary.started_at")
        evidence._timestamp(record["finished_at"], "non-release summary.finished_at")
    except evidence.EvidenceError as exc:
        raise H0RunnerError(f"non-release summary binding is invalid: {exc}") from exc
    expected_artifacts = [
        {"digest": _raw_digest(body), "name": name}
        for name, body in sorted(artifact_bodies.items())
    ]
    identity_inputs = {item["name"]: item for item in identity["inputs"]}
    expected_inputs = []
    for name, path in sorted(evidence.FUTURE_RUNNER_INPUTS.items()):
        item = identity_inputs.get(name)
        if item is None or item["path"] != path:
            raise H0RunnerError(f"non-release summary omits future runner input {name!r}")
        expected_inputs.append({"digest": item["digest"], "name": name})
    if (
        record["schema_version"] != H0_NON_RELEASE_SUMMARY_SCHEMA
        or record["authority"] != "none"
        or record["purpose"] != "development-diagnostic-only"
        or record["promotion_eligible"] is not False
        or record["a_taxonomy"] != {
            "id": H0_DIAGNOSTIC_ID,
            "reason": H0_REASON,
            "status": "open",
        }
        or record["candidate"] != evidence.candidate_summary(identity)
        or record["candidate_identity_artifact_digest"]
        != _raw_digest(artifact_bodies["candidate-identity"])
        or record["artifact_digests"] != expected_artifacts
        or record["runner_inputs"] != expected_inputs
    ):
        raise H0RunnerError("non-release summary differs from its exact authority-none binding")
    if len(_canonical_line(record)) > evidence.MAX_RECORD_BYTES:
        raise H0RunnerError("development H0 summary exceeds its exact byte contract")
    return record


def build_nonauthoritative_summary(
    *,
    identity: dict,
    profile: dict,
    taxonomy: dict,
    artifact_bodies: Mapping[str, bytes],
    runtime: dict,
    started_at: str,
    finished_at: str,
) -> dict:
    """Build a diagnostic-only summary that cannot be read as release evidence."""
    if profile != _EXPECTED_PROFILE:
        raise H0RunnerError("cannot summarize a non-canonical development profile")
    if identity.get("package_version") != H0_PACKAGE_VERSION:
        raise H0RunnerError("development H0 summary refuses a package other than 0.3.9")
    if set(artifact_bodies) != set(_ARTIFACT_MEDIA_TYPES):
        raise H0RunnerError("development H0 summary artifact inventory is incomplete")
    if artifact_bodies["candidate-identity"] != _canonical_line(identity):
        raise H0RunnerError("summary candidate identity artifact differs from validated identity")
    if artifact_bodies["development-profile"] != _canonical_line(profile):
        raise H0RunnerError("summary development profile artifact differs from exact profile")
    if artifact_bodies["pytest-taxonomy"] != evidence.canonical_json_bytes(taxonomy):
        raise H0RunnerError("summary taxonomy artifact differs from validated taxonomy")
    if artifact_bodies["runtime"] != _canonical_line(runtime):
        raise H0RunnerError("summary runtime artifact differs from validated runtime")
    collector = taxonomy["collector"]
    components = {item["name"]: item for item in runtime["probe"]["components"]}
    if (
        collector["python_implementation"] != runtime["probe"]["implementation"]
        or collector["python_version"] != runtime["probe"]["python_version"]
        or collector["version"] != components["pytest"]["version"]
    ):
        raise H0RunnerError("taxonomy collector provenance disagrees with the runtime descriptor")
    runner_inputs = []
    identity_inputs = {record["name"]: record for record in identity["inputs"]}
    for name in sorted(evidence.FUTURE_RUNNER_INPUTS):
        record = identity_inputs.get(name)
        if record is None or record["path"] != evidence.FUTURE_RUNNER_INPUTS[name]:
            raise H0RunnerError(f"summary input omits future runner contract {name!r}")
        runner_inputs.append({"digest": record["digest"], "name": name})

    artifact_digests = [
        {
            "digest": _raw_digest(body),
            "name": name,
        }
        for name, body in sorted(artifact_bodies.items())
    ]
    record = {
        "a_taxonomy": {
            "id": H0_DIAGNOSTIC_ID,
            "reason": H0_REASON,
            "status": "open",
        },
        "artifact_digests": artifact_digests,
        "authority": "none",
        "candidate": evidence.candidate_summary(identity),
        "candidate_identity_artifact_digest": _raw_digest(
            artifact_bodies["candidate-identity"]
        ),
        "finished_at": finished_at,
        "promotion_eligible": False,
        "purpose": "development-diagnostic-only",
        "runner_inputs": runner_inputs,
        "schema_version": H0_NON_RELEASE_SUMMARY_SCHEMA,
        "started_at": started_at,
    }
    return _validate_nonauthoritative_summary(record, artifact_bodies=artifact_bodies)


_OUTPUT_FILENAMES = {
    "bwrap-status": "bwrap-status.json",
    "candidate-identity": "candidate-identity.json",
    "development-profile": "development-profile.json",
    "development-profile-schema": "development-profile.schema.json",
    "isolation": "isolation.json",
    "pytest-stderr": "pytest-stderr.log",
    "pytest-stdout": "pytest-stdout.log",
    "pytest-taxonomy": "pytest-taxonomy.json",
    "pytest-taxonomy-schema": "pytest-taxonomy.schema.json",
    "runtime": "runtime.json",
    "toolchain": "toolchain.json",
    "verification-job-map": "verification-job-map.json",
    "verification-job-map-schema": "verification-job-map.schema.json",
    "verification-workflow": "verification-workflow.yml",
}
_SUMMARY_FILENAME = "NOT-RELEASE-EVIDENCE.json"


def _output_target(
    value: str | os.PathLike[str],
    *,
    source_root: str,
) -> tuple[Path, str, Path]:
    text = _normalized_absolute(value, "output directory")
    target = Path(text)
    if target.name in {"", ".", ".."}:
        raise H0RunnerError("output directory must have one exact basename")
    try:
        parent = target.parent.resolve(strict=True)
    except OSError as exc:
        raise H0RunnerError(f"cannot resolve output parent directory: {exc}") from exc
    if os.fspath(parent) != os.fspath(target.parent) or not parent.is_dir():
        raise H0RunnerError("output parent must be a symlink-free absolute directory")
    normalized_target = parent / target.name
    if normalized_target.exists() or normalized_target.is_symlink():
        raise H0RunnerError("output directory already exists; overwrite is forbidden")
    source = Path(source_root)
    if normalized_target == source or normalized_target.is_relative_to(source):
        raise H0RunnerError("release diagnostic output must remain outside the source checkout")
    return parent, target.name, normalized_target


def _write_new_private_at(directory_fd: int, name: str, body: bytes) -> None:
    if type(name) is not str or not name or "/" in name or name in {".", ".."}:
        raise H0RunnerError("output artifact name must be one basename")
    if type(body) is not bytes or len(body) > evidence.MAX_TAXONOMY_RECORD_BYTES:
        raise H0RunnerError(f"output artifact {name!r} exceeds its byte contract")
    descriptor = -1
    primary: BaseException | None = None
    created = False
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, body)
        os.fsync(descriptor)
    except BaseException as exc:
        primary = exc
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except BaseException as close_fault:
            if primary is None or (
                type(primary) not in {KeyboardInterrupt, SystemExit}
                and type(close_fault) in {KeyboardInterrupt, SystemExit}
            ):
                primary = close_fault
    if primary is not None:
        cleanup_fault: BaseException | None = None
        if created:
            try:
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except BaseException as exc:
                cleanup_fault = exc
        if type(primary) in {KeyboardInterrupt, SystemExit}:
            raise primary
        if type(cleanup_fault) in {KeyboardInterrupt, SystemExit}:
            raise cleanup_fault
        if cleanup_fault is not None:
            raise PublicationSettlementError(
                f"cannot settle failed artifact {name!r}: {primary}; cleanup failed: {cleanup_fault}"
            ) from cleanup_fault
        if isinstance(primary, OSError):
            raise H0RunnerError(f"cannot publish artifact {name!r}: {primary}") from primary
        raise primary

    # Reopen through the owned directory and verify exact bytes/mode before the
    # artifact may contribute a digest to the final diagnostic summary.
    verify = -1
    verify_primary: BaseException | None = None
    try:
        verify = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
        value = os.fstat(verify)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_size != len(body)
        ):
            raise H0RunnerError(f"published artifact {name!r} has invalid private-file metadata")
        chunks = []
        while True:
            chunk = os.read(verify, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        if b"".join(chunks) != body:
            raise H0RunnerError(f"published artifact {name!r} differs from validated bytes")
    except BaseException as exc:
        verify_primary = exc
    if verify >= 0:
        try:
            os.close(verify)
        except BaseException as close_fault:
            if verify_primary is None or (
                type(verify_primary) not in {KeyboardInterrupt, SystemExit}
                and type(close_fault) in {KeyboardInterrupt, SystemExit}
            ):
                verify_primary = close_fault
    if verify_primary is not None:
        cleanup_fault: BaseException | None = None
        try:
            os.unlink(name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except BaseException as exc:
            cleanup_fault = exc
        if type(verify_primary) in {KeyboardInterrupt, SystemExit}:
            raise verify_primary
        if type(cleanup_fault) in {KeyboardInterrupt, SystemExit}:
            raise cleanup_fault
        if cleanup_fault is not None:
            raise PublicationSettlementError(
                f"cannot settle verification failure for {name!r}: "
                f"{verify_primary}; cleanup failed: {cleanup_fault}"
            ) from cleanup_fault
        if isinstance(verify_primary, OSError):
            raise H0RunnerError(
                f"cannot verify published artifact {name!r}: {verify_primary}"
            ) from verify_primary
        raise verify_primary


def _publish_output_bundle(
    parent: Path,
    basename: str,
    artifacts: Mapping[str, bytes],
    summary_body: bytes,
    settle_deadline: Callable[[], None],
) -> Path:
    if set(artifacts) != set(_OUTPUT_FILENAMES):
        raise H0RunnerError("output artifact bundle is incomplete")
    summary = _read_canonical_line(summary_body, "non-release diagnostic summary")
    _validate_nonauthoritative_summary(summary, artifact_bodies=artifacts)
    parent_fd = -1
    directory_fd = -1
    primary: BaseException | None = None
    output = parent / basename
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        os.mkdir(basename, 0o700, dir_fd=parent_fd)
        directory_fd = os.open(
            basename,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
        directory_stat = os.fstat(directory_fd)
        if (
            directory_stat.st_uid != os.geteuid()
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
        ):
            raise H0RunnerError("new output directory is not private and caller-owned")
        for name in sorted(artifacts):
            _write_new_private_at(directory_fd, _OUTPUT_FILENAMES[name], artifacts[name])
        os.fsync(directory_fd)
        # This unmistakably non-authoritative file is deliberately last.  A
        # fault may leave a partial diagnostic directory, but no byte written
        # here is a release-gate record or a promotion result.
        _write_new_private_at(directory_fd, _SUMMARY_FILENAME, summary_body)
        os.fsync(directory_fd)
        settle_deadline()
        os.close(directory_fd)
        directory_fd = -1
        os.close(parent_fd)
        parent_fd = -1
        return output
    except BaseException as exc:
        primary = exc
    close_fault: BaseException | None = None
    for descriptor in (directory_fd, parent_fd):
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except BaseException as exc:
            if close_fault is None:
                close_fault = exc
    if type(primary) in {KeyboardInterrupt, SystemExit}:
        raise primary
    if type(close_fault) in {KeyboardInterrupt, SystemExit}:
        raise close_fault
    if close_fault is not None:
        raise PublicationSettlementError(
            f"output publication failed ({primary}) and descriptor close failed: {close_fault}"
        ) from close_fault
    if isinstance(primary, FileExistsError):
        raise H0RunnerError("output directory already exists; overwrite is forbidden") from primary
    if isinstance(primary, OSError):
        raise H0RunnerError(f"cannot publish H0 diagnostic output: {primary}") from primary
    raise primary


def _artifact_bodies(
    *,
    identity: dict,
    contracts: Mapping[str, object],
    execution: Mapping[str, object],
    taxonomy_body: bytes,
    runtime: dict,
    toolchain: dict,
) -> dict[str, bytes]:
    tracked = contracts["bodies"]
    assert isinstance(tracked, dict)
    for name in ("stderr", "stdout"):
        value = execution[name]
        if type(value) is not bytes:
            raise H0RunnerError(f"pytest {name} log is not exact bytes")
        try:
            value.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise H0RunnerError(f"pytest {name} log is not strict UTF-8") from exc
    job_map = contracts["job_map"]
    assert isinstance(job_map, dict)
    workflows = job_map["workflows"]
    if [record["path"] for record in workflows] != [".github/workflows/ci.yml"]:
        raise H0RunnerError("development H0 artifact bundle requires the exact single CI workflow")
    artifacts = {
        "bwrap-status": execution["bwrap_status"],
        "candidate-identity": _canonical_line(identity),
        "development-profile": tracked[evidence.H0_DEVELOPMENT_PROFILE_PATH],
        "development-profile-schema": tracked[evidence.H0_DEVELOPMENT_PROFILE_SCHEMA_PATH],
        "isolation": execution["isolation"],
        "pytest-stderr": execution["stderr"],
        "pytest-stdout": execution["stdout"],
        "pytest-taxonomy": taxonomy_body,
        "pytest-taxonomy-schema": tracked[evidence.PYTEST_TAXONOMY_SCHEMA_PATH],
        "runtime": _canonical_line(runtime),
        "toolchain": _canonical_line(toolchain),
        "verification-job-map": tracked[evidence.VERIFICATION_JOB_MAP_PATH],
        "verification-job-map-schema": tracked[evidence.VERIFICATION_JOB_MAP_SCHEMA_PATH],
        "verification-workflow": tracked[".github/workflows/ci.yml"],
    }
    if any(type(body) is not bytes for body in artifacts.values()):
        raise H0RunnerError("development H0 artifact bundle contains non-byte content")
    if set(artifacts) != set(_ARTIFACT_MEDIA_TYPES):
        raise H0RunnerError("development H0 artifact bundle has an invalid inventory")
    return artifacts


def _cleanup_private_run(
    *,
    descriptors: Sequence[int],
    pins: Sequence[_ToolPin],
    scratch: Path | None,
    candidate: Path | None,
) -> None:
    primary: BaseException | None = None
    cancellation: BaseException | None = None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException as exc:
            if primary is None:
                primary = exc
            if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
                cancellation = exc
    try:
        _close_tool_pins(pins)
    except BaseException as exc:
        if primary is None:
            primary = exc
        if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
            cancellation = exc
    if candidate is not None:
        try:
            os.chmod(candidate, 0o700, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except BaseException as exc:
            if primary is None:
                primary = exc
            if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
                cancellation = exc
    if scratch is not None:
        try:
            shutil.rmtree(scratch)
        except BaseException as exc:
            if primary is None:
                primary = exc
            if type(exc) in {KeyboardInterrupt, SystemExit} and cancellation is None:
                cancellation = exc
    if cancellation is not None:
        raise cancellation
    if primary is not None:
        if isinstance(primary, OSError):
            raise H0RunnerError(f"cannot settle private H0 workspace: {primary}") from primary
        raise primary


def _private_scratch_directory(source_root: str, output: Path) -> Path:
    scratch_parent = Path("/tmp")
    value = os.lstat(scratch_parent)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or stat.S_IMODE(value.st_mode) != 0o1777
        or scratch_parent.resolve(strict=True) != scratch_parent
    ):
        raise H0RunnerError("private scratch requires literal root-owned sticky mode-1777 /tmp")
    source = Path(source_root)

    def overlaps(left: Path, right: Path) -> bool:
        return (
            left == right
            or left.is_relative_to(right)
            or right.is_relative_to(left)
        )

    if overlaps(source, output):
        raise H0RunnerError("scratch, source, and output authorities are not pairwise disjoint")
    if scratch_parent == source or scratch_parent.is_relative_to(source):
        raise H0RunnerError("source authority contains the fixed scratch parent")
    if scratch_parent == output or scratch_parent.is_relative_to(output):
        raise H0RunnerError("output authority contains the fixed scratch parent")

    scratch: Path | None = None
    try:
        scratch = Path(tempfile.mkdtemp(prefix="quarry-h0-development-", dir="/tmp"))
        resolved = scratch.resolve(strict=True)
        if resolved != scratch:
            raise H0RunnerError("private scratch path is not symlink-free")
        if overlaps(scratch, source) or overlaps(scratch, output):
            raise H0RunnerError("scratch, source, and output authorities are not pairwise disjoint")
        value = os.lstat(scratch)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o700
        ):
            raise H0RunnerError("private H0 scratch directory is not caller-owned mode 0700")
        return scratch
    except BaseException as primary:
        cleanup_fault: BaseException | None = None
        if scratch is not None:
            try:
                shutil.rmtree(scratch)
            except BaseException as exc:
                cleanup_fault = exc
        if cleanup_fault is not None:
            raise H0RunnerError(
                f"private scratch validation failed ({primary}); cleanup failed: {cleanup_fault}"
            ) from cleanup_fault
        raise


def run_development_h0(
    repository: str | os.PathLike[str],
    output_directory: str | os.PathLike[str],
    *,
    git_executable: str | os.PathLike[str],
    bwrap_executable: str | os.PathLike[str],
    python_executable: str | os.PathLike[str],
) -> Path:
    """Collect and publish one candidate-bound OPEN H0 diagnostic bundle."""
    started_at = _utc_timestamp()
    pins: list[_ToolPin] = []
    descriptors: list[int] = []
    scratch: Path | None = None
    candidate: Path | None = None
    source_root = ""
    output_parent: Path | None = None
    output_basename = ""
    artifacts: dict[str, bytes] | None = None
    summary_body: bytes | None = None
    primary: BaseException | None = None
    cleanup_fault: BaseException | None = None

    try:
        with _wall_deadline(H0_PROFILE_DEADLINE_SECONDS) as deadline_control:
            deadline = deadline_control.deadline
            try:
                git = _open_tool(git_executable, "git")
                pins.append(git)
                bwrap = _open_tool(bwrap_executable, "bwrap")
                pins.append(bwrap)
                python = _open_tool(python_executable, "python")
                pins.append(python)
                _probe_tool_versions(pins, deadline=deadline)

                source_root = _resolve_source_repository(repository, git, deadline=deadline)
                output_parent, output_basename, output_target = _output_target(
                    output_directory,
                    source_root=source_root,
                )
                commit, tree = _capture_source_identity(source_root, git, deadline=deadline)

                scratch = _private_scratch_directory(source_root, output_target)
                private_repository = scratch / "private-repository"
                entries = _private_clone(
                    source_root,
                    private_repository,
                    commit,
                    tree,
                    git,
                    deadline=deadline,
                )
                identity = _collect_private_identity(
                    private_repository,
                    python,
                    git,
                    deadline=deadline,
                )
                if identity["git_commit"] != commit or identity["git_tree"] != tree:
                    raise H0RunnerError("private candidate identity changed captured commit/tree")

                candidate = scratch / "candidate"
                _export_candidate(
                    private_repository,
                    candidate,
                    entries,
                    git,
                    deadline=deadline,
                )
                contracts = _candidate_contracts(candidate, identity)
                profile = contracts["profile"]
                assert isinstance(profile, dict)
                runtime = _runtime_record(python, profile, deadline=deadline)

                work = scratch / "work"
                _prepare_work(work)
                candidate_fd = _open_mount_directory(candidate, "candidate")
                descriptors.append(candidate_fd)
                work_fd = _open_mount_directory(work, "work")
                descriptors.append(work_fd)
                runtime_fd, runtime_signature = _open_runtime_mount(profile)
                descriptors.append(runtime_fd)
                host_namespaces = _host_namespaces()
                execution = _execute_bwrap(
                    profile,
                    bwrap=bwrap,
                    python=python,
                    candidate_fd=candidate_fd,
                    work_fd=work_fd,
                    runtime_fd=runtime_fd,
                    runtime_signature=runtime_signature,
                    host_namespaces=host_namespaces,
                    deadline=deadline,
                )
                taxonomy, taxonomy_body = _read_taxonomy_artifact(work)

                # Re-read every candidate-bound contract and loaded outer source
                # after collection; another host writer cannot silently change
                # the producer bytes during the diagnostic.
                final_contracts = _candidate_contracts(candidate, identity)
                if final_contracts["bodies"] != contracts["bodies"]:
                    raise H0RunnerError("candidate runner contracts changed during collection")
                toolchain = _toolchain_record(pins, runtime)
                finished_at = _utc_timestamp()
                artifacts = _artifact_bodies(
                    identity=identity,
                    contracts=contracts,
                    execution=execution,
                    taxonomy_body=taxonomy_body,
                    runtime=runtime,
                    toolchain=toolchain,
                )
                summary = build_nonauthoritative_summary(
                    identity=identity,
                    profile=profile,
                    taxonomy=taxonomy,
                    artifact_bodies=artifacts,
                    runtime=runtime,
                    started_at=started_at,
                    finished_at=finished_at,
                )
                summary_body = _canonical_line(summary)
            except BaseException as exc:
                primary = exc
            try:
                _cleanup_private_run(
                    descriptors=descriptors,
                    pins=pins,
                    scratch=scratch,
                    candidate=candidate,
                )
            except BaseException as exc:
                cleanup_fault = exc
            if primary is not None:
                if type(primary) in {KeyboardInterrupt, SystemExit}:
                    raise primary
                if type(cleanup_fault) in {KeyboardInterrupt, SystemExit}:
                    raise cleanup_fault
                if cleanup_fault is not None:
                    raise H0RunnerError(
                        f"H0 diagnostic failed ({primary}); private cleanup also failed: {cleanup_fault}"
                    ) from cleanup_fault
                raise primary
            if cleanup_fault is not None:
                raise cleanup_fault
            if artifacts is None or summary_body is None or output_parent is None:
                raise H0RunnerError(
                    "H0 diagnostic reached publication without a complete validated bundle"
                )
            output_parent, output_basename, _output = _output_target(
                output_directory,
                source_root=source_root,
            )
            return _publish_output_bundle(
                output_parent,
                output_basename,
                artifacts,
                summary_body,
                deadline_control.settle,
            )
    except BaseException:  # noqa: TRY203 - preserve cancellations and typed faults exactly
        raise

    raise H0RunnerError("H0 diagnostic exited without publishing its validated OPEN bundle")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m quarry_recon.release_h0",
        allow_abbrev=False,
        description="emit an OPEN-only candidate-bound Linux H0 collection diagnostic",
    )
    parser.add_argument("--repository", required=True, help="exact Git worktree root")
    parser.add_argument("--output-directory", required=True, help="new external evidence directory")
    parser.add_argument("--git", required=True, help="absolute pinned Git executable")
    parser.add_argument("--bwrap", required=True, help="absolute pinned bubblewrap executable")
    parser.add_argument("--python", required=True, help="absolute pinned CPython executable")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    options = parser.parse_args(argv)
    try:
        output = run_development_h0(
            options.repository,
            options.output_directory,
            git_executable=options.git,
            bwrap_executable=options.bwrap,
            python_executable=options.python,
        )
    except H0RunnerError as exc:
        parser.exit(2, f"release-h0: {exc}\n")
    sys.stdout.write(os.fspath(output) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
