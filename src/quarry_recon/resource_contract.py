"""Finite v0.3.x resource support and semantic release-gate evidence.

This module deliberately does not pretend to remove the v0.3 store's whole-corpus
materialisation.  It publishes the finite envelope, provides cross-process
filesystem/destination ownership for acquisition writers, samples aggregate
process-tree resources on Linux, and validates the obligation-specific V310-06
gate report.  The v0.4 indexed repository remains a separate design.
"""
from __future__ import annotations

import copy
import contextlib
import hashlib
import math
import os
import re
import secrets
import stat
import tempfile
import threading
import time
import weakref
from dataclasses import dataclass
from pathlib import Path


SCHEMA_VERSION = "quarry.resource-gate-report.v1"
SUPPORT_SCHEMA_VERSION = "quarry.resource-support-envelope.v1"
MAX_ACQUISITION_LEASE_WAIT_SECONDS = 5.0
MAX_RESOLVER_CORPUS_DEADLINE_SECONDS = 30.0
MAX_RESOLVER_HOSTS = 100_000
MAX_RESOLVER_HOST_BYTES = 253
MAX_RESOLVER_RESULT_BYTES = 64 * 1024
MAX_RESOLVER_REMAINDER_BYTES = (
    (MAX_RESOLVER_HOSTS + 1) * (MAX_RESOLVER_HOST_BYTES + 128) + 1024
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z",
)
_GATE_CASES = {
    "C-FAULT-DISK": frozenset({
        "concurrent-processes", "exhausted-reserve", "same-destination",
        "partial-write", "spill-failure",
    }),
    "C-FAULT-RESOLVER": frozenset({
        "hung-resolver", "late-response", "worker-crash", "huge-corpus",
        "cancellation",
    }),
    "C-PERF-INGEST": frozenset({
        "small-ingest", "medium-ingest", "large-ingest", "reopen", "merge",
        "export",
    }),
    "C-PERF-DISK": frozenset({"concurrent-governors"}),
    "C-PERF-RESOLVER": frozenset({"mixed-fast-hung-corpus"}),
    "C-PERF-PHASE-FAIRNESS": frozenset({"finite-run-budget"}),
}
_GATE_ASSERTIONS = {
    "C-FAULT-DISK": {
        "concurrent-processes": {
            "aggregate_limit_not_exceeded", "all_reservations_settled",
            "cross_process_reservation_shared",
        },
        "exhausted-reserve": {
            "contact_refused_or_stream_truncated", "remainder_truthful",
            "reserve_preserved",
        },
        "same-destination": {
            "no_stage_collision", "one_destination_owner",
            "published_bytes_from_one_writer",
        },
        "partial-write": {
            "destination_not_false_complete", "landed_bytes_charged",
            "partial_durable_or_terminal",
        },
        "spill-failure": {
            "failure_replayable_or_terminal", "reserve_preserved",
            "same_filesystem_not_called_spill",
        },
    },
    "C-FAULT-RESOLVER": {
        "hung-resolver": {
            "corpus_deadline_enforced", "unresolved_durable_or_terminal",
            "workers_reaped",
        },
        "late-response": {
            "late_result_discarded", "sealed_state_unchanged", "worker_reaped",
        },
        "worker-crash": {
            "crash_reported", "unresolved_durable_or_terminal", "worker_reaped",
        },
        "huge-corpus": {
            "contact_attempts_zero", "refusal_durable_or_terminal",
            "support_bound_enforced",
        },
        "cancellation": {
            "all_workers_reaped", "original_cancellation_preserved",
            "unresolved_durable_or_terminal",
        },
    },
    "C-PERF-INGEST": {
        case: {
            "aggregate_resources_complete", "fixture_digest_bound",
            "operation_completed", "refusal_count_reconciled",
        }
        for case in ("small-ingest", "medium-ingest", "large-ingest", "reopen",
                     "merge", "export")
    },
    "C-PERF-DISK": {
        "concurrent-governors": {
            "aggregate_reserve_preserved", "destinations_uncorrupted",
            "fairness_measured", "reservations_settled",
        },
    },
    "C-PERF-RESOLVER": {
        "mixed-fast-hung-corpus": {
            "bounded_outstanding_queue", "bounded_worker_processes",
            "durable_remainder_reconciled", "late_results_discarded",
            "single_corpus_deadline",
        },
    },
    "C-PERF-PHASE-FAIRNESS": {
        "finite-run-budget": {
            "every_obligation_disposed", "finite_budget_observed",
            "independent_lanes_started_or_terminal", "silent_starvation_zero",
        },
    },
}
_GATE_METRICS = {
    "C-FAULT-DISK": {
        "reserve_overshoot": ("at_most", "maximum", "bytes"),
        "destination_corruptions": ("at_most", "maximum", "count"),
        "lost_reservations": ("at_most", "maximum", "count"),
        "untruthful_remainders": ("at_most", "maximum", "count"),
        "lease_leaks": ("at_most", "maximum", "count"),
    },
    "C-FAULT-RESOLVER": {
        "worker_leaks": ("at_most", "maximum", "count"),
        "late_mutations": ("at_most", "maximum", "count"),
        "lost_remainders": ("at_most", "maximum", "count"),
        "deadline_overshoot": ("at_most", "maximum", "milliseconds"),
        "unbounded_queue_observations": ("at_most", "maximum", "count"),
    },
    "C-PERF-INGEST": {
        "peak_aggregate_rss": ("at_most", "p95", "bytes"),
        "wall_time": ("at_most", "p95", "milliseconds"),
        "write_amplification": ("at_most", "maximum", "basis_points"),
        "disk_growth": ("at_most", "maximum", "bytes"),
        "refused_remainders": ("at_most", "maximum", "count"),
        "wall_time_delta": ("at_most", "median", "basis_points"),
    },
    "C-PERF-DISK": {
        "reserve_overshoot": ("at_most", "maximum", "bytes"),
        "fairness": ("at_least", "minimum", "basis_points"),
        "destination_corruptions": ("at_most", "maximum", "count"),
        "lost_reservations": ("at_most", "maximum", "count"),
        "throughput_delta": ("at_most", "median", "basis_points"),
    },
    "C-PERF-RESOLVER": {
        "corpus_deadline": ("at_most", "maximum", "milliseconds"),
        "worker_processes": ("at_most", "maximum", "count"),
        "outstanding_queue": ("at_most", "maximum", "count"),
        "lost_remainders": ("at_most", "maximum", "count"),
        "late_mutations": ("at_most", "maximum", "count"),
        "deadline_delta": ("at_most", "median", "basis_points"),
    },
    "C-PERF-PHASE-FAIRNESS": {
        "terminal_obligations": ("at_least", "minimum", "count"),
        "silent_starvation": ("at_most", "maximum", "count"),
        "unstarted_obligations": ("at_most", "maximum", "count"),
        "completion_time_delta": ("at_most", "median", "basis_points"),
    },
}
_ZERO_INVARIANTS = {
    "reserve_overshoot", "destination_corruptions", "lost_reservations",
    "untruthful_remainders", "lease_leaks", "worker_leaks", "late_mutations",
    "lost_remainders", "unbounded_queue_observations",
    "silent_starvation", "unstarted_obligations", "refused_remainders",
}
_TRIAL_KEYS = {
    "case", "outcome", "resource", "metric_facts", "assertions",
    "artifact_digests",
}
_RESOURCE_KEYS = {
    "peak_aggregate_rss_bytes", "peak_disk_bytes", "peak_fd_count",
    "peak_process_count", "complete",
}
_MEASUREMENT_KEYS = {
    "metric", "operator", "statistic", "unit", "value", "limit", "passed",
    "baseline_digest",
}
_THRESHOLD_KEYS = {
    "operator", "statistic", "unit", "limit", "baseline_digest",
}
_REPORT_KEYS = {
    "schema_version", "candidate_identity_digest", "gate_id", "evidence_instance_id",
    "started_at", "finished_at", "support_envelope", "support_envelope_digest",
    "trials", "measurements", "threshold_manifest_digest",
    "benchmark_manifest_digest", "verdict",
}

_PROCESS_LEASE_CONDITION = threading.Condition()
_PROCESS_FILESYSTEM_LEASES: dict[str, dict] = {}
_PROCESS_RESERVATION_GROUPS: dict[str, dict] = {}
_PROCESS_DESTINATION_LEASE_FDS: set[int] = set()
_DESTINATION_THREAD_LOCKS = weakref.WeakValueDictionary()


def _reset_process_leases_after_fork() -> None:
    """A child must acquire its own locks, not trust the parent's copied map/fds."""
    global _PROCESS_LEASE_CONDITION, _PROCESS_FILESYSTEM_LEASES
    global _PROCESS_RESERVATION_GROUPS, _PROCESS_DESTINATION_LEASE_FDS
    global _DESTINATION_THREAD_LOCKS
    for state in _PROCESS_FILESYSTEM_LEASES.values():
        fd = state.get("fd", -1) if isinstance(state, dict) else -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    for fd in _PROCESS_DESTINATION_LEASE_FDS:
        try:
            os.close(fd)
        except OSError:
            pass
    _PROCESS_LEASE_CONDITION = threading.Condition()
    _PROCESS_FILESYSTEM_LEASES = {}
    _PROCESS_RESERVATION_GROUPS = {}
    _PROCESS_DESTINATION_LEASE_FDS = set()
    _DESTINATION_THREAD_LOCKS = weakref.WeakValueDictionary()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_process_leases_after_fork)


class ResourceContractError(ValueError):
    """A resource policy/evidence object cannot be trusted."""


class ResourceLeaseUnavailable(RuntimeError):
    """A cross-process reservation could not be obtained within its finite wait."""


class ResourcePublicationUncertain(RuntimeError):
    """Publication bytes landed, but their authoritative durability was not settled."""

    def __init__(self, message: str, *, payload_digest: str, errors=()):
        super().__init__(message)
        self.resource_publication_landed = True
        self.resource_publication_durable = False
        self.resource_publication_committed = False
        self.resource_payload_digest = payload_digest
        self.resource_durability_errors = tuple(errors)


def canonical_bytes(document: object) -> bytes:
    """The canonical JSON bytes used for support/report digests."""
    from . import release_evidence

    return release_evidence.canonical_json_bytes(document) + b"\n"


def digest_document(document: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()


def support_envelope() -> dict:
    """Exact finite support Quarry v0.3.10 enforces for this work package.

    Refused store records retain identity/count metadata, not their complete payload,
    so they are explicitly terminal evidence gaps.  They are never described as a
    replay queue.  Raising the bound can only help when the source can be replayed.
    """
    from . import envelope, netguard

    return {
        "schema_version": SUPPORT_SCHEMA_VERSION,
        "release_line": "0.3.x",
        "store": {
            **envelope.declaration(),
            "whole_corpus_materialized": True,
            "overflow_payload_retained": False,
            "overflow_disposition": "terminal-unschedulable-gap",
        },
        "acquisition": {
            "cross_process_run_reservations": True,
            "cross_process_project_reservations": True,
            "cross_process_filesystem_reserve": True,
            "cross_process_destination_lease": True,
            "cross_process_writers_per_filesystem": 1,
            "distinct_governor_groups_per_filesystem": 1,
            "same_governor_threads_share_reservations": True,
            "managed_durable_project_limit": "refused-before-contact",
            "lease_wait_milliseconds": int(MAX_ACQUISITION_LEASE_WAIT_SECONDS * 1000),
        },
        "resolver": {
            "hosts_per_batch": MAX_RESOLVER_HOSTS,
            "host_utf8_bytes": MAX_RESOLVER_HOST_BYTES,
            "worker_result_bytes": MAX_RESOLVER_RESULT_BYTES,
            "remainder_record_bytes": MAX_RESOLVER_REMAINDER_BYTES,
            "corpus_deadline_milliseconds": int(
                MAX_RESOLVER_CORPUS_DEADLINE_SECONDS * 1000
            ),
            "worker_processes": netguard._MAX_WORKERS,
            "outstanding_queue": netguard._MAX_WORKERS,
            "terminate_grace_milliseconds": int(netguard._KILL_GRACE * 1000),
            "hard_kill_fallback_milliseconds": int(
                (netguard._KILL_GRACE + max(2.0, netguard._KILL_GRACE * 4)) * 1000
            ),
            "late_results_mutate_sealed_state": False,
        },
        "resource_metrics": [
            "peak_aggregate_rss_bytes", "peak_disk_bytes", "peak_fd_count",
            "peak_process_count",
        ],
        "deferred": [
            "disk-backed-indexed-repository", "unbounded-corpus-claims",
            "cross-lane-distributed-rate-governor",
        ],
    }


def _private_lock_root() -> tuple[int, Path]:
    """Open the uid-private persistent lock directory and prove its identity."""
    root = Path(tempfile.gettempdir()) / f"quarry-resource-locks-{os.geteuid()}"
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed = os.fstat(fd)
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o700):
        os.close(fd)
        raise ResourceLeaseUnavailable("resource lock root is not an owner-private directory")
    return fd, root


def _lock_name(prefix: str, identity: str) -> str:
    return f"{prefix}-{hashlib.sha256(identity.encode('utf-8')).hexdigest()}.lock"


def _open_lock(root_fd: int, name: str) -> int:
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
    observed = os.fstat(fd)
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o600 or observed.st_nlink != 1):
        os.close(fd)
        raise ResourceLeaseUnavailable(f"resource lock {name} is not an owner-private regular file")
    return fd


def _take_lock(fd: int, *, deadline: float) -> None:
    import errno
    import fcntl

    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise ResourceLeaseUnavailable(f"resource lock failed: {exc}") from exc
            if time.monotonic() >= deadline:
                raise ResourceLeaseUnavailable("resource lease wait expired") from exc
            time.sleep(0.01)


def _acquire_process_filesystem_lease(root_fd: int, name: str, *, deadline: float) -> None:
    """Take one OS lease per process while allowing its threads to share it.

    A kernel ``flock`` is shared by every thread using the same open file
    description. A separate short-lived local reservation group fence below
    serializes distinct governors only around free-space observation and the
    bounded write, leaving their network reads concurrent.
    """
    leader = False
    with _PROCESS_LEASE_CONDITION:
        while True:
            state = _PROCESS_FILESYSTEM_LEASES.get(name)
            if state is None:
                _PROCESS_FILESYSTEM_LEASES[name] = {
                    "status": "acquiring", "refs": 1, "fd": -1, "error": None,
                }
                leader = True
                break
            if state["status"] == "held":
                state["refs"] += 1
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResourceLeaseUnavailable("resource lease wait expired")
            _PROCESS_LEASE_CONDITION.wait(min(0.05, remaining))
    if not leader:  # pragma: no cover - the loop has only leader/return/raise exits
        raise AssertionError("filesystem lease has no acquisition owner")
    fd = -1
    fault = None
    try:
        fd = _open_lock(root_fd, name)
        _take_lock(fd, deadline=deadline)
    except BaseException as exc:
        fault = exc
    with _PROCESS_LEASE_CONDITION:
        state = _PROCESS_FILESYSTEM_LEASES.get(name)
        if fault is None:
            state.update(status="held", fd=fd)
        else:
            _PROCESS_FILESYSTEM_LEASES.pop(name, None)
        _PROCESS_LEASE_CONDITION.notify_all()
    if fault is not None:
        if fd >= 0:
            os.close(fd)
        raise fault


def _release_process_filesystem_lease(name: str) -> None:
    fd = -1
    with _PROCESS_LEASE_CONDITION:
        state = _PROCESS_FILESYSTEM_LEASES.get(name)
        if state is None or state["status"] != "held" or state["refs"] <= 0:
            raise RuntimeError("filesystem lease reference accounting is inconsistent")
        state["refs"] -= 1
        if state["refs"] == 0:
            fd = state["fd"]
            _PROCESS_FILESYSTEM_LEASES.pop(name, None)
        _PROCESS_LEASE_CONDITION.notify_all()
    if fd >= 0:
        os.close(fd)


def _acquire_local_reservation_group(name: str, local_group, *, deadline: float) -> None:
    """Admit one governor group to the filesystem observation/write section."""
    with _PROCESS_LEASE_CONDITION:
        while True:
            state = _PROCESS_RESERVATION_GROUPS.get(name)
            if state is None:
                _PROCESS_RESERVATION_GROUPS[name] = {
                    "local_group": local_group, "refs": 1,
                }
                return
            if state["local_group"] is local_group:
                state["refs"] += 1
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResourceLeaseUnavailable("local filesystem reservation wait expired")
            _PROCESS_LEASE_CONDITION.wait(min(0.05, remaining))


def _release_local_reservation_group(name: str, local_group) -> None:
    with _PROCESS_LEASE_CONDITION:
        state = _PROCESS_RESERVATION_GROUPS.get(name)
        if (state is None or state["local_group"] is not local_group
                or state["refs"] <= 0):
            raise RuntimeError("local filesystem reservation accounting is inconsistent")
        state["refs"] -= 1
        if state["refs"] == 0:
            _PROCESS_RESERVATION_GROUPS.pop(name, None)
        _PROCESS_LEASE_CONDITION.notify_all()


@contextlib.contextmanager
def reservation_fence(
    lease: "AcquisitionLease", local_group, *,
    timeout_s: float = MAX_ACQUISITION_LEASE_WAIT_SECONDS,
):
    """Serialize distinct governors only around reserve observation/spend."""
    if (isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s) or timeout_s < 0):
        raise ValueError("local reservation timeout must be finite and non-negative")
    held = False
    primary = None
    cleanup = None
    try:
        _acquire_local_reservation_group(
            lease.filesystem_name, local_group,
            deadline=time.monotonic() + float(timeout_s),
        )
        held = True
        yield
    except BaseException as exc:
        primary = exc
    if held:
        try:
            _release_local_reservation_group(lease.filesystem_name, local_group)
        except BaseException as exc:
            cleanup = exc
    if primary is not None:
        if cleanup is not None:
            try:
                primary.resource_cleanup_errors = (
                    *getattr(primary, "resource_cleanup_errors", ()), cleanup,
                )
            except BaseException:
                pass
        raise primary
    if cleanup is not None:
        raise cleanup


def _destination_thread_lock(identity: str) -> threading.Lock:
    with _PROCESS_LEASE_CONDITION:
        return _DESTINATION_THREAD_LOCKS.setdefault(identity, threading.Lock())


def _open_parent(path: Path, *, create: bool) -> tuple[int, str, Path]:
    """Descriptor-walk every ancestor without following a symlink.

    The returned parent stays pinned through the caller's final publication.
    ``display`` is lexical only; it is used to prove the name still reaches the
    pinned inode, never as mutation authority.
    """
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if len(parts) < 2 or parts[0] != os.sep or parts[-1] in {"", ".", ".."}:
        raise ResourceLeaseUnavailable("acquisition destination is not a normal absolute file name")
    try:
        parent_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ResourceLeaseUnavailable("cannot pin the acquisition filesystem root") from exc
    try:
        for component in parts[1:-1]:
            child = -1
            try:
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError as missing:
                if not create:
                    raise ResourceLeaseUnavailable(
                        f"acquisition ancestor {component!r} does not exist",
                    ) from missing
                try:
                    os.mkdir(component, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    # Another creator won the race.  The no-follow open below
                    # still proves that the winner made a directory, not a link.
                    pass
                except OSError as exc:
                    raise ResourceLeaseUnavailable(
                        f"acquisition ancestor {component!r} cannot be created safely",
                    ) from exc
                try:
                    child = os.open(
                        component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    raise ResourceLeaseUnavailable(
                        f"acquisition ancestor {component!r} is not a no-follow directory",
                    ) from exc
            except OSError as exc:
                raise ResourceLeaseUnavailable(
                    f"acquisition ancestor {component!r} is not a no-follow directory",
                ) from exc
            try:
                observed = os.fstat(child)
                if not stat.S_ISDIR(observed.st_mode):
                    raise ResourceLeaseUnavailable("acquisition ancestor is not a directory")
            except BaseException as primary:
                closing = child
                child = -1
                try:
                    os.close(closing)
                except BaseException as cleanup:
                    try:
                        primary.resource_cleanup_errors = (cleanup,)
                    except BaseException:
                        pass
                raise primary
            old_parent = parent_fd
            parent_fd = child
            child = -1
            os.close(old_parent)
        return parent_fd, parts[-1], absolute
    except BaseException as primary:
        if parent_fd >= 0:
            closing = parent_fd
            parent_fd = -1
            try:
                os.close(closing)
            except BaseException as cleanup:
                try:
                    prior = tuple(getattr(primary, "resource_cleanup_errors", ()))
                    primary.resource_cleanup_errors = prior + (cleanup,)
                except BaseException:
                    pass
        raise primary


@dataclass
class AcquisitionLease:
    """Pinned mutation authority yielded by ``acquisition_lease``."""

    parent_fd: int
    name: str
    display_path: Path
    parent_identity: tuple[int, int]
    filesystem_name: str

    @property
    def budget_path(self) -> str:
        return f"/proc/self/fd/{self.parent_fd}"

    def child_path(self, name: str) -> Path:
        return Path(self.budget_path) / name

    def assert_named_parent(self) -> None:
        """Refuse if the lexical destination now names another parent inode."""
        check = -1
        primary = None
        try:
            check, name, _absolute = _open_parent(self.display_path, create=False)
            observed = os.fstat(check)
            if name != self.name or (observed.st_dev, observed.st_ino) != self.parent_identity:
                raise ResourceLeaseUnavailable("acquisition destination parent changed")
        except (FileNotFoundError, NotADirectoryError, OSError) as exc:
            primary = ResourceLeaseUnavailable(
                "acquisition destination parent is no longer reachable",
            )
            primary.__cause__ = exc
        except BaseException as exc:
            primary = exc
        cleanup = None
        if check >= 0:
            closing = check
            check = -1
            try:
                os.close(closing)
            except BaseException as exc:
                cleanup = exc
        if primary is not None:
            if cleanup is not None:
                try:
                    primary.resource_cleanup_errors = (cleanup,)
                except BaseException:
                    pass
            raise primary
        if cleanup is not None:
            if not isinstance(cleanup, Exception):
                raise cleanup
            raise ResourceLeaseUnavailable(
                "acquisition destination parent descriptor cleanup failed",
            ) from cleanup


@contextlib.contextmanager
def acquisition_lease(
    destination, *, timeout_s: float = MAX_ACQUISITION_LEASE_WAIT_SECONDS,
                      filesystem_only: bool = False, local_group=None):
    """Hold one filesystem reservation and, normally, one exact destination lease.

    Locks are kernel-owned and therefore released on normal exit, cancellation, and
    process death.  Persistent zero-byte lock inodes are names, not live leases.
    All Quarry acquisition writers on a filesystem take the same first lock, so a
    free-space probe plus the subsequent bounded write is one cross-process action.
    """
    if (isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s) or timeout_s < 0):
        raise ValueError("resource lease timeout must be finite and non-negative")
    dest = Path(destination)
    parent_fd = -1
    root_fd = -1
    destination_fd = -1
    destination_lock = None
    destination_thread_held = False
    filesystem_name = ""
    filesystem_held = False
    primary = None
    cleanup_faults: list[BaseException] = []
    deadline = time.monotonic() + float(timeout_s)
    try:
        parent_fd, destination_name, display_path = _open_parent(dest, create=True)
        parent = os.fstat(parent_fd)
        fs_identity = f"uid={os.geteuid()}:dev={parent.st_dev}"
        dest_identity = (f"{fs_identity}:parent={parent.st_ino}:"
                         f"name={os.fsencode(destination_name).hex()}")
        filesystem_name = _lock_name("filesystem", fs_identity)
        lease = AcquisitionLease(
            parent_fd, destination_name, display_path, (parent.st_dev, parent.st_ino),
            filesystem_name,
        )
        root_fd, _root = _private_lock_root()
        _acquire_process_filesystem_lease(root_fd, filesystem_name, deadline=deadline)
        filesystem_held = True
        if not filesystem_only:
            destination_lock = _destination_thread_lock(dest_identity)
            remaining = max(0.0, deadline - time.monotonic())
            if not destination_lock.acquire(timeout=remaining):
                raise ResourceLeaseUnavailable("destination lease wait expired")
            destination_thread_held = True
            try:
                destination_fd = _open_lock(
                    root_fd, _lock_name("destination", dest_identity),
                )
                _take_lock(destination_fd, deadline=deadline)
                with _PROCESS_LEASE_CONDITION:
                    _PROCESS_DESTINATION_LEASE_FDS.add(destination_fd)
            except BaseException:
                destination_lock.release()
                destination_thread_held = False
                raise
        lease.assert_named_parent()
        yield lease
        lease.assert_named_parent()
    except BaseException as exc:
        primary = exc

    # Cancellation at any cleanup site is deferred until every owned lease and
    # descriptor has been relinquished.  The original body/setup result remains
    # primary, so cleanup cannot turn a cancellation into a different outcome.
    if destination_fd >= 0:
        closing = destination_fd
        destination_fd = -1
        with _PROCESS_LEASE_CONDITION:
            _PROCESS_DESTINATION_LEASE_FDS.discard(closing)
        try:
            os.close(closing)
        except BaseException as exc:
            cleanup_faults.append(exc)
    if destination_thread_held:
        try:
            destination_lock.release()
        except BaseException as exc:
            cleanup_faults.append(exc)
    if filesystem_held:
        try:
            _release_process_filesystem_lease(filesystem_name)
        except BaseException as exc:
            cleanup_faults.append(exc)
    for owned_fd in (root_fd, parent_fd):
        if owned_fd >= 0:
            try:
                os.close(owned_fd)
            except BaseException as exc:
                cleanup_faults.append(exc)
    if primary is None and cleanup_faults:
        primary = (next((fault for fault in cleanup_faults
                         if not isinstance(fault, Exception)), None)
                   or cleanup_faults[0])
    if primary is not None:
        if cleanup_faults:
            try:
                primary.resource_cleanup_errors = tuple(cleanup_faults)
            except BaseException:
                pass
        raise primary


def _private_fd_snapshot(fd: int, data: bytes):
    """Return one stable exact snapshot, or ``None`` for an ordinary mismatch."""
    initial = os.fstat(fd)
    if (not stat.S_ISREG(initial.st_mode) or initial.st_size != len(data)
            or initial.st_uid != os.geteuid()
            or stat.S_IMODE(initial.st_mode) != 0o600 or initial.st_nlink != 1):
        return None
    chunks = []
    remaining = initial.st_size
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        return None
    raw = b"".join(chunks)
    final = os.fstat(fd)
    if _stable_file_stat(final) != _stable_file_stat(initial) or raw != data:
        return None
    return raw, _stable_file_stat(final)


def _named_bytes_match(parent_fd: int, name: str, data: bytes) -> bool:
    """Prove the current name twice without discarding cleanup cancellation.

    A close can take effect and still deliver ``KeyboardInterrupt`` or
    ``SystemExit``.  The proof is attached to that cancellation so the outer
    publication settlement can finish its durability/name checks and then
    preserve the original control flow with truthful landed/durable/committed
    annotations.
    """
    fd = current_fd = -1
    result = False
    primary = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        first = _private_fd_snapshot(fd, data)
        if first is not None:
            current_fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent_fd,
            )
            second = _private_fd_snapshot(current_fd, data)
            result = second == first
    except OSError:
        result = False
    except BaseException as exc:
        primary = exc

    cleanup_faults: list[BaseException] = []
    for owned_fd in (current_fd, fd):
        if owned_fd < 0:
            continue
        closing = owned_fd
        if owned_fd == current_fd:
            current_fd = -1
        else:
            fd = -1
        try:
            os.close(closing)
        except BaseException as exc:
            cleanup_faults.append(exc)
    cleanup_cancellation = next(
        (fault for fault in cleanup_faults if not isinstance(fault, Exception)), None,
    )
    preferred = primary
    if preferred is None or (isinstance(preferred, Exception)
                             and cleanup_cancellation is not None):
        preferred = cleanup_cancellation
    if preferred is not None:
        try:
            preferred.resource_named_bytes_match = bool(result)
            if cleanup_faults:
                preferred.resource_cleanup_errors = tuple(cleanup_faults)
            if preferred is not primary and primary is not None:
                preferred.resource_operation_error = primary
        except BaseException:
            pass
        raise preferred
    return result


def _directory_durability_barrier(parent_fd: int) -> tuple[bool, tuple[BaseException, ...]]:
    """Settle a directory mutation with one finite retry.

    ``fsync`` can report an ordinary post-effect error.  A second successful
    barrier is authoritative; two failures leave the landed name uncertain.
    Cancellation is retained in the returned faults even when the retry proves
    durability, so callers can preserve it without calling the record lost.
    """
    faults: list[BaseException] = []
    for _attempt in range(2):
        try:
            os.fsync(parent_fd)
            return True, tuple(faults)
        except BaseException as exc:
            faults.append(exc)
    return False, tuple(faults)


def _annotate_publication_fault(exc: BaseException, *, payload_digest: str,
                                landed: bool, durable: bool, committed: bool,
                                durability_errors=()) -> None:
    try:
        exc.resource_publication_landed = bool(landed)
        exc.resource_publication_durable = bool(durable)
        exc.resource_publication_committed = bool(committed)
        exc.resource_payload_digest = payload_digest
        if durability_errors:
            exc.resource_durability_errors = tuple(durability_errors)
    except BaseException:
        pass


def atomic_private_write(path, data: bytes) -> None:
    """Durably replace one exact file under the same destination lease."""
    if type(data) is not bytes:
        raise TypeError("resource work-record bytes must be exact bytes")
    path = Path(path)
    payload_digest = "sha256:" + hashlib.sha256(data).hexdigest()
    publication_landed = False
    publication_durable = False
    publication_committed = False
    durability_faults: tuple[BaseException, ...] = ()
    try:
        with acquisition_lease(path) as lease:
            pfd = lease.parent_fd
            stage = f".quarry-resource-{secrets.token_hex(12)}"
            fd = -1
            primary = None
            try:
                fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=pfd)
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("resource work-record write made no progress")
                    view = view[count:]
                os.fsync(fd)
                closing = fd
                fd = -1
                os.close(closing)  # ownership was relinquished first: never double-close it
                lease.assert_named_parent()

                publication_fault = None
                reconciliation_faults: list[BaseException] = []
                try:
                    os.replace(stage, lease.name, src_dir_fd=pfd, dst_dir_fd=pfd)
                    publication_landed = True
                except BaseException as exc:
                    publication_fault = exc
                    # replace can land and then report a fault.  The pinned
                    # parent/name readback distinguishes that from no effect.
                    try:
                        publication_landed = _named_bytes_match(pfd, lease.name, data)
                    except BaseException as reconciliation_fault:
                        reconciliation_faults.append(reconciliation_fault)
                        publication_landed = bool(getattr(
                            reconciliation_fault, "resource_named_bytes_match", False,
                        ))
                        if not publication_landed:
                            preferred = (publication_fault
                                         if not isinstance(publication_fault, Exception)
                                         else reconciliation_fault)
                            try:
                                preferred.resource_publication_errors = (
                                    publication_fault, reconciliation_fault,
                                )
                            except BaseException:
                                pass
                            raise preferred
                if not publication_landed:
                    if publication_fault is not None:
                        raise publication_fault
                    raise ResourcePublicationUncertain(
                        "resource publication did not reconcile after replace",
                        payload_digest=payload_digest,
                    )

                publication_durable, durability_faults = _directory_durability_barrier(pfd)
                if not publication_durable:
                    cancellation = next(
                        (fault for fault in (
                            (publication_fault,) + tuple(reconciliation_faults)
                            + durability_faults
                        )
                         if fault is not None and not isinstance(fault, Exception)),
                        None,
                    )
                    if cancellation is not None:
                        _annotate_publication_fault(
                            cancellation, payload_digest=payload_digest, landed=True,
                            durable=False, committed=False,
                            durability_errors=durability_faults,
                        )
                        raise cancellation
                    uncertain = ResourcePublicationUncertain(
                        "resource publication landed but directory durability is uncertain",
                        payload_digest=payload_digest,
                        errors=((publication_fault,) if publication_fault is not None else ())
                        + tuple(reconciliation_faults) + durability_faults,
                    )
                    raise uncertain

                # A successful barrier is necessary but not sufficient: the
                # exact intended bytes must still occupy the canonical name and
                # every lexical ancestor must still reach the pinned parent.
                try:
                    final_match = _named_bytes_match(pfd, lease.name, data)
                except BaseException as reconciliation_fault:
                    reconciliation_faults.append(reconciliation_fault)
                    final_match = bool(getattr(
                        reconciliation_fault, "resource_named_bytes_match", False,
                    ))
                    if not final_match:
                        raise
                if not final_match:
                    raise ResourcePublicationUncertain(
                        "durable resource publication no longer names the intended bytes",
                        payload_digest=payload_digest,
                        errors=tuple(reconciliation_faults) + durability_faults,
                    )
                lease.assert_named_parent()
                publication_committed = True

                cancellation = next(
                    (fault for fault in (
                        (publication_fault,) + tuple(reconciliation_faults)
                        + durability_faults
                    )
                     if fault is not None and not isinstance(fault, Exception)),
                    None,
                )
                if cancellation is not None:
                    _annotate_publication_fault(
                        cancellation, payload_digest=payload_digest, landed=True,
                        durable=True, committed=True,
                        durability_errors=durability_faults,
                    )
                    raise cancellation
                # Ordinary replace/fsync diagnostics followed by an exact
                # authoritative readback and successful barrier are settled.
            except BaseException as exc:
                primary = exc

            cleanup_faults: list[BaseException] = []
            if fd >= 0:
                closing = fd
                fd = -1
                try:
                    os.close(closing)
                except BaseException as exc:
                    cleanup_faults.append(exc)
            try:
                os.unlink(stage, dir_fd=pfd)
            except FileNotFoundError:
                pass
            except BaseException as exc:
                cleanup_faults.append(exc)

            cleanup_cancellation = next(
                (fault for fault in cleanup_faults if not isinstance(fault, Exception)), None,
            )
            preferred = primary
            if preferred is None or (isinstance(preferred, Exception)
                                     and cleanup_cancellation is not None):
                preferred = cleanup_cancellation or (cleanup_faults[0] if cleanup_faults else None)
            if preferred is not None:
                if cleanup_faults:
                    try:
                        preferred.resource_cleanup_errors = tuple(cleanup_faults)
                    except BaseException:
                        pass
                if preferred is not primary and primary is not None:
                    try:
                        preferred.resource_operation_error = primary
                    except BaseException:
                        pass
                if publication_committed:
                    _annotate_publication_fault(
                        preferred, payload_digest=payload_digest, landed=True,
                        durable=True, committed=True,
                        durability_errors=durability_faults,
                    )
                elif publication_landed:
                    _annotate_publication_fault(
                        preferred, payload_digest=payload_digest, landed=True,
                        durable=publication_durable, committed=False,
                        durability_errors=durability_faults,
                    )
                if (primary is not None or not publication_committed
                        or not isinstance(preferred, Exception)):
                    raise preferred
    except BaseException as exc:
        # acquisition_lease can itself report cleanup failure after the body has
        # durably committed.  Preserve that exact ordinary/KI/SE outcome while
        # making the already-authoritative record visible to its caller.
        _annotate_publication_fault(
            exc, payload_digest=payload_digest, landed=publication_landed,
            durable=publication_durable, committed=publication_committed,
            durability_errors=durability_faults,
        )
        raise


def _stable_file_stat(observed) -> tuple[int, ...]:
    return (
        observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid,
        observed.st_nlink, observed.st_size, observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def read_private_file(path, *, maximum: int) -> bytes:
    """Read one stable owner-private file through a pinned parent/name authority."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError("private-file maximum must be a non-negative integer")
    parent_fd = file_fd = current_fd = check_fd = -1
    primary = None
    raw = None
    try:
        parent_fd, name, display = _open_parent(Path(path), create=False)
        parent = os.fstat(parent_fd)
        parent_identity = (parent.st_dev, parent.st_ino)
        file_fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd,
        )
        initial = os.fstat(file_fd)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.geteuid()
                or stat.S_IMODE(initial.st_mode) != 0o600 or initial.st_nlink != 1
                or initial.st_size > maximum):
            raise ValueError("private file is not a bounded owner-private single-link regular file")
        chunks = []
        remaining = initial.st_size
        while remaining:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("private file ended before its initial size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise ValueError("private file grew while it was read")
        raw = b"".join(chunks)
        final = os.fstat(file_fd)
        if _stable_file_stat(final) != _stable_file_stat(initial):
            raise ValueError("private file changed while it was read")

        current_fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd,
        )
        current = os.fstat(current_fd)
        if _stable_file_stat(current) != _stable_file_stat(final):
            raise ValueError("private file name changed while it was read")
        current_chunks = []
        current_remaining = current.st_size
        while current_remaining:
            chunk = os.read(current_fd, min(1024 * 1024, current_remaining))
            if not chunk:
                raise ValueError("private file name ended before its stable size")
            current_chunks.append(chunk)
            current_remaining -= len(chunk)
        if os.read(current_fd, 1):
            raise ValueError("private file name grew during reconciliation")
        current_final = os.fstat(current_fd)
        if (_stable_file_stat(current_final) != _stable_file_stat(current)
                or b"".join(current_chunks) != raw):
            raise ValueError("private file bytes changed while they were reconciled")

        check_fd, check_name, _absolute = _open_parent(display, create=False)
        check_parent = os.fstat(check_fd)
        if (check_name != name
                or (check_parent.st_dev, check_parent.st_ino) != parent_identity):
            raise ValueError("private file ancestor changed while it was read")
    except BaseException as exc:
        primary = exc

    cleanup_faults: list[BaseException] = []
    for owned in (check_fd, current_fd, file_fd, parent_fd):
        if owned >= 0:
            try:
                os.close(owned)
            except BaseException as exc:
                cleanup_faults.append(exc)
    cleanup_cancellation = next(
        (fault for fault in cleanup_faults if not isinstance(fault, Exception)), None,
    )
    if primary is None:
        primary = cleanup_cancellation or (cleanup_faults[0] if cleanup_faults else None)
    elif isinstance(primary, Exception) and cleanup_cancellation is not None:
        try:
            cleanup_cancellation.resource_operation_error = primary
        except BaseException:
            pass
        primary = cleanup_cancellation
    if primary is not None:
        if cleanup_faults:
            try:
                primary.resource_cleanup_errors = tuple(cleanup_faults)
            except BaseException:
                pass
        raise primary
    return raw


@dataclass(frozen=True)
class ResourceSnapshot:
    peak_aggregate_rss_bytes: int
    peak_disk_bytes: int
    peak_fd_count: int
    peak_process_count: int
    complete: bool

    def as_record(self) -> dict:
        return {
            "peak_aggregate_rss_bytes": self.peak_aggregate_rss_bytes,
            "peak_disk_bytes": self.peak_disk_bytes,
            "peak_fd_count": self.peak_fd_count,
            "peak_process_count": self.peak_process_count,
            "complete": self.complete,
        }


def _proc_table() -> tuple[dict[int, int], bool]:
    table: dict[int, int] = {}
    try:
        entries = list(os.scandir("/proc"))
    except OSError:
        return table, False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = Path(entry.path, "stat").read_text(encoding="ascii")
            close = raw.rfind(")")
            if close < 0:
                raise ValueError("malformed proc stat")
            fields = raw[close + 2:].split()
            table[int(entry.name)] = int(fields[1])
        except (OSError, UnicodeError, ValueError, IndexError):
            # An unrelated process can exit between scandir and stat.  It was
            # never a member of the sampled tree, so its disappearance does not
            # make the selected tree's resource total incomplete.
            continue
    return table, True


def _tree_pids(root_pid: int) -> tuple[set[int], bool]:
    table, complete = _proc_table()
    if root_pid not in table and root_pid != os.getpid():
        return set(), False
    found = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in table.items():
            if parent in found and pid not in found:
                found.add(pid)
                changed = True
    return found, complete


def _disk_usage(root: Path) -> tuple[int, bool]:
    total = 0
    complete = True
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        observed = entry.stat(follow_symlinks=False)
                    except OSError:
                        complete = False
                        continue
                    if stat.S_ISDIR(observed.st_mode):
                        stack.append(Path(entry.path))
                    elif stat.S_ISREG(observed.st_mode):
                        total += observed.st_size
        except FileNotFoundError:
            complete = False
            continue
        except OSError:
            complete = False
    return total, complete


def aggregate_snapshot(*, root_pid: int | None = None, disk_root=None) -> ResourceSnapshot:
    """Current aggregate RSS/FD/process facts for one process tree plus disk bytes.

    Linux `/proc` is the accepted v0.3.10 H0/H1 runner contract.  A missing or
    partially unreadable process tree is marked incomplete; it is never rendered
    as a trustworthy zero.
    """
    root_pid = os.getpid() if root_pid is None else root_pid
    if isinstance(root_pid, bool) or not isinstance(root_pid, int) or root_pid <= 0:
        raise ValueError("resource root pid must be an exact positive integer")
    pids, complete = _tree_pids(root_pid)
    rss = 0
    fds = 0
    page = os.sysconf("SC_PAGE_SIZE")
    for pid in pids:
        try:
            fields = Path(f"/proc/{pid}/statm").read_text(encoding="ascii").split()
            rss += int(fields[1]) * page
            fds += len(os.listdir(f"/proc/{pid}/fd"))
        except (OSError, UnicodeError, ValueError, IndexError):
            complete = False
    disk, disk_complete = (0, True) if disk_root is None else _disk_usage(Path(disk_root))
    return ResourceSnapshot(rss, disk, fds, len(pids), complete and disk_complete)


def _exact_object(value, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ResourceContractError(f"{where} must carry exactly {sorted(keys)}")
    return value


def _count(value, where: str) -> int:
    if type(value) is not int or value < 0:
        raise ResourceContractError(f"{where} must be an exact non-negative integer")
    return value


def _text(value, where: str) -> str:
    if type(value) is not str or not value:
        raise ResourceContractError(f"{where} must be an exact non-empty string")
    return value


def _timestamp(value, where: str) -> float:
    from datetime import datetime
    text = _text(value, where)
    if not _RFC3339.fullmatch(text):
        raise ResourceContractError(f"{where} must be canonical UTC RFC3339")
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00").timestamp()
    except ValueError as exc:
        raise ResourceContractError(f"{where} is not a real timestamp") from exc


def _measurement_passes(operator: str, value: int, limit: int) -> bool:
    return value <= limit if operator == "at_most" else value >= limit


def _statistic(values: list[int], statistic: str) -> int:
    """Compute the report's exact integer statistic from retained trial facts."""
    if not values:
        raise ResourceContractError("resource metric has no retained trial facts")
    ordered = sorted(values)
    if statistic == "maximum":
        return ordered[-1]
    if statistic == "minimum":
        return ordered[0]
    if statistic == "median":
        return ordered[(len(ordered) - 1) // 2]
    if statistic == "p95":
        return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]
    raise ResourceContractError("resource metric requests an unknown statistic")


def _accepted_threshold_policy(accepted, gate_id: str) -> dict:
    required = _GATE_METRICS.get(gate_id, {})
    if not isinstance(accepted, dict) or set(accepted) != set(required):
        raise ResourceContractError(
            "accepted threshold policy must exactly cover the resource gate metrics",
        )
    checked = {}
    for metric, raw in accepted.items():
        item = _exact_object(raw, _THRESHOLD_KEYS, f"accepted_thresholds.{metric}")
        expected = required[metric]
        if (item["operator"], item["statistic"], item["unit"]) != expected:
            raise ResourceContractError(
                f"accepted threshold {metric!r} changes the gate's committed semantics",
            )
        _count(item["limit"], f"accepted_thresholds.{metric}.limit")
        regression = metric.endswith("_delta")
        baseline = item["baseline_digest"]
        if regression:
            if type(baseline) is not str or not _DIGEST.fullmatch(baseline):
                raise ResourceContractError(
                    f"accepted regression threshold {metric!r} needs its baseline identity",
                )
        elif baseline is not None:
            raise ResourceContractError(
                f"accepted absolute threshold {metric!r} cannot invent a baseline",
            )
        checked[metric] = item
    return checked


def _trial_metric_values(trials, gate_id: str) -> dict[str, list[int]]:
    required = _GATE_METRICS.get(gate_id, {})
    values = {metric: [] for metric in required}
    for index, trial in enumerate(trials):
        facts = trial.get("metric_facts") if isinstance(trial, dict) else None
        if not isinstance(facts, dict) or set(facts) != set(required):
            raise ResourceContractError(
                f"trials[{index}].metric_facts must exactly cover the gate metrics",
            )
        for metric, value in facts.items():
            values[metric].append(_count(
                value, f"trials[{index}].metric_facts.{metric}",
            ))
    return values


def build_gate_report(*, candidate_identity_digest: str, gate_id: str,
                      evidence_instance_id: str,
                      started_at: str, finished_at: str, trials, measurements,
                      threshold_manifest_digest: str, accepted_thresholds,
                      benchmark_manifest_digest: str | None = None) -> dict:
    """Collect one deterministic resource report and compute its verdict.

    Callers supply retained trial facts plus the already-accepted threshold and
    benchmark identities/policy; they do not supply a trusted ``passed`` bit.
    A failing/incomplete report is still serializable for diagnosis, but
    ``verify_gate_report`` will never promote it.
    """
    support = support_envelope()
    copied_trials = copy.deepcopy(list(trials))
    try:
        policy = _accepted_threshold_policy(accepted_thresholds, gate_id)
        trial_values = _trial_metric_values(copied_trials, gate_id)
    except ResourceContractError:
        policy = {}
        trial_values = {}
    copied_measurements = []
    for raw in measurements:
        item = dict(raw)
        metric = item.get("metric")
        expected = _GATE_METRICS.get(gate_id, {}).get(metric)
        operator = expected[0] if expected is not None else None
        value, limit = item.get("value"), item.get("limit")
        accepted = policy.get(metric)
        observed = (
            _statistic(trial_values[metric], expected[1])
            if expected is not None and metric in trial_values else None
        )
        item["passed"] = (
            expected is not None
            and (item.get("operator"), item.get("statistic"), item.get("unit")) == expected
            and type(value) is int and not isinstance(value, bool) and value >= 0
            and type(limit) is int and not isinstance(limit, bool) and limit >= 0
            and accepted is not None
            and all(item.get(name) == accepted[name] for name in _THRESHOLD_KEYS)
            and value == observed
            and _measurement_passes(operator, value, limit)
        )
        copied_measurements.append(item)
    report = {
        "schema_version": SCHEMA_VERSION,
        "candidate_identity_digest": candidate_identity_digest,
        "gate_id": gate_id,
        "evidence_instance_id": evidence_instance_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "support_envelope": support,
        "support_envelope_digest": digest_document(support),
        "trials": copied_trials,
        "measurements": copied_measurements,
        "threshold_manifest_digest": threshold_manifest_digest,
        "benchmark_manifest_digest": benchmark_manifest_digest,
        "verdict": "pass",
    }
    try:
        verify_gate_report(
            report, gate_id=gate_id,
            candidate_identity_digest=candidate_identity_digest,
            evidence_instance_id=evidence_instance_id,
            threshold_manifest_digest=threshold_manifest_digest,
            benchmark_manifest_digest=benchmark_manifest_digest,
            accepted_thresholds=accepted_thresholds,
        )
    except ResourceContractError:
        report["verdict"] = "fail"
    return report


def write_gate_report(path, document) -> str:
    """Persist exact canonical report bytes and return their sha256 identity."""
    body = canonical_bytes(document)
    atomic_private_write(path, body)
    return "sha256:" + hashlib.sha256(body).hexdigest()


def read_gate_report(body: bytes, **expected) -> dict:
    """Read one bounded canonical JSON line and semantically verify a pass."""
    from . import release_evidence

    if (type(body) is not bytes or len(body) > release_evidence.MAX_RECORD_BYTES
            or not body.endswith(b"\n") or body.endswith(b"\n\n")):
        raise ResourceContractError(
            "resource gate report must be one bounded canonical JSON line",
        )
    try:
        report = release_evidence.load_json_bytes(
            body[:-1], maximum=release_evidence.MAX_RECORD_BYTES,
        )
    except release_evidence.EvidenceError as exc:
        raise ResourceContractError(f"resource gate report is not strict JSON: {exc}") from exc
    if canonical_bytes(report) != body:
        raise ResourceContractError("resource gate report bytes are not canonical JSON")
    return verify_gate_report(report, **expected)


def verify_gate_report(document, *, gate_id: str | None = None,
                       candidate_identity_digest: str | None = None,
                       evidence_instance_id: str | None = None,
                       threshold_manifest_digest: str | None = None,
                       benchmark_manifest_digest: str | None = None,
                       accepted_thresholds=None) -> dict:
    """Strict semantic parser for the six V310-06 gate reports.

    Structural validity, a declared ``pass`` string, or generic pytest success is
    insufficient.  Required fault cases, aggregate resource facts, metric
    vocabulary/units/statistics, retained trial facts, accepted threshold and
    benchmark identities, threshold arithmetic, zero-loss invariants, resolver
    support bounds, and candidate/support bindings all reconcile here.
    """
    report = _exact_object(document, _REPORT_KEYS, "resource gate report")
    if report["schema_version"] != SCHEMA_VERSION:
        raise ResourceContractError("unknown resource gate report schema")
    observed_gate = _text(report["gate_id"], "gate_id")
    if observed_gate not in _GATE_CASES or (gate_id is not None and observed_gate != gate_id):
        raise ResourceContractError("resource report gate identity is not the required V310-06 gate")
    candidate = _text(report["candidate_identity_digest"], "candidate_identity_digest")
    if not _DIGEST.fullmatch(candidate):
        raise ResourceContractError("candidate identity digest is not canonical sha256")
    if candidate_identity_digest is not None and candidate != candidate_identity_digest:
        raise ResourceContractError("resource report belongs to another candidate")
    instance = _text(report["evidence_instance_id"], "evidence_instance_id")
    if not _TOKEN.fullmatch(instance):
        raise ResourceContractError("resource report evidence instance id is not canonical")
    if (type(evidence_instance_id) is not str
            or not _TOKEN.fullmatch(evidence_instance_id)):
        raise ResourceContractError("the expected canonical evidence instance id is required")
    if instance != evidence_instance_id:
        raise ResourceContractError("resource report belongs to another evidence instance")
    committed_thresholds = report["threshold_manifest_digest"]
    if (type(threshold_manifest_digest) is not str
            or not _DIGEST.fullmatch(threshold_manifest_digest)):
        raise ResourceContractError(
            "the expected committed threshold manifest identity is required",
        )
    if committed_thresholds != threshold_manifest_digest:
        raise ResourceContractError(
            "resource report belongs to another committed threshold manifest",
        )
    threshold_policy = _accepted_threshold_policy(
        accepted_thresholds, observed_gate,
    )
    started = _timestamp(report["started_at"], "started_at")
    finished = _timestamp(report["finished_at"], "finished_at")
    if finished < started:
        raise ResourceContractError("resource report finishes before it starts")
    benchmark = report["benchmark_manifest_digest"]
    if observed_gate.startswith("C-PERF-"):
        if type(benchmark) is not str or not _DIGEST.fullmatch(benchmark):
            raise ResourceContractError(
                "performance resource report requires its benchmark manifest digest",
            )
        if (type(benchmark_manifest_digest) is not str
                or not _DIGEST.fullmatch(benchmark_manifest_digest)
                or benchmark != benchmark_manifest_digest):
            raise ResourceContractError(
                "performance resource report does not bind the expected benchmark identity",
            )
    elif benchmark is not None:
        raise ResourceContractError("fault resource report cannot invent a benchmark manifest")
    elif benchmark_manifest_digest is not None:
        raise ResourceContractError("fault resource verification cannot select a benchmark identity")

    declared_support = report["support_envelope"]
    if declared_support != support_envelope():
        raise ResourceContractError("resource report does not carry the supported v0.3.x envelope")
    support_digest = _text(report["support_envelope_digest"], "support_envelope_digest")
    if support_digest != digest_document(declared_support):
        raise ResourceContractError("resource support envelope digest does not bind its bytes")

    trials = report["trials"]
    if not isinstance(trials, list) or not trials:
        raise ResourceContractError("resource report requires non-empty trials")
    cases: list[str] = []
    trial_metric_values = {metric: [] for metric in _GATE_METRICS[observed_gate]}
    for index, raw in enumerate(trials):
        trial = _exact_object(raw, _TRIAL_KEYS, f"trials[{index}]")
        case = _text(trial["case"], f"trials[{index}].case")
        cases.append(case)
        if trial["outcome"] != "pass":
            raise ResourceContractError(f"resource trial {case!r} did not pass")
        resource = _exact_object(trial["resource"], _RESOURCE_KEYS,
                                 f"trials[{index}].resource")
        if resource["complete"] is not True:
            raise ResourceContractError(f"trial {case!r} has an incomplete resource sample")
        for name, value in resource.items():
            if name == "complete":
                continue
            _count(value, f"trials[{index}].resource.{name}")
        if (resource["peak_aggregate_rss_bytes"] == 0
                or resource["peak_fd_count"] == 0
                or resource["peak_process_count"] == 0):
            raise ResourceContractError(
                f"trial {case!r} renders a required aggregate resource as zero",
            )
        facts = trial["metric_facts"]
        if (not isinstance(facts, dict)
                or set(facts) != set(_GATE_METRICS[observed_gate])):
            raise ResourceContractError(
                f"trial {case!r} does not carry every obligation-specific metric fact",
            )
        for metric, value in facts.items():
            trial_metric_values[metric].append(_count(
                value, f"trials[{index}].metric_facts.{metric}",
            ))
        if ("peak_aggregate_rss" in facts
                and facts["peak_aggregate_rss"] != resource["peak_aggregate_rss_bytes"]):
            raise ResourceContractError(
                f"trial {case!r} aggregate RSS metric contradicts its resource sample",
            )
        if ("worker_processes" in facts
                and facts["worker_processes"] > resource["peak_process_count"]):
            raise ResourceContractError(
                f"trial {case!r} worker metric exceeds its aggregate process sample",
            )
        assertions = trial["assertions"]
        expected_assertions = _GATE_ASSERTIONS[observed_gate].get(case)
        if (not isinstance(assertions, dict) or set(assertions) != expected_assertions
                or any(type(name) is not str or not name or value is not True
                       for name, value in assertions.items())):
            raise ResourceContractError(
                f"trial {case!r} changes or fails its exact semantic assertions",
            )
        artifacts = trial["artifact_digests"]
        if (not isinstance(artifacts, list) or not artifacts
                or len(artifacts) != len(set(artifacts))
                or any(type(item) is not str or not _DIGEST.fullmatch(item) for item in artifacts)):
            raise ResourceContractError(
                f"trial {case!r} needs unique canonical artifact digests",
            )
    if len(cases) != len(set(cases)) or frozenset(cases) != _GATE_CASES[observed_gate]:
        raise ResourceContractError("resource report cases do not exactly cover the gate's fault/workload matrix")

    measurements = report["measurements"]
    if not isinstance(measurements, list):
        raise ResourceContractError("resource measurements must be an array")
    seen = set()
    required = _GATE_METRICS[observed_gate]
    for index, raw in enumerate(measurements):
        item = _exact_object(raw, _MEASUREMENT_KEYS, f"measurements[{index}]")
        metric = _text(item["metric"], f"measurements[{index}].metric")
        if metric in seen or metric not in required:
            raise ResourceContractError(f"unexpected or duplicate resource metric {metric!r}")
        seen.add(metric)
        expected_operator, expected_statistic, expected_unit = required[metric]
        if (item["operator"], item["statistic"], item["unit"]) != (
                expected_operator, expected_statistic, expected_unit):
            raise ResourceContractError(f"resource metric {metric!r} changes its accepted semantics")
        value = _count(item["value"], f"measurements[{index}].value")
        limit = _count(item["limit"], f"measurements[{index}].limit")
        if metric in _ZERO_INVARIANTS and (value != 0 or limit != 0):
            raise ResourceContractError(f"safety invariant {metric!r} must be exact zero")
        baseline = item["baseline_digest"]
        regression = metric.endswith("_delta")
        if regression:
            if type(baseline) is not str or not _DIGEST.fullmatch(baseline):
                raise ResourceContractError(f"regression metric {metric!r} needs its baseline digest")
        elif baseline is not None:
            raise ResourceContractError(f"absolute metric {metric!r} cannot claim a baseline")
        if metric == "worker_processes" and limit > declared_support["resolver"]["worker_processes"]:
            raise ResourceContractError("resolver worker threshold exceeds the published support bound")
        if metric == "outstanding_queue" and limit > declared_support["resolver"]["outstanding_queue"]:
            raise ResourceContractError("resolver queue threshold exceeds the published support bound")
        if (metric == "corpus_deadline"
                and limit > declared_support["resolver"]["corpus_deadline_milliseconds"]):
            raise ResourceContractError("resolver deadline threshold exceeds the published support bound")
        accepted = threshold_policy[metric]
        if any(item[name] != accepted[name] for name in _THRESHOLD_KEYS):
            raise ResourceContractError(
                f"resource metric {metric!r} contradicts the accepted threshold policy",
            )
        reconciled = _statistic(trial_metric_values[metric], expected_statistic)
        if value != reconciled:
            raise ResourceContractError(
                f"resource metric {metric!r} contradicts its retained trial facts",
            )
        passed = _measurement_passes(expected_operator, value, limit)
        if item["passed"] is not passed or not passed:
            raise ResourceContractError(f"resource metric {metric!r} does not meet its threshold")
    if seen != set(required):
        raise ResourceContractError("resource report does not carry every obligation-specific metric")
    if report["verdict"] != "pass":
        raise ResourceContractError("resource report verdict is not pass")
    return report
