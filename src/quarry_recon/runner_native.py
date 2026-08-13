"""Repository-owned transactions for tool-native argv output paths.

Some tools do not write their primary evidence to stdout.  They receive one or
more output paths in argv and create files or directory trees themselves.  A
plain path into a run would let such a tool truncate canonical evidence before
the execution transaction settled.  This module gives those paths a private
attempt root and publishes them only after the caller proves execution clean.

The API is deliberately independent of :mod:`quarry_recon.runner`: the runner
facade may compose it, while focused tests and native lanes can exercise the
filesystem transaction directly.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from . import privfs, store
from .repository_identity import validate_artifact_component
from .state import ContractError


_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_CREATE_FILE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_CREATE_STAGE_FLAGS = (
    os.O_RDWR
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_RENAME_EXCHANGE = 2
_CONSTRUCTOR = object()
_MAX_POLICIES = 64


class NativeOutputKind(str, Enum):
    """The closed set of native argv sink shapes."""

    FILE = "file"
    TREE = "tree"


@dataclass(frozen=True, slots=True, repr=False)
class NativeArgvBinding:
    """One exact argv slot and its suffix below a policy destination."""

    argv_index: int
    relative_suffix: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if type(self.argv_index) is not int or self.argv_index < 0:
            raise TypeError("native output argv index must be a non-negative int")
        if type(self.relative_suffix) is not tuple:
            raise TypeError("native output suffix must be a tuple")
        validated = tuple(
            validate_artifact_component(component, "native output suffix")
            for component in self.relative_suffix
        )
        object.__setattr__(self, "relative_suffix", validated)

    def __repr__(self) -> str:
        return (
            "NativeArgvBinding("
            f"argv_index={self.argv_index}, depth={len(self.relative_suffix)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RepositoryNativeOutput:
    """An immutable repository destination bound to exact argv slots."""

    kind: NativeOutputKind
    components: tuple[str, ...] = field(repr=False)
    bindings: tuple[NativeArgvBinding, ...] = field(repr=False)
    seed_prior: bool = False
    required: bool = True

    def __post_init__(self) -> None:
        if type(self.kind) is not NativeOutputKind:
            raise TypeError("invalid native output kind")
        if type(self.components) is not tuple:
            raise TypeError("native output components must be a tuple")
        components = store._validated_artifact_components(self.components)
        if type(self.bindings) is not tuple or not self.bindings:
            raise TypeError("native output bindings must be a non-empty tuple")
        if any(type(binding) is not NativeArgvBinding for binding in self.bindings):
            raise TypeError("invalid native output binding")
        if type(self.seed_prior) is not bool or type(self.required) is not bool:
            raise TypeError("native output flags must be exact booleans")
        indices = tuple(binding.argv_index for binding in self.bindings)
        suffixes = tuple(binding.relative_suffix for binding in self.bindings)
        if len(indices) != len(set(indices)) or len(suffixes) != len(set(suffixes)):
            raise ContractError("native output bindings overlap")
        if self.kind is NativeOutputKind.FILE:
            if len(self.bindings) != 1 or suffixes != ((),) or self.seed_prior:
                raise ContractError("file output requires one root binding")
        else:
            if () not in suffixes:
                raise ContractError("tree output requires one root binding")
        object.__setattr__(self, "components", components)

    @classmethod
    def file(
        cls, argv_index: int, *components: str, required: bool = True,
    ) -> "RepositoryNativeOutput":
        return cls(
            NativeOutputKind.FILE,
            tuple(components),
            (NativeArgvBinding(argv_index),),
            required=required,
        )

    @classmethod
    def tree(
        cls,
        bindings: tuple[tuple[int, tuple[str, ...]], ...],
        *components: str,
        seed_prior: bool = False,
        required: bool = True,
    ) -> "RepositoryNativeOutput":
        if type(bindings) is not tuple:
            raise TypeError("tree bindings must be a tuple")
        normalized: list[NativeArgvBinding] = []
        for item in bindings:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("each tree binding must be an (index, suffix) tuple")
            index, suffix = item
            normalized.append(NativeArgvBinding(index, suffix))
        return cls(
            NativeOutputKind.TREE,
            tuple(components),
            tuple(normalized),
            seed_prior=seed_prior,
            required=required,
        )

    def __repr__(self) -> str:
        return (
            "RepositoryNativeOutput("
            f"kind={self.kind.value!r}, bindings={len(self.bindings)}, "
            f"required={self.required}, seed_prior={self.seed_prior})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NativeOutputEvidence:
    """Authenticated terminal fact for one native output policy."""

    policy_index: int
    kind: NativeOutputKind
    components: tuple[str, ...] = field(repr=False)
    present: bool
    size: int
    sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.policy_index) is not int or self.policy_index < 0:
            raise TypeError("invalid native output evidence index")
        if type(self.kind) is not NativeOutputKind:
            raise TypeError("invalid native output evidence kind")
        if type(self.components) is not tuple or not self.components:
            raise TypeError("invalid native output evidence identity")
        if type(self.present) is not bool:
            raise TypeError("invalid native output presence")
        if type(self.size) is not int or self.size < 0:
            raise TypeError("invalid native output size")
        if self.present:
            if (type(self.sha256) is not str or len(self.sha256) != 64
                    or any(char not in "0123456789abcdef" for char in self.sha256)):
                raise TypeError("invalid native output digest")
        elif self.size != 0 or self.sha256 is not None:
            raise ValueError("absent native output cannot authenticate bytes")

    def __repr__(self) -> str:
        return (
            "NativeOutputEvidence("
            f"policy_index={self.policy_index}, kind={self.kind.value!r}, "
            f"present={self.present}, size={self.size})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NativeOutputReceipt:
    """Immutable, complete and disjoint native-output publication partition."""

    policy_count: int
    committed: tuple[NativeOutputEvidence, ...] = field(default=(), repr=False)
    uncertain: tuple[NativeOutputEvidence, ...] = field(default=(), repr=False)
    unpublished: tuple[NativeOutputEvidence, ...] = field(default=(), repr=False)
    cleanup_settled: bool = True
    claim_retained: bool = False
    fault_operation: str | None = field(default=None, repr=False)
    fault_type: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.policy_count) is not int or self.policy_count < 1:
            raise TypeError("invalid native output policy count")
        for group in (self.committed, self.uncertain, self.unpublished):
            if (type(group) is not tuple
                    or any(type(item) is not NativeOutputEvidence for item in group)):
                raise TypeError("invalid native output receipt partition")
        indices = tuple(
            item.policy_index
            for group in (self.committed, self.uncertain, self.unpublished)
            for item in group
        )
        if len(indices) != len(set(indices)) or set(indices) != set(range(self.policy_count)):
            raise ValueError("native output receipt partition is incomplete or overlapping")
        if type(self.cleanup_settled) is not bool:
            raise TypeError("invalid native output cleanup state")
        if type(self.claim_retained) is not bool:
            raise TypeError("invalid native output claim state")
        if self.claim_retained and self.cleanup_settled:
            raise ValueError("a retained native output claim is not settled")
        if self.fault_operation not in {
            None, "execute", "validate", "publish", "cleanup", "release",
        }:
            raise ValueError("invalid native output fault operation")
        if self.fault_type is not None and type(self.fault_type) is not str:
            raise TypeError("invalid native output fault type")

    @property
    def clean(self) -> bool:
        return (
            len(self.committed) == self.policy_count
            and not self.uncertain
            and not self.unpublished
            and self.cleanup_settled
            and not self.claim_retained
            and self.fault_operation is None
        )

    def __repr__(self) -> str:
        return (
            "NativeOutputReceipt("
            f"clean={self.clean}, committed={len(self.committed)}, "
            f"uncertain={len(self.uncertain)}, "
            f"unpublished={len(self.unpublished)}, "
            f"cleanup_settled={self.cleanup_settled}, "
            f"claim_retained={self.claim_retained})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _TreeEntry:
    suffix: tuple[str, ...] = field(repr=False)
    directory: bool
    size: int
    sha256: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _Snapshot:
    evidence: NativeOutputEvidence
    entries: tuple[_TreeEntry, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _PublishResult:
    disposition: str
    cleanup_settled: bool = True
    fault: BaseException | None = field(default=None, repr=False)


@dataclass(slots=True)
class _FilePublishOwner:
    components: tuple[str, ...]
    temporary_name: str
    anchor_fd: int = -1
    parent_fd: int = -1
    file_fd: int = -1
    file_identity: tuple[int, int] | None = None
    present: bool = False
    stage: object | None = None


@dataclass(slots=True)
class _TreePublishOwner:
    name: str
    fd: int = -1
    identity: tuple[int, int] | None = None
    present: bool = False


@dataclass(slots=True)
class _PolicySettlement:
    evidence: NativeOutputEvidence
    name: str
    result: _PublishResult | None = None
    file_owner: _FilePublishOwner | None = None
    tree_owner: _TreePublishOwner | None = None

    def record(self, result: _PublishResult) -> None:
        self.result = result


@dataclass(slots=True)
class _FinishLedger:
    requested_clean: bool
    validation_done: bool = False
    snapshots: tuple[_Snapshot, ...] | None = None
    validation_fault: BaseException | None = None
    settlements: list[_PolicySettlement] = field(default_factory=list)
    cleanup_done: bool = False
    cleanup_settled: bool = True
    cleanup_fault: BaseException | None = None
    release_done: bool = False
    release_fault: BaseException | None = None
    cancellation: BaseException | None = None


class NativeOutputUnsupported(RuntimeError):
    """The host cannot provide the exact native-output transaction."""


@dataclass(slots=True)
class _PrepareOwnership:
    """Mutable ownership ledger updated inside effectful prepare helpers.

    In particular, the unique names exist in this object before their create
    syscalls.  A BaseException at a call/assignment boundary can therefore
    reconcile the named effect instead of losing its only cleanup authority.
    """

    run: store.Run
    policies: tuple[RepositoryNativeOutput, ...]
    base_path: Path
    _root_name: str
    _claim_name: str
    _base_fd: int = -1
    _root_fd: int = -1
    _root_identity: tuple[int, int] | None = None
    _root_present: bool = False
    _claim_identity: tuple[int, int] | None = None
    _claim_present: bool = False


class NativeOutputAdoption:
    """Opaque caller-owned slot spanning the prepare return boundary.

    The facade allocates this exact object before calling
    :func:`prepare_native_outputs`.  Preparation installs its raw ownership
    ledger before its first filesystem effect, and a completed transaction
    installs itself before its constructor returns.  ``fence()`` therefore has
    exact cleanup authority even when an exception lands before the caller can
    assign the function's return value.
    """

    __slots__ = ("_owner", "_transaction", "_receipt")

    def __init__(self) -> None:
        self._owner = None
        self._transaction = None
        self._receipt = None

    def __repr__(self) -> str:
        state = (
            "settled" if self._receipt is not None
            else "transaction" if self._transaction is not None
            else "preparing" if self._owner is not None
            else "empty"
        )
        return f"NativeOutputAdoption(state={state!r})"

    def _adopt_prepare(self, owner: _PrepareOwnership) -> None:
        if type(owner) is not _PrepareOwnership or self._owner is not None:
            raise ContractError("native output adoption is invalid or already used")
        self._owner = owner

    def _adopt_transaction(self, transaction) -> None:
        if (self._owner is None or self._transaction is not None
                or type(transaction) is not NativeOutputTransaction):
            raise ContractError("native output transaction adoption is invalid")
        self._transaction = transaction

    def fence(self) -> NativeOutputReceipt | None:
        """Idempotently fence whichever side of preparation was adopted."""
        transaction = self._transaction
        if transaction is not None:
            if transaction._receipt is not None:
                self._receipt = transaction._receipt
                return self._receipt
            try:
                receipt = transaction.finish(clean=False)
            except BaseException:
                if transaction._receipt is None:
                    raise
                receipt = transaction._receipt
                self._receipt = receipt
                raise
            self._receipt = receipt
            return receipt

        owner = self._owner
        if owner is None:
            return None
        if self._receipt is not None:
            return self._receipt

        settled = False
        cleanup_fault = None
        cancellation = None
        for _attempt in range(2):
            try:
                attempt_settled, attempt_fault = _cleanup_prepare_ownership(
                    owner.run, owner,
                )
            except BaseException as exc:
                attempt_settled, attempt_fault = False, exc
            settled = attempt_settled
            if cleanup_fault is None and attempt_fault is not None:
                cleanup_fault = attempt_fault
            if (cancellation is None and attempt_fault is not None
                    and not isinstance(attempt_fault, Exception)):
                cancellation = attempt_fault
            if settled:
                break

        released = not owner._claim_present
        release_fault = None
        if settled and owner._claim_present:
            for _attempt in range(2):
                try:
                    with owner.run._mutation(store.MutationScope.CONTROL):
                        attempt_released, attempt_fault = _release_known_claim_locked(
                            owner.run, owner,
                        )
                except BaseException as exc:
                    attempt_released, attempt_fault = False, exc
                released = attempt_released
                if release_fault is None and attempt_fault is not None:
                    release_fault = attempt_fault
                if (cancellation is None and attempt_fault is not None
                        and not isinstance(attempt_fault, Exception)):
                    cancellation = attempt_fault
                if released:
                    break

        claim_retained = owner._claim_present or not released
        cleanup_settled = settled and released and not claim_retained
        fault = cleanup_fault or release_fault
        receipt = NativeOutputReceipt(
            policy_count=len(owner.policies),
            unpublished=tuple(
                _default_evidence(index, policy)
                for index, policy in enumerate(owner.policies)
            ),
            cleanup_settled=cleanup_settled,
            claim_retained=claim_retained,
            fault_operation=(
                "cleanup" if not settled
                else "release" if not released
                else "execute"
            ),
            fault_type=None if fault is None else type(fault).__name__,
        )
        if cleanup_settled:
            self._receipt = receipt
        if cancellation is not None:
            raise cancellation
        return receipt


def _identity(observed: os.stat_result) -> tuple[int, int]:
    return observed.st_dev, observed.st_ino


def _file_signature(observed: os.stat_result) -> tuple[int, ...]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_uid,
        stat.S_IMODE(observed.st_mode),
        observed.st_nlink,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _dir_signature(observed: os.stat_result) -> tuple[int, ...]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_uid,
        stat.S_IMODE(observed.st_mode),
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _validate_private_dir(observed: os.stat_result, *, normalize: bool, fd: int) -> None:
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid():
        raise ContractError("native output directory identity is unsafe")
    if normalize and stat.S_IMODE(observed.st_mode) != privfs.DIR_MODE:
        os.fchmod(fd, privfs.DIR_MODE)
        observed = os.fstat(fd)
    if stat.S_IMODE(observed.st_mode) != privfs.DIR_MODE:
        raise ContractError("native output directory mode is unsafe")


def _validate_private_file(observed: os.stat_result, *, normalize: bool, fd: int) -> None:
    if (not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or observed.st_nlink != 1):
        raise ContractError("native output file identity is unsafe")
    if normalize and stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE:
        os.fchmod(fd, privfs.FILE_MODE)
        observed = os.fstat(fd)
    if stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE:
        raise ContractError("native output file mode is unsafe")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("native output write made no progress")
        view = view[written:]


def _mkdir_at(parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    os.mkdir(name, privfs.DIR_MODE, dir_fd=parent_fd)
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    try:
        os.fchmod(fd, privfs.DIR_MODE)
        observed = os.fstat(fd)
        _validate_private_dir(observed, normalize=False, fd=fd)
        os.fsync(parent_fd)
        return fd, _identity(observed)
    except BaseException:
        os.close(fd)
        raise


def _claim_identity_at(directory_fd: int, name: str) -> tuple[int, int]:
    fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    try:
        observed = os.fstat(fd)
        _validate_private_file(observed, normalize=False, fd=fd)
        return _identity(observed)
    finally:
        os.close(fd)


def _reconcile_known_claim(directory_fd: int, owner) -> bool:
    """Update ``owner`` from the exact pre-minted claim name."""
    try:
        identity = _claim_identity_at(directory_fd, owner._claim_name)
    except FileNotFoundError:
        owner._claim_present = False
        owner._claim_identity = None
        return False
    if (owner._claim_identity is not None
            and identity != owner._claim_identity):
        raise ContractError("native output claim marker identity changed")
    owner._claim_identity = identity
    owner._claim_present = True
    return True


def _create_known_claim(run: store.Run, owner) -> None:
    """Durably create the owner's pre-minted finalization blocker.

    This helper returns no authority.  It writes the identity into ``owner``
    before returning, closing the usual effect-return/local-assignment gap.
    """
    directory = privfs.private_dir(run._artifact_claim_dir)
    directory_fd = os.open(directory, _DIR_FLAGS)
    marker_fd = -1
    try:
        try:
            os.stat(owner._claim_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ContractError("native output claim name collided")

        owner._claim_present = True
        try:
            marker_fd = os.open(
                owner._claim_name,
                _CREATE_FILE_FLAGS,
                privfs.FILE_MODE,
                dir_fd=directory_fd,
            )
            os.fchmod(marker_fd, privfs.FILE_MODE)
            body = json.dumps({
                "schema_version": 1,
                "run_id": run.run_id,
                "pid": os.getpid(),
                "owner": "native-output",
            }, sort_keys=True).encode("utf-8")
            _write_all(marker_fd, body)
            os.fsync(marker_fd)
            observed = os.fstat(marker_fd)
            _validate_private_file(observed, normalize=False, fd=marker_fd)
            owner._claim_identity = _identity(observed)
            os.fsync(directory_fd)
        except BaseException:
            _reconcile_known_claim(directory_fd, owner)
            raise
    finally:
        if marker_fd >= 0:
            os.close(marker_fd)
        os.close(directory_fd)


def _release_known_claim_locked(run: store.Run, owner) -> tuple[bool, BaseException | None]:
    """Release or retain an exact blocker, reconciling action uncertainty."""
    if not owner._claim_present:
        return True, None
    directory_fd = -1
    fault = None
    released = False
    try:
        directory_fd = os.open(run._artifact_claim_dir, _DIR_FLAGS)
        identity = _claim_identity_at(directory_fd, owner._claim_name)
        if identity != owner._claim_identity:
            raise ContractError("native output claim marker identity changed")
        try:
            os.unlink(owner._claim_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            owner._claim_present = False
            owner._claim_identity = None
            released = True
        except BaseException as exc:
            fault = exc
            try:
                present = _reconcile_known_claim(directory_fd, owner)
            except BaseException:
                present = True
            if not present:
                try:
                    # If unlink landed before the exception, this fsync
                    # completes the same durable release.
                    os.fsync(directory_fd)
                except BaseException:
                    # Keep an observable blocker when absence cannot be made
                    # durable.  Its name is recorded before the create action.
                    owner._claim_name = f"{os.urandom(16).hex()}.claim"
                    owner._claim_identity = None
                    owner._claim_present = False
                    try:
                        _create_known_claim(run, owner)
                    except BaseException:
                        pass
                else:
                    owner._claim_present = False
                    owner._claim_identity = None
                    released = True
    except BaseException as exc:
        if fault is None:
            fault = exc
    finally:
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except BaseException as exc:
                if fault is None:
                    fault = exc
    return released, fault


def _open_prepare_base(owner: _PrepareOwnership) -> None:
    try:
        owner._base_fd = os.open(owner.base_path, _DIR_FLAGS)
    except BaseException:
        # An injected open wrapper may have returned a descriptor before
        # reporting a fault.  No named mutation occurred, so a fresh owned
        # descriptor is sufficient for later reconciliation.
        try:
            owner._base_fd = os.open(owner.base_path, _DIR_FLAGS)
        except BaseException:
            pass
        raise


def _create_prepare_root(owner: _PrepareOwnership) -> None:
    """Create the pre-named attempt root and publish ownership into the ledger."""
    try:
        os.stat(owner._root_name, dir_fd=owner._base_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ContractError("native output attempt name collided")

    owner._root_present = True
    try:
        os.mkdir(owner._root_name, privfs.DIR_MODE, dir_fd=owner._base_fd)
        _open_prepare_root(owner)
        os.fchmod(owner._root_fd, privfs.DIR_MODE)
        observed = os.fstat(owner._root_fd)
        _validate_private_dir(observed, normalize=False, fd=owner._root_fd)
        owner._root_identity = _identity(observed)
        os.fsync(owner._base_fd)
    except BaseException:
        # The mkdir may have landed before its helper reported the exception.
        # Reopen only the exact pre-minted name without following links.
        try:
            root_fd = owner._root_fd
            if root_fd < 0:
                root_fd = os.open(
                    owner._root_name, _DIR_FLAGS, dir_fd=owner._base_fd,
                )
            observed = os.fstat(root_fd)
            _validate_private_dir(observed, normalize=True, fd=root_fd)
            owner._root_fd = root_fd
            owner._root_identity = _identity(os.fstat(root_fd))
            owner._root_present = True
        except FileNotFoundError:
            owner._root_present = False
            owner._root_identity = None
        raise


def _open_prepare_root(owner: _PrepareOwnership) -> None:
    """Publish the root descriptor into its ledger before helper return."""
    owner._root_fd = os.open(
        owner._root_name,
        _DIR_FLAGS,
        dir_fd=owner._base_fd,
    )


def _ensure_dirs_at(anchor_fd: int, components: tuple[str, ...]) -> None:
    current = os.dup(anchor_fd)
    try:
        for component in components:
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=current)
            except FileNotFoundError:
                child, _unused = _mkdir_at(current, component)
            observed = os.fstat(child)
            _validate_private_dir(observed, normalize=True, fd=child)
            os.close(current)
            current = child
    finally:
        os.close(current)


def _digest_open_file(fd: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return size, digest.hexdigest()


def _snapshot_file_at(
    parent_fd: int,
    name: str,
    *,
    policy_index: int,
    policy: RepositoryNativeOutput,
    normalize: bool,
) -> _Snapshot:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if policy.required:
            raise ContractError("required native file output is absent") from None
        return _Snapshot(NativeOutputEvidence(
            policy_index, policy.kind, policy.components, False, 0, None,
        ))
    try:
        before = os.fstat(fd)
        _validate_private_file(before, normalize=normalize, fd=fd)
        before = os.fstat(fd)
        named_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _file_signature(named_before) != _file_signature(before):
            raise ContractError("native output file name changed")
        size, digest = _digest_open_file(fd)
        os.fsync(fd)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (_file_signature(after) != _file_signature(before)
                or _file_signature(named_after) != _file_signature(before)
                or size != after.st_size):
            raise ContractError("native output file changed during authentication")
        return _Snapshot(NativeOutputEvidence(
            policy_index, policy.kind, policy.components, True, size, digest,
        ))
    finally:
        os.close(fd)


def _tree_digest(entries: tuple[_TreeEntry, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(b"quarry-native-tree-v1\0")
    for entry in entries:
        path = "/".join(entry.suffix).encode("utf-8")
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(b"d" if entry.directory else b"f")
        digest.update(entry.size.to_bytes(8, "big"))
        if entry.sha256 is not None:
            digest.update(bytes.fromhex(entry.sha256))
    return digest.hexdigest()


def _snapshot_tree_recursive(
    directory_fd: int,
    prefix: tuple[str, ...],
    *,
    normalize: bool,
) -> tuple[_TreeEntry, ...]:
    before = os.fstat(directory_fd)
    _validate_private_dir(before, normalize=normalize, fd=directory_fd)
    before = os.fstat(directory_fd)
    entries: list[_TreeEntry] = []
    for name in sorted(os.listdir(directory_fd)):
        component = validate_artifact_component(name, "native tree entry")
        suffix = prefix + (component,)
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
            try:
                if _identity(os.fstat(child)) != _identity(observed):
                    raise ContractError("native tree directory name changed")
                nested = _snapshot_tree_recursive(child, suffix, normalize=normalize)
                os.fsync(child)
                after = os.fstat(child)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                _validate_private_dir(after, normalize=False, fd=child)
                if (_identity(after) != _identity(observed)
                        or _identity(named) != _identity(observed)):
                    raise ContractError("native tree directory changed")
                entries.append(_TreeEntry(suffix, True, 0, None))
                entries.extend(nested)
            finally:
                os.close(child)
        elif stat.S_ISREG(observed.st_mode):
            child = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
            try:
                if _identity(os.fstat(child)) != _identity(observed):
                    raise ContractError("native tree file name changed")
                file_before = os.fstat(child)
                _validate_private_file(file_before, normalize=normalize, fd=child)
                file_before = os.fstat(child)
                size, digest = _digest_open_file(child)
                os.fsync(child)
                file_after = os.fstat(child)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (_file_signature(file_after) != _file_signature(file_before)
                        or _file_signature(named) != _file_signature(file_before)
                        or size != file_after.st_size):
                    raise ContractError("native tree file changed")
                entries.append(_TreeEntry(suffix, False, size, digest))
            finally:
                os.close(child)
        else:
            raise ContractError("native tree contains a link or special object")
    os.fsync(directory_fd)
    after = os.fstat(directory_fd)
    _validate_private_dir(after, normalize=False, fd=directory_fd)
    if _identity(after) != _identity(before):
        raise ContractError("native tree root identity changed")
    return tuple(entries)


def _snapshot_tree_at(
    parent_fd: int,
    name: str,
    *,
    policy_index: int,
    policy: RepositoryNativeOutput,
    normalize: bool,
) -> _Snapshot:
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if policy.required:
            raise ContractError("required native tree output is absent") from None
        return _Snapshot(NativeOutputEvidence(
            policy_index, policy.kind, policy.components, False, 0, None,
        ))
    try:
        before = os.fstat(fd)
        _validate_private_dir(before, normalize=normalize, fd=fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(named) != _identity(before):
            raise ContractError("native tree name changed")
        entries = _snapshot_tree_recursive(fd, (), normalize=normalize)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (_identity(after) != _identity(before)
                or _identity(named_after) != _identity(before)):
            raise ContractError("native tree changed during authentication")
        total = sum(entry.size for entry in entries if not entry.directory)
        return _Snapshot(
            NativeOutputEvidence(
                policy_index,
                policy.kind,
                policy.components,
                True,
                total,
                _tree_digest(entries),
            ),
            entries,
        )
    finally:
        os.close(fd)


def _copy_file_exact(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    expected_size: int,
    expected_digest: str,
) -> None:
    source = os.open(source_name, _FILE_FLAGS, dir_fd=source_parent_fd)
    destination = -1
    try:
        before = os.fstat(source)
        _validate_private_file(before, normalize=False, fd=source)
        destination = os.open(
            destination_name,
            _CREATE_FILE_FLAGS,
            privfs.FILE_MODE,
            dir_fd=destination_parent_fd,
        )
        os.fchmod(destination, privfs.FILE_MODE)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            _write_all(destination, chunk)
            digest.update(chunk)
            size += len(chunk)
        os.fsync(destination)
        after = os.fstat(source)
        named = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
        if (_file_signature(after) != _file_signature(before)
                or _file_signature(named) != _file_signature(before)
                or size != expected_size
                or digest.hexdigest() != expected_digest):
            raise ContractError("native output source changed while copying")
        written = os.fstat(destination)
        _validate_private_file(written, normalize=False, fd=destination)
        if written.st_size != expected_size:
            raise ContractError("native output copy is incomplete")
    finally:
        if destination >= 0:
            os.close(destination)
        os.close(source)


def _open_dir_suffix(anchor_fd: int, suffix: tuple[str, ...]) -> int:
    current = os.dup(anchor_fd)
    try:
        for component in suffix:
            child = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _copy_tree_snapshot(
    source_fd: int,
    destination_fd: int,
    snapshot: _Snapshot,
) -> None:
    directories = [entry for entry in snapshot.entries if entry.directory]
    files = [entry for entry in snapshot.entries if not entry.directory]
    for entry in sorted(directories, key=lambda item: (len(item.suffix), item.suffix)):
        parent = _open_dir_suffix(destination_fd, entry.suffix[:-1])
        try:
            os.mkdir(entry.suffix[-1], privfs.DIR_MODE, dir_fd=parent)
            child = os.open(entry.suffix[-1], _DIR_FLAGS, dir_fd=parent)
            try:
                os.fchmod(child, privfs.DIR_MODE)
            finally:
                os.close(child)
        finally:
            os.close(parent)
    for entry in files:
        source_parent = _open_dir_suffix(source_fd, entry.suffix[:-1])
        destination_parent = _open_dir_suffix(destination_fd, entry.suffix[:-1])
        try:
            _copy_file_exact(
                source_parent,
                entry.suffix[-1],
                destination_parent,
                entry.suffix[-1],
                expected_size=entry.size,
                expected_digest=entry.sha256 or "",
            )
        finally:
            os.close(destination_parent)
            os.close(source_parent)
    copied_entries = _snapshot_tree_recursive(destination_fd, (), normalize=False)
    if copied_entries != snapshot.entries or _tree_digest(copied_entries) != snapshot.evidence.sha256:
        raise ContractError("native tree copy does not match authenticated source")


def _remove_tree_contents(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(observed.st_mode):
            child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
            try:
                _remove_tree_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _remove_named_tree(
    parent_fd: int,
    name: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    directory = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    try:
        observed = os.fstat(directory)
        if expected_identity is not None and _identity(observed) != expected_identity:
            raise ContractError("refusing to remove a substituted native stage")
        _remove_tree_contents(directory)
    finally:
        os.close(directory)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _cleanup_prepare_ownership(
    run: store.Run,
    owner: _PrepareOwnership,
) -> tuple[bool, BaseException | None]:
    """Fence a failed prepare without ever guessing at an effect outcome."""
    fault = None
    settled = True
    with run._mutation(store.MutationScope.CONTROL):
        if owner._root_present:
            try:
                if owner._base_fd < 0:
                    owner._base_fd = os.open(owner.base_path, _DIR_FLAGS)
                if owner._root_fd < 0:
                    owner._root_fd = os.open(
                        owner._root_name, _DIR_FLAGS, dir_fd=owner._base_fd,
                    )
                observed = os.fstat(owner._root_fd)
                _validate_private_dir(observed, normalize=True, fd=owner._root_fd)
                identity = _identity(observed)
                if (owner._root_identity is not None
                        and identity != owner._root_identity):
                    raise ContractError("native output attempt identity changed")
                named = os.stat(
                    owner._root_name,
                    dir_fd=owner._base_fd,
                    follow_symlinks=False,
                )
                if _identity(named) != identity:
                    raise ContractError("native output attempt name changed")
                owner._root_identity = identity
                _remove_tree_contents(owner._root_fd)
                os.rmdir(owner._root_name, dir_fd=owner._base_fd)
                os.fsync(owner._base_fd)
                owner._root_present = False
            except FileNotFoundError:
                try:
                    if owner._base_fd < 0:
                        owner._base_fd = os.open(owner.base_path, _DIR_FLAGS)
                    os.fsync(owner._base_fd)
                    owner._root_present = False
                except BaseException as exc:
                    settled, fault = False, exc
            except BaseException as exc:
                settled, fault = False, exc
        for attribute in ("_root_fd", "_base_fd"):
            fd = getattr(owner, attribute)
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as exc:
                    settled = False
                    if fault is None:
                        fault = exc
                setattr(owner, attribute, -1)
    return settled and not owner._root_present, fault


def _named_identity(parent_fd: int, name: str) -> tuple[int, int] | None:
    try:
        return _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None


def _rename_exchange(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise NativeOutputUnsupported("atomic directory exchange is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_parent_fd,
        os.fsencode(source_name),
        destination_parent_fd,
        os.fsencode(destination_name),
        _RENAME_EXCHANGE,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _canonical_path(run: store.Run, components: tuple[str, ...]) -> str:
    return os.path.abspath(os.path.normpath(str(run.dir.joinpath(*components))))


def _validate_prepare_inputs(
    run,
    cmd,
    policies,
) -> tuple[tuple[str, ...], tuple[RepositoryNativeOutput, ...]]:
    if type(run) is not store.Run:
        raise TypeError("native outputs require an exact opened Run authority")
    if type(cmd) not in (list, tuple) or not cmd:
        raise TypeError("native output argv must be a non-empty list or tuple")
    argv = tuple(cmd)
    if any(type(item) is not str or "\x00" in item for item in argv):
        raise TypeError("native output argv items must be exact NUL-free strings")
    if (type(policies) is not tuple or not 1 <= len(policies) <= _MAX_POLICIES
            or any(type(policy) is not RepositoryNativeOutput for policy in policies)):
        raise TypeError("native output policies must be a bounded exact tuple")

    claimed_indices: set[int] = set()
    destinations: list[tuple[str, ...]] = []
    for policy in policies:
        for prior in destinations:
            shared = min(len(prior), len(policy.components))
            if prior[:shared] == policy.components[:shared]:
                raise ContractError("native output destinations overlap")
        destinations.append(policy.components)
        for binding in policy.bindings:
            if binding.argv_index >= len(argv) or binding.argv_index in claimed_indices:
                raise ContractError("native output argv bindings overlap or are out of range")
            claimed_indices.add(binding.argv_index)
            expected = _canonical_path(run, policy.components + binding.relative_suffix)
            if argv[binding.argv_index] != expected:
                raise ContractError("native output binding does not match canonical argv path")
    return argv, policies


def _default_evidence(
    index: int,
    policy: RepositoryNativeOutput,
) -> NativeOutputEvidence:
    return NativeOutputEvidence(index, policy.kind, policy.components, False, 0, None)


def _fence_private_stage(run: store.Run, stage) -> bool:
    """Remove one provably unpublished repository sibling stage."""
    if stage is None or stage.state in {"committed", "replaced_uncertain"}:
        return stage is None or stage.state == "committed"
    identity = stage.file_identity
    components = stage.components
    with run._mutation(store.MutationScope.CONTROL):
        try:
            privfs.abort_private_stage(stage)
        except BaseException:
            return False
        anchor = store._open_run_fd(run.project_dir, run.run_id)
        parent = -1
        try:
            parent = privfs.open_strict_dir_at(anchor, components[:-1])
            for name in os.listdir(parent):
                if not (name.startswith(".quarry-discard-") and name.endswith(".stage")):
                    continue
                observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(observed) == identity:
                    os.unlink(name, dir_fd=parent)
                    os.fsync(parent)
                    return True
            return True
        except BaseException:
            return False
        finally:
            if parent >= 0:
                os.close(parent)
            os.close(anchor)


def _create_owned_file_stage(
    anchor_fd: int,
    policy: RepositoryNativeOutput,
    owner: _FilePublishOwner,
) -> None:
    """Create a privfs-compatible stage while publishing every owner transition."""
    owner.anchor_fd = privfs.open_strict_dir_at(anchor_fd, ())
    owner.parent_fd = privfs.open_strict_dir_at(
        owner.anchor_fd, policy.components[:-1],
    )
    anchor_identity = _identity(os.fstat(owner.anchor_fd))
    parent_identity = _identity(os.fstat(owner.parent_fd))
    owner.present = True
    owner.file_fd = os.open(
        owner.temporary_name,
        _CREATE_STAGE_FLAGS,
        privfs.FILE_MODE,
        dir_fd=owner.parent_fd,
    )
    os.fchmod(owner.file_fd, privfs.FILE_MODE)
    observed = os.fstat(owner.file_fd)
    _validate_private_file(observed, normalize=False, fd=owner.file_fd)
    owner.file_identity = _identity(observed)
    os.fsync(owner.parent_fd)
    owner.stage = privfs.PrivateFileStage(
        anchor_fd=owner.anchor_fd,
        parent_fd=owner.parent_fd,
        file_fd=owner.file_fd,
        temporary_name=owner.temporary_name,
        destination_name=policy.components[-1],
        components=policy.components,
        anchor_identity=anchor_identity,
        parent_identity=parent_identity,
        file_identity=owner.file_identity,
        _constructor_token=privfs._PRIVATE_STAGE_CONSTRUCTOR,
    )


def _close_untransferred_file_owner(owner: _FilePublishOwner) -> bool:
    settled = True
    for attribute in ("file_fd", "parent_fd", "anchor_fd"):
        fd = getattr(owner, attribute)
        if fd >= 0:
            try:
                os.close(fd)
            except BaseException:
                settled = False
            setattr(owner, attribute, -1)
    return settled


def _fence_owned_file_stage(run: store.Run, owner: _FilePublishOwner) -> bool:
    """Fence exactly one hidden FILE stage or retain the run claim."""
    stage = owner.stage
    if stage is not None:
        if stage.state in {"publishing", "replaced_uncertain"}:
            owner.present = True
            return False
        if stage.state == "committed":
            owner.present = False
            return True
        settled = _fence_private_stage(run, stage)
        owner.present = not settled
        return settled

    settled = True
    try:
        with run._mutation(store.MutationScope.CONTROL):
            if owner.present:
                if owner.parent_fd < 0:
                    anchor = store._open_run_fd(run.project_dir, run.run_id)
                    try:
                        owner.parent_fd = privfs.open_strict_dir_at(
                            anchor, owner.components[:-1],
                        )
                    finally:
                        os.close(anchor)
                try:
                    observed = os.stat(
                        owner.temporary_name,
                        dir_fd=owner.parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    os.fsync(owner.parent_fd)
                    owner.present = False
                else:
                    if (owner.file_identity is not None
                            and _identity(observed) != owner.file_identity):
                        raise ContractError("native file stage identity changed")
                    if not stat.S_ISREG(observed.st_mode):
                        raise ContractError("native file stage type changed")
                    os.unlink(owner.temporary_name, dir_fd=owner.parent_fd)
                    os.fsync(owner.parent_fd)
                    owner.present = False
    except BaseException:
        settled = False
    return _close_untransferred_file_owner(owner) and settled and not owner.present


def _create_owned_tree(parent_fd: int, owner: _TreePublishOwner) -> None:
    """Create a pre-named tree candidate into its mutable ownership ledger."""
    owner.present = True
    os.mkdir(owner.name, privfs.DIR_MODE, dir_fd=parent_fd)
    owner.fd = os.open(owner.name, _DIR_FLAGS, dir_fd=parent_fd)
    os.fchmod(owner.fd, privfs.DIR_MODE)
    observed = os.fstat(owner.fd)
    _validate_private_dir(observed, normalize=False, fd=owner.fd)
    owner.identity = _identity(observed)
    os.fsync(parent_fd)


class NativeOutputTransaction:
    """One durable claim spanning private native output staging and publication."""

    __slots__ = (
        "run", "policies", "rewritten_cmd", "_base_fd", "_root_fd",
        "_root_name", "_root_identity", "_root_present", "_claim_name",
        "_claim_identity", "_claim_present", "_receipt", "_finish_ledger",
        "_stage_names", "_adoption", "_constructor_token",
    )

    def __init__(
        self,
        *,
        run: store.Run,
        policies: tuple[RepositoryNativeOutput, ...],
        rewritten_cmd: tuple[str, ...],
        base_fd: int,
        root_fd: int,
        root_name: str,
        root_identity: tuple[int, int],
        claim_name: str,
        claim_identity: tuple[int, int],
        stage_names: tuple[str, ...],
        adoption: NativeOutputAdoption,
        _constructor_token,
    ) -> None:
        if _constructor_token is not _CONSTRUCTOR:
            raise ContractError("construct native output transactions through prepare_native_outputs")
        self.run = run
        self.policies = policies
        self.rewritten_cmd = rewritten_cmd
        self._base_fd = base_fd
        self._root_fd = root_fd
        self._root_name = root_name
        self._root_identity = root_identity
        self._root_present = True
        self._claim_name = claim_name
        self._claim_identity = claim_identity
        self._claim_present = True
        self._receipt = None
        self._finish_ledger = None
        self._stage_names = stage_names
        self._adoption = adoption
        self._constructor_token = _constructor_token
        adoption._adopt_transaction(self)

    def __repr__(self) -> str:
        return (
            "NativeOutputTransaction("
            f"policies={len(self.policies)}, finished={self._receipt is not None})"
        )

    def __enter__(self) -> "NativeOutputTransaction":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self._receipt is None:
            self.finish(clean=False)
        return False

    def _validate_root(self) -> None:
        observed = os.fstat(self._root_fd)
        _validate_private_dir(observed, normalize=True, fd=self._root_fd)
        named = os.stat(self._root_name, dir_fd=self._base_fd, follow_symlinks=False)
        if (_identity(observed) != self._root_identity
                or _identity(named) != self._root_identity):
            raise ContractError("native output staging root identity changed")

    def _snapshots(self) -> tuple[_Snapshot, ...]:
        self._validate_root()
        snapshots: list[_Snapshot] = []
        for index, (policy, name) in enumerate(zip(self.policies, self._stage_names)):
            if policy.kind is NativeOutputKind.FILE:
                snapshots.append(_snapshot_file_at(
                    self._root_fd,
                    name,
                    policy_index=index,
                    policy=policy,
                    normalize=True,
                ))
            else:
                snapshots.append(_snapshot_tree_at(
                    self._root_fd,
                    name,
                    policy_index=index,
                    policy=policy,
                    normalize=True,
                ))
        os.fsync(self._root_fd)
        return tuple(snapshots)

    def _source_file_fd(self, name: str) -> int:
        self._validate_root()
        return os.open(name, _FILE_FLAGS, dir_fd=self._root_fd)

    def _publish_file(
        self,
        policy: RepositoryNativeOutput,
        snapshot: _Snapshot,
        name: str,
        settlement: _PolicySettlement,
    ) -> None:
        if not snapshot.evidence.present:
            settlement.record(self._publish_file_absence(policy))
            return
        owner = settlement.file_owner
        if owner is None:
            owner = _FilePublishOwner(
                policy.components,
                f".quarry-native-file-{os.urandom(16).hex()}.stage",
            )
            settlement.file_owner = owner
        source = -1
        fault = None
        disposition = "unpublished"
        cleanup_settled = True
        try:
            source = self._source_file_fd(name)
            before = os.fstat(source)
            _validate_private_file(before, normalize=False, fd=source)
            with self.run._mutation(store.MutationScope.BASE_EVIDENCE):
                self.run._ensure_artifact_parent(policy.components)
                anchor = store._open_run_fd(self.run.project_dir, self.run.run_id)
                try:
                    _create_owned_file_stage(anchor, policy, owner)
                finally:
                    os.close(anchor)
                stage = owner.stage
                if type(stage) is not privfs.PrivateFileStage:
                    raise ContractError("native file stage construction did not settle")
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = os.read(source, 1024 * 1024)
                    if not chunk:
                        break
                    _write_all(stage.file_fd, chunk)
                    digest.update(chunk)
                    size += len(chunk)
                after = os.fstat(source)
                if (_file_signature(after) != _file_signature(before)
                        or size != snapshot.evidence.size
                        or digest.hexdigest() != snapshot.evidence.sha256):
                    raise ContractError("native file changed before publication")
                privfs._set_stage(
                    stage,
                    "expected_digest",
                    (snapshot.evidence.size, snapshot.evidence.sha256),
                )
                privfs.replace_private_stage(stage)
                owner.present = False
            disposition = "committed"
        except privfs.PrivateReplaceCommittedWithFault as exc:
            owner.present = False
            disposition, cleanup_settled, fault = "committed", False, exc
        except privfs.PrivateReplaceUncertain as exc:
            disposition, cleanup_settled, fault = "uncertain", False, exc
        except BaseException as exc:
            fault = exc
            stage = owner.stage
            if stage is not None and stage.state in {"publishing", "replaced_uncertain"}:
                disposition, cleanup_settled = "uncertain", False
            elif stage is not None and stage.state == "committed":
                owner.present = False
                disposition, cleanup_settled = "committed", False
            else:
                cleanup_settled = _fence_owned_file_stage(self.run, owner)
        finally:
            if source >= 0:
                try:
                    os.close(source)
                except BaseException as exc:
                    cleanup_settled = False
                    if fault is None:
                        fault = exc
        settlement.record(_PublishResult(disposition, cleanup_settled, fault))

    def _publish_file_absence(self, policy: RepositoryNativeOutput) -> _PublishResult:
        fault = None
        disposition = "unpublished"
        cleanup_settled = True
        parent = -1
        prior = -1
        backup = f".quarry-native-prior-{os.urandom(16).hex()}"
        prior_identity = None
        action_started = False
        try:
            with self.run._mutation(store.MutationScope.BASE_EVIDENCE):
                anchor = store._open_run_fd(self.run.project_dir, self.run.run_id)
                try:
                    try:
                        parent = privfs.open_strict_dir_at(anchor, policy.components[:-1])
                    except privfs.PrivatePathMissing:
                        return _PublishResult("committed")
                finally:
                    os.close(anchor)
                try:
                    prior = os.open(policy.components[-1], _FILE_FLAGS, dir_fd=parent)
                except FileNotFoundError:
                    return _PublishResult("committed")
                observed = os.fstat(prior)
                _validate_private_file(observed, normalize=False, fd=prior)
                prior_identity = _identity(observed)
                action_started = True
                os.rename(
                    policy.components[-1], backup,
                    src_dir_fd=parent, dst_dir_fd=parent,
                )
                if _named_identity(parent, backup) != prior_identity:
                    raise ContractError("native output absence could not retain prior evidence")
                os.fsync(parent)
                if _named_identity(parent, policy.components[-1]) is not None:
                    raise ContractError("native output absence did not settle")
                disposition = "committed"
                try:
                    os.unlink(backup, dir_fd=parent)
                    os.fsync(parent)
                except BaseException as cleanup_error:
                    cleanup_settled, fault = False, cleanup_error
        except BaseException as exc:
            fault = exc
            if action_started and prior_identity is not None:
                final_identity = _named_identity(parent, policy.components[-1]) if parent >= 0 else None
                backup_identity = _named_identity(parent, backup) if parent >= 0 else None
                if final_identity is None and backup_identity == prior_identity:
                    disposition, cleanup_settled = "uncertain", False
                elif final_identity == prior_identity:
                    disposition = "unpublished"
                else:
                    disposition, cleanup_settled = "uncertain", False
        finally:
            if prior >= 0:
                os.close(prior)
            if parent >= 0:
                os.close(parent)
        return _PublishResult(disposition, cleanup_settled, fault)

    def _publish_tree(
        self,
        policy: RepositoryNativeOutput,
        snapshot: _Snapshot,
        name: str,
        settlement: _PolicySettlement,
    ) -> None:
        if not snapshot.evidence.present:
            settlement.record(_PublishResult("committed"))
            return
        owner = settlement.tree_owner
        if owner is None:
            owner = _TreePublishOwner(
                f".quarry-native-tree-{os.urandom(16).hex()}",
            )
            settlement.tree_owner = owner
        source = -1
        parent = -1
        prior = -1
        prior_identity = None
        action_started = False
        exchanged = False
        disposition = "unpublished"
        cleanup_settled = True
        fault = None
        try:
            self._validate_root()
            source = os.open(name, _DIR_FLAGS, dir_fd=self._root_fd)
            with self.run._mutation(store.MutationScope.BASE_EVIDENCE):
                self.run._ensure_artifact_parent(policy.components)
                anchor = store._open_run_fd(self.run.project_dir, self.run.run_id)
                try:
                    parent = privfs.open_strict_dir_at(anchor, policy.components[:-1])
                finally:
                    os.close(anchor)
                _create_owned_tree(parent, owner)
                _copy_tree_snapshot(source, owner.fd, snapshot)
                os.fsync(owner.fd)
                try:
                    prior = privfs.open_strict_dir_at(parent, (policy.components[-1],))
                except privfs.PrivatePathMissing:
                    prior = -1
                if prior >= 0:
                    prior_identity = _identity(os.fstat(prior))
                    action_started = True
                    try:
                        _rename_exchange(
                            parent, owner.name, parent, policy.components[-1],
                        )
                    except BaseException as exchange_error:
                        final_identity = _named_identity(parent, policy.components[-1])
                        hidden_identity = _named_identity(parent, owner.name)
                        if (final_identity == owner.identity
                                and hidden_identity == prior_identity):
                            exchanged = True
                            fault = exchange_error
                        elif (final_identity == prior_identity
                                and hidden_identity == owner.identity):
                            raise
                        else:
                            raise privfs.PrivateReplaceUncertain(
                                "native tree exchange outcome is uncertain",
                                components=policy.components,
                            ) from exchange_error
                    else:
                        exchanged = True
                    owner.present = False
                else:
                    action_started = True
                    try:
                        os.rename(
                            owner.name,
                            policy.components[-1],
                            src_dir_fd=parent,
                            dst_dir_fd=parent,
                        )
                    except BaseException as rename_error:
                        final_identity = _named_identity(parent, policy.components[-1])
                        hidden_identity = _named_identity(parent, owner.name)
                        if final_identity == owner.identity and hidden_identity is None:
                            fault = rename_error
                        elif final_identity is None and hidden_identity == owner.identity:
                            raise
                        else:
                            raise privfs.PrivateReplaceUncertain(
                                "native tree rename outcome is uncertain",
                                components=policy.components,
                            ) from rename_error
                    owner.present = False
                os.fsync(parent)
                final = privfs.open_strict_dir_at(parent, (policy.components[-1],))
                try:
                    if _identity(os.fstat(final)) != owner.identity:
                        raise ContractError("native tree final identity changed")
                    final_entries = _snapshot_tree_recursive(final, (), normalize=False)
                    if (final_entries != snapshot.entries
                            or _tree_digest(final_entries) != snapshot.evidence.sha256):
                        raise ContractError("native tree final bytes changed")
                finally:
                    os.close(final)
                disposition = "committed"
                if exchanged and prior_identity is not None:
                    try:
                        _remove_named_tree(
                            parent,
                            owner.name,
                            expected_identity=prior_identity,
                        )
                    except BaseException as cleanup_error:
                        cleanup_settled = False
                        if fault is None:
                            fault = cleanup_error
        except privfs.PrivateReplaceUncertain as exc:
            disposition, cleanup_settled, fault = "uncertain", False, exc
        except BaseException as exc:
            if fault is None:
                fault = exc
            if action_started and parent >= 0 and owner.identity is not None:
                final_identity = _named_identity(parent, policy.components[-1])
                hidden_identity = _named_identity(parent, owner.name)
                if final_identity == owner.identity:
                    owner.present = False
                    disposition, cleanup_settled = "uncertain", False
                elif hidden_identity == owner.identity:
                    owner.present = True
                    disposition = "unpublished"
                else:
                    disposition, cleanup_settled = "uncertain", False
            if disposition == "unpublished" and parent >= 0 and owner.identity is not None:
                try:
                    if _named_identity(parent, owner.name) == owner.identity:
                        _remove_named_tree(
                            parent, owner.name, expected_identity=owner.identity,
                        )
                        owner.present = False
                except BaseException:
                    cleanup_settled = False
        finally:
            for fd in (prior, owner.fd, parent, source):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        cleanup_settled = False
            owner.fd = -1
        settlement.record(_PublishResult(disposition, cleanup_settled, fault))

    def _cleanup_attempt(self) -> tuple[bool, BaseException | None]:
        fault = None
        settled = True
        if self._root_present:
            try:
                with self.run._mutation(store.MutationScope.CONTROL):
                    self._validate_root()
                    _remove_tree_contents(self._root_fd)
                    os.rmdir(self._root_name, dir_fd=self._base_fd)
                    os.fsync(self._base_fd)
                    self._root_present = False
            except BaseException as exc:
                fault = exc
                settled = self._reconcile_attempt_absence()
        for attribute in ("_root_fd", "_base_fd"):
            fd = getattr(self, attribute)
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as exc:
                    settled = False
                    if fault is None:
                        fault = exc
                setattr(self, attribute, -1)
        return settled and not self._root_present, fault

    def _reconcile_attempt_absence(self) -> bool:
        """Prove and durably settle a possibly-landed attempt-root removal."""
        directory = -1
        try:
            with self.run._mutation(store.MutationScope.CONTROL):
                base = (
                    self.run.project_dir / "recon" / "state"
                    / "native-stages" / self.run.run_id
                )
                directory = os.open(base, _DIR_FLAGS)
                try:
                    os.stat(
                        self._root_name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    os.fsync(directory)
                    self._root_present = False
                    return True
                self._root_present = True
                return False
        except BaseException:
            return False
        finally:
            if directory >= 0:
                try:
                    os.close(directory)
                except BaseException:
                    pass

    def _reconcile_claim_boundary(self) -> bool:
        """Settle a release-call boundary or leave a visible blocker."""
        directory = -1
        try:
            with self.run._mutation(store.MutationScope.CONTROL):
                directory = os.open(self.run._artifact_claim_dir, _DIR_FLAGS)
                try:
                    present = _reconcile_known_claim(directory, self)
                except BaseException:
                    self._claim_present = True
                    return False
                if present:
                    return False
                try:
                    os.fsync(directory)
                except BaseException:
                    self._claim_name = f"{os.urandom(16).hex()}.claim"
                    self._claim_identity = None
                    self._claim_present = False
                    try:
                        _create_known_claim(self.run, self)
                    except BaseException:
                        pass
                    return False
                self._claim_present = False
                self._claim_identity = None
                return True
        except BaseException:
            return False
        finally:
            if directory >= 0:
                try:
                    os.close(directory)
                except BaseException:
                    pass

    def _release_claim(self) -> tuple[bool, BaseException | None]:
        if not self._claim_present:
            return True, None
        try:
            with self.run._mutation(store.MutationScope.CONTROL):
                return _release_known_claim_locked(self.run, self)
        except BaseException as exc:
            return self._reconcile_claim_boundary(), exc

    def _recover_publish_escape(
        self,
        policy: RepositoryNativeOutput,
        settlement: _PolicySettlement,
        fault: BaseException,
    ) -> None:
        """Convert an escaped publisher boundary into one conservative fact."""
        if settlement.result is not None:
            return
        if policy.kind is NativeOutputKind.FILE:
            owner = settlement.file_owner
            if owner is None:
                settlement.record(_PublishResult("unpublished", True, fault))
                return
            stage = owner.stage
            if stage is not None and stage.state == "committed":
                owner.present = False
                settlement.record(_PublishResult("committed", False, fault))
            elif stage is not None and stage.state in {
                "publishing", "replaced_uncertain",
            }:
                settlement.record(_PublishResult("uncertain", False, fault))
            else:
                settled = _fence_owned_file_stage(self.run, owner)
                settlement.record(_PublishResult("unpublished", settled, fault))
            return

        owner = settlement.tree_owner
        if owner is None:
            settlement.record(_PublishResult("unpublished", True, fault))
            return
        parent = -1
        try:
            with self.run._mutation(store.MutationScope.CONTROL):
                anchor = store._open_run_fd(self.run.project_dir, self.run.run_id)
                try:
                    parent = privfs.open_strict_dir_at(
                        anchor, policy.components[:-1],
                    )
                finally:
                    os.close(anchor)
                if owner.identity is None and owner.fd >= 0:
                    owner.identity = _identity(os.fstat(owner.fd))
                final_identity = _named_identity(parent, policy.components[-1])
                hidden_identity = _named_identity(parent, owner.name)
                if owner.identity is None and hidden_identity is not None:
                    hidden = os.open(owner.name, _DIR_FLAGS, dir_fd=parent)
                    try:
                        observed = os.fstat(hidden)
                        _validate_private_dir(observed, normalize=True, fd=hidden)
                        owner.identity = _identity(observed)
                    finally:
                        os.close(hidden)
                    hidden_identity = owner.identity
                if owner.identity is not None and final_identity == owner.identity:
                    owner.present = False
                    settlement.record(_PublishResult("uncertain", False, fault))
                elif owner.identity is not None and hidden_identity == owner.identity:
                    _remove_named_tree(
                        parent, owner.name, expected_identity=owner.identity,
                    )
                    owner.present = False
                    settlement.record(_PublishResult("unpublished", True, fault))
                elif final_identity is None and hidden_identity is None:
                    owner.present = False
                    settlement.record(_PublishResult("unpublished", True, fault))
                else:
                    settlement.record(_PublishResult("uncertain", False, fault))
        except BaseException:
            settlement.record(_PublishResult("uncertain", False, fault))
        finally:
            if parent >= 0:
                try:
                    os.close(parent)
                except BaseException:
                    result = settlement.result
                    if result is not None:
                        settlement.record(_PublishResult(
                            result.disposition, False, result.fault or fault,
                        ))

    def _store_receipt(
        self,
        receipt: NativeOutputReceipt,
    ) -> None:
        self._receipt = receipt

    def finish(self, *, clean: bool) -> NativeOutputReceipt:
        """Resume, fence or publish this attempt and return its exact partition."""
        if type(clean) is not bool:
            raise TypeError("native output completion must be an exact boolean")
        if self._receipt is not None:
            return self._receipt
        ledger = self._finish_ledger
        if ledger is None:
            ledger = _FinishLedger(clean)
            self._finish_ledger = ledger

        if not ledger.validation_done:
            if not ledger.requested_clean:
                ledger.settlements = [
                    _PolicySettlement(
                        _default_evidence(index, policy),
                        self._stage_names[index],
                        result=_PublishResult("unpublished"),
                    )
                    for index, policy in enumerate(self.policies)
                ]
                ledger.validation_done = True
            else:
                try:
                    snapshots = self._snapshots()
                except BaseException as exc:
                    ledger.validation_fault = exc
                    ledger.cancellation = (
                        exc if not isinstance(exc, Exception) else None
                    )
                    ledger.settlements = [
                        _PolicySettlement(
                            _default_evidence(index, policy),
                            self._stage_names[index],
                            result=_PublishResult("unpublished"),
                        )
                        for index, policy in enumerate(self.policies)
                    ]
                else:
                    ledger.snapshots = snapshots
                    ledger.settlements = [
                        _PolicySettlement(snapshot.evidence, name)
                        for snapshot, name in zip(snapshots, self._stage_names)
                    ]
                ledger.validation_done = True

        stopped = False
        if ledger.snapshots is not None:
            for policy, snapshot, settlement in zip(
                self.policies, ledger.snapshots, ledger.settlements,
            ):
                if settlement.result is not None:
                    stopped |= settlement.result.disposition != "committed"
                    continue
                if stopped:
                    settlement.record(_PublishResult("unpublished"))
                    continue
                try:
                    if policy.kind is NativeOutputKind.FILE:
                        self._publish_file(
                            policy, snapshot, settlement.name, settlement,
                        )
                    else:
                        self._publish_tree(
                            policy, snapshot, settlement.name, settlement,
                        )
                except BaseException as exc:
                    self._recover_publish_escape(policy, settlement, exc)
                result = settlement.result
                if result is None:
                    result = _PublishResult(
                        "uncertain", False,
                        ContractError("native publisher did not settle"),
                    )
                    settlement.record(result)
                if result.fault is not None and not isinstance(result.fault, Exception):
                    ledger.cancellation = ledger.cancellation or result.fault
                stopped |= result.disposition != "committed"

        if not ledger.cleanup_done:
            try:
                attempt_settled, cleanup_fault = self._cleanup_attempt()
            except BaseException as exc:
                attempt_settled = self._reconcile_attempt_absence()
                cleanup_fault = exc
            ledger.cleanup_settled = attempt_settled
            ledger.cleanup_fault = cleanup_fault
            ledger.cleanup_done = True
            if cleanup_fault is not None and not isinstance(cleanup_fault, Exception):
                ledger.cancellation = ledger.cancellation or cleanup_fault

        results = tuple(
            settlement.result or _PublishResult(
                "uncertain", False,
                ContractError("native output lacks a terminal settlement"),
            )
            for settlement in ledger.settlements
        )
        publications_settled = (
            all(result.cleanup_settled for result in results)
            and not any(result.disposition == "uncertain" for result in results)
        )
        if ledger.cleanup_settled and publications_settled and not ledger.release_done:
            try:
                released, release_fault = self._release_claim()
            except BaseException as exc:
                released = self._reconcile_claim_boundary()
                release_fault = exc
            ledger.release_done = released
            ledger.release_fault = release_fault
            if release_fault is not None and not isinstance(release_fault, Exception):
                ledger.cancellation = ledger.cancellation or release_fault

        committed = tuple(
            settlement.evidence
            for settlement, result in zip(ledger.settlements, results)
            if result.disposition == "committed"
        )
        uncertain = tuple(
            settlement.evidence
            for settlement, result in zip(ledger.settlements, results)
            if result.disposition == "uncertain"
        )
        unpublished = tuple(
            settlement.evidence
            for settlement, result in zip(ledger.settlements, results)
            if result.disposition == "unpublished"
        )
        publication_fault = next(
            (result.fault for result in results if result.fault is not None),
            None,
        )
        if ledger.validation_fault is not None:
            fault_operation, fault = "validate", ledger.validation_fault
        elif publication_fault is not None:
            fault_operation, fault = "publish", publication_fault
        elif ledger.cleanup_fault is not None:
            fault_operation, fault = "cleanup", ledger.cleanup_fault
        elif ledger.release_fault is not None:
            fault_operation, fault = "release", ledger.release_fault
        elif not ledger.requested_clean:
            fault_operation, fault = "execute", None
        else:
            fault_operation, fault = None, None
        claim_retained = self._claim_present or not ledger.release_done
        cleanup_settled = (
            ledger.cleanup_settled
            and all(result.cleanup_settled for result in results)
            and ledger.release_done
            and not claim_retained
        )
        receipt = NativeOutputReceipt(
            policy_count=len(self.policies),
            committed=committed,
            uncertain=uncertain,
            unpublished=unpublished,
            cleanup_settled=cleanup_settled,
            claim_retained=claim_retained,
            fault_operation=fault_operation,
            fault_type=None if fault is None else type(fault).__name__,
        )
        self._store_receipt(receipt)
        if ledger.cancellation is not None:
            raise ledger.cancellation
        return receipt


def _seed_tree(
    run: store.Run,
    policy: RepositoryNativeOutput,
    destination_fd: int,
) -> None:
    with run._mutation(store.MutationScope.BASE_EVIDENCE):
        anchor = store._open_run_fd(run.project_dir, run.run_id)
        try:
            try:
                source = privfs.open_strict_dir_at(anchor, policy.components)
            except privfs.PrivatePathMissing:
                return
        finally:
            os.close(anchor)
        try:
            entries = _snapshot_tree_recursive(source, (), normalize=False)
            snapshot = _Snapshot(
                NativeOutputEvidence(
                    0,
                    NativeOutputKind.TREE,
                    policy.components,
                    True,
                    sum(entry.size for entry in entries if not entry.directory),
                    _tree_digest(entries),
                ),
                entries,
            )
            _copy_tree_snapshot(source, destination_fd, snapshot)
        finally:
            os.close(source)


def _write_stage_claim(
    root_fd: int,
    run: store.Run,
    policies,
    *,
    claim_name: str,
) -> None:
    body = json.dumps({
        "schema_version": 1,
        "run_id": run.run_id,
        "pid": os.getpid(),
        "artifact_claim": claim_name,
        "outputs": [
            {"kind": policy.kind.value, "components": list(policy.components)}
            for policy in policies
        ],
    }, sort_keys=True).encode("utf-8")
    fd = os.open(
        ".claim.json", _CREATE_FILE_FLAGS, privfs.FILE_MODE, dir_fd=root_fd,
    )
    try:
        os.fchmod(fd, privfs.FILE_MODE)
        _write_all(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(root_fd)


def prepare_native_outputs(
    run,
    cmd,
    policies,
    *,
    adoption: NativeOutputAdoption | None = None,
) -> NativeOutputTransaction:
    """Claim private argv sinks and return the sole owner of their settlement."""
    argv, policies = _validate_prepare_inputs(run, cmd, policies)
    if adoption is None:
        adoption = NativeOutputAdoption()
    elif type(adoption) is not NativeOutputAdoption:
        raise TypeError("native output adoption must be an exact owner")
    base = (
        run.project_dir / "recon" / "state" / "native-stages" / run.run_id
    )
    owner = _PrepareOwnership(
        run=run,
        policies=policies,
        base_path=base,
        _root_name=f"attempt-{os.urandom(16).hex()}",
        _claim_name=f"{os.urandom(16).hex()}.claim",
    )
    adoption._adopt_prepare(owner)
    try:
        with run._mutation(store.MutationScope.BASE_EVIDENCE):
            _create_known_claim(run, owner)
            privfs.private_dir(base)
            _open_prepare_base(owner)
            _create_prepare_root(owner)
            _write_stage_claim(
                owner._root_fd,
                run,
                policies,
                claim_name=owner._claim_name,
            )
            stage_names: list[str] = []
            rewritten = list(argv)
            for index, policy in enumerate(policies):
                name = f"output-{index:02d}" + (
                    ".tree" if policy.kind is NativeOutputKind.TREE else ".file"
                )
                stage_names.append(name)
                if policy.kind is NativeOutputKind.TREE:
                    tree_fd, _tree_identity = _mkdir_at(owner._root_fd, name)
                    try:
                        if policy.seed_prior:
                            _seed_tree(run, policy, tree_fd)
                        for binding in policy.bindings:
                            _ensure_dirs_at(tree_fd, binding.relative_suffix[:-1])
                    finally:
                        os.close(tree_fd)
                for binding in policy.bindings:
                    rewritten[binding.argv_index] = os.path.abspath(str(
                        Path(base) / owner._root_name / name
                        / Path(*binding.relative_suffix)
                    ))
            os.fsync(owner._root_fd)
            os.fsync(owner._base_fd)
        return NativeOutputTransaction(
            run=run,
            policies=policies,
            rewritten_cmd=tuple(rewritten),
            base_fd=owner._base_fd,
            root_fd=owner._root_fd,
            root_name=owner._root_name,
            root_identity=owner._root_identity,
            claim_name=owner._claim_name,
            claim_identity=owner._claim_identity,
            stage_names=tuple(stage_names),
            adoption=adoption,
            _constructor_token=_CONSTRUCTOR,
        )
    except BaseException:
        try:
            adoption.fence()
        except BaseException:
            pass
        raise
