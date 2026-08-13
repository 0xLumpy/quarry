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
import errno
import hashlib
import json
import os
import stat
from contextlib import contextmanager
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
_TREE_BUILDER_CONSTRUCTOR = object()
_MAX_POLICIES = 64
_MAX_REPOSITORY_IDENTITY_BYTES = 4 * 1024 * 1024


@contextmanager
def _settled_descriptors(owners, what):
    """Activate two settlement passes for one preinstalled owner tuple."""
    settlement = store._SettlementOwner(
        lambda: store._settle_descriptor_owners(
            owners, what,
        ),
    )
    with store._SettlementFence(settlement):
        with store._SettlementFence(settlement):
            yield owners


@contextmanager
def _owned_descriptor(what, *, expected_identity=None):
    """Activate two settlement passes before one descriptor can be allocated."""
    owner = store._OwnedDescriptor(expected_identity)
    with _settled_descriptors((owner,), what):
        yield owner


@contextmanager
def _owned_run_anchor(run: store.Run):
    """Keep one exact run descriptor owned across native publication."""
    with _owned_descriptor(
        "native runner descriptor",
        expected_identity=run._run_directory_identity,
    ) as owner:
        store._open_run_fd_into(
            owner,
            run.project_dir,
            run.run_id,
            expected_identity=run._run_directory_identity,
        )
        yield owner.fd


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
class NativeTreeBuildReceipt:
    """Immutable terminal fact for one transaction-owned tree builder."""

    policy_index: int
    sealed: bool
    aborted: bool
    cleanup_settled: bool
    directories: int = 0
    files: int = 0
    size: int = 0
    sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.policy_index) is not int or self.policy_index < 0:
            raise TypeError("invalid native tree builder policy index")
        if (type(self.sealed) is not bool or type(self.aborted) is not bool
                or self.sealed == self.aborted):
            raise TypeError("native tree builder must have one terminal state")
        if type(self.cleanup_settled) is not bool:
            raise TypeError("invalid native tree builder cleanup state")
        for value in (self.directories, self.files, self.size):
            if type(value) is not int or value < 0:
                raise TypeError("invalid native tree builder count")
        if self.sealed:
            if (not self.cleanup_settled or type(self.sha256) is not str
                    or len(self.sha256) != 64
                    or any(char not in "0123456789abcdef" for char in self.sha256)):
                raise TypeError("sealed native tree builder lacks exact evidence")
        elif (self.directories or self.files or self.size or self.sha256 is not None):
            raise ValueError("aborted native tree builder cannot authenticate bytes")

    def __repr__(self) -> str:
        return (
            "NativeTreeBuildReceipt("
            f"policy_index={self.policy_index}, sealed={self.sealed}, "
            f"aborted={self.aborted}, cleanup_settled={self.cleanup_settled}, "
            f"directories={self.directories}, files={self.files}, size={self.size})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class NativeTreeEntryEvidence:
    """Immutable bytes authenticated while one builder copy was pinned."""

    components: tuple[str, ...] = field(repr=False)
    size: int
    sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.components) is not tuple or not self.components:
            raise TypeError("native tree entry evidence requires exact components")
        components = tuple(
            validate_artifact_component(component, "native tree evidence")
            for component in self.components
        )
        if type(self.size) is not int or self.size < 0:
            raise TypeError("invalid native tree entry size")
        if (type(self.sha256) is not str or len(self.sha256) != 64
                or any(char not in "0123456789abcdef" for char in self.sha256)):
            raise TypeError("invalid native tree entry digest")
        object.__setattr__(self, "components", components)

    def __repr__(self) -> str:
        return (
            "NativeTreeEntryEvidence("
            f"components={len(self.components)}, size={self.size})"
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
    anchor_descriptor: store._OwnedDescriptor = field(
        default_factory=store._OwnedDescriptor,
        repr=False,
    )
    parent_descriptor: store._OwnedDescriptor = field(
        default_factory=store._OwnedDescriptor,
        repr=False,
    )
    file_descriptor: store._OwnedDescriptor = field(
        default_factory=store._OwnedDescriptor,
        repr=False,
    )
    file_identity: tuple[int, int] | None = None
    present: bool = False
    stage: object | None = None

    @property
    def anchor_fd(self) -> int:
        return self.anchor_descriptor.fd

    @property
    def parent_fd(self) -> int:
        return self.parent_descriptor.fd

    @property
    def file_fd(self) -> int:
        return self.file_descriptor.fd


@dataclass(slots=True)
class _TreePublishOwner:
    name: str
    descriptor: store._OwnedDescriptor = field(
        default_factory=store._OwnedDescriptor,
        repr=False,
    )
    identity: tuple[int, int] | None = None
    present: bool = False

    @property
    def fd(self) -> int:
        return self.descriptor.fd


@dataclass(slots=True)
class _BuilderDescriptorAllocation:
    """Pre-registered owner for a builder descriptor allocation boundary."""

    fd: int = -1
    identity: tuple[int, int] | None = None
    close_attempted: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class _NativeRunAuthority:
    """Frozen owner and identity facts captured with one native transaction."""

    owner: store.Run = field(repr=False)
    project_dir: Path = field(repr=False)
    repository_root: Path = field(repr=False)
    run_id: str
    target: str = field(repr=False)
    started: str = field(repr=False)
    directory_identity: tuple[int, int] = field(repr=False)
    witness: object = field(repr=False)


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
    builders_done: bool = False
    builders_settled: bool = True
    builder_fault: BaseException | None = None
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
        except Exception:
            return False
        with _owned_run_anchor(run) as anchor:
            with _owned_descriptor("native discard parent descriptor") as parent:
                store._open_strict_directory_into(
                    parent, anchor, components[:-1],
                )
                try:
                    for name in os.listdir(parent.fd):
                        if not (name.startswith(".quarry-discard-") and name.endswith(".stage")):
                            continue
                        observed = os.stat(
                            name, dir_fd=parent.fd, follow_symlinks=False,
                        )
                        if _identity(observed) == identity:
                            os.unlink(name, dir_fd=parent.fd)
                            os.fsync(parent.fd)
                            return True
                    return True
                except Exception:
                    return False


def _settle_untransferred_file_name(
    owner: _FilePublishOwner,
    parent_fd: int,
) -> None:
    """Remove one exact pre-stage file while its parent descriptor is pinned."""
    try:
        observed = os.stat(
            owner.temporary_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        os.fsync(parent_fd)
        owner.present = False
    else:
        if (owner.file_identity is not None
                and _identity(observed) != owner.file_identity):
            raise ContractError("native file stage identity changed")
        if not stat.S_ISREG(observed.st_mode):
            raise ContractError("native file stage type changed")
        os.unlink(owner.temporary_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        owner.present = False


def _create_owned_file_stage(
    anchor_fd: int,
    policy: RepositoryNativeOutput,
    owner: _FilePublishOwner,
) -> None:
    """Create a privfs-compatible stage while publishing every owner transition."""
    store._open_strict_directory_into(owner.anchor_descriptor, anchor_fd, ())
    store._open_strict_directory_into(
        owner.parent_descriptor, owner.anchor_fd, policy.components[:-1],
    )
    anchor_identity = _identity(os.fstat(owner.anchor_fd))
    parent_identity = _identity(os.fstat(owner.parent_fd))
    owner.present = True
    owner.file_descriptor.open(
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
    try:
        store._settle_descriptor_owners(
            (
                owner.file_descriptor,
                owner.parent_descriptor,
                owner.anchor_descriptor,
            ),
            "native file stage descriptors",
        )
    except BaseException as fault:
        if not isinstance(fault, Exception):
            raise
        return False
    return True


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
                if owner.file_identity is None:
                    owner.file_identity = owner.file_descriptor.identity
                if owner.parent_fd < 0:
                    with _owned_run_anchor(run) as anchor:
                        with _owned_descriptor(
                            "native file recovery parent descriptor",
                        ) as parent:
                            store._open_strict_directory_into(
                                parent, anchor, owner.components[:-1],
                            )
                            _settle_untransferred_file_name(owner, parent.fd)
                else:
                    _settle_untransferred_file_name(owner, owner.parent_fd)
    except Exception:
        settled = False
    return _close_untransferred_file_owner(owner) and settled and not owner.present


def _create_owned_tree(parent_fd: int, owner: _TreePublishOwner) -> None:
    """Create a pre-named tree candidate into its mutable ownership ledger."""
    owner.present = True
    os.mkdir(owner.name, privfs.DIR_MODE, dir_fd=parent_fd)
    owner.descriptor.open(owner.name, _DIR_FLAGS, dir_fd=parent_fd)
    os.fchmod(owner.fd, privfs.DIR_MODE)
    observed = os.fstat(owner.fd)
    _validate_private_dir(observed, normalize=False, fd=owner.fd)
    owner.identity = _identity(observed)
    os.fsync(parent_fd)


def _preferred_builder_fault(
    faults: tuple[BaseException | None, ...],
) -> BaseException | None:
    """Keep the first cancellation, otherwise the first ordinary fault."""
    for fault in faults:
        if fault is not None and not isinstance(fault, Exception):
            return fault
    return next((fault for fault in faults if fault is not None), None)


class NativeTreeBuilder:
    """Opaque descriptor-relative writer for one transaction-owned TREE stage.

    Destination methods accept validated repository components only.  The sole
    path-like input is an already-open source root descriptor for ``copy_file``;
    callers never receive a destination path or destination descriptor.
    """

    __slots__ = (
        "_transaction", "_policy_index", "_stage_name", "_fd", "_identity",
        "_allocation_slots", "_effects", "_receipt", "_fault",
        "_cancellation", "_constructor_token",
    )

    def __init__(
        self,
        transaction: "NativeOutputTransaction",
        policy_index: int,
        stage_name: str,
        *,
        _constructor_token,
    ) -> None:
        if (_constructor_token is not _TREE_BUILDER_CONSTRUCTOR
                or type(transaction) is not NativeOutputTransaction):
            raise ContractError(
                "construct native tree builders through open_tree_builder",
            )
        self._transaction = transaction
        self._policy_index = policy_index
        self._stage_name = stage_name
        self._fd = -1
        self._identity = None
        self._allocation_slots: list[_BuilderDescriptorAllocation] = []
        self._effects: set[tuple[str, ...]] = set()
        self._receipt = None
        self._fault = None
        self._cancellation = None
        self._constructor_token = _constructor_token

    def __repr__(self) -> str:
        state = (
            "sealed" if self._receipt is not None and self._receipt.sealed
            else "aborted" if self._receipt is not None
            else "faulted" if self._fault is not None
            else "open"
        )
        return (
            "NativeTreeBuilder("
            f"policy_index={self._policy_index}, state={state!r})"
        )

    @property
    def receipt(self) -> NativeTreeBuildReceipt | None:
        return self._receipt

    def _remember_fault(self, fault: BaseException | None) -> None:
        if fault is None:
            return
        if (self._fault is None
                or (isinstance(self._fault, Exception)
                    and not isinstance(fault, Exception))):
            self._fault = fault
        if (self._cancellation is None
                and not isinstance(fault, Exception)):
            self._cancellation = fault

    def _track_fd(
        self,
        fd: int,
        slot: _BuilderDescriptorAllocation,
    ) -> int:
        # Publish ownership immediately after open/dup returns, before the
        # first validating syscall can be interrupted.
        observed = os.fstat(fd)
        identity = _identity(observed)
        slot.identity = identity
        return fd

    def _allocate_owned(self, allocator) -> int:
        """Allocate directly into a pre-registered mutable ownership slot."""
        slot = _BuilderDescriptorAllocation()
        self._allocation_slots.append(slot)
        # Allocation and retained-slot assignment deliberately share one line:
        # cooperative source-line cancellation cannot observe an unowned fd.
        slot.fd = allocator()
        return self._track_fd(slot.fd, slot)

    def _open_owned(
        self,
        name: str,
        flags: int,
        *,
        dir_fd: int,
        mode: int | None = None,
    ) -> int:
        if mode is None:
            return self._allocate_owned(
                lambda: os.open(name, flags, dir_fd=dir_fd),
            )
        return self._allocate_owned(
            lambda: os.open(name, flags, mode, dir_fd=dir_fd),
        )

    def _dup_owned(self, fd: int) -> int:
        return self._allocate_owned(lambda: os.dup(fd))

    def _live_descriptor_numbers(self) -> tuple[int, ...]:
        return tuple(dict.fromkeys(
            slot.fd for slot in self._allocation_slots if slot.fd >= 0
        ))

    def _close_tracked(
        self,
        fd: int,
    ) -> tuple[bool, BaseException | None]:
        slots = tuple(slot for slot in self._allocation_slots if slot.fd == fd)
        if not slots:
            return True, None
        if len(slots) != 1:
            return False, ContractError(
                "native tree descriptor ownership is ambiguous",
            )
        slot = slots[0]
        expected = slot.identity
        faults: list[BaseException] = []
        settled = False

        # A prior attempt may have closed the descriptor and then been
        # cancelled before it could tombstone the numeric slot.  Probe before
        # every retry: a missing or differently-owned number is settled, while
        # the same identity is deliberately retained because it is ambiguous
        # with same-inode descriptor reuse.
        if slot.close_attempted:
            try:
                observed = os.fstat(fd)
            except OSError as probe_fault:
                if probe_fault.errno == errno.EBADF:
                    settled = True
                else:
                    faults.append(probe_fault)
            except BaseException as probe_fault:
                faults.append(probe_fault)
            else:
                if expected is not None and _identity(observed) != expected:
                    settled = True
        else:
            try:
                # The syscall, effect marker and numeric tombstone share one
                # source line.  Cooperative source-line cancellation can occur
                # before the effect or after the tombstone, never in the unsafe
                # successful-close/stale-number gap.  The descriptor remains
                # live before the syscall; an ambiguous reported close is
                # reconciled below rather than pre-syscall tombstoned.
                os.close(fd); slot.close_attempted = True; slot.fd = -1
            except BaseException as exc:
                faults.append(exc)
                slot.close_attempted = True
                try:
                    observed = os.fstat(fd)
                except OSError as probe_fault:
                    if probe_fault.errno == errno.EBADF:
                        settled = True
                    else:
                        faults.append(probe_fault)
                except BaseException as probe_fault:
                    faults.append(probe_fault)
                else:
                    if expected is not None and _identity(observed) != expected:
                        settled = True
            else:
                settled = True  # descriptor close effect is fully recorded
        if settled:  # reconcile the terminal allocation slot
            slot.fd = -1
            if self._fd == fd:
                self._fd = -1
        return settled, _preferred_builder_fault(tuple(faults))

    def _close_many(
        self,
        descriptors: tuple[int, ...],
    ) -> tuple[bool, BaseException | None]:
        settled = True
        faults: list[BaseException | None] = []
        for fd in descriptors:
            if fd < 0:
                continue
            try:
                closed, fault = self._close_tracked(fd)
            except BaseException as exc:
                faults.append(exc)
                try:
                    closed, fault = self._close_tracked(fd)
                except BaseException as reconcile_fault:
                    closed, fault = False, reconcile_fault
            settled &= closed
            faults.append(fault)
        return settled, _preferred_builder_fault(tuple(faults))

    def _raise_operation_fault(
        self,
        primary: BaseException | None,
        cleanup: BaseException | None,
    ) -> None:
        self._remember_fault(primary)
        self._remember_fault(cleanup)
        fault = _preferred_builder_fault((primary, cleanup))
        if fault is not None:
            if primary is not None and fault is not primary:
                raise fault from primary
            raise fault

    def _validate_stage_name(self) -> None:
        transaction = self._transaction
        transaction._validate_root()
        observed = os.stat(
            self._stage_name,
            dir_fd=transaction._root_fd,
            follow_symlinks=False,
        )
        if (self._identity is not None
                and _identity(observed) != self._identity):
            raise ContractError("native tree builder stage identity changed")
        if not stat.S_ISDIR(observed.st_mode):
            raise ContractError("native tree builder stage type changed")

    def _assert_active(self) -> None:
        transaction = self._transaction
        if (type(transaction) is not NativeOutputTransaction
                or transaction._builders.get(self._policy_index) is not self):
            raise ContractError("native tree builder owner changed")
        if self._receipt is not None:
            raise ContractError("native tree builder is already terminal")
        if transaction._receipt is not None or transaction._finish_ledger is not None:
            raise ContractError("native tree builder transaction is finishing")
        if self._fd < 0 or self._identity is None:
            raise ContractError("native tree builder is not pinned")
        self._validate_stage_name()

    def _pin(self) -> None:
        transaction = self._transaction
        transaction._validate_root()
        observed = os.stat(
            self._stage_name,
            dir_fd=transaction._root_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(observed.st_mode):
            raise ContractError("native tree builder policy stage is not a directory")
        fd = self._open_owned(
            self._stage_name,
            _DIR_FLAGS,
            dir_fd=transaction._root_fd,
        )
        self._fd = fd
        pinned = os.fstat(fd)
        _validate_private_dir(pinned, normalize=False, fd=fd)
        if _identity(pinned) != _identity(observed):
            raise ContractError("native tree builder stage name changed")
        self._identity = _identity(pinned)
        self._validate_stage_name()

    @staticmethod
    def _components(
        components: tuple[str, ...],
        label: str,
        *,
        allow_empty: bool,
    ) -> tuple[str, ...]:
        if type(components) is not tuple:
            raise TypeError(f"{label} must be an exact component tuple")
        if not allow_empty and not components:
            raise ContractError(f"{label} cannot be empty")
        return tuple(
            validate_artifact_component(component, label)
            for component in components
        )

    def _open_directory_chain(
        self,
        anchor_fd: int,
        components: tuple[str, ...],
        *,
        create: bool,
        destination_prefix: tuple[str, ...] = (),
    ) -> int:
        opened: list[int] = []
        primary = None
        result = -1
        try:
            current = self._dup_owned(anchor_fd)
            opened.append(current)
            root = os.fstat(current)
            _validate_private_dir(root, normalize=False, fd=current)
            for depth, component in enumerate(components, start=1):
                created = False
                try:
                    child = self._open_owned(
                        component, _DIR_FLAGS, dir_fd=current,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    self._effects.add(
                        destination_prefix + components[:depth],
                    )
                    os.mkdir(component, privfs.DIR_MODE, dir_fd=current)
                    child = self._open_owned(
                        component, _DIR_FLAGS, dir_fd=current,
                    )
                    os.fchmod(child, privfs.DIR_MODE)
                    os.fsync(current)
                    created = True
                opened.append(child)
                pinned = os.fstat(child)
                _validate_private_dir(pinned, normalize=False, fd=child)
                named = os.stat(
                    component, dir_fd=current, follow_symlinks=False,
                )
                if _identity(named) != _identity(pinned):
                    raise ContractError("native tree directory name changed")
                if created:
                    os.fsync(child)
                current = child
            result = opened.pop()
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many(tuple(reversed(opened)))
        if not settled and cleanup is None:
            cleanup = ContractError("native tree directory descriptor did not close")
        if primary is not None or cleanup is not None:
            if result >= 0:
                extra_settled, extra_fault = self._close_many((result,))
                if not extra_settled and extra_fault is None:
                    extra_fault = ContractError(
                        "native tree result descriptor did not close",
                    )
                cleanup = _preferred_builder_fault((cleanup, extra_fault))
            self._raise_operation_fault(primary, cleanup)
        return result

    def mkdir(self, *components: str) -> None:
        """Create or authenticate one private directory chain."""
        self._assert_active()
        suffix = self._components(
            tuple(components), "native tree destination", allow_empty=False,
        )
        directory = -1
        primary = None
        try:
            directory = self._open_directory_chain(
                self._fd, suffix, create=True,
            )
            os.fsync(directory)
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many((directory,))
        if not settled and cleanup is None:
            cleanup = ContractError("native tree directory did not close")
        self._raise_operation_fault(primary, cleanup)

    def write_bytes(self, data: bytes, *components: str) -> None:
        """Create one exact private 0600 file below the TREE root."""
        self._assert_active()
        if type(data) is not bytes:
            raise TypeError("native tree data must be exact bytes")
        suffix = self._components(
            tuple(components), "native tree destination", allow_empty=False,
        )
        self._effects.add(suffix)
        parent = target = -1
        primary = None
        try:
            parent = self._open_directory_chain(
                self._fd, suffix[:-1], create=True,
            )
            target = self._open_owned(
                suffix[-1],
                _CREATE_FILE_FLAGS,
                dir_fd=parent,
                mode=privfs.FILE_MODE,
            )
            os.fchmod(target, privfs.FILE_MODE)
            _write_all(target, data)
            os.fsync(target)
            written = os.fstat(target)
            _validate_private_file(written, normalize=False, fd=target)
            named = os.stat(
                suffix[-1], dir_fd=parent, follow_symlinks=False,
            )
            if (_file_signature(named) != _file_signature(written)
                    or written.st_size != len(data)):
                raise ContractError("native tree byte write changed")
            os.fsync(parent)
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many((target, parent))
        if not settled and cleanup is None:
            cleanup = ContractError("native tree byte-write descriptor did not close")
        self._raise_operation_fault(primary, cleanup)

    def copy_file(
        self,
        source_root_fd: int,
        source_components: tuple[str, ...],
        *destination_components: str,
    ) -> NativeTreeEntryEvidence:
        """Copy one stable regular file from a pinned external source root."""
        self._assert_active()
        if type(source_root_fd) is not int or source_root_fd < 0:
            raise TypeError("native tree source root must be an open descriptor")
        source_suffix = self._components(
            source_components, "native tree source", allow_empty=False,
        )
        destination_suffix = self._components(
            tuple(destination_components),
            "native tree destination",
            allow_empty=False,
        )
        self._effects.add(destination_suffix)
        source_parent = source = destination_parent = destination = -1
        primary = None
        evidence = None
        try:
            source_parent = self._open_directory_chain(
                source_root_fd, source_suffix[:-1], create=False,
            )
            source = self._open_owned(
                source_suffix[-1], _FILE_FLAGS, dir_fd=source_parent,
            )
            before = os.fstat(source)
            _validate_private_file(before, normalize=False, fd=source)
            named_before = os.stat(
                source_suffix[-1],
                dir_fd=source_parent,
                follow_symlinks=False,
            )
            if _file_signature(named_before) != _file_signature(before):
                raise ContractError("native tree source name changed")

            destination_parent = self._open_directory_chain(
                self._fd, destination_suffix[:-1], create=True,
            )
            destination = self._open_owned(
                destination_suffix[-1],
                _CREATE_FILE_FLAGS,
                dir_fd=destination_parent,
                mode=privfs.FILE_MODE,
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
            named_after = os.stat(
                source_suffix[-1],
                dir_fd=source_parent,
                follow_symlinks=False,
            )
            if (_file_signature(after) != _file_signature(before)
                    or _file_signature(named_after) != _file_signature(before)
                    or size != before.st_size):
                raise ContractError("native tree source changed while copying")
            written = os.fstat(destination)
            _validate_private_file(written, normalize=False, fd=destination)
            named_destination = os.stat(
                destination_suffix[-1],
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
            if (_file_signature(named_destination) != _file_signature(written)
                    or written.st_size != size):
                raise ContractError("native tree destination changed while copying")
            # Keep the content digest live until all identity checks completed;
            # seal independently authenticates the entire resulting tree.
            evidence = NativeTreeEntryEvidence(
                destination_suffix, size, digest.hexdigest(),
            )
            os.fsync(destination_parent)
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many((
            destination, destination_parent, source, source_parent,
        ))
        if not settled and cleanup is None:
            cleanup = ContractError("native tree copy descriptor did not close")
        self._raise_operation_fault(primary, cleanup)
        if evidence is None:  # pragma: no cover - operation faults raise above
            raise ContractError("native tree copy lacks authenticated evidence")
        return evidence

    def _open_repository_source_root(self) -> int:
        """Pin this transaction's exact Run through builder-owned fds."""
        authority = self._transaction._require_run_authority()
        repository_root = authority.repository_root
        root = run_fd = -1
        primary = None
        try:
            root = self._allocate_owned(
                lambda: os.open(repository_root, _DIR_FLAGS),
            )
            root_observed = os.fstat(root)
            _validate_private_dir(root_observed, normalize=False, fd=root)
            run_fd = self._open_owned(
                authority.run_id, _DIR_FLAGS, dir_fd=root,
            )
            observed = os.fstat(run_fd)
            _validate_private_dir(observed, normalize=False, fd=run_fd)
            if _identity(observed) != authority.directory_identity:
                raise ContractError("native tree source Run identity changed")
            creation = self._read_repository_identity_file(
                run_fd, "run.json", required=True,
            )
            manifest = self._read_repository_identity_file(
                run_fd, "manifest.json", required=False,
            )
            expected = (
                authority.run_id, authority.target, authority.started,
            )
            if (creation.get("run_id"), creation.get("target"),
                    creation.get("started")) != expected:
                raise ContractError("native tree source Run authority changed")
            if (manifest is not None
                    and (manifest.get("run_id"), manifest.get("target"),
                         manifest.get("started")) != expected):
                raise ContractError("native tree source Run identities disagree")
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many((root,))
        if not settled and cleanup is None:
            cleanup = ContractError(
                "native tree repository-root descriptor did not close",
            )
        if primary is not None or cleanup is not None:
            if run_fd >= 0:
                extra_settled, extra_fault = self._close_many((run_fd,))
                if not extra_settled and extra_fault is None:
                    extra_fault = ContractError(
                        "native tree Run descriptor did not close",
                    )
                cleanup = _preferred_builder_fault((cleanup, extra_fault))
            self._raise_operation_fault(primary, cleanup)
        return run_fd

    def _read_repository_identity_file(
        self,
        run_fd: int,
        name: str,
        *,
        required: bool,
    ) -> dict | None:
        """Read one bounded Run identity through builder-owned descriptors."""
        identity_fd = -1
        try:
            identity_fd = self._open_owned(name, _FILE_FLAGS, dir_fd=run_fd)
        except FileNotFoundError as exc:
            if required:
                raise ContractError(
                    f"native tree source Run lacks {name}",
                ) from exc
            return None
        primary = None
        record = None
        try:
            before = os.fstat(identity_fd)
            _validate_private_file(before, normalize=False, fd=identity_fd)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(
                    identity_fd,
                    min(
                        65536,
                        _MAX_REPOSITORY_IDENTITY_BYTES + 1 - size,
                    ),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > _MAX_REPOSITORY_IDENTITY_BYTES:
                    raise ContractError(
                        f"native tree source Run {name} is too large",
                    )
            after = os.fstat(identity_fd)
            if _file_signature(after) != _file_signature(before):
                raise ContractError(
                    f"native tree source Run {name} changed while reading",
                )
            try:
                candidate = json.loads(b"".join(chunks).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError,
                    RecursionError) as exc:
                if required:
                    raise ContractError(
                        f"native tree source Run {name} is malformed",
                    ) from exc
            else:
                if type(candidate) is dict:
                    record = candidate
                elif required:
                    raise ContractError(
                        f"native tree source Run {name} is malformed",
                    )
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many((identity_fd,))
        if not settled and cleanup is None:
            cleanup = ContractError(
                "native tree Run identity descriptor did not close",
            )
        self._raise_operation_fault(primary, cleanup)
        if required and record is None:
            raise ContractError(
                f"native tree source Run {name} is malformed",
            )
        return record

    def copy_repository_file(
        self,
        source_components: tuple[str, ...],
        *destination_components: str,
    ) -> NativeTreeEntryEvidence:
        """Copy one stable file from this transaction's exact repository Run."""
        self._assert_active()
        source_suffix = self._components(
            source_components, "native tree repository source", allow_empty=False,
        )
        destination_suffix = self._components(
            tuple(destination_components),
            "native tree destination",
            allow_empty=False,
        )
        source_root = -1
        evidence = None
        primary = None
        try:
            source_root = self._open_repository_source_root()
            evidence = self.copy_file(
                source_root, source_suffix, *destination_suffix,
            )
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_many((source_root,))
        if not settled and cleanup is None:
            cleanup = ContractError("native tree Run descriptor did not close")
        self._raise_operation_fault(primary, cleanup)
        if evidence is None:  # pragma: no cover - operation faults raise above
            raise ContractError("repository copy lacks authenticated evidence")
        return evidence

    def _close_pinned(self) -> tuple[bool, BaseException | None]:
        return self._close_many((self._fd,))

    def seal(self) -> NativeTreeBuildReceipt:
        """Authenticate and durably close the exact current tree generation."""
        if self._receipt is not None:
            if self._receipt.sealed:
                return self._receipt
            raise ContractError("aborted native tree builder cannot be sealed")
        self._assert_active()
        if self._fault is not None or self._cancellation is not None:
            raise ContractError("faulted native tree builder cannot be sealed")
        if set(self._live_descriptor_numbers()) != {self._fd}:
            raise ContractError("native tree builder has unsettled descriptors")
        primary = None
        entries = None
        try:
            self._validate_stage_name()
            entries = _snapshot_tree_recursive(self._fd, (), normalize=False)
            self._validate_stage_name()
        except BaseException as exc:
            primary = exc
        settled, cleanup = self._close_pinned()
        if not settled and cleanup is None:
            cleanup = ContractError("native tree builder descriptor did not close")
        fault = _preferred_builder_fault((primary, cleanup))
        self._remember_fault(primary)
        self._remember_fault(cleanup)
        if primary is None and settled and entries is not None:
            receipt = NativeTreeBuildReceipt(
                policy_index=self._policy_index,
                sealed=True,
                aborted=False,
                cleanup_settled=True,
                directories=sum(entry.directory for entry in entries),
                files=sum(not entry.directory for entry in entries),
                size=sum(entry.size for entry in entries if not entry.directory),
                sha256=_tree_digest(entries),
            )
            self._receipt = receipt
        if fault is not None:
            if primary is not None and fault is not primary:
                raise fault from primary
            raise fault
        if self._receipt is None:
            raise ContractError("native tree builder could not be sealed")
        return self._receipt

    def abort(self) -> NativeTreeBuildReceipt:
        """Idempotently fence every descriptor without publishing the tree."""
        if self._receipt is not None:
            return self._receipt
        settled = True
        faults: list[BaseException | None] = []
        attempt_settled, fault = self._close_many(
            self._live_descriptor_numbers(),
        )
        settled &= attempt_settled
        faults.append(fault)
        if self._live_descriptor_numbers():
            settled = False
        fault = _preferred_builder_fault(tuple(faults))
        self._remember_fault(fault)
        receipt = NativeTreeBuildReceipt(
            policy_index=self._policy_index,
            sealed=False,
            aborted=True,
            cleanup_settled=settled,
        )
        self._receipt = receipt
        if fault is not None:
            raise fault
        return receipt


class NativeOutputTransaction:
    """One durable claim spanning private native output staging and publication."""

    __slots__ = (
        "_run_authority", "_run_witness", "policies", "rewritten_cmd",
        "_base_fd", "_root_fd",
        "_root_name", "_root_identity", "_root_present", "_claim_name",
        "_claim_identity", "_claim_present", "_receipt", "_finish_ledger",
        "_stage_names", "_builders", "_adoption", "_constructor_token",
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
        witness = object()
        project_dir = Path(run.project_dir)
        self._run_witness = witness
        self._run_authority = _NativeRunAuthority(
            owner=run,
            project_dir=project_dir,
            repository_root=Path(os.path.abspath(project_dir)) / "recon",
            run_id=run.run_id,
            target=run.target,
            started=run.started,
            directory_identity=run._run_directory_identity,
            witness=witness,
        )
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
        self._builders: dict[int, NativeTreeBuilder] = {}
        self._adoption = adoption
        self._constructor_token = _constructor_token
        adoption._adopt_transaction(self)

    @property
    def run(self) -> store.Run:
        """The exact immutable Run owner captured by this transaction."""
        return self._run_authority.owner

    @run.setter
    def run(self, _replacement) -> None:
        raise ContractError("native output Run authority is immutable")

    def _require_run_authority(self) -> _NativeRunAuthority:
        authority = self._run_authority
        owner = authority.owner
        if (type(authority) is not _NativeRunAuthority
                or authority.witness is not self._run_witness
                or type(owner) is not store.Run
                or Path(owner.project_dir) != authority.project_dir
                or owner.run_id != authority.run_id
                or owner.target != authority.target
                or owner.started != authority.started
                or owner._run_directory_identity != authority.directory_identity):
            raise ContractError("native output Run authority changed")
        return authority

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

    def open_tree_builder(self, policy_index: int = 0) -> NativeTreeBuilder:
        """Pin one TREE stage behind a destination-path-free build capability."""
        if type(self) is not NativeOutputTransaction:
            raise TypeError("native tree builder requires an exact transaction")
        if type(policy_index) is not int:
            raise TypeError("native tree builder policy index must be an exact int")
        if policy_index < 0 or policy_index >= len(self.policies):
            raise IndexError("native tree builder policy index is out of range")
        if self.policies[policy_index].kind is not NativeOutputKind.TREE:
            raise ContractError("native tree builder requires a TREE policy")
        if self._receipt is not None or self._finish_ledger is not None:
            raise ContractError("native output transaction is already finishing")
        if policy_index in self._builders:
            raise ContractError("native tree builder policy is already owned")
        builder = NativeTreeBuilder(
            self,
            policy_index,
            self._stage_names[policy_index],
            _constructor_token=_TREE_BUILDER_CONSTRUCTOR,
        )
        # Publish ownership before pinning a descriptor.  A reported fault at
        # the helper return boundary therefore remains fenceable by finish().
        self._builders[policy_index] = builder
        primary = None
        try:
            builder._pin()
        except BaseException as exc:
            primary = exc
        if primary is not None:
            cleanup = None
            try:
                builder.abort()
            except BaseException as exc:
                cleanup = exc
            fault = _preferred_builder_fault((primary, cleanup))
            if fault is not None:
                if fault is not primary:
                    raise fault from primary
                raise fault
            raise primary
        return builder

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

    def _validate_builder_snapshots(
        self,
        snapshots: tuple[_Snapshot, ...],
    ) -> None:
        """Bind every sealed builder to the generation finish will publish."""
        for policy_index, builder in self._builders.items():
            receipt = builder.receipt
            if receipt is None or not receipt.sealed:
                raise ContractError("native tree builder is not sealed")
            if builder._identity is None:
                raise ContractError("native tree builder lacks a stage identity")
            named = os.stat(
                self._stage_names[policy_index],
                dir_fd=self._root_fd,
                follow_symlinks=False,
            )
            snapshot = snapshots[policy_index]
            if (_identity(named) != builder._identity
                    or not snapshot.evidence.present
                    or snapshot.evidence.size != receipt.size
                    or snapshot.evidence.sha256 != receipt.sha256
                    or sum(entry.directory for entry in snapshot.entries)
                    != receipt.directories
                    or sum(not entry.directory for entry in snapshot.entries)
                    != receipt.files):
                raise ContractError(
                    "native tree builder generation changed after seal",
                )

    def _open_source_file_into(
        self,
        destination: store._OwnedDescriptor,
        name: str,
    ) -> None:
        self._validate_root()
        destination.open(name, _FILE_FLAGS, dir_fd=self._root_fd)

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
        fault = None
        disposition = "unpublished"
        cleanup_settled = True
        source = store._OwnedDescriptor()
        try:
            with _settled_descriptors(
                (
                    owner.file_descriptor,
                    owner.parent_descriptor,
                    owner.anchor_descriptor,
                    source,
                ),
                "native file publication descriptors",
            ):
                try:
                    self._open_source_file_into(source, name)
                    before = os.fstat(source.fd)
                    _validate_private_file(before, normalize=False, fd=source.fd)
                    with self.run._mutation(store.MutationScope.BASE_EVIDENCE):
                        self.run._ensure_artifact_parent(policy.components)
                        with _owned_run_anchor(self.run) as anchor:
                            _create_owned_file_stage(anchor, policy, owner)
                        stage = owner.stage
                        if type(stage) is not privfs.PrivateFileStage:
                            raise ContractError("native file stage construction did not settle")
                        digest = hashlib.sha256()
                        size = 0
                        while True:
                            chunk = os.read(source.fd, 1024 * 1024)
                            if not chunk:
                                break
                            _write_all(stage.file_fd, chunk)
                            digest.update(chunk)
                            size += len(chunk)
                        after = os.fstat(source.fd)
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
        except BaseException as ownership_fault:
            cleanup_settled = False
            fault = store._preferred_settlement_fault(fault, [ownership_fault])
        settlement.record(_PublishResult(disposition, cleanup_settled, fault))

    def _publish_file_absence(self, policy: RepositoryNativeOutput) -> _PublishResult:
        fault = None
        disposition = "unpublished"
        cleanup_settled = True
        backup = f".quarry-native-prior-{os.urandom(16).hex()}"
        prior_identity = None
        action_started = False
        try:
            with self.run._mutation(store.MutationScope.BASE_EVIDENCE):
                with _owned_run_anchor(self.run) as anchor:
                    with _owned_descriptor(
                        "native absence parent descriptor",
                    ) as parent:
                        try:
                            store._open_strict_directory_into(
                                parent, anchor, policy.components[:-1],
                            )
                        except privfs.PrivatePathMissing:
                            disposition = "committed"
                            parent_missing = True
                        else:
                            parent_missing = False
                        if not parent_missing:
                            with _owned_descriptor(
                                "native absence prior descriptor",
                            ) as prior:
                                try:
                                    prior.open(
                                        policy.components[-1],
                                        _FILE_FLAGS,
                                        dir_fd=parent.fd,
                                    )
                                except FileNotFoundError:
                                    disposition = "committed"
                                    prior_missing = True
                                else:
                                    prior_missing = False
                                if not prior_missing:
                                    try:
                                        observed = os.fstat(prior.fd)
                                        _validate_private_file(
                                            observed, normalize=False, fd=prior.fd,
                                        )
                                        prior_identity = _identity(observed)
                                        action_started = True
                                        os.rename(
                                            policy.components[-1], backup,
                                            src_dir_fd=parent.fd,
                                            dst_dir_fd=parent.fd,
                                        )
                                        if _named_identity(parent.fd, backup) != prior_identity:
                                            raise ContractError(
                                                "native output absence could not retain prior evidence",
                                            )
                                        os.fsync(parent.fd)
                                        if _named_identity(
                                            parent.fd, policy.components[-1],
                                        ) is not None:
                                            raise ContractError(
                                                "native output absence did not settle",
                                            )
                                        disposition = "committed"
                                        try:
                                            os.unlink(backup, dir_fd=parent.fd)
                                            os.fsync(parent.fd)
                                        except BaseException as cleanup_error:
                                            cleanup_settled, fault = False, cleanup_error
                                    except BaseException as exc:
                                        fault = exc
                                        if action_started and prior_identity is not None:
                                            final_identity = _named_identity(
                                                parent.fd, policy.components[-1],
                                            )
                                            backup_identity = _named_identity(
                                                parent.fd, backup,
                                            )
                                            if (final_identity is None
                                                    and backup_identity == prior_identity):
                                                disposition, cleanup_settled = "uncertain", False
                                            elif final_identity == prior_identity:
                                                disposition = "unpublished"
                                            else:
                                                disposition, cleanup_settled = "uncertain", False
        except BaseException as ownership_fault:
            cleanup_settled = False
            fault = store._preferred_settlement_fault(fault, [ownership_fault])
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
        prior_identity = None
        action_started = False
        exchanged = False
        disposition = "unpublished"
        cleanup_settled = True
        fault = None
        source = store._OwnedDescriptor()
        parent = store._OwnedDescriptor()
        prior = store._OwnedDescriptor()
        final = store._OwnedDescriptor()
        try:
            with _settled_descriptors(
                (final, prior, parent, source, owner.descriptor),
                "native tree publication descriptors",
            ):
                try:
                    self._validate_root()
                    source.open(name, _DIR_FLAGS, dir_fd=self._root_fd)
                    builder = self._builders.get(settlement.evidence.policy_index)
                    if (builder is not None
                            and _identity(os.fstat(source.fd)) != builder._identity):
                        raise ContractError(
                            "native tree builder stage changed before publication",
                        )
                    with self.run._mutation(store.MutationScope.BASE_EVIDENCE):
                        self.run._ensure_artifact_parent(policy.components)
                        with _owned_run_anchor(self.run) as anchor:
                            store._open_strict_directory_into(
                                parent, anchor, policy.components[:-1],
                            )
                        _create_owned_tree(parent.fd, owner)
                        _copy_tree_snapshot(source.fd, owner.fd, snapshot)
                        os.fsync(owner.fd)
                        try:
                            store._open_strict_directory_into(
                                prior, parent.fd, (policy.components[-1],),
                            )
                        except privfs.PrivatePathMissing:
                            pass
                        if prior.fd >= 0:
                            prior_identity = _identity(os.fstat(prior.fd))
                            action_started = True
                            try:
                                _rename_exchange(
                                    parent.fd,
                                    owner.name,
                                    parent.fd,
                                    policy.components[-1],
                                )
                            except BaseException as exchange_error:
                                final_identity = _named_identity(
                                    parent.fd, policy.components[-1],
                                )
                                hidden_identity = _named_identity(
                                    parent.fd, owner.name,
                                )
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
                                    src_dir_fd=parent.fd,
                                    dst_dir_fd=parent.fd,
                                )
                            except BaseException as rename_error:
                                final_identity = _named_identity(
                                    parent.fd, policy.components[-1],
                                )
                                hidden_identity = _named_identity(
                                    parent.fd, owner.name,
                                )
                                if (final_identity == owner.identity
                                        and hidden_identity is None):
                                    fault = rename_error
                                elif (final_identity is None
                                        and hidden_identity == owner.identity):
                                    raise
                                else:
                                    raise privfs.PrivateReplaceUncertain(
                                        "native tree rename outcome is uncertain",
                                        components=policy.components,
                                    ) from rename_error
                            owner.present = False
                        os.fsync(parent.fd)
                        store._open_strict_directory_into(
                            final, parent.fd, (policy.components[-1],),
                        )
                        if _identity(os.fstat(final.fd)) != owner.identity:
                            raise ContractError("native tree final identity changed")
                        final_entries = _snapshot_tree_recursive(
                            final.fd, (), normalize=False,
                        )
                        if (final_entries != snapshot.entries
                                or _tree_digest(final_entries) != snapshot.evidence.sha256):
                            raise ContractError("native tree final bytes changed")
                        disposition = "committed"
                        if exchanged and prior_identity is not None:
                            try:
                                _remove_named_tree(
                                    parent.fd,
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
                    if owner.identity is None:
                        owner.identity = owner.descriptor.identity
                    if action_started and parent.fd >= 0 and owner.identity is not None:
                        final_identity = _named_identity(
                            parent.fd, policy.components[-1],
                        )
                        hidden_identity = _named_identity(parent.fd, owner.name)
                        if final_identity == owner.identity:
                            owner.present = False
                            disposition, cleanup_settled = "uncertain", False
                        elif hidden_identity == owner.identity:
                            owner.present = True
                            disposition = "unpublished"
                        else:
                            disposition, cleanup_settled = "uncertain", False
                    if (disposition == "unpublished"
                            and parent.fd >= 0 and owner.identity is not None):
                        try:
                            if _named_identity(parent.fd, owner.name) == owner.identity:
                                _remove_named_tree(
                                    parent.fd,
                                    owner.name,
                                    expected_identity=owner.identity,
                                )
                                owner.present = False
                        except BaseException:
                            cleanup_settled = False
        except BaseException as ownership_fault:
            cleanup_settled = False
            fault = store._preferred_settlement_fault(fault, [ownership_fault])
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
        parent = store._OwnedDescriptor()
        hidden = store._OwnedDescriptor()
        try:
            with _settled_descriptors(
                (hidden, parent), "native tree recovery descriptors",
            ):
                with self.run._mutation(store.MutationScope.CONTROL):
                    with _owned_run_anchor(self.run) as anchor:
                        store._open_strict_directory_into(
                            parent, anchor, policy.components[:-1],
                        )
                    if owner.identity is None and owner.fd >= 0:
                        owner.identity = _identity(os.fstat(owner.fd))
                    final_identity = _named_identity(
                        parent.fd, policy.components[-1],
                    )
                    hidden_identity = _named_identity(parent.fd, owner.name)
                    if owner.identity is None and hidden_identity is not None:
                        hidden.open(owner.name, _DIR_FLAGS, dir_fd=parent.fd)
                        observed = os.fstat(hidden.fd)
                        _validate_private_dir(
                            observed, normalize=True, fd=hidden.fd,
                        )
                        owner.identity = _identity(observed)
                        hidden_identity = owner.identity
                    if owner.identity is not None and final_identity == owner.identity:
                        owner.present = False
                        settlement.record(_PublishResult("uncertain", False, fault))
                    elif owner.identity is not None and hidden_identity == owner.identity:
                        _remove_named_tree(
                            parent.fd, owner.name, expected_identity=owner.identity,
                        )
                        owner.present = False
                        settlement.record(_PublishResult("unpublished", True, fault))
                    elif final_identity is None and hidden_identity is None:
                        owner.present = False
                        settlement.record(_PublishResult("unpublished", True, fault))
                    else:
                        settlement.record(_PublishResult("uncertain", False, fault))
        except BaseException as recovery_fault:
            settlement.record(_PublishResult("uncertain", False, fault))
            result = settlement.result
            if result is not None and recovery_fault is not fault:
                settlement.record(_PublishResult(
                    result.disposition,
                    False,
                    store._preferred_settlement_fault(
                        result.fault or fault, [recovery_fault],
                    ),
                ))

    def _store_receipt(
        self,
        receipt: NativeOutputReceipt,
    ) -> None:
        self._receipt = receipt

    def _settle_tree_builders(self, ledger: _FinishLedger) -> None:
        """Close every builder before validation, preserving cancellation."""
        if ledger.builders_done:
            return
        settled = True
        builder_faults: list[BaseException | None] = []
        refused = False
        for builder in tuple(self._builders.values()):
            receipt = builder.receipt
            if (ledger.requested_clean
                    and (receipt is None or not receipt.sealed
                         or builder._fault is not None
                         or builder._cancellation is not None)):
                refused = True
            if receipt is None:
                try:
                    receipt = builder.abort()
                except BaseException as exc:
                    builder_faults.append(exc)
                    receipt = builder.receipt
            builder_faults.append(builder._fault)
            if builder._cancellation is not None and ledger.cancellation is None:
                ledger.cancellation = builder._cancellation
            if receipt is None or not receipt.cleanup_settled:
                settled = False
        if refused and ledger.validation_fault is None:
            ledger.validation_fault = ContractError(
                "native tree builder must be fault-free and sealed before clean finish",
            )
        ledger.builders_settled = settled
        ledger.builder_fault = _preferred_builder_fault(tuple(builder_faults))
        if (ledger.builder_fault is not None
                and not isinstance(ledger.builder_fault, Exception)
                and ledger.cancellation is None):
            ledger.cancellation = ledger.builder_fault
        ledger.builders_done = True

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

        if not ledger.builders_done:
            self._settle_tree_builders(ledger)

        if not ledger.validation_done:
            if not ledger.requested_clean or ledger.validation_fault is not None:
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
                    self._validate_builder_snapshots(snapshots)
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
            ledger.cleanup_settled = ledger.builders_settled and attempt_settled
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
        elif ledger.builder_fault is not None:
            fault_operation, fault = "cleanup", ledger.builder_fault
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
        with _owned_run_anchor(run) as anchor:
            with _owned_descriptor("native seed source descriptor") as source:
                try:
                    store._open_strict_directory_into(
                        source, anchor, policy.components,
                    )
                except privfs.PrivatePathMissing:
                    return
                entries = _snapshot_tree_recursive(
                    source.fd, (), normalize=False,
                )
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
                _copy_tree_snapshot(source.fd, destination_fd, snapshot)


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
    except BaseException as primary:
        cancellation = primary if not isinstance(primary, Exception) else None
        for _attempt in range(2):
            try:
                receipt = adoption.fence()
            except BaseException as cleanup_fault:
                if (cancellation is None
                        and not isinstance(cleanup_fault, Exception)):
                    cancellation = cleanup_fault
                continue
            if (receipt is None
                    or (receipt.cleanup_settled and not receipt.claim_retained)):
                break
        if cancellation is not None and cancellation is not primary:
            raise cancellation from primary
        raise
