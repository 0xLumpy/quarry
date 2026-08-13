"""Repository-owned publication seam for authenticated runner executions.

``runner_supervisor`` deliberately returns settled private stages without
publishing them.  This module composes that execution fact with the run's one
mutation authority.  A durable lifecycle claim spans stage preparation,
execution, settlement and the final publish-or-fence decision.

The two output policies are named and mandatory.  ``publish`` means the exact
settled artifact is requested at one validated base-evidence identity;
``discard`` means the worker drains the stream but receives no retention
descriptor.  Absence is therefore never guessed to mean a requested artifact.
"""
from __future__ import annotations

import math
import os
import stat
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum

from . import privfs, store
from .privfs import (
    PrivateStageArtifactProof,
    PrivateStageHandoffBatch,
    PrivateStageHandoffError,
    PrivateStagePublicationCommittedWithFault,
    PrivateStagePublicationPartial,
)
from .runner_protocol import NormalizedInvocation, StreamRole
from .runner_supervisor import ExecutionOutcome, ExecutionReason, supervise_execution
from .state import ContractError


@contextmanager
def _owned_descriptor(what, *, expected_identity=None):
    """Activate two settlement passes before one descriptor can be allocated."""
    owner = store._OwnedDescriptor(expected_identity)
    settlement = store._SettlementOwner(
        lambda: store._settle_descriptor_owners(
            (owner,), what,
        ),
    )
    with store._SettlementFence(settlement):
        with store._SettlementFence(settlement):
            yield owner


@contextmanager
def _owned_run_anchor(run: store.Run):
    """Keep one exact run descriptor owned across repository publication."""
    with _owned_descriptor(
        "repository runner descriptor",
        expected_identity=run._run_directory_identity,
    ) as owner:
        store._open_run_fd_into(
            owner,
            run.project_dir,
            run.run_id,
            expected_identity=run._run_directory_identity,
        )
        yield owner.fd


class ArtifactDisposition(str, Enum):
    """One explicit caller decision for a worker output stream."""

    PUBLISH = "publish"
    DISCARD = "discard"


@dataclass(frozen=True, slots=True, repr=False)
class RepositoryOutput:
    """Validated repository destination policy for one named output stream."""

    disposition: ArtifactDisposition
    components: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if type(self.disposition) is not ArtifactDisposition:
            raise TypeError("invalid repository output disposition")
        if type(self.components) is not tuple:
            raise TypeError("repository output components must be a tuple")
        if self.disposition is ArtifactDisposition.PUBLISH:
            validated = store._validated_artifact_components(self.components)
            object.__setattr__(self, "components", validated)
        elif self.components:
            raise ContractError("discarded output cannot name an artifact")

    @classmethod
    def publish(cls, *components: str) -> "RepositoryOutput":
        return cls(ArtifactDisposition.PUBLISH, tuple(components))

    @classmethod
    def publish_path(cls, run: store.Run, path) -> "RepositoryOutput":
        """Bind one caller-held path to an exact opened ``Run`` authority."""
        if type(run) is not store.Run:
            raise TypeError("publication path requires an exact repository Run")
        managed = store.managed_run_for_artifact(path)
        if managed is None:
            raise ContractError("publication path is not a managed run artifact")
        owner, components = managed
        if (owner._authority_key != run._authority_key
                or owner._run_directory_identity != run._run_directory_identity):
            raise ContractError("publication path belongs to a different run")
        return cls.publish(*components)

    @classmethod
    def discard(cls) -> "RepositoryOutput":
        return cls(ArtifactDisposition.DISCARD)

    def __repr__(self) -> str:
        return f"RepositoryOutput(disposition={self.disposition.value!r})"


class RepositoryPublication(str, Enum):
    """Terminal repository disposition of one execution's output claims."""

    NOT_REQUESTED = "not_requested"
    PUBLISHED = "published"
    FENCED = "fenced"
    PARTIAL = "partial"
    COMMITTED_WITH_FAULT = "committed_with_fault"


def _proof_tuple(value, label: str) -> tuple[PrivateStageArtifactProof, ...]:
    if (type(value) is not tuple
            or any(type(item) is not PrivateStageArtifactProof for item in value)):
        raise TypeError(f"invalid {label} artifact proof tuple")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RepositoryExecutionOutcome:
    """Immutable execution plus the repository's exact publication partition."""

    execution: ExecutionOutcome = field(repr=False)
    publication: RepositoryPublication
    requested_roles: tuple[StreamRole, ...]
    discarded_roles: tuple[StreamRole, ...]
    published: tuple[PrivateStageArtifactProof, ...] = field(
        default=(), repr=False,
    )
    uncertain: tuple[PrivateStageArtifactProof, ...] = field(
        default=(), repr=False,
    )
    unpublished: tuple[PrivateStageArtifactProof, ...] = field(
        default=(), repr=False,
    )
    ownership_settled: bool = True
    fault_operation: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.execution) is not ExecutionOutcome:
            raise TypeError("repository outcome requires supervisor authority")
        if type(self.publication) is not RepositoryPublication:
            raise TypeError("invalid repository publication state")
        if type(self.ownership_settled) is not bool:
            raise TypeError("invalid repository ownership state")
        output_roles = (StreamRole.STDOUT, StreamRole.STDERR)
        for value, label in (
            (self.requested_roles, "requested roles"),
            (self.discarded_roles, "discarded roles"),
        ):
            if (type(value) is not tuple
                    or any(type(role) is not StreamRole for role in value)):
                raise TypeError(f"invalid {label}")
        combined = tuple(
            role for role in output_roles
            if role in self.requested_roles or role in self.discarded_roles
        )
        if (combined != output_roles
                or set(self.requested_roles).intersection(self.discarded_roles)
                or tuple(role for role in output_roles if role in self.requested_roles)
                != self.requested_roles
                or tuple(role for role in output_roles if role in self.discarded_roles)
                != self.discarded_roles):
            raise ValueError("repository output policies are not a partition")
        published = _proof_tuple(self.published, "published")
        uncertain = _proof_tuple(self.uncertain, "uncertain")
        unpublished = _proof_tuple(self.unpublished, "unpublished")
        proof_ids = [id(proof) for group in (published, uncertain, unpublished)
                     for proof in group]
        if len(proof_ids) != len(set(proof_ids)):
            raise ValueError("artifact publication partitions overlap")
        execution_ids = tuple(id(proof) for proof in self.execution.artifact_proofs)
        partition_ids = tuple(id(proof) for group in (
            published, uncertain, unpublished,
        ) for proof in group)
        if sorted(partition_ids) != sorted(execution_ids):
            raise ValueError("artifact publication partition is incomplete")
        if self.fault_operation not in {None, "execute", "fence", "publish", "cleanup"}:
            raise ValueError("invalid repository publication fault")
        if self.publication is RepositoryPublication.NOT_REQUESTED:
            if self.requested_roles or execution_ids:
                raise ValueError("unrequested publication owns artifact proofs")
        elif self.publication is RepositoryPublication.PUBLISHED:
            if (not self.requested_roles or self.published is not self.execution.artifact_proofs
                    or uncertain or unpublished or self.fault_operation is not None
                    or not self.ownership_settled):
                raise ValueError("invalid clean publication outcome")
        elif self.publication is RepositoryPublication.FENCED:
            if published or uncertain:
                raise ValueError("fenced execution published evidence")
        elif self.publication is RepositoryPublication.COMMITTED_WITH_FAULT:
            if (self.published != self.execution.artifact_proofs
                    or uncertain or unpublished):
                raise ValueError("invalid committed-with-fault partition")

    @property
    def clean(self) -> bool:
        expected = (
            RepositoryPublication.PUBLISHED
            if self.requested_roles
            else RepositoryPublication.NOT_REQUESTED
        )
        return (self.execution.transaction_complete
                and self.publication is expected
                and self.ownership_settled)

    def __repr__(self) -> str:
        return (
            "RepositoryExecutionOutcome("
            f"execution={self.execution.reason.value!r}, "
            f"publication={self.publication.value!r}, clean={self.clean}, "
            f"ownership_settled={self.ownership_settled}, "
            f"requested={len(self.requested_roles)}, "
            f"published={len(self.published)}, uncertain={len(self.uncertain)}, "
            f"unpublished={len(self.unpublished)})"
        )


def _expected_output_path(run: store.Run, output: RepositoryOutput) -> str | None:
    if output.disposition is ArtifactDisposition.DISCARD:
        return None
    return os.path.abspath(os.path.normpath(str(run.dir.joinpath(*output.components))))


def _validate_output_policies(
    run: store.Run,
    invocation: NormalizedInvocation,
    stdout: RepositoryOutput,
    stderr: RepositoryOutput,
) -> tuple[tuple[StreamRole, RepositoryOutput], ...]:
    """Validate every identity without creating a marker, directory or stage."""
    if type(run) is not store.Run:
        raise TypeError("run must be an opened repository Run")
    if type(invocation) is not NormalizedInvocation:
        raise TypeError("invocation must be normalized before repository execution")
    if type(stdout) is not RepositoryOutput or type(stderr) is not RepositoryOutput:
        raise TypeError("stdout and stderr require explicit repository policies")

    policies = (
        (StreamRole.STDOUT, stdout),
        (StreamRole.STDERR, stderr),
    )
    for role, policy in policies:
        label = role.value
        observed_path = (
            invocation.raw_path
            if role is StreamRole.STDOUT
            else invocation.stderr_path
        )
        expected_path = _expected_output_path(run, policy)
        claim = invocation.worker.claim_for(role)
        requested = policy.disposition is ArtifactDisposition.PUBLISH
        if (requested != (claim is not None)
                or requested != (observed_path is not None)
                or observed_path != expected_path):
            raise ContractError(f"{label} policy does not match normalized invocation")
        if not requested:
            continue
        managed = store.managed_run_for_artifact(observed_path)
        if managed is None:
            raise ContractError(f"{label} policy is not a managed run artifact")
        owner, components = managed
        if (owner._authority_key != run._authority_key
                or owner._run_directory_identity != run._run_directory_identity
                or components != policy.components):
            raise ContractError(f"{label} policy belongs to a different run artifact")
    return policies


@dataclass(slots=True, repr=False)
class _DurableRunClaim:
    """One durable claim marker whose release requires proven terminal ownership."""

    run: store.Run
    marker: store._ArtifactMarkerRelease = field(repr=False)
    released: bool = False

    @classmethod
    def acquire(cls, run: store.Run) -> "_DurableRunClaim":
        claim = cls(run, store._ArtifactMarkerRelease(run))
        settlement = store._SettlementOwner(
            lambda: claim._settle() if settlement.primary is not None else None,
        )
        with store._SettlementFence(settlement):
            with store._SettlementFence(settlement):
                with run._mutation(store.MutationScope.BASE_EVIDENCE):
                    claim.marker.allocate()
                return claim

    def _settle(self) -> None:
        if self.released:
            return
        with self.run._mutation(store.MutationScope.CONTROL):
            self.marker.settle()
        if not self.marker.released:
            raise ContractError("durable run claim marker remains live")
        self.released = True

    def release(self) -> None:
        settlement = store._SettlementOwner(self._settle)
        with store._SettlementFence(settlement):
            with store._SettlementFence(settlement):
                self._settle()


def _stage_cleanup_settled(stage: privfs.PrivateFileStage) -> bool:
    ledger = stage._cleanup_ledger
    return (stage.state == "aborted"
            and stage.file_fd == stage.parent_fd == stage.anchor_fd == -1
            and (ledger is None or not ledger.pending))


def _abort_created_stages(
    stages: list[privfs.PrivateFileStage],
) -> tuple[bool, BaseException | None]:
    settled = True
    cancellation = None
    for stage in reversed(stages):
        try:
            if stage.state not in {"aborted", "committed", "fenced"}:
                privfs.abort_private_stage(stage)
        except BaseException as exc:
            # The caller retains the durable lifecycle marker while propagating
            # the preparation fault.  Never mutate a final destination here.
            settled = False
            if not isinstance(exc, Exception) and cancellation is None:
                cancellation = exc
        settled &= _stage_cleanup_settled(stage)
    return settled, cancellation


def _prepare_stage_batch(
    run: store.Run,
    invocation: NormalizedInvocation,
    policies: tuple[tuple[StreamRole, RepositoryOutput], ...],
) -> PrivateStageHandoffBatch | None:
    requested = tuple(
        policy for _role, policy in policies
        if policy.disposition is ArtifactDisposition.PUBLISH
    )
    if not requested:
        return None
    stages: list[privfs.PrivateFileStage] = []
    with run._mutation(store.MutationScope.BASE_EVIDENCE):
        for output in requested:
            run._ensure_artifact_parent(output.components)
        try:
            with _owned_run_anchor(run) as anchor_fd:
                for output in requested:
                    stages.append(privfs.create_private_stage(
                        anchor_fd, output.components,
                    ))
                return privfs.prepare_private_stage_handoff(
                    tuple(stages), invocation.worker.request_id,
                )
        except BaseException as primary:
            settled, cancellation = _abort_created_stages(stages)
            try:
                primary.repository_ownership_settled = settled
            except BaseException:
                pass
            if cancellation is not None and isinstance(primary, Exception):
                raise cancellation from primary
            raise


def _batch_ownership_settled(batch: PrivateStageHandoffBatch | None) -> bool:
    if batch is None:
        return True
    ledger = batch._cleanup_ledger
    return (batch.state in {
                "aborted", "fenced", "partial", "committed",
                "committed_with_fault",
            }
            and type(ledger) is privfs._PrivateStageCleanupLedger
            and not ledger.pending
            and not privfs._publication_cleanup_pending(batch))


def _fence_batch(batch: PrivateStageHandoffBatch | None) -> BaseException | None:
    """Consume remaining stage authority without ever attempting publication."""
    if batch is None:
        return None
    try:
        if batch.state == "prepared":
            privfs.abort_unspawned_private_stage_handoff(batch)
        elif batch.state in {
            "spawn_prepared", "worker_spawned_unverified", "worker_claim_bound",
            "parent_writers_closed", "transfer_uncertain", "settled", "publishing",
        }:
            privfs.fence_private_stage_handoff(batch)
        elif batch.state in {"partial", "committed", "committed_with_fault"}:
            privfs.cleanup_private_stage_handoff(batch)
        elif batch.state not in {"aborted", "fenced"}:
            raise PrivateStageHandoffError("fence")
    except BaseException as exc:
        return exc
    return None


def _execution_ownership_settled(execution: ExecutionOutcome) -> bool:
    """Whether the supervisor result leaves no live process/control owner."""
    if execution.reason in {ExecutionReason.COMPLETE, ExecutionReason.INCOMPLETE}:
        return True
    if execution.worker_spawned:
        return (execution.worker_reaped and execution.parent_pipes_closed
                and execution.containment_settled)
    if execution.containment_settled:
        return execution.parent_pipes_closed
    # These dispositions precede successful containment acquisition and process
    # launch.  Other no-worker failures may retain an unresolved cgroup owner.
    return (execution.parent_pipes_closed
            and execution.reason in {
                ExecutionReason.UNSUPPORTED,
                ExecutionReason.DEADLINE,
                ExecutionReason.INPUT_FAILED,
                ExecutionReason.REQUEST_FAILED,
            })


def _ownership_settled(
    execution: ExecutionOutcome,
    batch: PrivateStageHandoffBatch | None,
) -> bool:
    return (_execution_ownership_settled(execution)
            and _batch_ownership_settled(batch))


def _raise_cancellation(error: BaseException | None) -> None:
    """Preserve asynchronous cancellation after terminal reconciliation."""
    candidates = [] if error is None else [error, error.__cause__]
    for candidate in candidates:
        if candidate is not None and not isinstance(candidate, Exception):
            raise candidate


def _role_partition(
    policies: tuple[tuple[StreamRole, RepositoryOutput], ...],
) -> tuple[tuple[StreamRole, ...], tuple[StreamRole, ...]]:
    requested = tuple(
        role for role, policy in policies
        if policy.disposition is ArtifactDisposition.PUBLISH
    )
    discarded = tuple(
        role for role, policy in policies
        if policy.disposition is ArtifactDisposition.DISCARD
    )
    return requested, discarded


def _clock_now(clock) -> float:
    now = clock()
    if (type(now) not in (int, float) or type(now) is bool
            or not math.isfinite(now) or not 0 <= now <= (1 << 53) - 1):
        raise TypeError("clock must return a finite monotonic instant")
    return float(now)


def _validate_deadline_inputs(deadline, clock) -> None:
    if type(deadline) not in (int, float) or type(deadline) is bool:
        raise TypeError("deadline must be a finite absolute monotonic instant")
    if not math.isfinite(deadline) or not 0 <= deadline <= (1 << 53) - 1:
        raise ValueError("deadline must be a finite absolute monotonic instant")
    _clock_now(clock)


class _ExecutionClaimOwner:
    """Mutable claim and release decision held by two outer settlement fences."""

    __slots__ = (
        "acquire_claim", "claim", "batch", "execution", "retain",
        "prepared", "supervisor_started",
    )

    def __init__(self, acquire_claim) -> None:
        self.acquire_claim = acquire_claim
        self.claim = None
        self.batch = None
        self.execution = None
        self.retain = False
        self.prepared = False
        self.supervisor_started = False

    def acquire(self) -> None:
        self.claim = self.acquire_claim()

    def prepare(self, prepare_batch):
        # Once preparation starts, retain the marker unless an exact terminal
        # preparation failure or a later authenticated outcome proves ownership
        # settled.  The batch is assigned directly into this stable owner.
        try:
            # Keep arming and the callback on one traced source line: a
            # cancellation before it starts has no preparation owner, while a
            # returned batch is adopted together with its phase transition.
            self.retain = True; self.prepared, self.batch = True, prepare_batch()
        except BaseException as preparation_error:
            self.retain = self.retain and (
                getattr(
                    preparation_error,
                    "repository_ownership_settled",
                    False,
                ) is not True
            )
            raise
        return self.batch

    def supervise(self, operation):
        # As above, there is no traced gap between declaring the supervisor
        # possibly active and entering it, nor after a returned outcome.
        self.supervisor_started = True; self.execution = operation()
        return self.execution

    def settle(self) -> None:
        if self.claim is None:
            return
        terminal = not self.retain
        if self.prepared:
            fence_fault = _fence_batch(self.batch)
            if fence_fault is not None:
                raise fence_fault
            if not self.supervisor_started:
                terminal = _batch_ownership_settled(self.batch)
        if self.execution is not None:
            terminal = _ownership_settled(self.execution, self.batch)
        if terminal:
            self.claim.release()


def _supervise_owned_execution_claimed(
    invocation,
    *,
    policies,
    deadline,
    clock,
    popen_factory,
    claim_owner,
    prepare_batch,
    publish_batch,
) -> RepositoryExecutionOutcome:
    """Execution body entered only after outer claim fences are active."""
    requested_roles, discarded_roles = _role_partition(policies)
    claim_owner.acquire()
    batch = claim_owner.prepare(prepare_batch)

    try:
        try:
            execution = claim_owner.supervise(
                lambda: supervise_execution(
                    invocation,
                    stage_batch=batch,
                    deadline=deadline,
                    clock=clock,
                    popen_factory=popen_factory,
                ),
            )
        except BaseException:
            fence_error = _fence_batch(batch)
            # Without a supervisor outcome, process/containment ownership is
            # unknowable.  Retain the durable marker even if stages fenced.
            _raise_cancellation(fence_error)
            raise

        if (type(execution) is not ExecutionOutcome
                or execution.request_id != invocation.worker.request_id):
            fence_error = _fence_batch(batch)
            _raise_cancellation(fence_error)
            raise ContractError("execution supervisor returned invalid authority")

        if not execution.transaction_complete:
            fence_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            _raise_cancellation(fence_fault)
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=(
                    RepositoryPublication.FENCED
                    if requested_roles else RepositoryPublication.NOT_REQUESTED
                ),
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                unpublished=execution.artifact_proofs,
                ownership_settled=ownership_settled,
                fault_operation="fence" if fence_fault is not None else "execute",
            )

        if not requested_roles:
            if execution.artifact_proofs or batch is not None:
                fence_error = _fence_batch(batch)
                _raise_cancellation(fence_error)
                raise ContractError("discard-only execution returned artifact authority")
            ownership_settled = _ownership_settled(execution, batch)
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=RepositoryPublication.NOT_REQUESTED,
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                ownership_settled=ownership_settled,
            )

        # Execution and publication share the caller's one absolute budget.  An
        # already-expired transaction fences its settled stage rather than adding
        # a fresh publication window.
        try:
            publication_expired = _clock_now(clock) >= float(deadline)
        except BaseException:
            fence_error = _fence_batch(batch)
            _raise_cancellation(fence_error)
            raise
        if publication_expired:
            fence_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            _raise_cancellation(fence_fault)
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=RepositoryPublication.FENCED,
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                unpublished=execution.artifact_proofs,
                ownership_settled=ownership_settled,
                fault_operation="fence" if fence_fault is not None else "publish",
            )

        try:
            published = publish_batch(batch, execution.artifact_proofs)
        except PrivateStagePublicationPartial as partial:
            cleanup_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            _raise_cancellation(cleanup_fault)
            _raise_cancellation(partial)
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=RepositoryPublication.PARTIAL,
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                published=partial.committed,
                uncertain=partial.uncertain,
                unpublished=partial.unpublished,
                ownership_settled=ownership_settled,
                fault_operation="publish",
            )
        except PrivateStagePublicationCommittedWithFault as committed:
            # The publication facts are authoritative, but cleanup faulted.  One
            # idempotent drain is safe and never retries a rename.
            cleanup_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            _raise_cancellation(cleanup_fault)
            _raise_cancellation(committed)
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=RepositoryPublication.COMMITTED_WITH_FAULT,
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                published=committed.committed,
                ownership_settled=ownership_settled,
                fault_operation="cleanup",
            )
        except PrivateStageHandoffError as publication_error:
            fence_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            _raise_cancellation(fence_fault)
            _raise_cancellation(publication_error)
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=RepositoryPublication.FENCED,
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                unpublished=execution.artifact_proofs,
                ownership_settled=ownership_settled,
                fault_operation="fence" if fence_fault is not None else "publish",
            )
        except BaseException:
            fence_fault = _fence_batch(batch)
            _raise_cancellation(fence_fault)
            raise

        ownership_settled = _ownership_settled(execution, batch)
        if ownership_settled:
            return RepositoryExecutionOutcome(
                execution=execution,
                publication=RepositoryPublication.PUBLISHED,
                requested_roles=requested_roles,
                discarded_roles=discarded_roles,
                published=published,
            )
        return RepositoryExecutionOutcome(
            execution=execution,
            publication=RepositoryPublication.COMMITTED_WITH_FAULT,
            requested_roles=requested_roles,
            discarded_roles=discarded_roles,
            published=published,
            ownership_settled=False,
            fault_operation="cleanup",
        )
    finally:
        claim_owner.settle()


def _supervise_owned_execution(
    invocation,
    *,
    policies,
    deadline,
    clock,
    popen_factory,
    acquire_claim,
    prepare_batch,
    publish_batch,
) -> RepositoryExecutionOutcome:
    """Run one transaction with claim cleanup active before acquisition."""
    claim_owner = _ExecutionClaimOwner(acquire_claim)
    settlement = store._SettlementOwner(claim_owner.settle)
    with store._SettlementFence(settlement):
        with store._SettlementFence(settlement):
            return _supervise_owned_execution_claimed(
                invocation,
                policies=policies,
                deadline=deadline,
                clock=clock,
                popen_factory=popen_factory,
                claim_owner=claim_owner,
                prepare_batch=prepare_batch,
                publish_batch=publish_batch,
            )


def supervise_repository_execution(
    run,
    invocation,
    *,
    stdout,
    stderr,
    deadline,
    clock=time.monotonic,
    popen_factory=subprocess.Popen,
) -> RepositoryExecutionOutcome:
    """Supervise one invocation and terminally publish or fence its outputs.

    Validation is side-effect free.  Once accepted, a durable run claim spans
    private stage creation, the killable worker transaction, authenticated parent
    settlement and the repository-locked publication decision.  Only an exact
    ``ExecutionReason.COMPLETE`` outcome may publish.  Every other outcome fences
    all settled bytes and preserves prior authoritative names.
    """
    if not callable(clock) or not callable(popen_factory):
        raise TypeError("execution dependencies must be callable")
    policies = _validate_output_policies(run, invocation, stdout, stderr)
    _validate_deadline_inputs(deadline, clock)

    def publish_batch(batch, proofs):
        with run._mutation(store.MutationScope.BASE_EVIDENCE):
            return privfs.publish_private_stage_handoff(batch, proofs)

    return _supervise_owned_execution(
        invocation,
        policies=policies,
        deadline=deadline,
        clock=clock,
        popen_factory=popen_factory,
        acquire_claim=lambda: _DurableRunClaim.acquire(run),
        prepare_batch=lambda: _prepare_stage_batch(run, invocation, policies),
        publish_batch=publish_batch,
    )


@dataclass(slots=True, repr=False)
class _DurableOsintClaim:
    """A crash-conservative execution marker for one unsealed OSINT session."""

    session: object = field(repr=False)
    marker: str = field(repr=False)
    identity: tuple[int, int] = field(repr=False)
    released: bool = False

    @classmethod
    def acquire(cls, session, request_id: str) -> "_DurableOsintClaim":
        with session._execution_mutation():
            directory_fd = session._open_execution_claims_dir()
            fd = -1
            try:
                fd = os.open(
                    request_id,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    privfs.FILE_MODE,
                    dir_fd=directory_fd,
                )
                os.fchmod(fd, privfs.FILE_MODE)
                view = memoryview(b"active\n")
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("OSINT claim marker write made no progress")
                    view = view[written:]
                os.fsync(fd)
                observed = os.fstat(fd)
                named = os.stat(
                    request_id, dir_fd=directory_fd, follow_symlinks=False,
                )
                if (not stat.S_ISREG(observed.st_mode)
                        or not stat.S_ISREG(named.st_mode)
                        or (observed.st_dev, observed.st_ino)
                        != (named.st_dev, named.st_ino)
                        or observed.st_uid != os.geteuid()
                        or observed.st_nlink != 1
                        or observed.st_mode & 0o777 != privfs.FILE_MODE):
                    raise ContractError("OSINT claim marker identity is unsafe")
                os.fsync(directory_fd)
            except BaseException:
                if fd >= 0:
                    try:
                        os.unlink(request_id, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                    except OSError:
                        pass
                raise
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(directory_fd)
        return cls(session, request_id, (observed.st_dev, observed.st_ino))

    def release(self) -> None:
        if self.released:
            return
        with self.session._execution_mutation():
            directory_fd = self.session._open_execution_claims_dir()
            marker_fd = -1
            try:
                marker_fd = os.open(
                    self.marker,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_fd,
                )
                observed = os.fstat(marker_fd)
                named = os.stat(
                    self.marker, dir_fd=directory_fd, follow_symlinks=False,
                )
                if (not stat.S_ISREG(observed.st_mode)
                        or not stat.S_ISREG(named.st_mode)
                        or (observed.st_dev, observed.st_ino) != self.identity
                        or (named.st_dev, named.st_ino) != self.identity
                        or observed.st_uid != os.geteuid()
                        or observed.st_nlink != 1):
                    raise ContractError("OSINT claim marker identity changed")
                os.unlink(self.marker, dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                if marker_fd >= 0:
                    os.close(marker_fd)
                os.close(directory_fd)
            session_fd = os.open(
                self.session.dir,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                os.fsync(session_fd)
            finally:
                os.close(session_fd)
            self.released = True


def _validate_osint_output_policies(session, invocation, stdout, stderr):
    from .osint import OsintSession

    if type(session) is not OsintSession:
        raise TypeError("session must be an exact OSINT repository authority")
    if type(invocation) is not NormalizedInvocation:
        raise TypeError("invocation must be normalized before OSINT execution")
    if type(stdout) is not RepositoryOutput or type(stderr) is not RepositoryOutput:
        raise TypeError("stdout and stderr require explicit repository policies")
    policies = ((StreamRole.STDOUT, stdout), (StreamRole.STDERR, stderr))
    with session._execution_mutation():
        for role, policy in policies:
            observed = invocation.raw_path if role is StreamRole.STDOUT else invocation.stderr_path
            expected = (
                None if policy.disposition is ArtifactDisposition.DISCARD
                else os.path.abspath(str(session.dir.joinpath(*policy.components)))
            )
            requested = policy.disposition is ArtifactDisposition.PUBLISH
            if (requested != (invocation.worker.claim_for(role) is not None)
                    or observed != expected
                    or (requested and policy.components[:1] != ("raw",))):
                raise ContractError(f"{role.value} policy does not match OSINT session")
    return policies


def _prepare_osint_stage_batch(session, invocation, policies):
    requested = tuple(
        policy for _role, policy in policies
        if policy.disposition is ArtifactDisposition.PUBLISH
    )
    if not requested:
        return None
    stages = []
    try:
        with session._execution_mutation():
            for output in requested:
                privfs.private_dir(session.dir.joinpath(*output.components[:-1]))
            anchor_fd = privfs._walk_dirfd(session.dir)
            try:
                for output in requested:
                    stages.append(privfs.create_private_stage(anchor_fd, output.components))
                return privfs.prepare_private_stage_handoff(
                    tuple(stages), invocation.worker.request_id,
                )
            finally:
                os.close(anchor_fd)
    except BaseException as primary:
        settled, cancellation = _abort_created_stages(stages)
        try:
            primary.repository_ownership_settled = settled
        except BaseException:
            pass
        if cancellation is not None and isinstance(primary, Exception):
            raise cancellation from primary
        raise


def supervise_osint_execution(
    session,
    invocation,
    *,
    stdout,
    stderr,
    deadline,
    clock=time.monotonic,
    popen_factory=subprocess.Popen,
) -> RepositoryExecutionOutcome:
    """Execute one OSINT tool under its exact session publication authority."""
    if not callable(clock) or not callable(popen_factory):
        raise TypeError("execution dependencies must be callable")
    policies = _validate_osint_output_policies(
        session, invocation, stdout, stderr,
    )
    _validate_deadline_inputs(deadline, clock)

    def publish_batch(batch, proofs):
        with session._execution_mutation():
            return privfs.publish_private_stage_handoff(batch, proofs)

    return _supervise_owned_execution(
        invocation,
        policies=policies,
        deadline=deadline,
        clock=clock,
        popen_factory=popen_factory,
        acquire_claim=lambda: _DurableOsintClaim.acquire(
            session, invocation.worker.request_id,
        ),
        prepare_batch=lambda: _prepare_osint_stage_batch(
            session, invocation, policies,
        ),
        publish_batch=publish_batch,
    )
