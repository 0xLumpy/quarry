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
import subprocess
import time
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
        """Bind one caller-held path back to an exact repository authority.

        Production lanes historically asked ``Run.raw_path`` for a ``Path`` and
        passed that path directly to the runner.  During the compatibility
        window they may keep the convenient local variable, but publication is
        authorized only after this method resolves it to validated artifact
        components and proves that the supplying ``Run`` owns the same opened
        run identity.  The resulting policy contains no ambient path.
        """
        if type(run) is not store.Run:
            raise TypeError("run must be an opened repository Run")
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
    name: str = field(repr=False)
    identity: tuple[int, int] = field(repr=False)
    released: bool = False

    @classmethod
    def acquire(cls, run: store.Run) -> "_DurableRunClaim":
        with run._mutation(store.MutationScope.BASE_EVIDENCE):
            name, identity = run._create_artifact_claim_marker()
        return cls(run, name, identity)

    def release(self) -> None:
        if self.released:
            return
        with self.run._mutation(store.MutationScope.CONTROL):
            self.run._release_artifact_claim_marker(self.name, self.identity)
        self.released = True


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
        anchor_fd = store._open_run_fd(run.project_dir, run.run_id)
        try:
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
        finally:
            os.close(anchor_fd)


def _batch_ownership_settled(batch: PrivateStageHandoffBatch | None) -> bool:
    if batch is None:
        return True
    ledger = batch._cleanup_ledger
    return (batch.state in {
                "aborted", "fenced", "partial", "committed",
                "committed_with_fault",
            }
            and type(ledger) is privfs._PrivateStageCleanupLedger
            and not ledger.pending)


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
    requested_roles, discarded_roles = _role_partition(policies)

    claim = _DurableRunClaim.acquire(run)
    release_claim = False
    batch = None
    try:
        try:
            batch = _prepare_stage_batch(run, invocation, policies)
        except BaseException as preparation_error:
            release_claim = (
                getattr(
                    preparation_error,
                    "repository_ownership_settled",
                    False,
                ) is True
            )
            raise

        try:
            execution = supervise_execution(
                invocation,
                stage_batch=batch,
                deadline=deadline,
                clock=clock,
                popen_factory=popen_factory,
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
            release_claim = ownership_settled
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
            release_claim = ownership_settled
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
            release_claim = _ownership_settled(execution, batch)
            _raise_cancellation(fence_error)
            raise
        if publication_expired:
            fence_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            release_claim = ownership_settled
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
            with run._mutation(store.MutationScope.BASE_EVIDENCE):
                published = privfs.publish_private_stage_handoff(
                    batch, execution.artifact_proofs,
                )
        except PrivateStagePublicationPartial as partial:
            cleanup_fault = _fence_batch(batch)
            ownership_settled = _ownership_settled(execution, batch)
            release_claim = ownership_settled
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
            release_claim = ownership_settled
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
            release_claim = ownership_settled
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

        ownership_settled = _ownership_settled(execution, batch)
        release_claim = ownership_settled
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
        if release_claim:
            claim.release()
