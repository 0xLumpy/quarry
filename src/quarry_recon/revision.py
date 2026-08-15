"""Late evidence for a run whose base manifest is committed, as append-only supplements and revisions of
the combined view (docs/design/REVISION-DESIGN.md)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import envelope, privfs, run_manifest, store
from .state import RUN_STATES, STATE_UNKNOWN, Fault

SCHEMA_VERSION = 2
REVISIONS_DIR = "revisions"
POINTER_NAME = "revision.json"
SEGMENT_NAME = "observations.jsonl"
LOCK_NAME = ".publish.lock"
STATE_FILE = "state.json"                   # the run lifecycle marker, when one is persisted
#: states whose base manifest is committed, so the run is sealed and only a supplement may be added.
BASE_COMMITTED_STATES = frozenset({"finished", "finalization_failed"})
#: `unknown` is the store's word for a lifecycle record that exists but cannot be read; reusing it keeps
#: one verdict for that fact on both sides of the seam.
SEALED, LIVE, UNKNOWN, FINALIZING = "sealed", "live", STATE_UNKNOWN, "finalizing"
#: summary fields a revision does not certify — the only ones `Run.reconcile_finalization` rewrites, and
#: bookkeeping about the derived views rather than evidence the run discovered.
VOLATILE_SUMMARY_FIELDS = frozenset({"faults", "verdict"})
_REV_RE = re.compile(r"^rev(\d{4,})$")

# Revision files are private control/evidence records, not an unbounded byte
# store.  Every pathname read below names one of these envelopes explicitly;
# no caller may allocate a file first and decide whether it was supported
# afterwards.
MAX_REVISION_POINTER_BYTES = run_manifest.MAX_MANIFEST_BYTES
MAX_REVISION_SEGMENT_BYTES = run_manifest.MAX_STRUCTURED_FILE_BYTES
MAX_REVISION_SUPPLEMENT_BYTES = 256 * 1024 * 1024
MAX_REVISION_RAW_FILE_BYTES = run_manifest.MAX_STRUCTURED_FILE_BYTES
MAX_REVISION_RAW_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REVISION_RAW_FILES = 10_000
MAX_REVISION_VIEW_FILE_BYTES = run_manifest.MAX_STRUCTURED_FILE_BYTES
MAX_REVISION_VIEW_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REVISION_VIEW_FILES = 10_000
MAX_REVISION_TREE_DEPTH = 64
MAX_REVISION_SEGMENTS = 10_000
MAX_REVISION_ROOT_ENTRIES = 20_000


class RevisionError(RuntimeError):
    """A revision could not be published, or a published one could not be certified."""

    def __init__(self, message: str, fault: Fault | None = None, *, retryable: bool = False):
        super().__init__(message)
        self.fault = fault or Fault(kind="publication", where="revision", detail=message)
        self.retryable = bool(retryable)


class RevisionPublicationError(RevisionError):
    """Pointer publication could not be reduced to a safe retry decision."""

    def __init__(self, message: str, *, outcome: str):
        super().__init__(message, retryable=outcome == "not_landed")
        self.outcome = outcome


class _PointerPostCommitFault(BaseException):
    """A primitive fault after the new pointer's parent fsync completed."""

    def __init__(self, primary: BaseException):
        super().__init__(str(primary))
        self.primary = primary


@dataclass(frozen=True)
class _PointerSettlement:
    """Settled authority after a fallible pointer publication attempt."""

    outcome: str
    revision: Revision | None = None


@dataclass(frozen=True)
class OOBResumeCandidate:
    """One sealed-run polling attempt, isolated from canonical base names."""

    name: str
    log: Path
    session_file: Path


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rev_name(n: int) -> str:
    return f"rev{n:04d}"


def revisions_dir(run_dir) -> Path:
    return Path(run_dir) / REVISIONS_DIR


def pointer_path(run_dir) -> Path:
    return revisions_dir(run_dir) / POINTER_NAME


# ── the base run's lifecycle ──────────────────────────────────────────────────────────────────────

def _manifest_committed(run_dir) -> bool:
    """Whether the base manifest is committed — `store.manifest_committed` is the one rule, called rather
    than copied so the two sides cannot drift."""
    return store.manifest_committed(Path(run_dir) / "manifest.json")


def base_disposition(run_dir) -> tuple[str, str]:
    """How late evidence may reach this run — `sealed` / `live` / `finalizing` / `unknown`, with the reason
    when it may not (REVISION-DESIGN.md §2)."""
    run_dir = Path(run_dir)
    committed = _manifest_committed(run_dir)
    p = run_dir / STATE_FILE
    if not p.exists():                                # written before the lifecycle record existed
        return (SEALED, "") if committed else (LIVE, "")
    record = store._read_json(p)
    state = record.get("state") if isinstance(record, dict) else None
    if state not in RUN_STATES:
        return UNKNOWN, f"{p} is present but records no known run state"
    if state in BASE_COMMITTED_STATES and not committed:
        return UNKNOWN, f"{p} records {state!r} while the base manifest is not committed"
    if state == FINALIZING:
        # a run seals its manifest, publishes views, then seals again; a supplement landing between the two
        # would certify against a manifest that is about to be replaced
        return FINALIZING, f"run {run_dir.name} is still finalising — retry once it settles"
    return (SEALED, "") if committed else (LIVE, "")


def base_finished(run_dir) -> bool:
    """Whether the base manifest is committed, so a combined view may be read over it.

    True while the run is re-finalising as well: `quarry report` reopens a run to republish its views and
    must still render the revision. Writing late evidence is the narrower question — `_require_disposition`
    refuses that until the manifest settles.
    """
    return base_disposition(run_dir)[0] in (SEALED, FINALIZING)


def _require_disposition(run_dir) -> str:
    disposition, why = base_disposition(run_dir)
    if disposition in (UNKNOWN, FINALIZING):
        raise RevisionError(
            f"{run_dir}: {why} — refusing to record late evidence against it; retry once lifecycle settles",
            retryable=True,
        )
    return disposition


def raw_path(run, phase: str, tool: str, name: str) -> Path:
    """Where raw evidence acquired now belongs: the run's own `raw/` while it is live, `revisions/raw/`
    once it is sealed, because a sealed run's raw tree is part of what its manifest certifies."""
    phase = store.validate_artifact_component(phase, "raw phase")
    tool = store.validate_artifact_component(tool, "raw tool")
    name = store.validate_artifact_component(name, "raw filename")
    if _require_disposition(run.dir) == LIVE:
        return run.raw_path(phase, tool, name)
    return privfs.private_dir(revisions_dir(run.dir) / "raw" / phase / tool) / name


def _oob_counts(rows: list[dict], sink, published) -> dict:
    added = 0
    correlated = 0
    by_protocol: dict[str, int] = {}
    for row in rows:
        if sink.add("oob_interaction", row):
            added += 1
            protocol = row.get("protocol")
            if isinstance(protocol, str):
                by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
            if row.get("correlation") == "correlated":
                correlated += 1
    return {
        "added": added,
        "by_protocol": by_protocol,
        "correlated": correlated,
        "refused": int(sink.refused),
        "outstanding": len(published.refused) if published is not None else 0,
        "revision": published,
    }


def commit_oob_candidate(
    run, *, raw_name: str, raw_bytes: bytes, rows: list[dict], origin: str, scope=None,
) -> dict:
    """Choose and commit one complete live-or-revision OOB candidate.

    Raw proof and normalized rows are named only after the shared per-run lock
    has selected the lifecycle disposition.  No call to this function can
    choose a base raw path and later discover that its rows belong to a
    revision.
    """
    raw_name = store.validate_artifact_component(raw_name, "OOB raw filename")
    if type(raw_bytes) is not bytes or not isinstance(rows, list):
        raise TypeError("invalid OOB candidate")
    prior_raw = None
    raw = None
    try:
        with run._mutation(store.MutationScope.CONTROL):
            disposition = _require_disposition(run.dir)
            if disposition == LIVE:
                components = ("raw", "oob", "import", raw_name)
                raw_ref = "/".join(components)
                run._replace_artifact(store.MutationScope.BASE_EVIDENCE, components, raw_bytes)
                for row in rows:
                    row["raw_ref"] = raw_ref
                sink = _Live(run)
                result = _oob_counts(rows, sink, None)
                sink.commit(scope)
                return result

            sink = _Supplement(run, origin)
            # _Supplement.commit normally acquires the same re-entrant repository
            # authority.  Keeping its public method intact also preserves the
            # existing concurrent writer adoption behavior.
            preliminary = _oob_counts(rows, sink, None)
            if not sink._pending and not sink._refused:
                # A repeat callback publishes neither a new pointer nor stray
                # raw evidence.  The previously committed candidate remains
                # the authoritative proof for the deduplicated row.
                return preliminary
            raw = privfs.private_dir(revisions_dir(run.dir) / "raw" / "oob" / "import") / raw_name
            if raw.exists():
                prior_raw = raw.read_bytes()
            privfs.write_private(raw, raw_bytes.decode("utf-8", errors="replace"))
            raw_ref = str(raw.relative_to(run.dir))
            for row in rows:
                row["raw_ref"] = raw_ref
            for pending in sink._pending:
                pending["record"]["raw_ref"] = raw_ref
                pending["fp"] = store.fingerprint(pending["entity"], pending["record"])
            published = sink.commit(scope)
            preliminary["outstanding"] = len(published.refused) if published is not None else 0
            preliminary["revision"] = published
            return preliminary
    except Exception as exc:
        rollback_safe = not isinstance(exc, RevisionPublicationError) or exc.outcome == "not_landed"
        if raw is not None and rollback_safe:
            try:
                if prior_raw is None:
                    raw.unlink(missing_ok=True)
                else:
                    privfs.write_private(raw, prior_raw.decode("utf-8", errors="replace"))
            except OSError:
                pass
        from .state import ContractError
        if isinstance(exc, ContractError) and run.state == UNKNOWN:
            raise RevisionError(
                f"{run.dir}: unknown lifecycle state — refusing OOB mutation; retry after repair",
                retryable=True,
            ) from exc
        raise


@contextmanager
def _publish_lock(run):
    """Use the repository's sole per-run mutation authority for revisions."""
    if not hasattr(run, "_mutation"):
        raise RevisionError("revision publication requires a repository Run authority")
    with run._mutation(store.MutationScope.REVISION):
        yield


def stage_oob_resume_candidate(run, base_log: Path, base_session: Path) -> OOBResumeCandidate:
    """Copy a sealed session into one unique, unpublished revision candidate.

    The existing revision pointer/segment format remains unchanged; this is
    acquisition staging only, not a new revision publication design.
    """
    with run._mutation(store.MutationScope.REVISION):
        _require_disposition(run.dir)
        name = f"oob-{os.urandom(16).hex()}"
        directory = privfs.private_dir(revisions_dir(run.dir) / "candidates" / name)
        log = directory / "interactions.jsonl"
        session_file = directory / "interactsh.session"
        try:
            privfs.write_private(log, Path(base_log).read_text(encoding="utf-8", errors="replace"))
            privfs.write_private(
                session_file,
                Path(base_session).read_text(encoding="utf-8", errors="surrogateescape"),
                encoding="utf-8",
            )
        except BaseException:
            # Unique candidate bytes remain non-authoritative if cleanup itself
            # faults; no canonical base or pointer name was changed.
            raise
        return OOBResumeCandidate(name=name, log=log, session_file=session_file)


def _evidence_manifest(doc: dict) -> dict:
    """The manifest minus `VOLATILE_SUMMARY_FIELDS` — what a revision certifies (REVISION-DESIGN.md §2)."""
    out = dict(doc)
    summary = out.get("summary")
    if isinstance(summary, dict):
        out["summary"] = {k: v for k, v in summary.items() if k not in VOLATILE_SUMMARY_FIELDS}
    return out


def _base_manifest(run_dir) -> tuple[str, dict]:
    """`(evidence digest, entity_counts)` of the sealed base run; raises when it cannot be certified.

    The digest covers the evidence-bearing manifest in canonical form, not the file's bytes: a resumed
    finalisation rewrites its own bookkeeping, and a revision that broke on that would drop the very rows
    it exists to carry. A change to real evidence still moves this digest.
    """
    p = Path(run_dir) / "manifest.json"
    if not p.exists():
        raise RevisionError(f"{p}: the base manifest is unreadable (FileNotFoundError)")
    doc = store._read_json(p)
    counts = doc.get("entity_counts") if isinstance(doc, dict) else None
    if not isinstance(counts, dict):
        raise RevisionError(f"{p}: the base manifest carries no entity_counts")
    body = json.dumps(_evidence_manifest(doc), sort_keys=True, ensure_ascii=False)
    return _sha(body.encode("utf-8")), counts


def _entity_content_digests(run_dir) -> dict:
    """`{entity: digest}` over each normalized log's bytes — the evidence itself, not its count.

    The manifest records how many of each entity a run found; it does not record WHICH. Without this a
    same-count content swap leaves a revision certified over evidence it never saw.
    """
    out = {}
    d = Path(run_dir) / "normalized"
    try:
        mode = d.lstat().st_mode
    except FileNotFoundError:
        return out
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise RevisionError(f"{d}: base evidence directory is unsafe")
    for p in sorted(d.glob("*.jsonl")):
        try:
            body = _read_regular(
                p, root=Path(run_dir), maximum=run_manifest.MAX_STRUCTURED_FILE_BYTES,
            )
        except OSError as e:
            raise RevisionError(f"{p}: base evidence is unreadable ({type(e).__name__})")
        out[p.stem] = _sha(body)
    return out


def _certified_base_snapshot(run_dir):
    """One strict manifest identity, claim set, and semantic base fold.

    Revision certification must not validate ``manifest.json`` and then reopen
    it (or its normalized files) through mutable pathnames.  ``run_manifest``
    captures all of these facts under one held run-directory descriptor.
    """
    try:
        manifest = run_manifest.read(
            Path(run_dir) / "manifest.json", verify_lifecycle=False,
        )
    except run_manifest.ManifestError as exc:
        raise RevisionError(f"the base manifest cannot be certified: {exc}") from exc
    document = manifest.document
    counts = dict(document["entity_counts"])
    body = json.dumps(_evidence_manifest(document), sort_keys=True, ensure_ascii=False)
    digest = _sha(body.encode("utf-8"))
    contents = {}
    for claim in document["base_files"]:
        match = re.fullmatch(r"normalized/([a-z][a-z0-9_]*)\.jsonl", claim["path"])
        if match is None or match.group(1) not in store.ENTITY_KEYS:
            continue
        value = claim["digest"]
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise RevisionError("the base manifest carries an invalid normalized-file digest")
        contents[match.group(1)] = value[len("sha256:"):]
    records = {
        entity: dict(folded.records)
        for entity, folded in manifest.folded_by_entity.items()
    }
    return manifest, digest, counts, contents, records


# ── the published pointer ─────────────────────────────────────────────────────────────────────────

@dataclass
class Revision:
    """One certified combined view plus private in-memory authenticated folds."""

    revision: int = 0
    status: str = "absent"                  # absent | valid | unusable
    reason: str = ""
    created: str = ""
    base: dict = field(default_factory=dict)
    segments: list = field(default_factory=list)
    supplement_lines: int = 0
    supplement_digest: str = ""
    entity_counts: dict = field(default_factory=dict)
    entity_digests: dict = field(default_factory=dict)
    raw_files: dict = field(default_factory=dict)
    views: dict = field(default_factory=dict)
    stale_views: list = field(default_factory=list)
    refused: list = field(default_factory=list)
    digest: str = ""
    pointer_digest: str = ""
    orphans: list = field(default_factory=list)      # revision dirs above the pointer: written, never published
    base_records: dict = field(default_factory=dict, repr=False, compare=False)
    effective_records: dict = field(default_factory=dict, repr=False, compare=False)
    provenance: dict = field(default_factory=dict, repr=False, compare=False)
    snapshot_bound: bool = field(default=False, repr=False, compare=False)

    @property
    def trustworthy(self) -> bool:
        return self.status in ("valid", "absent")


def _segment_path(run_dir, name) -> Path:
    """A segment path from the pointer, confined to `revisions/rev<N>/<SEGMENT_NAME>` so a crafted pointer
    cannot name a file outside the run."""
    if not isinstance(name, str):
        raise ValueError("segment file is not a string")
    parts = Path(name).parts
    match = _REV_RE.fullmatch(parts[0]) if len(parts) == 2 else None
    if (match is None or parts[0] != _rev_name(int(match.group(1)))
            or parts[1] != SEGMENT_NAME):
        raise ValueError(f"segment file {name!r} is not a revision segment")
    return revisions_dir(run_dir) / parts[0] / parts[1]


def _revision_root_entries(run_dir) -> tuple[list[tuple[str, int]], str]:
    """Bounded no-follow inventory of the revision authority directory."""
    root = revisions_dir(run_dir)
    try:
        iterator = os.scandir(root)
    except FileNotFoundError:
        return [], ""
    except OSError as exc:
        return [], f"revision directory is unreadable: {exc}"
    entries: list[tuple[str, int]] = []
    try:
        with iterator:
            for entry in iterator:
                if len(entries) >= MAX_REVISION_ROOT_ENTRIES:
                    return [], "revision directory exceeds its object-count bound"
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError as exc:
                    return [], f"revision directory entry {entry.name!r} is unreadable: {exc}"
                entries.append((entry.name, mode))
    except OSError as exc:
        return [], f"revision directory enumeration failed: {exc}"
    return entries, ""


def _orphans(run_dir, published: int) -> list[str]:
    """Revision directories numbered above the pointer — bytes an interrupted publication left, kept and
    named rather than reused."""
    entries, fault = _revision_root_entries(run_dir)
    if fault:
        return [f"<unavailable: {fault}>"]
    out = []
    for name, mode in entries:
        m = _REV_RE.match(name)
        if m and stat.S_ISDIR(mode) and int(m.group(1)) > published:
            out.append(name)
    return sorted(out)


def _canonical_bytes(value) -> bytes:
    """One stable JSON encoding for identities recorded inside a revision pointer."""
    try:
        run_manifest._validate_json_value(value, "revision value")
        return json.dumps(
            value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
        ).encode("utf-8")
    except (run_manifest.ManifestError, TypeError, ValueError, UnicodeEncodeError,
            RecursionError) as exc:
        raise RevisionError(f"revision value is not portable JSON: {exc}") from exc


def _strict_json(raw: bytes, where: str):
    """Decode one bounded revision record with the manifest's portable JSON rules."""
    try:
        value = run_manifest._parse_json(raw, where)
        run_manifest._validate_json_value(value, where)
        return value
    except run_manifest.ManifestError as exc:
        raise RevisionError(str(exc)) from exc


_DIR_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                   | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
_FILE_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))


def _private_directory_claim(observed, where) -> tuple[int, ...]:
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != privfs.DIR_MODE):
        raise OSError(f"unsafe private directory: {where}")
    return observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid


def _private_file_claim(observed, where) -> tuple[int, ...]:
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE
            or observed.st_nlink != 1):
        raise OSError(f"unsafe owner-private single-link file: {where}")
    return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid,
            observed.st_nlink, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)


def _open_private_directory_path(
    path: Path, *, expected_identity: tuple[int, int] | None = None,
) -> int:
    """Open a private directory one no-follow component at a time.

    ``O_NOFOLLOW`` on an absolute multi-component pathname protects only its
    leaf.  Beginning at a held filesystem/cwd descriptor and opening every
    component relative to the prior descriptor prevents an ancestor rename to
    a symlink from redirecting revision authority outside its tree.
    """
    path = Path(path)
    components = path.parts[1:] if path.is_absolute() else path.parts
    if any(component in ("", ".", "..") for component in components):
        raise OSError(f"unsafe private directory path: {path}")
    current = os.open(os.sep if path.is_absolute() else ".", _DIR_READ_FLAGS)
    transient = -1
    try:
        for component in components:
            transient = os.open(component, _DIR_READ_FLAGS, dir_fd=current)
            os.close(current)
            current = transient
            transient = -1
        claim = _private_directory_claim(os.fstat(current), path)
        if expected_identity is not None and claim[:2] != expected_identity:
            raise OSError(f"private directory authority changed before open: {path}")
        owned, current = current, -1
        return owned
    finally:
        for fd in (transient, current):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _pointer_digest(doc: dict) -> str:
    """Digest every pointer claim except the digest field itself."""
    body = dict(doc)
    body.pop("pointer_digest", None)
    return _sha(_canonical_bytes(body))


def _evidence_digest(*, base: str, supplement: str, counts: dict,
                     entity_digests: dict, raw_files: dict) -> str:
    """Identity of the effective evidence view (derived views deliberately excluded)."""
    return _sha(_canonical_bytes({
        "base": base,
        "supplement": supplement,
        "entity_counts": counts,
        "entity_digests": entity_digests,
        "raw_files": raw_files,
    }))


def _read_regular(
    path: Path, *, root: Path | None = None, maximum: int,
    expected_root_identity: tuple[int, int] | None = None,
    identity_out: dict | None = None,
) -> bytes:
    """Read one stable owner-private file through pinned directory descriptors."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError("managed file byte bound is invalid")
    path = Path(path)
    root = Path(root) if root is not None else path.parent
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise OSError(f"file escapes managed root: {path}") from exc
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise OSError(f"unsafe managed file path: {path}")

    root_fd = parent_fd = file_fd = check_fd = current_fd = transient_fd = named_root_fd = -1
    try:
        root_fd = _open_private_directory_path(
            root, expected_identity=expected_root_identity,
        )
        root_claim = _private_directory_claim(os.fstat(root_fd), root)
        directory_identities: list[tuple[int, ...]] = []
        parent_fd = os.dup(root_fd)
        os.set_inheritable(parent_fd, False)
        for component in relative.parts[:-1]:
            transient_fd = os.open(component, _DIR_READ_FLAGS, dir_fd=parent_fd)
            directory_identities.append(_private_directory_claim(os.fstat(transient_fd), component))
            os.close(parent_fd)
            parent_fd = transient_fd
            transient_fd = -1
        file_fd = os.open(relative.parts[-1], _FILE_READ_FLAGS, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = -1

        file_identity = _private_file_claim(os.fstat(file_fd), path)
        if file_identity[5] > maximum:
            raise OSError(f"managed file exceeds its {maximum}-byte bound: {path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise OSError(f"managed file exceeds its {maximum}-byte bound: {path}")
            chunks.append(chunk)
        if _private_file_claim(os.fstat(file_fd), path) != file_identity:
            raise OSError(f"file changed while it was read: {path}")
        os.close(file_fd)
        file_fd = -1

        # Rewalk every lexical name from the still-pinned root.  A renamed or
        # substituted ancestor/final component may not certify the old inode.
        check_fd = os.dup(root_fd)
        os.set_inheritable(check_fd, False)
        for index, component in enumerate(relative.parts[:-1]):
            transient_fd = os.open(component, _DIR_READ_FLAGS, dir_fd=check_fd)
            if (_private_directory_claim(os.fstat(transient_fd), component)
                    != directory_identities[index]):
                raise OSError(f"file ancestry changed while it was read: {path}")
            os.close(check_fd)
            check_fd = transient_fd
            transient_fd = -1
        current_fd = os.open(relative.parts[-1], _FILE_READ_FLAGS, dir_fd=check_fd)
        if _private_file_claim(os.fstat(current_fd), path) != file_identity:
            raise OSError(f"file name changed while it was read: {path}")
        os.close(current_fd)
        current_fd = -1
        os.close(check_fd)
        check_fd = -1

        named_root_fd = _open_private_directory_path(
            root, expected_identity=expected_root_identity,
        )
        if _private_directory_claim(os.fstat(named_root_fd), root) != root_claim:
            raise OSError(f"managed root changed while file was read: {root}")
        os.close(named_root_fd)
        named_root_fd = -1
        if identity_out is not None:
            identity_out.clear()
            identity_out.update({
                "root": root_claim,
                "directories": tuple(directory_identities),
                "file": file_identity,
            })
        return b"".join(chunks)
    finally:
        for owned in (transient_fd, current_fd, file_fd, parent_fd, check_fd,
                      named_root_fd, root_fd):
            if owned >= 0:
                try:
                    os.close(owned)
                except OSError:
                    pass


def _revision_raw_path(run_dir, ref: str) -> Path:
    """Resolve a late-evidence raw reference, confined below ``revisions/raw``."""
    if not isinstance(ref, str):
        raise ValueError("raw reference is not a string")
    parts = Path(ref).parts
    if (Path(ref).is_absolute() or len(parts) < 4 or len(parts) > MAX_REVISION_TREE_DEPTH
            or parts[:2] != (REVISIONS_DIR, "raw")
            or any(part in ("", ".", "..") for part in parts)):
        raise ValueError(f"raw reference {ref!r} is not a revision raw file")
    return Path(run_dir).joinpath(*parts)


def _late_raw_refs(rows: list[dict]) -> set[str]:
    refs: set[str] = set()
    for row in rows:
        record = row.get("record") if isinstance(row, dict) else None
        if not isinstance(record, dict):
            continue
        for ref in store._all_refs(record):
            if isinstance(ref, str) and Path(ref).parts[:2] == (REVISIONS_DIR, "raw"):
                refs.add(ref)
                if len(refs) > MAX_REVISION_RAW_FILES:
                    raise ValueError("revision raw evidence exceeds its file-count bound")
    return refs


def _raw_file_claims(
    run_dir, rows: list[dict], *, root_identity: tuple[int, int] | None = None,
    identity_claims: dict | None = None,
) -> dict:
    claims = {}
    if identity_claims is not None:
        identity_claims.clear()
    total = 0
    for ref in sorted(_late_raw_refs(rows)):
        path = _revision_raw_path(run_dir, ref)
        identity = {}
        body = _read_regular(
            path, root=revisions_dir(run_dir), maximum=MAX_REVISION_RAW_FILE_BYTES,
            expected_root_identity=root_identity, identity_out=identity,
        )
        total += len(body)
        if total > MAX_REVISION_RAW_TOTAL_BYTES:
            raise OSError("revision raw evidence exceeds its aggregate byte bound")
        claims[ref] = {"bytes": len(body), "digest": _sha(body)}
        if identity_claims is not None:
            identity_claims[ref] = identity
    return claims


def _records_digest(entity: str, records: dict) -> str:
    return _sha(_canonical_bytes(
        [[key, store.fingerprint(entity, record)] for key, record in sorted(records.items())]
    ))


def _effective_records_from_snapshot(
        manifest: run_manifest.RunManifest, base_counts: dict, rows: list[dict],
) -> tuple[dict, str]:
    """Fold supplements onto the exact base bytes held by manifest authority."""
    declared = manifest.document.get("envelope")
    if not isinstance(declared, dict):
        return {}, "the base manifest carries no corpus envelope"
    limits = {
        "max_keys": declared.get("max_keys_per_entity"),
        "max_bytes_per_key": declared.get("max_bytes_per_key"),
        "max_corpus_bytes": declared.get("max_corpus_bytes_per_entity"),
    }
    if any(type(value) is not int or value < 0 for value in limits.values()):
        return {}, "the base manifest carries an invalid corpus envelope"
    entities = set(base_counts)
    entities.update(row["entity"] for row in rows)
    records_by_entity: dict[str, dict] = {}
    for entity in sorted(entities):
        if entity not in store.ENTITY_KEYS:
            return {}, f"the base manifest names an unknown entity {entity!r}"
        expected = base_counts.get(entity, 0)
        base = manifest.folded_by_entity.get(entity)
        if base is None:
            if expected != 0:
                return {}, f"{entity} cannot be read whole: authenticated log is absent"
            records = {}
        else:
            if not base.trustworthy or base.refused or len(base.records) != expected:
                return {}, f"{entity} cannot be read whole: {base.reason}"
            records = dict(base.records)
        corpus_bytes = sum(store._record_bytes(record) for record in records.values())
        if len(records) > limits["max_keys"]:
            return {}, f"{entity} exceeds the declared key envelope"
        if any(store._record_bytes(record) > limits["max_bytes_per_key"]
               for record in records.values()):
            return {}, f"{entity} exceeds the declared per-key byte envelope"
        if corpus_bytes > limits["max_corpus_bytes"]:
            return {}, f"{entity} exceeds the declared corpus byte envelope"
        for row in rows:
            if row["entity"] != entity:
                continue
            key, record = row["id"], row["record"]
            previous = records.get(key)
            candidate = store.merge(entity, previous, record) if previous is not None else record
            candidate_bytes = store._record_bytes(candidate)
            previous_bytes = store._record_bytes(previous) if previous is not None else 0
            if candidate_bytes > limits["max_bytes_per_key"]:
                return {}, f"{entity} late evidence exceeds the declared per-key byte envelope"
            if previous is None and len(records) >= limits["max_keys"]:
                return {}, f"{entity} late evidence exceeds the declared key envelope"
            next_corpus_bytes = corpus_bytes - previous_bytes + candidate_bytes
            if next_corpus_bytes > limits["max_corpus_bytes"]:
                return {}, f"{entity} late evidence exceeds the declared corpus byte envelope"
            records[key] = candidate
            corpus_bytes = next_corpus_bytes
        records_by_entity[entity] = records
    return records_by_entity, ""


def _effective_records(run_dir, base_counts: dict, rows: list[dict]) -> tuple[dict, str]:
    """Compatibility wrapper using one strict authenticated base snapshot."""
    try:
        manifest, _digest, current_counts, _contents, _records = _certified_base_snapshot(run_dir)
    except RevisionError as exc:
        return {}, str(exc)
    if current_counts != base_counts:
        return {}, "the base manifest entity counts changed"
    return _effective_records_from_snapshot(manifest, base_counts, rows)


def read(run_dir) -> Revision:
    """The combined view published for `run_dir`, or an `absent` Revision when none was.

    Every listed segment is re-hashed against disk and the base manifest is re-hashed against the digest
    the revision was published over, so a truncated segment or a mutated base run fails closed.
    """
    run_dir = Path(run_dir)
    p = pointer_path(run_dir)
    try:
        p.lstat()
    except FileNotFoundError:
        return Revision()
    try:
        body = _read_regular(
            p, root=revisions_dir(run_dir), maximum=MAX_REVISION_POINTER_BYTES,
        )
        doc = _strict_json(body, "revision pointer")
        if type(doc) is not dict or body != _pointer_bytes(doc):
            raise RevisionError("revision pointer is not in canonical form")
    except (OSError, RevisionError, ValueError):
        doc = None
    if not isinstance(doc, dict):
        return Revision(status="unusable", reason="the revision pointer is unreadable")
    return _certify_document(run_dir, doc)


def _unusable(n: int, reason: str, run_dir) -> Revision:
    return Revision(revision=n, status="unusable", reason=reason,
                    orphans=_orphans(run_dir, n))


def _certify_document(run_dir, doc: dict) -> Revision:
    """Certify one pointer document against the bytes on disk.

    Publication calls this before exposing the document; ``read`` calls the same
    function afterwards.  There is consequently no weaker pre-publication rule.
    """
    run_dir = Path(run_dir)
    if doc.get("schema_version") != SCHEMA_VERSION:
        return Revision(status="unusable", reason=f"unknown revision schema {doc.get('schema_version')!r}")
    n = doc.get("revision")
    if type(n) is not int or n < 1:
        return Revision(status="unusable", reason="the revision pointer carries no exact revision number")
    _entries, root_fault = _revision_root_entries(run_dir)
    if root_fault:
        return _unusable(n, root_fault, run_dir)
    expected_fields = {
        "schema_version", "revision", "created", "base", "supplement", "entity_counts",
        "entity_digests", "raw_files", "views", "refused", "digest", "pointer_digest",
    }
    if set(doc) != expected_fields:
        return _unusable(n, f"revision {n} pointer fields do not match schema", run_dir)
    try:
        run_manifest._timestamp(doc.get("created"), f"revision {n} created")
    except run_manifest.ManifestError as exc:
        return _unusable(n, str(exc), run_dir)
    base = doc.get("base")
    if not isinstance(base, dict) or set(base) != {
        "run_id", "target", "manifest_digest", "entity_counts", "entity_contents",
    }:
        return _unusable(n, f"revision {n} base claim is malformed", run_dir)
    supplement = doc.get("supplement")
    if not isinstance(supplement, dict) or set(supplement) != {"segments", "lines", "digest"}:
        return _unusable(n, f"revision {n} supplement claim is malformed", run_dir)
    segments = supplement.get("segments") if isinstance(supplement, dict) else None
    if not isinstance(segments, list) or not segments:
        return _unusable(n, f"revision {n} lists no supplement segment", run_dir)
    if len(segments) > MAX_REVISION_SEGMENTS:
        return _unusable(n, f"revision {n} exceeds the supplement segment bound", run_dir)
    rev = Revision(revision=n, status="valid", created=str(doc.get("created", "")),
                   base=doc.get("base") if isinstance(doc.get("base"), dict) else {},
                   segments=segments,
                   supplement_lines=supplement.get("lines") if type(supplement.get("lines")) is int else 0,
                   supplement_digest=str(supplement.get("digest", "")),
                   entity_counts=doc.get("entity_counts") if isinstance(doc.get("entity_counts"), dict) else {},
                   entity_digests=doc.get("entity_digests") if isinstance(doc.get("entity_digests"), dict) else {},
                   raw_files=doc.get("raw_files") if isinstance(doc.get("raw_files"), dict) else {},
                   views=doc.get("views") if isinstance(doc.get("views"), dict) else {},
                   refused=doc.get("refused") if isinstance(doc.get("refused"), list) else [],
                   digest=str(doc.get("digest", "")),
                   pointer_digest=str(doc.get("pointer_digest", "")),
                   orphans=_orphans(run_dir, n))
    if not rev.created or not isinstance(doc.get("created"), str):
        return _unusable(n, f"revision {n} carries no creation time", run_dir)
    if not isinstance(doc.get("entity_counts"), dict) or not isinstance(doc.get("entity_digests"), dict):
        return _unusable(n, f"revision {n} entity claims are malformed", run_dir)
    if not isinstance(doc.get("raw_files"), dict) or not isinstance(doc.get("refused"), list):
        return _unusable(n, f"revision {n} raw/refusal claims are malformed", run_dir)
    if not isinstance(doc.get("views"), dict) or set(doc["views"]) != {"dir", "files"}:
        return _unusable(n, f"revision {n} view claims are malformed", run_dir)
    for entry in rev.refused:
        if (not isinstance(entry, dict) or set(entry) not in (
                    {"entity", "key", "kind"}, {"entity", "key", "kind", "fp"},
                )
                or entry.get("entity") not in store.ENTITY_KEYS
                or not isinstance(entry.get("key"), str) or not entry["key"]
                or not isinstance(entry.get("kind"), str) or not entry["kind"]
                or ("fp" in entry and (
                    type(entry["fp"]) is not str
                    or re.fullmatch(r"[0-9a-f]{32}", entry["fp"]) is None
                ))):
            return _unusable(n, f"revision {n} carries a malformed refusal", run_dir)
    bad = _view_dir_fault(rev)
    if bad:
        return _unusable(n, bad, run_dir)
    held = doc.get("base", {}).get("manifest_digest") if isinstance(doc.get("base"), dict) else None
    try:
        manifest, current, base_counts, contents, base_records = _certified_base_snapshot(run_dir)
    except RevisionError as e:
        return _unusable(n, f"the base evidence changed after revision {n} was published or became "
                            f"uncertifiable ({e})", run_dir)
    if held != current:
        return _unusable(n, f"the base run changed after revision {n} was published", run_dir)
    manifest_doc = manifest.document
    if (rev.base.get("run_id") != manifest_doc.get("run_id")
            or rev.base.get("target") != manifest_doc.get("target")):
        return _unusable(n, f"revision {n} does not name the sealed base identity", run_dir)
    if rev.base.get("entity_counts") != base_counts:
        return _unusable(n, f"revision {n} does not carry the base manifest's entity counts", run_dir)
    # the manifest counts the evidence; these digest it, so a same-count content swap is still a change
    recorded = rev.base.get("entity_contents")
    if not isinstance(recorded, dict) or recorded != contents:
        moved = sorted(set(contents) ^ set(recorded or {})
                       | {e for e in contents if isinstance(recorded, dict) and e in recorded
                          and recorded[e] != contents[e]})
        return _unusable(n, f"the base evidence changed after revision {n} was published "
                          f"({', '.join(moved[:4]) or 'no recorded content digests'})", run_dir)
    previous_number = 0
    total_segment_bytes = 0
    certified_rows: list[dict] = []
    dropped_rows = 0
    for seg in segments:
        if not isinstance(seg, dict) or set(seg) != {"revision", "file", "lines", "bytes", "digest"}:
            return _unusable(n, "a supplement segment is malformed", run_dir)
        number = seg.get("revision")
        if type(number) is not int or number <= previous_number:
            return _unusable(n, f"revision {n} has a non-monotonic segment chain", run_dir)
        if (type(seg.get("lines")) is not int or seg["lines"] < 0
                or type(seg.get("bytes")) is not int or not 0 <= seg["bytes"] <= MAX_REVISION_SEGMENT_BYTES
                or not isinstance(seg.get("digest"), str)):
            return _unusable(n, "a supplement segment claim is malformed", run_dir)
        total_segment_bytes += seg["bytes"]
        if total_segment_bytes > MAX_REVISION_SUPPLEMENT_BYTES:
            return _unusable(n, f"revision {n} exceeds the supplement byte bound", run_dir)
        try:
            segment_path = _segment_path(run_dir, seg.get("file"))
            body = _read_regular(
                segment_path, root=revisions_dir(run_dir), maximum=MAX_REVISION_SEGMENT_BYTES,
            )
        except (OSError, ValueError) as e:
            return _unusable(n, f"supplement segment {seg.get('file')!r} is unusable: {e}", run_dir)
        path_number = int(Path(seg["file"]).parts[0][3:])
        if number != path_number:
            return _unusable(n, f"supplement segment {seg.get('file')!r} has the wrong revision", run_dir)
        if (len(body) != seg["bytes"] or _sha(body) != seg["digest"]
                or (body and not body.endswith(b"\n"))
                or len(body.splitlines()) != seg["lines"]):
            return _unusable(
                n, f"supplement segment {seg.get('file')!r} is not the one revision {n} published", run_dir,
            )
        parsed, lost = _segment_rows(body, seg["file"])
        certified_rows.extend(parsed)
        dropped_rows += lost
        previous_number = number
    if previous_number != n:
        return _unusable(n, f"revision {n} does not end at its own supplement segment", run_dir)
    if _chain_digest(segments) != rev.supplement_digest:
        return _unusable(n, f"revision {n} does not certify its own segment chain", run_dir)
    expected_lines = sum(seg["lines"] for seg in segments)
    if rev.supplement_lines != expected_lines:
        return _unusable(n, f"revision {n} records the wrong supplement line count", run_dir)
    rows = certified_rows
    if dropped_rows:
        return _unusable(n, f"{dropped_rows} unusable supplement row(s) in revision {n}", run_dir)
    if len(rows) != expected_lines:
        return _unusable(n, f"revision {n} does not yield every segment row", run_dir)

    records_by_entity, effective_fault = _effective_records_from_snapshot(
        manifest, base_counts, rows,
    )
    if effective_fault:
        return _unusable(n, effective_fault, run_dir)
    counts = {entity: len(records) for entity, records in records_by_entity.items()}
    digests = {entity: _records_digest(entity, records)
               for entity, records in records_by_entity.items()}
    if (any(type(value) is not int or value < 0 for value in rev.entity_counts.values())
            or rev.entity_counts != counts):
        moved = sorted(set(rev.entity_counts) ^ set(counts)
                       | {entity for entity in counts if rev.entity_counts.get(entity) != counts[entity]})
        entity = moved[0] if moved else "evidence"
        return _unusable(n, f"revision {n} entity counts do not match {entity}", run_dir)
    if rev.entity_digests != digests:
        return _unusable(n, f"revision {n} entity digests do not match the effective evidence", run_dir)

    try:
        raw_files = _raw_file_claims(run_dir, rows)
    except (OSError, ValueError) as exc:
        return _unusable(n, f"revision {n} late raw evidence is unusable: {exc}", run_dir)
    if rev.raw_files != raw_files:
        return _unusable(n, f"revision {n} late raw evidence claims do not match disk", run_dir)

    expected_digest = _evidence_digest(
        base=current,
        supplement=rev.supplement_digest,
        counts=counts,
        entity_digests=digests,
        raw_files=raw_files,
    )
    if rev.digest != expected_digest:
        return _unusable(n, f"revision {n} does not certify its effective evidence", run_dir)
    if rev.pointer_digest != _pointer_digest(doc):
        return _unusable(n, f"revision {n} pointer document digest does not match", run_dir)

    rev.base_records = base_records
    rev.effective_records = records_by_entity
    provenance: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        key = (row["entity"], row["id"])
        segment = row["segment"]
        if segment not in provenance.setdefault(key, []):
            provenance[key].append(segment)
    rev.provenance = {key: tuple(value) for key, value in provenance.items()}
    rev.snapshot_bound = True

    try:
        rev.stale_views = _stale_view_files(run_dir, rev)
    except RevisionError as exc:
        return _unusable(n, str(exc), run_dir)
    return rev


def _view_dir_fault(rev: Revision) -> str:
    """Why a pointer's `views.dir` may not be used, or "" — it names a directory this process creates and
    writes, so an absolute or escaping value would put a run's reports outside the run."""
    name = rev.views.get("dir")
    if name is None:
        return ""                                     # no views recorded; the revision name is used instead
    if not isinstance(name, str) or not _REV_RE.match(name):
        return f"revision {rev.revision} names a view directory that is not a revision: {name!r}"
    if name != _rev_name(rev.revision):
        return f"revision {rev.revision} names another revision's view directory: {name!r}"
    return ""


def _view_dir(run_dir, rev: Revision) -> Path:
    """The validated directory holding a revision's derived views."""
    return revisions_dir(run_dir) / (rev.views.get("dir") or _rev_name(rev.revision))


def _merged_records(run_dir, entity: str, rows: list) -> tuple[dict | None, store.FoldedLog]:
    """`(combined records, the base fold)` for one entity — base evidence with the committed supplement
    rows merged on top. `None` records when the base itself cannot be read whole."""
    base = store.fold_run_entity(run_dir, entity)
    if not base.trustworthy:
        return None, base
    records = dict(base.records)
    for row in rows:
        if row["entity"] != entity:
            continue
        key, rec = row["id"], row["record"]
        records[key] = store.merge(entity, records[key], rec) if key in records else rec
    return records, base


def _count_fault(run_dir, rev: "Revision", base_counts: dict, rows: list) -> str:
    """Why the pointer's counts do not match the evidence, or "".

    A count nobody reconciles is a claim, not a record: without this a tampered count certified `valid`
    while the view it describes was unusable, and a caller that trusts certification exits clean on it.
    An entity the segments never touched is answered by the base manifest alone, so only supplemented
    entities are folded.
    """
    counts = rev.entity_counts
    touched = {row["entity"] for row in rows}
    for entity in sorted(set(counts) | set(base_counts)):
        if entity in touched:
            records, base = _merged_records(run_dir, entity, rows)
            if records is None:
                return f"{entity} cannot be read whole: {base.reason}"
            expected = len(records)
        else:
            expected = base_counts.get(entity, 0)    # untouched: the base manifest answers for it alone
        if counts.get(entity) != expected:
            return (f"revision {rev.revision} records {counts.get(entity)!r} {entity}, "
                    f"the evidence yields {expected}")
    return ""


def _chain_digest(segments: list) -> str:
    """One digest over the ordered segment digests — the supplement's identity without rereading it."""
    return _sha("\n".join(str(s.get("digest", "")) for s in segments if isinstance(s, dict)).encode("utf-8"))


def _segment_rows(body: bytes, segment: str) -> tuple[list[dict], int]:
    """Strict rows from one already-authenticated segment body."""
    rows: list[dict] = []
    dropped = 0
    if body and not body.endswith(b"\n"):
        return rows, 1
    for index, line in enumerate(body.splitlines(), 1):
        if not line or len(line) > run_manifest.MAX_JSONL_LINE_BYTES:
            dropped += 1
            continue
        try:
            row = _strict_json(line, f"revision segment {segment!r} row {index}")
        except RevisionError:
            dropped += 1
            continue
        entity = row.get("entity") if type(row) is dict else None
        rec = row.get("record") if type(row) is dict else None
        if type(entity) is not str or entity not in store.ENTITY_KEYS or type(rec) is not dict:
            dropped += 1
            continue
        key = store.canonical_key(entity, rec)
        try:
            fingerprint = store.fingerprint(entity, rec)
        except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
            dropped += 1
            continue
        if not key or row.get("id") != key or row.get("fp") != fingerprint:
            dropped += 1
            continue
        row["segment"] = segment
        rows.append(row)
    return rows, dropped


def _committed_rows(run_dir, rev: Revision) -> tuple[list[dict], int]:
    """`(rows, dropped)` from every committed segment, in publication order. A row whose recorded identity
    or fingerprint does not match its record is dropped and counted, never folded in."""
    rows: list[dict] = []
    dropped = 0
    total = 0
    for seg in rev.segments:
        try:
            claimed = seg.get("bytes")
            if type(claimed) is not int or claimed < 0 or claimed > MAX_REVISION_SEGMENT_BYTES:
                raise ValueError("invalid segment byte claim")
            total += claimed
            if total > MAX_REVISION_SUPPLEMENT_BYTES:
                raise ValueError("revision supplement exceeds its aggregate byte bound")
            body = _read_regular(
                _segment_path(run_dir, seg.get("file")), root=revisions_dir(run_dir),
                maximum=MAX_REVISION_SEGMENT_BYTES,
            )
        except (OSError, ValueError):
            dropped += 1
            continue
        parsed, lost = _segment_rows(body, str(seg.get("file")))
        rows.extend(parsed)
        dropped += lost
    return rows, dropped


def _provenance(run_dir, rev: Revision) -> dict:
    """`{(entity, key): (segment files...)}` for every committed supplement row.

    A later row may merge with the base and more than one prior supplement.
    Keeping the complete ordered source roster lets strict derived views bind
    every contributing artifact while ``store_ref`` retains its historic
    latest-segment compatibility result.
    """
    if rev.snapshot_bound:
        return dict(rev.provenance)
    rows, _ = _committed_rows(run_dir, rev)
    refs: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        key = (row["entity"], row["id"])
        segment = row["segment"]
        if segment not in refs.setdefault(key, []):
            refs[key].append(segment)
    return {key: tuple(value) for key, value in refs.items()}


# ── reading the combined view ─────────────────────────────────────────────────────────────────────

def combined_counts(run_dir) -> dict:
    """The manifested entity counts of the combined view: the published revision's when one is certified,
    else the base manifest's. Empty when neither can be read."""
    rev = read(run_dir)
    if rev.status == "valid":
        return dict(rev.entity_counts)
    if rev.status == "unusable":
        return {}
    try:
        manifest, _digest, counts, _contents, _records = _certified_base_snapshot(run_dir)
    except RevisionError:
        return {}
    return dict(counts)


def certification(run_dir) -> tuple[str, str]:
    """`(status, reason)` of the published revision: `absent` (no late evidence), `valid` (certified) or
    `unusable` (late evidence exists but can no longer be trusted).

    A caller that only sees "no view" cannot tell those apart, and would exit clean on the one case that
    means evidence was lost.
    """
    rev = read(run_dir)
    return rev.status, rev.reason


def refusals(run_dir) -> list[dict]:
    """Every identity the corpus envelope is still refusing, carried across revisions — the durable form of
    the count an ingest returns, so `status` and `report` keep reporting the gap after the import that hit
    it has exited. Empty when nothing is published; a broken revision reports none rather than guess."""
    rev = read(run_dir)
    return [dict(e) for e in rev.refused if isinstance(e, dict)] if rev.status == "valid" else []


def missing_views(run_dir) -> list[str]:
    """Derived views a certified revision recorded that are no longer on disk, so a caller can rebuild
    them rather than let a deleted view certify itself away. Empty when nothing is published."""
    rev = read(run_dir)
    if rev.status != "valid":
        return []
    return list(rev.stale_views)


def view_identity(run_dir) -> tuple[int, str]:
    """`(revision, digest)` of the published combined view — `(0, "")` when only the base run exists. A
    consumer records this pair and re-reads when it changes."""
    rev = read(run_dir)
    return (rev.revision, rev.digest) if rev.status == "valid" else (rev.revision, "")


def combined_fold(run_dir, entity: str) -> store.FoldedLog:
    """The base run's fold for `entity` with every committed supplement row merged in — what a consumer
    must read once a revision exists. An uncertified revision folds in nothing and says so."""
    entity = store.validate_entity(entity)
    rev = read(run_dir)
    if rev.status == "absent":
        try:
            manifest, _digest, _counts, _contents, _records = _certified_base_snapshot(run_dir)
        except RevisionError as exc:
            return store.FoldedLog(status="unknown", reason=str(exc))
        base = manifest.folded_by_entity.get(entity)
        return base if base is not None else store.FoldedLog()
    if rev.status != "valid":
        return store.FoldedLog(status="unknown", reason=rev.reason)
    records = rev.effective_records.get(entity, {})
    expected = rev.entity_counts.get(entity, 0)
    if type(expected) is not int or len(records) != expected:
        return store.FoldedLog(records=records, status="degraded",
                               reason=f"revision {rev.revision} records {expected} {entity}, "
                                      f"the combined view yields {len(records)}")
    return store.FoldedLog(records=records)


class CombinedRun:
    """A finished run read as its combined view, with a revision's own directory for derived views.

    Read-only over `read`/`count`/`values`; everything else is the base run, so the report and export
    renderers need to know nothing about revisions.
    """

    def __init__(self, run, overlay: dict, reports: Path, exports: Path, refs: dict | None = None,
                 base_records: dict | None = None):
        self._run = run
        self._overlay = overlay                   # entity -> {canonical key: combined record}
        self._refs = refs or {}                   # (entity, key) -> ordered contributing segment files
        self._base_snapshot_bound = base_records is not None
        self._base_keys: dict[str, set[str]] = {
            entity: set(records) for entity, records in (base_records or {}).items()
        }
        self.reports = privfs.private_dir(reports)
        self.exports = privfs.private_dir(exports)

    def read(self, entity: str) -> list[dict]:
        if self._base_snapshot_bound and entity in store.ENTITY_KEYS:
            return list(self._overlay.get(entity, {}).values())
        return list(self._overlay[entity].values()) if entity in self._overlay else self._run.read(entity)

    def count(self, entity: str) -> int:
        if self._base_snapshot_bound and entity in store.ENTITY_KEYS:
            return len(self._overlay.get(entity, {}))
        return len(self._overlay[entity]) if entity in self._overlay else self._run.count(entity)

    def values(self, entity: str) -> list[str]:
        key_field = store.ENTITY_KEYS.get(entity, "value")
        return [str(r.get(key_field, "")) for r in self.read(entity) if r.get(key_field)]

    def store_ref(self, entity: str, record: dict) -> str:
        """The run-relative file holding this observation: its supplement segment when it arrived after the
        run finished, else the run's own entity log."""
        segments = self._refs.get((entity, store.canonical_key(entity, record)), ())
        return f"{REVISIONS_DIR}/{segments[-1]}" if segments else f"normalized/{entity}.jsonl"

    def store_refs(self, entity: str, record: dict) -> list[str]:
        """Every canonical artifact whose row contributes to this effective record."""
        key = store.canonical_key(entity, record)
        if entity not in self._base_keys:
            self._base_keys[entity] = (set() if self._base_snapshot_bound else {
                store.canonical_key(entity, row) for row in self._run.read(entity)
            })
        out = [f"normalized/{entity}.jsonl"] if key in self._base_keys[entity] else []
        out.extend(f"{REVISIONS_DIR}/{segment}" for segment in self._refs.get((entity, key), ()))
        return out

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_run"), name)


def combined_view(run, rev: Revision | None = None) -> CombinedRun | None:
    """The published combined view of a finished run, rendering into its revision's directory, or None when
    no certified revision exists. The base run's own views stay as it finished them."""
    rev = read(run.dir) if rev is None else rev
    if rev.status != "valid":
        return None
    refs = _provenance(run.dir, rev)
    overlay = {
        entity: dict(records) for entity, records in rev.effective_records.items()
    }
    d = _view_dir(run.dir, rev)
    return CombinedRun(run, overlay, d, d / "exports", refs, rev.base_records)


def _bounded_tree_paths(root: Path) -> list[Path]:
    """Enumerate one private tree through held, no-follow directory descriptors."""
    root = Path(root)
    paths: list[Path] = []
    root_fd = _open_private_directory_path(root)

    def walk(directory_fd: int, relative: Path, depth: int) -> None:
        if depth > MAX_REVISION_TREE_DEPTH:
            raise RevisionError(f"{root}: revision tree exceeds its depth bound")
        try:
            iterator = os.scandir(directory_fd)
        except OSError as exc:
            raise RevisionError(f"{root / relative}: revision tree is unreadable: {exc}") from exc
        with iterator:
            for entry in iterator:
                path = root / relative / entry.name
                try:
                    observed = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise RevisionError(f"{path}: revision object is unreadable: {exc}") from exc
                if stat.S_ISLNK(observed.st_mode) or not (
                        stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)):
                    raise RevisionError(f"{path}: revision tree contains an unsafe object")
                paths.append(path)
                if len(paths) > MAX_REVISION_VIEW_FILES:
                    raise RevisionError(f"{root}: revision tree exceeds its file-count bound")
                child_fd = -1
                try:
                    if stat.S_ISDIR(observed.st_mode):
                        child_fd = os.open(entry.name, _DIR_READ_FLAGS, dir_fd=directory_fd)
                        if (_private_directory_claim(os.fstat(child_fd), path)
                                != _private_directory_claim(observed, path)):
                            raise RevisionError(f"{path}: revision directory changed during enumeration")
                        walk(child_fd, relative / entry.name, depth + 1)
                    else:
                        child_fd = os.open(entry.name, _FILE_READ_FLAGS, dir_fd=directory_fd)
                        if (_private_file_claim(os.fstat(child_fd), path)
                                != _private_file_claim(observed, path)):
                            raise RevisionError(f"{path}: revision file changed during enumeration")
                except OSError as exc:
                    raise RevisionError(f"{path}: revision object is unsafe: {exc}") from exc
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)

    try:
        walk(root_fd, Path(), 0)
        return sorted(paths)
    finally:
        os.close(root_fd)


def _view_files(rev_dir: Path) -> dict:
    """`{path relative to the revision dir: digest}` for every derived view it holds — the segment is
    evidence, not a view, so it is never listed."""
    out = {}
    total = 0
    paths = _bounded_tree_paths(rev_dir)
    for p in paths:
        try:
            mode = p.lstat().st_mode
        except OSError as exc:
            raise RevisionError(f"{p}: revision view is unreadable: {exc}") from exc
        if stat.S_ISLNK(mode):
            raise RevisionError(f"{p}: revision view may not be a symlink")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise RevisionError(f"{p}: revision view is not a regular file")
        if p.name != SEGMENT_NAME:
            body = _read_regular(p, root=rev_dir, maximum=MAX_REVISION_VIEW_FILE_BYTES)
            total += len(body)
            if total > MAX_REVISION_VIEW_TOTAL_BYTES:
                raise RevisionError(f"{rev_dir}: revision views exceed their aggregate byte bound")
            out[str(p.relative_to(rev_dir))] = _sha(body)
    return out


def _stale_view_files(run_dir, rev: Revision) -> list[str]:
    """Recompute every derived-view claim; stale bytes are rebuildable, unsafe paths are not."""
    files = rev.views.get("files")
    if not isinstance(files, dict):
        raise RevisionError(f"revision {rev.revision} carries no view-file claims")
    for name, digest in files.items():
        parts = Path(name).parts if isinstance(name, str) else ()
        if (not parts or Path(name).is_absolute() or any(part in ("", ".", "..") for part in parts)
                or parts[-1] == SEGMENT_NAME or not isinstance(digest, str)):
            raise RevisionError(f"revision {rev.revision} carries an unsafe view-file claim {name!r}")
    directory = _view_dir(run_dir, rev)
    if not directory.exists():
        return sorted(files)
    mode = directory.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise RevisionError(f"revision {rev.revision} view directory is unsafe")
    try:
        actual = _view_files(directory)
    except RevisionError:
        raise
    return sorted(set(files) ^ set(actual)
                  | {name for name in files if name in actual and files[name] != actual[name]})


def _fsync_directory(path: Path, *, directory_identity: tuple[int, int]) -> None:
    path = Path(path)
    fd = _open_private_directory_path(
        path, expected_identity=directory_identity,
    )
    check_fd = -1
    try:
        os.fsync(fd)
        check_fd = _open_private_directory_path(
            path, expected_identity=directory_identity,
        )
    finally:
        if check_fd >= 0:
            os.close(check_fd)
        os.close(fd)


def _validate_tree_identity_claims_fd(
    root_fd: int, root: Path,
    expected_tree: dict[tuple[str, ...], tuple[str, tuple[int, ...]]],
) -> None:
    root = Path(root)
    def validate(directory_fd: int, relative: Path) -> None:
        direct = {
            parts[-1]
            for parts in expected_tree
            if parts[:-1] == tuple(relative.parts)
        }
        seen: set[str] = set()
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                key = tuple((relative / entry.name).parts)
                expected = expected_tree.get(key)
                if expected is None or entry.name in seen:
                    raise OSError(f"staged revision tree changed during durability: {root}")
                seen.add(entry.name)
                kind, identity = expected
                opened = -1
                try:
                    if kind == "directory":
                        observed = _private_directory_claim(
                            entry.stat(follow_symlinks=False), root.joinpath(*key),
                        )
                        if observed != identity:
                            raise OSError(
                                f"staged revision directory name changed during durability: "
                                f"{root.joinpath(*key)}",
                            )
                        opened = os.open(entry.name, _DIR_READ_FLAGS, dir_fd=directory_fd)
                        if (_private_directory_claim(os.fstat(opened), root.joinpath(*key))
                                != identity):
                            raise OSError(
                                f"staged revision directory name changed during durability: "
                                f"{root.joinpath(*key)}",
                            )
                        validate(opened, relative / entry.name)
                    else:
                        observed = _private_file_claim(
                            entry.stat(follow_symlinks=False), root.joinpath(*key),
                        )
                        if observed != identity:
                            raise OSError(
                                f"staged revision file name changed during durability: "
                                f"{root.joinpath(*key)}",
                            )
                        opened = os.open(entry.name, _FILE_READ_FLAGS, dir_fd=directory_fd)
                        if (_private_file_claim(os.fstat(opened), root.joinpath(*key))
                                != identity):
                            raise OSError(
                                f"staged revision file name changed during durability: "
                                f"{root.joinpath(*key)}",
                            )
                finally:
                    if opened >= 0:
                        os.close(opened)
        if seen != direct:
            raise OSError(f"staged revision tree names changed during durability: {root}")

    validate(root_fd, Path())


def _validate_tree_identity_claims(
    root: Path, root_identity: tuple[int, int],
    expected_tree: dict[tuple[str, ...], tuple[str, tuple[int, ...]]],
) -> None:
    root = Path(root)
    root_fd = _open_private_directory_path(root, expected_identity=root_identity)
    try:
        _validate_tree_identity_claims_fd(root_fd, root, expected_tree)
    finally:
        os.close(root_fd)


def _fsync_tree(
    root: Path, *, root_identity: tuple[int, int],
) -> dict[tuple[str, ...], tuple[str, tuple[int, ...]]]:
    """Durably seal a staged tree without reopening any absolute descendant path."""
    root = Path(root)
    root_fd = _open_private_directory_path(root, expected_identity=root_identity)
    count = 0
    expected_tree: dict[tuple[str, ...], tuple[str, tuple[int, ...]]] = {}

    def sync(directory_fd: int, relative: Path, depth: int) -> None:
        nonlocal count
        if depth > MAX_REVISION_TREE_DEPTH:
            raise RevisionError(f"{root}: revision tree exceeds its depth bound")
        try:
            iterator = os.scandir(directory_fd)
        except OSError as exc:
            raise RevisionError(f"{root / relative}: revision tree is unreadable: {exc}") from exc
        with iterator:
            for entry in iterator:
                count += 1
                if count > MAX_REVISION_VIEW_FILES:
                    raise RevisionError(f"{root}: revision tree exceeds its file-count bound")
                path = root / relative / entry.name
                try:
                    observed = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise RevisionError(f"{path}: revision object is unreadable: {exc}") from exc
                child_fd = -1
                try:
                    if stat.S_ISREG(observed.st_mode):
                        claim = _private_file_claim(observed, path)
                        expected_tree[tuple((relative / entry.name).parts)] = ("file", claim)
                        child_fd = os.open(entry.name, _FILE_READ_FLAGS, dir_fd=directory_fd)
                        if (_private_file_claim(os.fstat(child_fd), path)
                                != claim):
                            raise OSError(f"staged revision file changed during durability: {path}")
                        os.fsync(child_fd)
                    elif stat.S_ISDIR(observed.st_mode):
                        claim = _private_directory_claim(observed, path)
                        expected_tree[tuple((relative / entry.name).parts)] = ("directory", claim)
                        child_fd = os.open(entry.name, _DIR_READ_FLAGS, dir_fd=directory_fd)
                        if (_private_directory_claim(os.fstat(child_fd), path)
                                != claim):
                            raise OSError(f"staged revision directory changed during durability: {path}")
                        sync(child_fd, relative / entry.name, depth + 1)
                        os.fsync(child_fd)
                    else:
                        raise OSError(f"unsafe staged revision object: {path}")
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)

    try:
        sync(root_fd, Path(), 0)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    _validate_tree_identity_claims(root, root_identity, expected_tree)
    return expected_tree


def _validate_file_identity_claims_fd(
    root_fd: int, root: Path, relative_paths: dict, identity_claims: dict,
    byte_counts: dict, *, noun: str,
) -> None:
    """Rewalk a complete named file roster below one held authority root."""
    root = Path(root)
    if not (set(relative_paths) == set(identity_claims) == set(byte_counts)):
        raise OSError(f"{noun} durability identities do not match its claims")
    root_identity = _private_directory_claim(os.fstat(root_fd), root)[:2]
    for key in sorted(relative_paths):
        relative = Path(relative_paths[key])
        expected = identity_claims[key]
        if (relative.is_absolute() or not relative.parts
                or any(part in ("", ".", "..") for part in relative.parts)
                or type(expected) is not dict
                or set(expected) != {"root", "directories", "file"}
                or type(expected.get("directories")) not in (tuple, list)
                or type(expected.get("file")) not in (tuple, list)
                or len(expected["root"]) < 2 or tuple(expected["root"][:2]) != root_identity
                or len(expected["directories"]) != len(relative.parts) - 1
                or len(expected["file"]) < 6
                or expected["file"][5] != byte_counts[key]):
            raise OSError(f"invalid {noun} durability identity: {key}")
        current = os.dup(root_fd)
        transient = file_fd = -1
        try:
            for index, component in enumerate(relative.parts[:-1]):
                transient = os.open(component, _DIR_READ_FLAGS, dir_fd=current)
                observed = _private_directory_claim(
                    os.fstat(transient), root.joinpath(*relative.parts[:index + 1]),
                )
                if observed != tuple(expected["directories"][index]):
                    raise OSError(
                        f"{noun} directory name changed during durability; authority changed: {key}",
                    )
                os.close(current)
                current = transient
                transient = -1
            file_fd = os.open(relative.parts[-1], _FILE_READ_FLAGS, dir_fd=current)
            if (_private_file_claim(os.fstat(file_fd), root / relative)
                    != tuple(expected["file"])):
                raise OSError(
                    f"{noun} file name changed during durability; authority changed: {key}",
                )
        finally:
            for owned in (file_fd, transient, current):
                if owned >= 0:
                    os.close(owned)


def _validate_file_identity_claims(
    root: Path, root_identity: tuple[int, int], relative_paths: dict,
    identity_claims: dict, byte_counts: dict, *, noun: str,
) -> None:
    root_fd = _open_private_directory_path(Path(root), expected_identity=root_identity)
    try:
        _validate_file_identity_claims_fd(
            root_fd, Path(root), relative_paths, identity_claims, byte_counts, noun=noun,
        )
    finally:
        os.close(root_fd)


def _fsync_file_identity_claims(
    root: Path, root_identity: tuple[int, int], relative_paths: dict,
    identity_claims: dict, byte_counts: dict, *, noun: str,
) -> None:
    """Fsync and finally revalidate every member of one complete file roster."""
    root = Path(root)
    root_fd = _open_private_directory_path(root, expected_identity=root_identity)
    try:
        _validate_file_identity_claims_fd(
            root_fd, root, relative_paths, identity_claims, byte_counts, noun=noun,
        )
        for key in sorted(relative_paths):
            relative = Path(relative_paths[key])
            expected = identity_claims[key]
            held = [os.dup(root_fd)]
            file_fd = -1
            try:
                for index, component in enumerate(relative.parts[:-1]):
                    child = -1
                    try:
                        child = os.open(component, _DIR_READ_FLAGS, dir_fd=held[-1])
                        if (_private_directory_claim(
                                os.fstat(child), root.joinpath(*relative.parts[:index + 1]),
                            ) != tuple(expected["directories"][index])):
                            raise OSError(f"{noun} directory authority changed: {key}")
                        held.append(child)
                        child = -1
                    finally:
                        if child >= 0:
                            os.close(child)
                file_fd = os.open(relative.parts[-1], _FILE_READ_FLAGS, dir_fd=held[-1])
                if (_private_file_claim(os.fstat(file_fd), root / relative)
                        != tuple(expected["file"])):
                    raise OSError(f"{noun} file authority changed: {key}")
                os.fsync(file_fd)
                if (_private_file_claim(os.fstat(file_fd), root / relative)
                        != tuple(expected["file"])):
                    raise OSError(f"{noun} file changed during durability: {key}")
                for index in range(len(held) - 1, 0, -1):
                    directory_fd = held[index]
                    if (_private_directory_claim(os.fstat(directory_fd), root / relative.parent)
                            != tuple(expected["directories"][index - 1])):
                        raise OSError(f"{noun} directory changed during durability: {key}")
                    os.fsync(directory_fd)
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
                for directory_fd in reversed(held):
                    os.close(directory_fd)
        os.fsync(root_fd)
        _validate_file_identity_claims_fd(
            root_fd, root, relative_paths, identity_claims, byte_counts, noun=noun,
        )
    finally:
        os.close(root_fd)
    _validate_file_identity_claims(
        root, root_identity, relative_paths, identity_claims, byte_counts, noun=noun,
    )


def _raw_identity_paths(run_dir, claims: dict) -> tuple[dict, dict]:
    root = revisions_dir(run_dir)
    relative_paths = {
        ref: _revision_raw_path(run_dir, ref).relative_to(root) for ref in claims
    }
    byte_counts = {ref: claims[ref].get("bytes") for ref in claims}
    return relative_paths, byte_counts


def _capture_raw_identity_claims(
    run_dir, claims: dict, *, root_identity: tuple[int, int],
) -> dict:
    root = revisions_dir(run_dir)
    identities: dict = {}
    for ref, claim in sorted(claims.items()):
        identity = {}
        body = _read_regular(
            _revision_raw_path(run_dir, ref), root=root,
            maximum=MAX_REVISION_RAW_FILE_BYTES,
            expected_root_identity=root_identity, identity_out=identity,
        )
        if (type(claim) is not dict or set(claim) != {"bytes", "digest"}
                or len(body) != claim.get("bytes") or _sha(body) != claim.get("digest")):
            raise OSError(f"revision raw evidence changed during durability: {ref}")
        identities[ref] = identity
    return identities


def _validate_raw_identity_claims(
    run_dir, claims: dict, *, root_identity: tuple[int, int], identity_claims: dict,
) -> None:
    relative_paths, byte_counts = _raw_identity_paths(run_dir, claims)
    _validate_file_identity_claims(
        revisions_dir(run_dir), root_identity, relative_paths, identity_claims,
        byte_counts, noun="revision raw",
    )


def _fsync_raw_claims(
    run_dir, claims: dict, *, root_identity: tuple[int, int], identity_claims: dict,
) -> None:
    relative_paths, byte_counts = _raw_identity_paths(run_dir, claims)
    _fsync_file_identity_claims(
        revisions_dir(run_dir), root_identity, relative_paths, identity_claims,
        byte_counts, noun="revision raw",
    )


def _capture_segment_identity_claims(
    run_dir, segments: list, *, root_identity: tuple[int, int],
) -> dict:
    root = revisions_dir(run_dir)
    identities: dict = {}
    for segment in segments:
        name = segment.get("file") if isinstance(segment, dict) else None
        path = _segment_path(run_dir, name)
        identity = {}
        body = _read_regular(
            path, root=root, maximum=MAX_REVISION_SEGMENT_BYTES,
            expected_root_identity=root_identity, identity_out=identity,
        )
        if (len(body) != segment.get("bytes") or _sha(body) != segment.get("digest")
                or (body and not body.endswith(b"\n"))):
            raise OSError(f"revision segment changed during durability: {name}")
        identities[name] = identity
    return identities


def _segment_identity_paths(segments: list) -> tuple[dict, dict]:
    relative_paths = {segment["file"]: Path(segment["file"]) for segment in segments}
    byte_counts = {segment["file"]: segment["bytes"] for segment in segments}
    return relative_paths, byte_counts


def _fsync_segment_identity_claims(
    run_dir, segments: list, *, root_identity: tuple[int, int], identity_claims: dict,
) -> None:
    relative_paths, byte_counts = _segment_identity_paths(segments)
    _fsync_file_identity_claims(
        revisions_dir(run_dir), root_identity, relative_paths, identity_claims,
        byte_counts, noun="revision segment",
    )


def _validate_publication_identity_snapshot(
    run_dir: Path, candidate: Revision, *, run_identity: tuple[int, int],
    revisions_identity: tuple[int, int], revision_identity: tuple[int, int],
    revision_tree: dict, segment_identities: dict, raw_identities: dict,
) -> None:
    """Bind every revision artifact to one coherent canonical hierarchy."""
    run_dir = Path(run_dir)
    run_fd, revisions_fd = _open_revision_authority(
        run_dir, run_identity=run_identity, revisions_identity=revisions_identity,
    )
    revision_fd = -1
    try:
        segment_paths, segment_bytes = _segment_identity_paths(candidate.segments)
        _validate_file_identity_claims_fd(
            revisions_fd, revisions_dir(run_dir), segment_paths, segment_identities,
            segment_bytes, noun="revision segment",
        )
        raw_paths, raw_bytes = _raw_identity_paths(run_dir, candidate.raw_files)
        _validate_file_identity_claims_fd(
            revisions_fd, revisions_dir(run_dir), raw_paths, raw_identities,
            raw_bytes, noun="revision raw",
        )
        revision_name = candidate.views.get("dir")
        if revision_name != _rev_name(candidate.revision):
            raise OSError("revision view authority does not name the published revision")
        revision_fd = os.open(revision_name, _DIR_READ_FLAGS, dir_fd=revisions_fd)
        if (_private_directory_claim(
                os.fstat(revision_fd), revisions_dir(run_dir) / revision_name,
            )[:2] != revision_identity):
            raise OSError("staged revision directory authority changed during publication")
        _validate_tree_identity_claims_fd(
            revision_fd, revisions_dir(run_dir) / revision_name, revision_tree,
        )
    finally:
        for fd in (revision_fd, revisions_fd, run_fd):
            if fd >= 0:
                os.close(fd)


def _read_fd_bounded(fd: int, maximum: int, where: Path) -> tuple[bytes, tuple[int, ...]]:
    identity = _private_file_claim(os.fstat(fd), where)
    if identity[5] > maximum:
        raise OSError(f"managed file exceeds its {maximum}-byte bound: {where}")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, maximum - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise OSError(f"managed file exceeds its {maximum}-byte bound: {where}")
        chunks.append(chunk)
    if _private_file_claim(os.fstat(fd), where) != identity:
        raise OSError(f"managed file changed while it was read: {where}")
    return b"".join(chunks), identity


def _read_pointer_authority(
    run_dir: Path, *, run_identity: tuple[int, int],
    revisions_identity: tuple[int, int],
) -> bytes | None:
    run_fd, revisions_fd = _open_revision_authority(
        run_dir, run_identity=run_identity, revisions_identity=revisions_identity,
    )
    pointer_fd = -1
    try:
        try:
            pointer_fd = os.open(POINTER_NAME, _FILE_READ_FLAGS, dir_fd=revisions_fd)
        except FileNotFoundError:
            return None
        body, _identity = _read_fd_bounded(
            pointer_fd, MAX_REVISION_POINTER_BYTES, pointer_path(run_dir),
        )
        return body
    finally:
        for fd in (pointer_fd, revisions_fd, run_fd):
            if fd >= 0:
                os.close(fd)


def _durably_settle_pointer_authority(
    run_dir: Path, expected: bytes, *, run_identity: tuple[int, int],
    revisions_identity: tuple[int, int],
) -> None:
    """Fsync the current canonical pointer, then prove its name and hierarchy."""
    run_fd, revisions_fd = _open_revision_authority(
        run_dir, run_identity=run_identity, revisions_identity=revisions_identity,
    )
    pointer_fd = check_fd = -1
    try:
        pointer_fd = os.open(POINTER_NAME, _FILE_READ_FLAGS, dir_fd=revisions_fd)
        body, identity = _read_fd_bounded(
            pointer_fd, MAX_REVISION_POINTER_BYTES, pointer_path(run_dir),
        )
        if body != expected:
            raise OSError("canonical revision pointer bytes changed during settlement")
        os.fsync(pointer_fd)
        if (_private_file_claim(os.fstat(pointer_fd), pointer_path(run_dir))
                != identity):
            raise OSError("canonical revision pointer changed during durability")
        os.fsync(revisions_fd)
        check_fd = os.open(POINTER_NAME, _FILE_READ_FLAGS, dir_fd=revisions_fd)
        checked, checked_identity = _read_fd_bounded(
            check_fd, MAX_REVISION_POINTER_BYTES, pointer_path(run_dir),
        )
        if checked != expected or checked_identity != identity:
            raise OSError("canonical revision pointer name changed during durability")
        os.fsync(run_fd)
    finally:
        for fd in (check_fd, pointer_fd, revisions_fd, run_fd):
            if fd >= 0:
                os.close(fd)
    # Reopen the canonical hierarchy after every effectful barrier.  A held
    # descriptor alone does not prove that its inode still owns the name.
    if _read_pointer_authority(
        run_dir, run_identity=run_identity, revisions_identity=revisions_identity,
    ) != expected:
        raise OSError("canonical revision pointer changed after durability")


def _write_all(fd: int, body: bytes) -> None:
    view = memoryview(body)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("revision pointer write made no progress")
        view = view[written:]


def _write_fsync_and_relinquish(fd: int, body: bytes) -> None:
    """Write/fsync one owned descriptor and never mask its primary fault on close."""
    primary: BaseException | None = None
    try:
        _write_all(fd, body)
        os.fsync(fd)
    except BaseException as exc:
        primary = exc
    try:
        os.close(fd)
    except BaseException as exc:
        if primary is None:
            primary = exc
    if primary is not None:
        raise primary


def _pointer_bytes(document: dict) -> bytes:
    try:
        run_manifest._validate_json_value(document, "revision pointer")
        body = (json.dumps(
            document, indent=2, ensure_ascii=False, allow_nan=False,
        ) + "\n").encode("utf-8")
    except (run_manifest.ManifestError, TypeError, ValueError, UnicodeEncodeError,
            RecursionError) as exc:
        raise RevisionError(f"revision pointer is not portable JSON: {exc}") from exc
    if len(body) > MAX_REVISION_POINTER_BYTES:
        raise RevisionError("revision pointer exceeds its byte bound")
    return body


def _private_directory_identity(path: Path) -> tuple[int, int]:
    """Authenticate one canonical private directory and return its stable name identity."""
    fd = _open_private_directory_path(Path(path))
    try:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def _open_revision_authority(
    run_dir: Path, *, run_identity: tuple[int, int] | None = None,
    revisions_identity: tuple[int, int] | None = None,
) -> tuple[int, int]:
    """Open the canonical run -> revisions hierarchy as one descriptor chain."""
    run_dir = Path(run_dir)
    run_fd = revisions_fd = -1
    try:
        run_fd = _open_private_directory_path(run_dir, expected_identity=run_identity)
        observed_run = _private_directory_claim(os.fstat(run_fd), run_dir)
        if run_identity is not None and observed_run[:2] != run_identity:
            raise OSError(f"run directory authority changed before open: {run_dir}")
        revisions_fd = os.open(REVISIONS_DIR, _DIR_READ_FLAGS, dir_fd=run_fd)
        observed_revisions = _private_directory_claim(
            os.fstat(revisions_fd), revisions_dir(run_dir),
        )
        if (revisions_identity is not None
                and observed_revisions[:2] != revisions_identity):
            raise OSError(
                f"revision directory authority changed before open: {revisions_dir(run_dir)}",
            )
        owned_run, run_fd = run_fd, -1
        owned_revisions, revisions_fd = revisions_fd, -1
        return owned_run, owned_revisions
    finally:
        for fd in (revisions_fd, run_fd):
            if fd >= 0:
                os.close(fd)


def _revision_hierarchy_identities(
    run_dir: Path, revision_name: str | None = None,
) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int] | None]:
    """Capture run, revisions, and optional revision-dir identities coherently."""
    run_fd, revisions_fd = _open_revision_authority(Path(run_dir))
    revision_fd = -1
    try:
        run_identity = _private_directory_claim(os.fstat(run_fd), run_dir)[:2]
        revisions_identity = _private_directory_claim(
            os.fstat(revisions_fd), revisions_dir(run_dir),
        )[:2]
        revision_identity = None
        if revision_name is not None:
            if _REV_RE.fullmatch(revision_name) is None:
                raise OSError(f"invalid revision directory name: {revision_name!r}")
            revision_fd = os.open(revision_name, _DIR_READ_FLAGS, dir_fd=revisions_fd)
            revision_identity = _private_directory_claim(
                os.fstat(revision_fd), revisions_dir(run_dir) / revision_name,
            )[:2]
        return run_identity, revisions_identity, revision_identity
    finally:
        for fd in (revision_fd, revisions_fd, run_fd):
            if fd >= 0:
                os.close(fd)


def _same_private_directory(path: Path, expected: tuple[int, int]) -> bool:
    try:
        return _private_directory_identity(path) == expected
    except OSError:
        return False


def _settle_pointer_fault(
    run_dir: Path,
    document: dict,
    candidate: Revision,
    previous: bytes | None,
    directory_identity: tuple[int, int],
    run_directory_identity: tuple[int, int],
    *, already_durable: bool = False, identity_validator=None,
) -> _PointerSettlement:
    """Classify a failed publication without guessing whether the pointer landed.

    A second directory fsync turns a byte-valid intended or restored pointer into
    a durable result before it is reported.  Anything else is ambiguous and may
    not be retried blindly (in particular, OOB raw proof must be retained).
    """
    run_dir = Path(run_dir)
    try:
        current = _read_pointer_authority(
            run_dir, run_identity=run_directory_identity,
            revisions_identity=directory_identity,
        )
    except OSError:
        return _PointerSettlement("ambiguous")

    intended = _pointer_bytes(document)
    if current == intended:
        try:
            # Even a publisher that observed its own directory fsync may have
            # had the canonical pointer inode substituted inside that callback.
            # Seal the exact current bytes and rebind their name before trust.
            _durably_settle_pointer_authority(
                run_dir, intended, run_identity=run_directory_identity,
                revisions_identity=directory_identity,
            )
            if identity_validator is not None:
                identity_validator()
        except Exception:
            return _PointerSettlement("ambiguous")
        settled = read(run_dir)
        if (settled.status != "valid" or settled.revision != candidate.revision
                or settled.pointer_digest != candidate.pointer_digest):
            return _PointerSettlement("ambiguous")
        try:
            if identity_validator is not None:
                identity_validator()
            if _read_pointer_authority(
                run_dir, run_identity=run_directory_identity,
                revisions_identity=directory_identity,
            ) != intended:
                return _PointerSettlement("ambiguous")
        except Exception:
            return _PointerSettlement("ambiguous")
        return _PointerSettlement("landed", settled)

    if current == previous:
        try:
            # Preserve the established cancellation/control-flow boundary for
            # a rollback that restored the prior pointer before settlement.
            _fsync_directory(
                revisions_dir(run_dir), directory_identity=directory_identity,
            )
            _fsync_directory(
                run_dir, directory_identity=run_directory_identity,
            )
            if previous is not None:
                _durably_settle_pointer_authority(
                    run_dir, previous, run_identity=run_directory_identity,
                    revisions_identity=directory_identity,
                )
            else:
                run_fd, revisions_fd = _open_revision_authority(
                    run_dir, run_identity=run_directory_identity,
                    revisions_identity=directory_identity,
                )
                try:
                    os.fsync(revisions_fd)
                    os.fsync(run_fd)
                finally:
                    os.close(revisions_fd)
                    os.close(run_fd)
                if _read_pointer_authority(
                    run_dir, run_identity=run_directory_identity,
                    revisions_identity=directory_identity,
                ) is not None:
                    return _PointerSettlement("ambiguous")
        except Exception:
            return _PointerSettlement("ambiguous")
        return _PointerSettlement("not_landed")
    return _PointerSettlement("ambiguous")


def _publish_pointer(
    path: Path, document: dict, *, directory_identity: tuple[int, int] | None = None,
) -> None:
    """Durably atomically replace the pointer after every candidate byte is sealed."""
    body = _pointer_bytes(document)
    dfd = _open_private_directory_path(path.parent)
    opened = os.fstat(dfd)
    if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != privfs.DIR_MODE
            or (directory_identity is not None
                and (opened.st_dev, opened.st_ino) != directory_identity)):
        os.close(dfd)
        raise OSError(f"revision directory authority changed before pointer publication: {path.parent}")
    temporary = f".{path.name}.{os.urandom(16).hex()}.tmp"
    fd = -1
    replaced = False
    previous = None
    primary: BaseException | None = None
    published_durable = False
    try:
        try:
            previous = _read_regular(path, maximum=MAX_REVISION_POINTER_BYTES)
        except FileNotFoundError:
            previous = None
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            privfs.FILE_MODE,
            dir_fd=dfd,
        )
        closing_fd, fd = fd, -1
        _write_fsync_and_relinquish(closing_fd, body)
        fd = -1
        os.replace(temporary, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
        replaced = True
        try:
            os.fsync(dfd)
        except BaseException:
            # A reported publication fault must not knowingly leave the new
            # pointer exposed.  Restore the exact previous bytes when possible.
            if previous is None:
                os.unlink(path.name, dir_fd=dfd)
            else:
                rollback = f".{path.name}.{os.urandom(16).hex()}.rollback"
                rfd = os.open(
                    rollback,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    privfs.FILE_MODE,
                    dir_fd=dfd,
                )
                _write_fsync_and_relinquish(rfd, previous)
                os.replace(rollback, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
            raise
        else:
            published_durable = True
    except BaseException as exc:
        primary = exc
        if fd >= 0:
            closing_fd, fd = fd, -1
            try:
                os.close(closing_fd)
            except BaseException:
                pass
        if not replaced:
            try:
                os.unlink(temporary, dir_fd=dfd)
            except BaseException:
                pass
    finally:
        closing_dfd, dfd = dfd, -1
        try:
            os.close(closing_dfd)
        except BaseException as exc:
            if primary is None:
                primary = exc
    if primary is not None:
        if published_durable:
            raise _PointerPostCommitFault(primary)
        raise primary


def reseal_views(run_dir) -> Revision | None:
    """Re-hash a published revision's derived views into its pointer, after they were regenerated. The
    revision number, segments and combined digest are untouched: a view is derived, not evidence.

    Under the publication lock: this is a read-modify-write of the same pointer, so an unlocked reseal
    would write back a pointer that predates a revision published beside it, dropping its segment.
    """
    # Recover the repository identity so view resealing cannot form a competing
    # authority beside finalization/OOB publication.
    identity = store.read_run_identity(Path(run_dir).parents[1], Path(run_dir).name)
    run = store.Run.open(Path(run_dir).parents[1], identity["target"], Path(run_dir).name)
    with _publish_lock(run):
        rev = read(run_dir)
        if rev.status != "valid":
            return None
        revision_root = revisions_dir(run_dir)
        try:
            previous_pointer = _read_regular(
                pointer_path(run_dir), root=revision_root, maximum=MAX_REVISION_POINTER_BYTES,
            )
        except OSError as exc:
            raise RevisionError(f"{run_dir}: prior revision pointer is unreadable: {exc}") from exc
        try:
            doc = _strict_json(previous_pointer, "revision pointer")
        except RevisionError:
            doc = None
        if not isinstance(doc, dict):
            return None
        d = _view_dir(run_dir, rev)
        (run_directory_identity, directory_identity,
         view_directory_identity) = _revision_hierarchy_identities(
            Path(run_dir), d.name,
        )
        assert view_directory_identity is not None
        doc["views"] = {"dir": d.name, "files": _view_files(d)}
        doc["pointer_digest"] = _pointer_digest(doc)
        candidate = _certify_document(run_dir, doc)
        if candidate.status != "valid":
            raise RevisionError(
                f"{run_dir}: regenerated revision views did not certify: {candidate.reason}",
            )
        revision_tree = _fsync_tree(d, root_identity=view_directory_identity)
        segment_identities = _capture_segment_identity_claims(
            run_dir, candidate.segments, root_identity=directory_identity,
        )
        raw_identities = _capture_raw_identity_claims(
            run_dir, candidate.raw_files, root_identity=directory_identity,
        )
        _fsync_segment_identity_claims(
            run_dir, candidate.segments, root_identity=directory_identity,
            identity_claims=segment_identities,
        )
        _fsync_raw_claims(
            run_dir, candidate.raw_files, root_identity=directory_identity,
            identity_claims=raw_identities,
        )
        _fsync_directory(revision_root, directory_identity=directory_identity)
        _fsync_directory(
            Path(run_dir), directory_identity=run_directory_identity,
        )
        candidate = _certify_document(run_dir, doc)
        if candidate.status != "valid":
            raise RevisionError(
                f"{run_dir}: regenerated revision views changed during durability settlement: "
                f"{candidate.reason}",
            )

        def validate_identity_snapshot() -> None:
            _validate_publication_identity_snapshot(
                Path(run_dir), candidate,
                run_identity=run_directory_identity,
                revisions_identity=directory_identity,
                revision_identity=view_directory_identity,
                revision_tree=revision_tree,
                segment_identities=segment_identities,
                raw_identities=raw_identities,
            )

        validate_identity_snapshot()
        publication_fault: BaseException | None = None
        publication_completed = False
        try:
            _publish_pointer(
                pointer_path(run_dir), doc, directory_identity=directory_identity,
            )
            publication_completed = True
        except _PointerPostCommitFault as exc:
            publication_fault = exc.primary
            publication_completed = True
        except BaseException as exc:
            publication_fault = exc
        settlement = _settle_pointer_fault(
            Path(run_dir), doc, candidate, previous_pointer, directory_identity,
            run_directory_identity,
            already_durable=publication_completed,
            identity_validator=validate_identity_snapshot,
        )
        if settlement.outcome == "landed" and settlement.revision is not None:
            if isinstance(publication_fault, (KeyboardInterrupt, SystemExit)):
                raise publication_fault
            return settlement.revision
        if settlement.outcome == "not_landed" and publication_fault is not None:
            raise publication_fault
        raise RevisionPublicationError(
            f"{run_dir}: revision view pointer publication outcome is ambiguous; inspect it before retrying",
            outcome="ambiguous",
        ) from publication_fault


# ── ingesting a late observation ──────────────────────────────────────────────────────────────────

def ingest(run, origin: str):
    """The sink every late observation goes through: the live store while the run still owns its log, an
    append-only supplement once its base manifest is committed. A run whose lifecycle cannot be read is
    refused rather than guessed at."""
    return _Live(run) if _require_disposition(run.dir) == LIVE else _Supplement(run, origin)


class _Live:
    """A run that has not finalized still owns its own log, so nothing is revised."""

    revised = False
    refused = 0                                  # the live store enforces its own envelope and reports it there

    def __init__(self, run):
        self._run = run

    def add(self, entity: str, record: dict) -> bool:
        return self._run.add(entity, record)

    def commit(self, scope=None):
        return None


class _Supplement:
    """Late observations for a finished run, published as the next revision of the combined view."""

    def __init__(self, run, origin: str):
        self._run = run
        self._origin = origin
        self._published = read(run.dir)
        if not self._published.trustworthy:
            raise RevisionError(f"{run.dir}: {self._published.reason} — refusing to revise an uncertified view")
        (manifest, self._base_digest, self._base_counts,
         self._base_contents, _base_records) = _certified_base_snapshot(run.dir)
        declared = manifest.document["envelope"]
        self._limits = {
            "max_keys": min(declared["max_keys_per_entity"], envelope.MAX_KEYS_PER_ENTITY),
            "max_bytes_per_key": min(declared["max_bytes_per_key"], envelope.MAX_BYTES_PER_KEY),
            "max_corpus_bytes": min(
                declared["max_corpus_bytes_per_entity"], envelope.MAX_CORPUS_BYTES_PER_ENTITY,
            ),
        }
        self._records: dict[str, dict] = {}       # entity -> combined {key: record}, materialized on demand
        self._corpus_bytes: dict[str, int] = {}
        self._pending: list[dict] = []
        self._refused: list[dict] = []
        self.revised = False

    def _combined(self, entity: str) -> dict:
        if entity not in self._records:
            folded = combined_fold(self._run.dir, entity)
            if not folded.trustworthy:
                raise RevisionError(f"{self._run.dir}: {entity} is {folded.status} ({folded.reason}) — "
                                    "refusing to supplement evidence that cannot be read whole")
            self._records[entity] = dict(folded.records)
            self._corpus_bytes[entity] = sum(
                store._record_bytes(record) for record in self._records[entity].values()
            )
        return self._records[entity]

    @property
    def refused(self) -> int:
        """Records the corpus envelope turned away — a caller must be able to report an incomplete ingest
        without reading the pointer, or a fully-refused import reads as clean success."""
        return len(self._refused)

    def _refuse(self, entity: str, key: str, kind: str, record: dict) -> None:
        entry = {"entity": entity, "key": key, "kind": kind,
                 "fp": store.fingerprint(entity, record)}
        if entry not in self._refused:           # re-admission may retest a row; it is one refusal
            self._refused.append(entry)

    def _record(self, entity: str, key: str, record: dict) -> None:
        self._pending.append({"seq": len(self._pending) + 1, "entity": entity, "id": key,
                              "record": record, "fp": store.fingerprint(entity, record),
                              "at": store._utc(), "origin": self._origin})

    def add(self, entity: str, record: dict) -> bool:
        """Returns True iff the identity is new, matching `Run.add`, so a caller's counting is unchanged.
        The declared corpus envelope is enforced here too; a refusal is published with the revision."""
        key = store.canonical_key(entity, record)
        if not key:
            return False
        record = {k: v for k, v in dict(record).items() if k != "_alt"}
        now = store._utc()
        record.setdefault("first_seen", now)
        record["last_seen"] = now
        if not self._admit(entity, key, record):
            return False
        held = self._combined(entity)
        if key not in held:
            held[key] = record
            self._corpus_bytes[entity] += store._record_bytes(record)
            self._record(entity, key, record)
            return True
        if not store._subsumed(held[key], record):
            previous_bytes = store._record_bytes(held[key])
            held[key] = store.merge(entity, held[key], record)
            self._corpus_bytes[entity] += store._record_bytes(held[key]) - previous_bytes
            self._record(entity, key, record)
        return False

    def _admit(self, entity: str, key: str, record: dict) -> bool:
        """Whether the corpus envelope admits this record into `entity`, recording a refusal when not.

        Called on the way in and again after adopting a concurrently-published revision, because the
        corpus a row was measured against may have grown since.
        """
        held = self._combined(entity)
        previous = held.get(key)
        candidate = store.merge(entity, previous, record) if previous is not None else record
        candidate_bytes = store._record_bytes(candidate)
        previous_bytes = store._record_bytes(previous) if previous is not None else 0
        if candidate_bytes > self._limits["max_bytes_per_key"]:
            self._refuse(entity, key, "growth" if previous is not None else "bytes", record)
            return False
        if previous is None and len(held) >= self._limits["max_keys"]:
            self._refuse(entity, key, "key", record)
            return False
        if (self._corpus_bytes[entity] - previous_bytes + candidate_bytes
                > self._limits["max_corpus_bytes"]):
            self._refuse(entity, key, "growth" if previous is not None else "corpus", record)
            return False
        return True

    def _next_revision(self) -> int:
        """A revision strictly above every directory that survives here, so an interrupted publication's
        bytes are never overwritten."""
        highest = int(self._published.revision)
        entries, fault = _revision_root_entries(self._run.dir)
        if fault:
            raise RevisionError(f"{self._run.dir}: {fault}")
        for name, mode in entries:
            m = _REV_RE.match(name)
            if m and stat.S_ISDIR(mode):
                highest = max(highest, int(m.group(1)))
        return highest + 1

    def commit(self, scope=None) -> Revision | None:
        """Publish the next revision: the segment whole, then the derived views, then one pointer swap.
        Nothing is published when no late observation was recorded."""
        if not self._pending and not self._refused:
            return None
        try:
            with _publish_lock(self._run):
                self._resettle()                     # another writer may have published since we opened
                return self._publish(scope)
        except (KeyboardInterrupt, SystemExit):
            raise
        except RevisionError:
            raise
        except BaseException as e:
            raise RevisionError(f"{self._run.dir}: revision could not be published: {type(e).__name__}: {e}")

    def _resettle(self) -> None:
        """Adopt whatever is published now, under the lock, and re-merge the pending rows onto it. A
        revision that landed while these rows were being collected keeps its segment and its evidence."""
        _require_disposition(self._run.dir)      # a re-finalisation may have started since these rows opened
        published = read(self._run.dir)
        if not published.trustworthy:
            raise RevisionError(f"{self._run.dir}: {published.reason} — refusing to revise an uncertified view")
        if published.digest == self._published.digest and published.revision == self._published.revision:
            return
        self._published = published
        (manifest, self._base_digest, self._base_counts,
         self._base_contents, _base_records) = _certified_base_snapshot(self._run.dir)
        declared = manifest.document["envelope"]
        self._limits = {
            "max_keys": min(declared["max_keys_per_entity"], envelope.MAX_KEYS_PER_ENTITY),
            "max_bytes_per_key": min(declared["max_bytes_per_key"], envelope.MAX_BYTES_PER_KEY),
            "max_corpus_bytes": min(
                declared["max_corpus_bytes_per_entity"], envelope.MAX_CORPUS_BYTES_PER_ENTITY,
            ),
        }
        self._records = {}
        self._corpus_bytes = {}
        # re-run envelope admission: the corpus these rows were admitted against has grown, so a row that
        # fitted then may not fit now, and a bound only two writers each honoured alone is not a bound
        kept = []
        for row in self._pending:
            entity, key, rec = row["entity"], row["id"], row["record"]
            if not self._admit(entity, key, rec):
                continue
            held = self._combined(entity)          # admitted rows rejoin the corpus the next row is measured against
            previous = held.get(key)
            previous_bytes = store._record_bytes(previous) if previous is not None else 0
            held[key] = store.merge(entity, previous, rec) if previous is not None else rec
            self._corpus_bytes[entity] += store._record_bytes(held[key]) - previous_bytes
            kept.append(row)
        self._pending = [{**row, "seq": i + 1} for i, row in enumerate(kept)]

    def _publish(self, scope) -> Revision:
        nxt = self._next_revision()
        revision_root = revisions_dir(self._run.dir)
        rev_dir = revision_root / _rev_name(nxt)
        if rev_dir.exists():
            raise RevisionError(f"{rev_dir}: revision {nxt} already exists")
        privfs.private_dir(rev_dir)
        (run_directory_identity, directory_identity,
         revision_view_identity) = _revision_hierarchy_identities(
            Path(self._run.dir), _rev_name(nxt),
        )
        assert revision_view_identity is not None
        encoded_rows: list[str] = []
        body_bytes = 0
        for index, row in enumerate(self._pending, 1):
            try:
                run_manifest._validate_json_value(row, f"revision row {index}")
                line = json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n"
                encoded = line.encode("utf-8")
            except (run_manifest.ManifestError, TypeError, ValueError, UnicodeEncodeError,
                    RecursionError) as exc:
                raise RevisionError(f"revision row {index} is not portable JSON: {exc}") from exc
            if len(encoded) > run_manifest.MAX_JSONL_LINE_BYTES:
                raise RevisionError(f"revision row {index} exceeds the JSONL record byte bound")
            body_bytes += len(encoded)
            if body_bytes > MAX_REVISION_SEGMENT_BYTES:
                raise RevisionError("revision supplement segment exceeds its byte bound")
            encoded_rows.append(line)
        body = "".join(encoded_rows)
        # discovered callback evidence: 0600 from creation, written whole, never rewritten
        privfs.write_private(rev_dir / SEGMENT_NAME, body)
        raw = body.encode("utf-8")
        segments = list(self._published.segments) + [
            {"revision": nxt, "file": f"{_rev_name(nxt)}/{SEGMENT_NAME}", "lines": len(self._pending),
             "bytes": len(raw), "digest": _sha(raw)}]
        if (len(segments) > MAX_REVISION_SEGMENTS
                or sum(segment["bytes"] for segment in segments) > MAX_REVISION_SUPPLEMENT_BYTES):
            raise RevisionError("revision supplement exceeds its supported envelope")
        staged = Revision(revision=nxt, status="valid", segments=segments)
        rows, dropped = _committed_rows(self._run.dir, staged)
        if dropped or len(rows) != sum(segment["lines"] for segment in segments):
            raise RevisionError(f"{rev_dir}: staged supplement segment cannot be read whole")
        records_by_entity, effective_fault = _effective_records(self._run.dir, self._base_counts, rows)
        if effective_fault:
            raise RevisionError(f"{self._run.dir}: {effective_fault}")
        self._records = records_by_entity
        counts = {entity: len(records) for entity, records in records_by_entity.items()}
        digests = {entity: _records_digest(entity, records)
                   for entity, records in records_by_entity.items()}
        supplement = {"segments": segments, "lines": sum(int(s.get("lines") or 0) for s in segments),
                      "digest": _chain_digest(segments)}
        raw_file_identities = {}
        try:
            raw_files = _raw_file_claims(
                self._run.dir, rows, root_identity=directory_identity,
                identity_claims=raw_file_identities,
            )
        except (OSError, ValueError) as exc:
            raise RevisionError(f"{self._run.dir}: late raw evidence cannot be certified: {exc}") from exc
        created = store._utc()
        evidence_digest = _evidence_digest(
            base=self._base_digest,
            supplement=supplement["digest"],
            counts=counts,
            entity_digests=digests,
            raw_files=raw_files,
        )
        staged_view = Revision(
            revision=nxt, status="valid", created=created, digest=evidence_digest,
            segments=segments, entity_counts=counts, entity_digests=digests,
            raw_files=raw_files,
        )
        views = self._render_views(rev_dir, scope, staged_view)
        pointer = {
            "schema_version": SCHEMA_VERSION,
            "revision": nxt,
            "created": created,
            "base": {"run_id": self._run.run_id, "target": self._run.target,
                     "manifest_digest": self._base_digest, "entity_counts": self._base_counts,
                     "entity_contents": self._base_contents},
            "supplement": supplement,
            "entity_counts": counts,
            "entity_digests": digests,
            "raw_files": raw_files,
            "views": views,
            "refused": self._outstanding_refusals(),
        }
        pointer["digest"] = evidence_digest
        pointer["pointer_digest"] = _pointer_digest(pointer)
        candidate = _certify_document(self._run.dir, pointer)
        if candidate.status != "valid":
            raise RevisionError(
                f"{self._run.dir}: revision {nxt} refused before publication: {candidate.reason}",
            )

        # All evidence and derived bytes reach stable storage before the one
        # authoritative name changes.  Any earlier fault leaves this directory
        # as a named orphan and the prior pointer byte-identical.
        revision_tree = _fsync_tree(rev_dir, root_identity=revision_view_identity)
        segment_identities = _capture_segment_identity_claims(
            self._run.dir, segments, root_identity=directory_identity,
        )
        _fsync_segment_identity_claims(
            self._run.dir, segments, root_identity=directory_identity,
            identity_claims=segment_identities,
        )
        _fsync_raw_claims(
            self._run.dir, raw_files, root_identity=directory_identity,
            identity_claims=raw_file_identities,
        )
        _fsync_directory(revision_root, directory_identity=directory_identity)
        # The revisions directory may itself have been created for this
        # publication.  Its canonical name is durable only after its parent is
        # synced; doing this unconditionally also settles pre-existing raw-tree
        # creation from OOB acquisition.
        _fsync_directory(
            self._run.dir, directory_identity=run_directory_identity,
        )

        # Certification must follow the durability callbacks: a short write or
        # mutation during a barrier may not publish a pointer to bytes that no
        # longer match its claims.
        candidate = _certify_document(self._run.dir, pointer)
        if candidate.status != "valid":
            raise RevisionError(
                f"{self._run.dir}: revision {nxt} changed during durability settlement: {candidate.reason}",
            )

        def validate_identity_snapshot() -> None:
            _validate_publication_identity_snapshot(
                Path(self._run.dir), candidate,
                run_identity=run_directory_identity,
                revisions_identity=directory_identity,
                revision_identity=revision_view_identity,
                revision_tree=revision_tree,
                segment_identities=segment_identities,
                raw_identities=raw_file_identities,
            )

        validate_identity_snapshot()

        try:
            previous_pointer = _read_regular(
                pointer_path(self._run.dir), root=revision_root,
                maximum=MAX_REVISION_POINTER_BYTES,
            )
        except FileNotFoundError:
            previous_pointer = None
        except OSError as exc:
            raise RevisionError(f"{self._run.dir}: prior revision pointer is unreadable: {exc}") from exc

        publication_fault: BaseException | None = None
        publication_completed = False
        try:
            _publish_pointer(
                pointer_path(self._run.dir), pointer, directory_identity=directory_identity,
            )
            publication_completed = True
        except _PointerPostCommitFault as exc:
            publication_fault = exc.primary
            publication_completed = True
        except BaseException as exc:
            publication_fault = exc

        settlement = _settle_pointer_fault(
            self._run.dir, pointer, candidate, previous_pointer, directory_identity,
            run_directory_identity,
            already_durable=publication_completed,
            identity_validator=validate_identity_snapshot,
        )
        if settlement.outcome == "landed" and settlement.revision is not None:
            self.revised = True
            if isinstance(publication_fault, (KeyboardInterrupt, SystemExit)):
                raise publication_fault
            return settlement.revision
        if settlement.outcome == "not_landed" and publication_fault is not None:
            raise publication_fault
        message = (
            f"{self._run.dir}: revision {nxt} pointer publication outcome is ambiguous; "
            "do not retry until the canonical revision pointer is inspected"
        )
        raise RevisionPublicationError(message, outcome="ambiguous") from publication_fault

    def _outstanding_refusals(self) -> list:
        """Every refusal still owed: the ones earlier revisions recorded plus this writer's, minus any
        identity now actually in the combined view.

        A refusal that a later revision erased would let an ingest report a gap and the next `status` call
        report none — the evidence would still be missing, and nothing would say so.
        """
        admitted = {
            (row["entity"], row["id"], row["fp"])
            for row in _committed_rows(self._run.dir, self._published)[0]
        }
        admitted.update(
            (row["entity"], row["id"], row["fp"])
            for row in self._pending
        )
        out = []
        for entry in list(self._published.refused) + self._refused:
            if not isinstance(entry, dict):
                continue
            entity, key = entry.get("entity"), entry.get("key")
            fingerprint = entry.get("fp")
            if type(fingerprint) is str:
                if (entity, key, fingerprint) in admitted:
                    continue                         # this exact refused material was admitted later
            elif entity in self._records and key in self._records[entity]:
                continue                             # legacy v2 refusal had no material identity
            if entry not in out:
                out.append(entry)
        return out

    def _pending_refs(self, segment: str) -> dict:
        """Complete per-identity segment provenance through the candidate being published."""
        refs = _provenance(self._run.dir, self._published)
        for row in self._pending:
            key = (row["entity"], row["id"])
            held = refs.get(key, ())
            refs[key] = held if segment in held else tuple((*held, segment))
        return refs

    def _render_views(self, rev_dir: Path, scope, staged_revision: Revision) -> dict:
        """Regenerate the run's reports and exports from the combined view into this revision's directory;
        the base run's own views stay exactly as it finished them."""
        from . import exports as _exports, report_truth, triage
        view = CombinedRun(self._run, self._records, rev_dir, rev_dir / "exports",
                           self._pending_refs(f"{rev_dir.name}/{SEGMENT_NAME}"))
        if scope is None:
            from .config import ScopeMatcher
            scope = ScopeMatcher([], [], [], False)
        privfs.write_private(rev_dir / "HOTLIST.md", triage.build(view, scope))
        privfs.write_private(rev_dir / "digest.json",
                             json.dumps(triage.digest_json(view, scope), indent=2, ensure_ascii=False))
        private_report = report_truth.build_private_report(
            view, staged_revision=staged_revision,
        )
        privfs.write_private(
            rev_dir / "private-report.json",
            report_truth.canonical_json_bytes(private_report).decode("utf-8"),
        )
        _exports.write_all(view)
        _exports.write_delta(view)
        return {"dir": rev_dir.name, "files": _view_files(rev_dir)}
