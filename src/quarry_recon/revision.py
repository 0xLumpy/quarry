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

from . import envelope, privfs, store
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
            body = _read_regular(p, root=Path(run_dir))  # the declared corpus envelope bounds this file
        except OSError as e:
            raise RevisionError(f"{p}: base evidence is unreadable ({type(e).__name__})")
        out[p.stem] = _sha(body)
    return out


# ── the published pointer ─────────────────────────────────────────────────────────────────────────

@dataclass
class Revision:
    """The manifest of one published combined view; it holds counts and digests, never records."""

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

    @property
    def trustworthy(self) -> bool:
        return self.status in ("valid", "absent")


def _segment_path(run_dir, name) -> Path:
    """A segment path from the pointer, confined to `revisions/rev<N>/<SEGMENT_NAME>` so a crafted pointer
    cannot name a file outside the run."""
    if not isinstance(name, str):
        raise ValueError("segment file is not a string")
    parts = Path(name).parts
    if len(parts) != 2 or not _REV_RE.match(parts[0]) or parts[1] != SEGMENT_NAME:
        raise ValueError(f"segment file {name!r} is not a revision segment")
    return revisions_dir(run_dir) / parts[0] / parts[1]


def _orphans(run_dir, published: int) -> list[str]:
    """Revision directories numbered above the pointer — bytes an interrupted publication left, kept and
    named rather than reused."""
    d = revisions_dir(run_dir)
    if not d.is_dir():
        return []
    out = []
    for child in d.iterdir():
        m = _REV_RE.match(child.name)
        if m and child.is_dir() and int(m.group(1)) > published:
            out.append(child.name)
    return sorted(out)


def _canonical_bytes(value) -> bytes:
    """One stable JSON encoding for identities recorded inside a revision pointer."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")


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


def _read_regular(path: Path, *, root: Path | None = None) -> bytes:
    """Read one stable regular file without following a symlink."""
    path = Path(path)
    if root is not None:
        root = Path(root)
        root_mode = root.lstat().st_mode
        if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
            raise OSError(f"unsafe managed root: {root}")
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise OSError(f"file escapes managed root: {path}") from exc
        cursor = root
        for component in relative.parts[:-1]:
            cursor = cursor / component
            mode = cursor.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise OSError(f"unsafe file ancestry: {cursor}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"not a regular file: {path}")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError(f"file changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _revision_raw_path(run_dir, ref: str) -> Path:
    """Resolve a late-evidence raw reference, confined below ``revisions/raw``."""
    if not isinstance(ref, str):
        raise ValueError("raw reference is not a string")
    parts = Path(ref).parts
    if (Path(ref).is_absolute() or len(parts) < 4 or parts[:2] != (REVISIONS_DIR, "raw")
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
    return refs


def _raw_file_claims(run_dir, rows: list[dict]) -> dict:
    claims = {}
    for ref in sorted(_late_raw_refs(rows)):
        path = _revision_raw_path(run_dir, ref)
        body = _read_regular(path, root=revisions_dir(run_dir))
        claims[ref] = {"bytes": len(body), "digest": _sha(body)}
    return claims


def _records_digest(entity: str, records: dict) -> str:
    return _sha(_canonical_bytes(
        [[key, store.fingerprint(entity, record)] for key, record in sorted(records.items())]
    ))


def _effective_records(run_dir, base_counts: dict, rows: list[dict]) -> tuple[dict, str]:
    """Fold the base plus every published supplement segment for every effective entity."""
    manifest = store._read_json(Path(run_dir) / "manifest.json")
    declared = manifest.get("envelope") if isinstance(manifest, dict) else None
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
        base = store.fold_observations(
            Path(run_dir) / "normalized" / f"{entity}.jsonl",
            **limits,
            require_newline=True,
        )
        expected = base_counts.get(entity, 0)
        if base.status == "absent" and expected == 0:
            base = store.FoldedLog()
        if not base.trustworthy or base.refused or len(base.records) != expected:
            return {}, f"{entity} cannot be read whole: {base.reason}"
        records = dict(base.records)
        for row in rows:
            if row["entity"] != entity:
                continue
            key, record = row["id"], row["record"]
            records[key] = store.merge(entity, records[key], record) if key in records else record
        records_by_entity[entity] = records
    return records_by_entity, ""


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
        doc = json.loads(_read_regular(p, root=revisions_dir(run_dir)).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
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
    expected_fields = {
        "schema_version", "revision", "created", "base", "supplement", "entity_counts",
        "entity_digests", "raw_files", "views", "refused", "digest", "pointer_digest",
    }
    if set(doc) != expected_fields:
        return _unusable(n, f"revision {n} pointer fields do not match schema", run_dir)
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
        if (not isinstance(entry, dict) or set(entry) != {"entity", "key", "kind"}
                or entry.get("entity") not in store.ENTITY_KEYS
                or not isinstance(entry.get("key"), str) or not entry["key"]
                or not isinstance(entry.get("kind"), str) or not entry["kind"]):
            return _unusable(n, f"revision {n} carries a malformed refusal", run_dir)
    bad = _view_dir_fault(rev)
    if bad:
        return _unusable(n, bad, run_dir)
    held = doc.get("base", {}).get("manifest_digest") if isinstance(doc.get("base"), dict) else None
    try:
        current, base_counts = _base_manifest(run_dir)
        contents = _entity_content_digests(run_dir)
    except RevisionError as e:
        return _unusable(n, str(e), run_dir)
    if held != current:
        return _unusable(n, f"the base run changed after revision {n} was published", run_dir)
    manifest_doc = store._read_json(run_dir / "manifest.json")
    if (not isinstance(manifest_doc, dict)
            or rev.base.get("run_id") != manifest_doc.get("run_id")
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
    for seg in segments:
        if not isinstance(seg, dict) or set(seg) != {"revision", "file", "lines", "bytes", "digest"}:
            return _unusable(n, "a supplement segment is malformed", run_dir)
        number = seg.get("revision")
        if type(number) is not int or number <= previous_number:
            return _unusable(n, f"revision {n} has a non-monotonic segment chain", run_dir)
        try:
            segment_path = _segment_path(run_dir, seg.get("file"))
            body = _read_regular(segment_path, root=revisions_dir(run_dir))
        except (OSError, ValueError) as e:
            return _unusable(n, f"supplement segment {seg.get('file')!r} is unusable: {e}", run_dir)
        path_number = int(Path(seg["file"]).parts[0][3:])
        if number != path_number:
            return _unusable(n, f"supplement segment {seg.get('file')!r} has the wrong revision", run_dir)
        if (type(seg.get("lines")) is not int or seg["lines"] < 0
                or type(seg.get("bytes")) is not int or seg["bytes"] < 0
                or not isinstance(seg.get("digest"), str)):
            return _unusable(n, "a supplement segment claim is malformed", run_dir)
        if (len(body) != seg["bytes"] or _sha(body) != seg["digest"]
                or len(body.splitlines()) != seg["lines"]):
            return _unusable(
                n, f"supplement segment {seg.get('file')!r} is not the one revision {n} published", run_dir,
            )
        previous_number = number
    if previous_number != n:
        return _unusable(n, f"revision {n} does not end at its own supplement segment", run_dir)
    if _chain_digest(segments) != rev.supplement_digest:
        return _unusable(n, f"revision {n} does not certify its own segment chain", run_dir)
    expected_lines = sum(seg["lines"] for seg in segments)
    if rev.supplement_lines != expected_lines:
        return _unusable(n, f"revision {n} records the wrong supplement line count", run_dir)
    rows, dropped = _committed_rows(run_dir, rev)
    if dropped:
        return _unusable(n, f"{dropped} unusable supplement row(s) in revision {n}", run_dir)
    if len(rows) != expected_lines:
        return _unusable(n, f"revision {n} does not yield every segment row", run_dir)

    records_by_entity, effective_fault = _effective_records(run_dir, base_counts, rows)
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


def _committed_rows(run_dir, rev: Revision) -> tuple[list[dict], int]:
    """`(rows, dropped)` from every committed segment, in publication order. A row whose recorded identity
    or fingerprint does not match its record is dropped and counted, never folded in."""
    rows: list[dict] = []
    dropped = 0
    for seg in rev.segments:
        try:
            text = _read_regular(
                _segment_path(run_dir, seg.get("file")), root=revisions_dir(run_dir),
            ).decode("utf-8")
        except (OSError, ValueError, UnicodeDecodeError):
            dropped += 1
            continue
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                dropped += 1
                continue
            entity = row.get("entity") if isinstance(row, dict) else None
            rec = row.get("record") if isinstance(row, dict) else None
            if not isinstance(entity, str) or entity not in store.ENTITY_KEYS or not isinstance(rec, dict):
                dropped += 1
                continue
            key = store.canonical_key(entity, rec)
            if not key or row.get("id") != key or row.get("fp") != store.fingerprint(entity, rec):
                dropped += 1
                continue
            row["segment"] = str(seg.get("file"))     # set after validation: a planted value never survives
            rows.append(row)
    return rows, dropped


def _provenance(run_dir, rev: Revision) -> dict:
    """`{(entity, key): segment file}` for every committed supplement row — which file actually holds it."""
    rows, _ = _committed_rows(run_dir, rev)
    return {(row["entity"], row["id"]): row["segment"] for row in rows}


# ── reading the combined view ─────────────────────────────────────────────────────────────────────

def combined_counts(run_dir) -> dict:
    """The manifested entity counts of the combined view: the published revision's when one is certified,
    else the base manifest's. Empty when neither can be read."""
    rev = read(run_dir)
    if rev.status == "valid":
        return dict(rev.entity_counts)
    if rev.status == "unusable":
        return {}
    manifest = store._read_json(Path(run_dir) / "manifest.json")
    counts = manifest.get("entity_counts") if isinstance(manifest, dict) else None
    return dict(counts) if isinstance(counts, dict) else {}


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
    base = store.fold_run_entity(run_dir, entity)
    rev = read(run_dir)
    if rev.status == "absent":
        return base
    if rev.status != "valid":
        return store.FoldedLog(records=base.records, status="unknown", dropped=base.dropped, reason=rev.reason)
    rows, dropped = _committed_rows(run_dir, rev)
    records_by_entity, fault = _effective_records(run_dir, rev.base.get("entity_counts", {}), rows)
    if fault:
        return store.FoldedLog(status="unknown", reason=fault)
    records = records_by_entity.get(entity, {})
    expected = rev.entity_counts.get(entity, 0)
    if type(expected) is not int or len(records) != expected:
        return store.FoldedLog(records=records, status="degraded", dropped=dropped,
                               reason=f"revision {rev.revision} records {expected} {entity}, "
                                      f"the combined view yields {len(records)}")
    if dropped:
        return store.FoldedLog(records=records, status="degraded", dropped=dropped,
                               reason=f"{dropped} unusable supplement row(s)")
    return store.FoldedLog(records=records)


class CombinedRun:
    """A finished run read as its combined view, with a revision's own directory for derived views.

    Read-only over `read`/`count`/`values`; everything else is the base run, so the report and export
    renderers need to know nothing about revisions.
    """

    def __init__(self, run, overlay: dict, reports: Path, exports: Path, refs: dict | None = None):
        self._run = run
        self._overlay = overlay                   # entity -> {canonical key: combined record}
        self._refs = refs or {}                   # (entity, key) -> the segment file that holds the row
        self.reports = privfs.private_dir(reports)
        self.exports = privfs.private_dir(exports)

    def read(self, entity: str) -> list[dict]:
        return list(self._overlay[entity].values()) if entity in self._overlay else self._run.read(entity)

    def count(self, entity: str) -> int:
        return len(self._overlay[entity]) if entity in self._overlay else self._run.count(entity)

    def values(self, entity: str) -> list[str]:
        key_field = store.ENTITY_KEYS.get(entity, "value")
        return [str(r.get(key_field, "")) for r in self.read(entity) if r.get(key_field)]

    def store_ref(self, entity: str, record: dict) -> str:
        """The run-relative file holding this observation: its supplement segment when it arrived after the
        run finished, else the run's own entity log."""
        seg = self._refs.get((entity, store.canonical_key(entity, record)))
        return f"{REVISIONS_DIR}/{seg}" if seg else f"normalized/{entity}.jsonl"

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_run"), name)


def combined_view(run, rev: Revision | None = None) -> CombinedRun | None:
    """The published combined view of a finished run, rendering into its revision's directory, or None when
    no certified revision exists. The base run's own views stay as it finished them."""
    rev = read(run.dir) if rev is None else rev
    if rev.status != "valid":
        return None
    refs = _provenance(run.dir, rev)
    overlay = {}
    for entity in sorted({e for e, _ in refs}):
        folded = combined_fold(run.dir, entity)
        if not folded.trustworthy:
            return None                       # an entity we cannot read whole may not be rendered as a view
        overlay[entity] = dict(folded.records)
    d = _view_dir(run.dir, rev)
    return CombinedRun(run, overlay, d, d / "exports", refs)


def _view_files(rev_dir: Path) -> dict:
    """`{path relative to the revision dir: digest}` for every derived view it holds — the segment is
    evidence, not a view, so it is never listed."""
    out = {}
    try:
        paths = sorted(rev_dir.rglob("*"))
    except OSError as exc:
        raise RevisionError(f"{rev_dir}: revision view tree is unreadable: {exc}") from exc
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
            out[str(p.relative_to(rev_dir))] = _sha(_read_regular(p, root=rev_dir))
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


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree(root: Path) -> None:
    """Durably seal every regular file and directory in a staged revision tree."""
    paths = sorted(root.rglob("*"))
    for path in paths:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise OSError(f"unsafe staged revision object: {path}")
        if stat.S_ISREG(mode):
            _fsync_file(path)
    directories = [path for path in paths if stat.S_ISDIR(path.lstat().st_mode)]
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)
    _fsync_directory(root)


def _fsync_raw_claims(run_dir, claims: dict) -> None:
    directories: set[Path] = set()
    root = revisions_dir(run_dir)
    for ref in claims:
        path = _revision_raw_path(run_dir, ref)
        _fsync_file(path)
        parent = path.parent
        while parent != root:
            directories.add(parent)
            parent = parent.parent
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)


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
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _private_directory_identity(path: Path) -> tuple[int, int]:
    """Authenticate one canonical private directory and return its stable name identity."""
    info = Path(path).lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != privfs.DIR_MODE):
        raise OSError(f"unsafe private directory authority: {path}")
    return info.st_dev, info.st_ino


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
    *, already_durable: bool = False,
) -> _PointerSettlement:
    """Classify a failed publication without guessing whether the pointer landed.

    A second directory fsync turns a byte-valid intended or restored pointer into
    a durable result before it is reported.  Anything else is ambiguous and may
    not be retried blindly (in particular, OOB raw proof must be retained).
    """
    root = revisions_dir(run_dir)
    if not _same_private_directory(root, directory_identity):
        return _PointerSettlement("ambiguous")
    try:
        current = _read_regular(pointer_path(run_dir), root=root)
    except FileNotFoundError:
        current = None
    except OSError:
        return _PointerSettlement("ambiguous")

    intended = _pointer_bytes(document)
    if current == intended:
        settled = read(run_dir)
        if (settled.status != "valid" or settled.revision != candidate.revision
                or settled.pointer_digest != candidate.pointer_digest):
            return _PointerSettlement("ambiguous")
        if not already_durable:
            try:
                _fsync_directory(root)
                _fsync_directory(Path(run_dir))
            except Exception:
                return _PointerSettlement("ambiguous")
        if not _same_private_directory(root, directory_identity):
            return _PointerSettlement("ambiguous")
        return _PointerSettlement("landed", settled)

    if current == previous:
        try:
            _fsync_directory(root)
            _fsync_directory(Path(run_dir))
        except Exception:
            return _PointerSettlement("ambiguous")
        if _same_private_directory(root, directory_identity):
            return _PointerSettlement("not_landed")
    return _PointerSettlement("ambiguous")


def _publish_pointer(
    path: Path, document: dict, *, directory_identity: tuple[int, int] | None = None,
) -> None:
    """Durably atomically replace the pointer after every candidate byte is sealed."""
    body = _pointer_bytes(document)
    parent_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0))
    dfd = os.open(path.parent, parent_flags)
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
            previous = _read_regular(path)
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
        directory_identity = _private_directory_identity(revision_root)
        try:
            previous_pointer = _read_regular(pointer_path(run_dir), root=revision_root)
        except OSError as exc:
            raise RevisionError(f"{run_dir}: prior revision pointer is unreadable: {exc}") from exc
        doc = store._read_json(pointer_path(run_dir))
        if not isinstance(doc, dict):
            return None
        d = _view_dir(run_dir, rev)
        doc["views"] = {"dir": d.name, "files": _view_files(d)}
        doc["pointer_digest"] = _pointer_digest(doc)
        candidate = _certify_document(run_dir, doc)
        if candidate.status != "valid":
            raise RevisionError(
                f"{run_dir}: regenerated revision views did not certify: {candidate.reason}",
            )
        _fsync_tree(d)
        _fsync_directory(revision_root)
        _fsync_directory(Path(run_dir))
        candidate = _certify_document(run_dir, doc)
        if candidate.status != "valid":
            raise RevisionError(
                f"{run_dir}: regenerated revision views changed during durability settlement: "
                f"{candidate.reason}",
            )
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
            already_durable=publication_completed,
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
        self._base_digest, self._base_counts = _base_manifest(run.dir)
        self._base_contents = _entity_content_digests(run.dir)
        self._records: dict[str, dict] = {}       # entity -> combined {key: record}, materialized on demand
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
        return self._records[entity]

    @property
    def refused(self) -> int:
        """Records the corpus envelope turned away — a caller must be able to report an incomplete ingest
        without reading the pointer, or a fully-refused import reads as clean success."""
        return len(self._refused)

    def _refuse(self, entity: str, key: str, kind: str) -> None:
        entry = {"entity": entity, "key": key, "kind": kind}
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
            self._record(entity, key, record)
            return True
        if not store._subsumed(held[key], record):
            held[key] = store.merge(entity, held[key], record)
            self._record(entity, key, record)
        return False

    def _admit(self, entity: str, key: str, record: dict) -> bool:
        """Whether the corpus envelope admits this record into `entity`, recording a refusal when not.

        Called on the way in and again after adopting a concurrently-published revision, because the
        corpus a row was measured against may have grown since.
        """
        held = self._combined(entity)
        if len(json.dumps(record, ensure_ascii=False).encode("utf-8")) > envelope.MAX_BYTES_PER_KEY:
            self._refuse(entity, key, "bytes")
            return False
        if key not in held and len(held) >= envelope.MAX_KEYS_PER_ENTITY:
            self._refuse(entity, key, "key")
            return False
        return True

    def _next_revision(self) -> int:
        """A revision strictly above every directory that survives here, so an interrupted publication's
        bytes are never overwritten."""
        highest = int(self._published.revision)
        d = revisions_dir(self._run.dir)
        if d.is_dir():
            for child in d.iterdir():
                m = _REV_RE.match(child.name)
                if m:
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
        self._base_digest, self._base_counts = _base_manifest(self._run.dir)
        self._base_contents = _entity_content_digests(self._run.dir)
        self._records = {}
        # re-run envelope admission: the corpus these rows were admitted against has grown, so a row that
        # fitted then may not fit now, and a bound only two writers each honoured alone is not a bound
        kept = []
        for row in self._pending:
            entity, key, rec = row["entity"], row["id"], row["record"]
            if not self._admit(entity, key, rec):
                continue
            held = self._combined(entity)          # admitted rows rejoin the corpus the next row is measured against
            held[key] = store.merge(entity, held[key], rec) if key in held else rec
            kept.append(row)
        self._pending = [{**row, "seq": i + 1} for i, row in enumerate(kept)]

    def _publish(self, scope) -> Revision:
        nxt = self._next_revision()
        revision_root = revisions_dir(self._run.dir)
        rev_dir = revision_root / _rev_name(nxt)
        if rev_dir.exists():
            raise RevisionError(f"{rev_dir}: revision {nxt} already exists")
        privfs.private_dir(rev_dir)
        directory_identity = _private_directory_identity(revision_root)
        body = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in self._pending)
        # discovered callback evidence: 0600 from creation, written whole, never rewritten
        privfs.write_private(rev_dir / SEGMENT_NAME, body)
        raw = body.encode("utf-8")
        segments = list(self._published.segments) + [
            {"revision": nxt, "file": f"{_rev_name(nxt)}/{SEGMENT_NAME}", "lines": len(self._pending),
             "bytes": len(raw), "digest": _sha(raw)}]
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
        views = self._render_views(rev_dir, scope)
        supplement = {"segments": segments, "lines": sum(int(s.get("lines") or 0) for s in segments),
                      "digest": _chain_digest(segments)}
        try:
            raw_files = _raw_file_claims(self._run.dir, rows)
        except (OSError, ValueError) as exc:
            raise RevisionError(f"{self._run.dir}: late raw evidence cannot be certified: {exc}") from exc
        pointer = {
            "schema_version": SCHEMA_VERSION,
            "revision": nxt,
            "created": store._utc(),
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
        pointer["digest"] = _evidence_digest(
            base=self._base_digest,
            supplement=supplement["digest"],
            counts=counts,
            entity_digests=digests,
            raw_files=raw_files,
        )
        pointer["pointer_digest"] = _pointer_digest(pointer)
        candidate = _certify_document(self._run.dir, pointer)
        if candidate.status != "valid":
            raise RevisionError(
                f"{self._run.dir}: revision {nxt} refused before publication: {candidate.reason}",
            )

        # All evidence and derived bytes reach stable storage before the one
        # authoritative name changes.  Any earlier fault leaves this directory
        # as a named orphan and the prior pointer byte-identical.
        _fsync_tree(rev_dir)
        _fsync_raw_claims(self._run.dir, raw_files)
        _fsync_directory(revision_root)
        # The revisions directory may itself have been created for this
        # publication.  Its canonical name is durable only after its parent is
        # synced; doing this unconditionally also settles pre-existing raw-tree
        # creation from OOB acquisition.
        _fsync_directory(self._run.dir)

        # Certification must follow the durability callbacks: a short write or
        # mutation during a barrier may not publish a pointer to bytes that no
        # longer match its claims.
        candidate = _certify_document(self._run.dir, pointer)
        if candidate.status != "valid":
            raise RevisionError(
                f"{self._run.dir}: revision {nxt} changed during durability settlement: {candidate.reason}",
            )

        try:
            previous_pointer = _read_regular(pointer_path(self._run.dir), root=revision_root)
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
            already_durable=publication_completed,
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
        out = []
        for entry in list(self._published.refused) + self._refused:
            if not isinstance(entry, dict):
                continue
            entity, key = entry.get("entity"), entry.get("key")
            if entity in self._records and key in self._records[entity]:
                continue                             # admitted since; it is no longer owed
            if entry not in out:
                out.append(entry)
        return out

    def _pending_refs(self, segment: str) -> dict:
        """`{(entity, key): segment file}` across the already-committed segments and the one being published,
        so a view names the file that actually holds each row."""
        refs = _provenance(self._run.dir, self._published)
        for row in self._pending:
            refs[(row["entity"], row["id"])] = segment
        return refs

    def _render_views(self, rev_dir: Path, scope) -> dict:
        """Regenerate the run's reports and exports from the combined view into this revision's directory;
        the base run's own views stay exactly as it finished them."""
        from . import exports as _exports, triage
        view = CombinedRun(self._run, self._records, rev_dir, rev_dir / "exports",
                           self._pending_refs(f"{rev_dir.name}/{SEGMENT_NAME}"))
        if scope is None:
            from .config import ScopeMatcher
            scope = ScopeMatcher([], [], [], False)
        privfs.write_private(rev_dir / "HOTLIST.md", triage.build(view, scope))
        privfs.write_private(rev_dir / "digest.json",
                             json.dumps(triage.digest_json(view, scope), indent=2, ensure_ascii=False))
        _exports.write_all(view)
        _exports.write_delta(view)
        return {"dir": rev_dir.name, "files": _view_files(rev_dir)}
