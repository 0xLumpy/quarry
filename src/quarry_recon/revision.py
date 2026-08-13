"""Late evidence for a run whose base manifest is committed, as append-only supplements and revisions of
the combined view (docs/design/REVISION-DESIGN.md)."""
from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import envelope, privfs, store
from .state import RUN_STATES, STATE_UNKNOWN, Fault

SCHEMA_VERSION = 1
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
        if raw is not None:
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
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.jsonl")):
        h = hashlib.sha256()
        try:
            with open(p, "rb") as fh:                 # streamed: a corpus is bounded, not small
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
        except OSError as e:
            raise RevisionError(f"{p}: base evidence is unreadable ({type(e).__name__})")
        out[p.stem] = h.hexdigest()
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
    views: dict = field(default_factory=dict)
    refused: list = field(default_factory=list)
    digest: str = ""
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


def read(run_dir) -> Revision:
    """The combined view published for `run_dir`, or an `absent` Revision when none was.

    Every listed segment is re-hashed against disk and the base manifest is re-hashed against the digest
    the revision was published over, so a truncated segment or a mutated base run fails closed.
    """
    run_dir = Path(run_dir)
    p = pointer_path(run_dir)
    if not p.exists():
        return Revision()
    doc = store._read_json(p)
    if not isinstance(doc, dict):
        return Revision(status="unusable", reason="the revision pointer is unreadable")
    if doc.get("schema_version") != SCHEMA_VERSION:
        return Revision(status="unusable", reason=f"unknown revision schema {doc.get('schema_version')!r}")
    n = doc.get("revision")
    if type(n) is not int or n < 1:
        return Revision(status="unusable", reason="the revision pointer carries no exact revision number")
    supplement = doc.get("supplement")
    segments = supplement.get("segments") if isinstance(supplement, dict) else None
    if not isinstance(segments, list) or not segments:
        return Revision(status="unusable", reason=f"revision {n} lists no supplement segment")
    rev = Revision(revision=n, status="valid", created=str(doc.get("created", "")),
                   base=doc.get("base") if isinstance(doc.get("base"), dict) else {},
                   segments=segments,
                   supplement_lines=supplement.get("lines") if type(supplement.get("lines")) is int else 0,
                   supplement_digest=str(supplement.get("digest", "")),
                   entity_counts=doc.get("entity_counts") if isinstance(doc.get("entity_counts"), dict) else {},
                   entity_digests=doc.get("entity_digests") if isinstance(doc.get("entity_digests"), dict) else {},
                   views=doc.get("views") if isinstance(doc.get("views"), dict) else {},
                   refused=doc.get("refused") if isinstance(doc.get("refused"), list) else [],
                   digest=str(doc.get("digest", "")),
                   orphans=_orphans(run_dir, n))
    bad = _view_dir_fault(rev)
    if bad:
        return Revision(revision=n, status="unusable", reason=bad, orphans=rev.orphans)
    held = doc.get("base", {}).get("manifest_digest") if isinstance(doc.get("base"), dict) else None
    try:
        current, _ = _base_manifest(run_dir)
        contents = _entity_content_digests(run_dir)
    except RevisionError as e:
        return Revision(revision=n, status="unusable", reason=str(e), orphans=rev.orphans)
    if held != current:
        return Revision(revision=n, status="unusable", orphans=rev.orphans,
                        reason=f"the base run changed after revision {n} was published")
    # the manifest counts the evidence; these digest it, so a same-count content swap is still a change
    recorded = rev.base.get("entity_contents")
    if not isinstance(recorded, dict) or recorded != contents:
        moved = sorted(set(contents) ^ set(recorded or {})
                       | {e for e in contents if isinstance(recorded, dict) and e in recorded
                          and recorded[e] != contents[e]})
        return Revision(revision=n, status="unusable", orphans=rev.orphans,
                        reason=f"the base evidence changed after revision {n} was published "
                               f"({', '.join(moved[:4]) or 'no recorded content digests'})")
    for seg in segments:
        if not isinstance(seg, dict):
            return Revision(revision=n, status="unusable", reason="a supplement segment is malformed",
                            orphans=rev.orphans)
        try:
            body = _segment_path(run_dir, seg.get("file")).read_bytes()
        except (OSError, ValueError) as e:
            return Revision(revision=n, status="unusable", orphans=rev.orphans,
                            reason=f"supplement segment {seg.get('file')!r} is unusable: {e}")
        if len(body) != seg.get("bytes") or _sha(body) != seg.get("digest"):
            return Revision(revision=n, status="unusable", orphans=rev.orphans,
                            reason=f"supplement segment {seg.get('file')!r} is not the one revision {n} published")
    if _chain_digest(segments) != rev.supplement_digest:
        return Revision(revision=n, status="unusable", orphans=rev.orphans,
                        reason=f"revision {n} does not certify its own segment chain")
    rows, dropped = _committed_rows(run_dir, rev)
    if dropped:
        return Revision(revision=n, status="unusable", orphans=rev.orphans,
                        reason=f"{dropped} unusable supplement row(s) in revision {n}")
    counts_bad = _count_fault(run_dir, rev, _base_manifest(run_dir)[1], rows)
    if counts_bad:
        return Revision(revision=n, status="unusable", orphans=rev.orphans, reason=counts_bad)
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
            text = _segment_path(run_dir, seg.get("file")).read_text(encoding="utf-8")
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
    d = _view_dir(run_dir, rev)
    files = rev.views.get("files")
    if not isinstance(files, dict):
        return []
    return sorted(name for name in files if not (d / name).is_file())


def view_identity(run_dir) -> tuple[int, str]:
    """`(revision, digest)` of the published combined view — `(0, "")` when only the base run exists. A
    consumer records this pair and re-reads when it changes."""
    rev = read(run_dir)
    return (rev.revision, rev.digest) if rev.status == "valid" else (rev.revision, "")


def combined_fold(run_dir, entity: str) -> store.FoldedLog:
    """The base run's fold for `entity` with every committed supplement row merged in — what a consumer
    must read once a revision exists. An uncertified revision folds in nothing and says so."""
    base = store.fold_run_entity(run_dir, entity)
    rev = read(run_dir)
    if rev.status == "absent":
        return base
    if rev.status != "valid":
        return store.FoldedLog(records=base.records, status="unknown", dropped=base.dropped, reason=rev.reason)
    if not base.trustworthy:
        return base
    rows, dropped = _committed_rows(run_dir, rev)
    records = dict(base.records)
    for row in rows:
        if row["entity"] != entity:
            continue
        key, rec = row["id"], row["record"]
        records[key] = store.merge(entity, records[key], rec) if key in records else rec
    expected = rev.entity_counts.get(entity, 0)
    if type(expected) is not int or len(records) != expected:
        return store.FoldedLog(records=records, status="degraded", dropped=base.dropped + dropped,
                               reason=f"revision {rev.revision} records {expected} {entity}, "
                                      f"the combined view yields {len(records)}")
    if dropped:
        return store.FoldedLog(records=records, status="degraded", dropped=base.dropped + dropped,
                               reason=f"{dropped} unusable supplement row(s)")
    return store.FoldedLog(records=records, dropped=base.dropped)


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
    for p in sorted(rev_dir.rglob("*")):
        if p.is_file() and p.name != SEGMENT_NAME:
            out[str(p.relative_to(rev_dir))] = _sha(p.read_bytes())
    return out


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
        doc = store._read_json(pointer_path(run_dir))
        if not isinstance(doc, dict):
            return None
        d = _view_dir(run_dir, rev)
        doc["views"] = {"dir": d.name, "files": _view_files(d)}
        store._atomic_write(pointer_path(run_dir), json.dumps(doc, indent=2))
        return read(run_dir)


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
        rev_dir = revisions_dir(self._run.dir) / _rev_name(nxt)
        if rev_dir.exists():
            raise RevisionError(f"{rev_dir}: revision {nxt} already exists")
        privfs.private_dir(rev_dir)
        body = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in self._pending)
        # discovered callback evidence: 0600 from creation, written whole, never rewritten
        privfs.write_private(rev_dir / SEGMENT_NAME, body)
        raw = body.encode("utf-8")
        segments = list(self._published.segments) + [
            {"revision": nxt, "file": f"{_rev_name(nxt)}/{SEGMENT_NAME}", "lines": len(self._pending),
             "bytes": len(raw), "digest": _sha(raw)}]
        counts = dict(self._base_counts)
        digests = {}
        for entity, records in self._records.items():
            counts[entity] = len(records)
            digests[entity] = _sha(json.dumps(
                [[k, store.fingerprint(entity, r)] for k, r in sorted(records.items())],
                ensure_ascii=False).encode("utf-8"))
        views = self._render_views(rev_dir, scope)
        supplement = {"segments": segments, "lines": sum(int(s.get("lines") or 0) for s in segments),
                      "digest": _chain_digest(segments)}
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
            "views": views,
            "refused": self._outstanding_refusals(),
        }
        pointer["digest"] = _sha(json.dumps(
            {"base": self._base_digest, "supplement": supplement["digest"], "entity_counts": counts},
            sort_keys=True, ensure_ascii=False).encode("utf-8"))
        store._atomic_write(pointer_path(self._run.dir), json.dumps(pointer, indent=2))
        self.revised = True
        published = read(self._run.dir)
        if published.status != "valid":
            raise RevisionError(f"{self._run.dir}: revision {nxt} did not certify after publication: "
                                f"{published.reason}")
        return published

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
