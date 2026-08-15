"""Strict, lossless private report projection for the v0.3.10 evidence boundary.

The canonical repository remains the source of truth.  This module does not add
an index or a second database: it projects one already-certified base/combined
view, records every effective entity exactly once, and binds every provenance
reference to a manifest or revision claim.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from . import revision, run_manifest, store


SCHEMA_VERSION = "quarry.private-report.v2"
MAX_REFERENCE_DEPTH = 64
MAX_REFERENCES_PER_OBSERVATION = 4096
MAX_PRIVATE_REPORT_INTEGER = (1 << 63) - 1
MAX_PRIVATE_REPORT_BYTES = 256 * 1024 * 1024

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
)
_MEDIA_TYPES = frozenset({
    "application/json", "application/octet-stream", "application/x-ndjson",
})
# Complete provider payloads are retained as evidence values.  Their member
# names are target/tool data, not Quarry provenance syntax; a payload member
# called ``raw_ref`` must not acquire filesystem authority.  Producers attach
# real refs alongside these opaque values (normally at top level/occurrences).
_OPAQUE_EVIDENCE_FIELDS = frozenset({
    "data", "provider_record", "provider_records", "request", "response",
})


class ReportTruthError(ValueError):
    """The committed evidence cannot support one exact private projection."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ReportTruthError(
            f"private-report value is not canonical JSON: {type(exc).__name__}: {exc}",
        ) from exc


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _named_digest(value: str) -> str:
    if type(value) is not str:
        raise ReportTruthError("artifact digest is not a string")
    if value.startswith("sha256:") and len(value) == 71:
        return value
    if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
        return "sha256:" + value
    raise ReportTruthError("artifact digest is not canonical SHA-256")


def _document_digest(value: object, field: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ReportTruthError(f"private report {field} is not canonical SHA-256")
    return value


def _timestamp(value: object) -> str:
    if type(value) is not str or _RFC3339_RE.fullmatch(value) is None:
        raise ReportTruthError("private report source timestamp is not RFC3339")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ReportTruthError("private report source timestamp is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise ReportTruthError("private report source timestamp has no offset")
    return value


def _count(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_PRIVATE_REPORT_INTEGER:
        raise ReportTruthError(f"private report {field} is not a portable count")
    return value


def _relative_path(value: object) -> str:
    if type(value) is not str or not value or value.strip() != value \
            or value[0].isspace() or value[-1].isspace() \
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value) \
            or "\\" in value or "\x00" in value or Path(value).is_absolute():
        raise ReportTruthError("private report artifact path is invalid")
    parts = value.split("/")
    if not parts or len(parts) > MAX_REFERENCE_DEPTH \
            or any(part in ("", ".", "..") for part in parts):
        raise ReportTruthError("private report artifact path is invalid")
    return value


def canonical_json_bytes(document: dict) -> bytes:
    return _canonical_bytes(document) + b"\n"


def _reference_values(value: Any, *, depth: int = 0) -> Iterable[str]:
    """Find raw refs at every JSON-object depth without interpreting target values."""
    if depth > MAX_REFERENCE_DEPTH:
        raise ReportTruthError("an observation exceeds the provenance nesting bound")
    if type(value) is dict:
        for key, item in dict.items(value):
            if type(key) is not str:
                raise ReportTruthError("an observation has a non-string member name")
            if key == "raw_ref":
                if item not in (None, ""):
                    if type(item) is not str:
                        raise ReportTruthError("raw_ref is not an exact string")
                    yield item
            elif key == "raw_refs":
                if type(item) is not list:
                    raise ReportTruthError("raw_refs is not an exact list")
                for ref in item:
                    if type(ref) is not str or not ref:
                        raise ReportTruthError("raw_refs contains an invalid reference")
                    yield ref
            elif key in _OPAQUE_EVIDENCE_FIELDS:
                continue
            else:
                yield from _reference_values(item, depth=depth + 1)
    elif type(value) is list:
        for item in value:
            yield from _reference_values(item, depth=depth + 1)


def _relative_reference(run_dir: Path, value: str) -> str:
    """Return one canonical POSIX path confined below the run directory."""
    if type(value) is not str or not value or value[0].isspace() or value[-1].isspace() \
            or "\\" in value or "\x00" in value or "//" in value:
        raise ReportTruthError("an evidence reference is not a canonical path")
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(run_dir)
        except ValueError as exc:
            raise ReportTruthError(f"evidence reference escapes the run: {value!r}") from exc
    relative = candidate.as_posix()
    parts = relative.split("/")
    if not parts or len(parts) > MAX_REFERENCE_DEPTH or any(part in ("", ".", "..") for part in parts):
        raise ReportTruthError(f"evidence reference is unsafe: {value!r}")
    if relative.startswith("/"):
        raise ReportTruthError(f"evidence reference is absolute: {value!r}")
    return relative


def _canonical_record(value: Any, run_dir: Path, *, depth: int = 0) -> Any:
    """Detach a record and make its provenance paths run-relative.

    A standalone report verifier deliberately has no ambient run-directory
    pathname.  Canonicalising only Quarry's provenance fields at projection
    time therefore lets it derive the exact declared ``record_refs`` from the
    emitted record itself.  Provider payloads remain opaque target/tool bytes.
    """
    if depth > MAX_REFERENCE_DEPTH:
        raise ReportTruthError("an observation exceeds the provenance nesting bound")
    if type(value) is dict:
        out = {}
        for key, item in dict.items(value):
            if type(key) is not str:
                raise ReportTruthError("an observation has a non-string member name")
            if key == "raw_ref":
                out[key] = (_relative_reference(run_dir, item)
                            if item not in (None, "") else item)
            elif key == "raw_refs":
                if type(item) is not list:
                    raise ReportTruthError("raw_refs is not an exact list")
                out[key] = [_relative_reference(run_dir, ref) for ref in item]
            elif key in _OPAQUE_EVIDENCE_FIELDS:
                # A JSON round trip both detaches the provider value and checks
                # it without interpreting target-controlled member names.
                out[key] = json.loads(_canonical_bytes(item))
            else:
                out[key] = _canonical_record(item, run_dir, depth=depth + 1)
        return out
    if type(value) is list:
        return [_canonical_record(item, run_dir, depth=depth + 1) for item in value]
    return value


def _record_reference_roster(record: dict) -> list[str]:
    refs = []
    for value in _reference_values(record):
        ref = _relative_path(value)
        if ref not in refs:
            refs.append(ref)
    return sorted(refs)


def _artifact_claims(manifest: run_manifest.RunManifest, rev: revision.Revision) -> dict[str, dict]:
    claims = {item["path"]: dict(item) for item in manifest.document["base_files"]}
    if len(claims) != len(manifest.document["base_files"]):
        raise ReportTruthError("manifest base-file claims contain a duplicate path")
    if rev.status == "valid":
        for segment in rev.segments:
            path = f"revisions/{segment['file']}"
            claim = {
                "path": path,
                "bytes": segment["bytes"],
                "rows": segment["lines"],
                "digest": segment["digest"],
                "media_type": "application/x-ndjson",
            }
            if path in claims:
                raise ReportTruthError(f"revision artifact aliases a base claim: {path!r}")
            claims[path] = claim
        for path, descriptor in rev.raw_files.items():
            if path in claims:
                raise ReportTruthError(f"revision raw artifact aliases another claim: {path!r}")
            claims[path] = {
                "path": path,
                "bytes": descriptor["bytes"],
                "rows": None,
                "digest": descriptor["digest"],
                "media_type": "application/octet-stream",
            }
    return claims


class _AuthenticatedView:
    """Effective records derived only from already-authenticated source bytes."""

    def __init__(self, records: dict[str, dict], base_keys: dict[str, set[str]],
                 segment_refs: dict[tuple[str, str], tuple[str, ...]]) -> None:
        self._records = records
        self._base_keys = base_keys
        self._segment_refs = segment_refs

    def read(self, entity: str) -> list[dict]:
        return list(self._records.get(entity, {}).values())

    def store_refs(self, entity: str, record: dict) -> list[str]:
        key = store.canonical_key(entity, record)
        out = ([f"normalized/{entity}.jsonl"]
               if key in self._base_keys.get(entity, set()) else [])
        out.extend(f"revisions/{name}"
                   for name in self._segment_refs.get((entity, key), ()))
        return out

    def store_ref(self, entity: str, record: dict) -> str:
        refs = self.store_refs(entity, record)
        if not refs:
            raise ReportTruthError(f"{entity} observation has no authenticated source")
        return refs[-1]


def _revision_rows(run_dir: Path, rev: revision.Revision) -> list[dict]:
    rows: list[dict] = []
    total_bytes = 0
    for segment in rev.segments:
        total_bytes += segment["bytes"]
        if total_bytes > revision.MAX_REVISION_SUPPLEMENT_BYTES:
            raise ReportTruthError("revision segments exceed the authenticated inventory bound")
        try:
            path = revision._segment_path(run_dir, segment["file"])
            body = revision._read_regular(
                path, root=revision.revisions_dir(run_dir),
                maximum=revision.MAX_REVISION_SEGMENT_BYTES,
            )
        except (OSError, ValueError) as exc:
            raise ReportTruthError(
                f"revision segment {segment.get('file')!r} cannot be snapshotted: {exc}",
            ) from exc
        if (len(body) != segment["bytes"]
                or hashlib.sha256(body).hexdigest() != segment["digest"]
                or (body and not body.endswith(b"\n"))
                or len(body.splitlines()) != segment["lines"]):
            raise ReportTruthError(
                f"revision segment {segment.get('file')!r} changed before projection",
            )
        for index, line in enumerate(body.splitlines(), 1):
            try:
                if not line or len(line) > run_manifest.MAX_JSONL_LINE_BYTES:
                    raise revision.RevisionError("revision row exceeds its JSONL envelope")
                row = revision._strict_json(
                    line, f"revision segment {segment['file']!r} row {index}",
                )
            except revision.RevisionError as exc:
                raise ReportTruthError(
                    f"revision segment {segment['file']!r} row {index} is invalid",
                ) from exc
            entity = row.get("entity") if type(row) is dict else None
            record = row.get("record") if type(row) is dict else None
            if type(entity) is not str or entity not in store.ENTITY_KEYS or type(record) is not dict:
                raise ReportTruthError(
                    f"revision segment {segment['file']!r} row {index} is invalid",
                )
            key = store.canonical_key(entity, record)
            if not key or row.get("id") != key or row.get("fp") != store.fingerprint(entity, record):
                raise ReportTruthError(
                    f"revision segment {segment['file']!r} row {index} has a false identity",
                )
            rows.append({"entity": entity, "id": key, "record": record,
                         "segment": segment["file"]})
    if len(rows) != sum(segment["lines"] for segment in rev.segments):
        raise ReportTruthError("revision snapshot does not yield every certified row")
    return rows


def _authenticated_view(manifest: run_manifest.RunManifest, rev: revision.Revision,
                        run_dir: Path) -> _AuthenticatedView:
    # Copy the fold captured inside run_manifest.read's held descriptor
    # authority.  No Run.read()/fold path is reopened after that point.
    records = {entity: dict(folded.records)
               for entity, folded in manifest.folded_by_entity.items()}
    base_keys = {entity: set(entity_records) for entity, entity_records in records.items()}
    refs: dict[tuple[str, str], list[str]] = {}
    if rev.status == "valid":
        if rev.snapshot_bound:
            records = {
                entity: dict(entity_records)
                for entity, entity_records in rev.effective_records.items()
            }
            refs = {key: list(names) for key, names in rev.provenance.items()}
        else:
            # Pre-publication staged revisions have not passed through
            # revision.read yet; their unique private segment names are read
            # through the same strict descriptor authority before exposure.
            for row in _revision_rows(run_dir, rev):
                entity, key, record = row["entity"], row["id"], row["record"]
                held = records.setdefault(entity, {})
                held[key] = store.merge(entity, held[key], record) if key in held else record
                bucket = refs.setdefault((entity, key), [])
                if row["segment"] not in bucket:
                    bucket.append(row["segment"])
        counts = {entity: len(rows) for entity, rows in records.items() if rows}
        digests = {entity: revision._records_digest(entity, rows)
                   for entity, rows in records.items() if rows}
        if counts != rev.entity_counts or digests != rev.entity_digests:
            raise ReportTruthError("revision snapshot does not match its certified effective evidence")
    return _AuthenticatedView(
        records,
        base_keys,
        {key: tuple(names) for key, names in refs.items()},
    )


def _artifact_record(claim: dict) -> dict:
    return {
        "path": claim["path"],
        "bytes": claim["bytes"],
        "rows": claim.get("rows"),
        "digest": _named_digest(claim["digest"]),
        "media_type": claim["media_type"],
    }


def build_private_report(run, *, staged_revision: revision.Revision | None = None) -> dict:
    """Build the deterministic v2 projection of one committed base/combined view."""
    run_dir = Path(run.dir)
    legacy_state_absent = not os.path.lexists(run_dir / "state.json")
    try:
        manifest = run_manifest.read(
            run_dir / "manifest.json", verify_lifecycle=not legacy_state_absent,
        )
    except Exception as exc:
        raise ReportTruthError(
            f"the private report requires a certified base manifest: {type(exc).__name__}: {exc}",
        ) from exc
    if legacy_state_absent and os.path.lexists(run_dir / "state.json"):
        raise ReportTruthError("the base lifecycle appeared while the private report was opened")
    rev = staged_revision if staged_revision is not None else revision.read(run_dir)
    if staged_revision is not None and (
            type(staged_revision) is not revision.Revision or staged_revision.status != "valid"
            or staged_revision.revision < 1 or not staged_revision.created):
        raise ReportTruthError("the staged private-report revision identity is invalid")
    if staged_revision is not None:
        try:
            _named_digest(staged_revision.digest)
        except ReportTruthError as exc:
            raise ReportTruthError("the staged private-report revision identity is invalid") from exc
    if rev.status == "unusable":
        raise ReportTruthError(f"the private report refuses an unusable revision: {rev.reason}")
    if staged_revision is not None and (
            type(run) is not revision.CombinedRun or Path(run.dir) != run_dir):
        raise ReportTruthError("a staged revision requires its exact combined-run projector")
    source = _authenticated_view(manifest, rev, run_dir)
    claims = _artifact_claims(manifest, rev)

    observations: list[dict] = []
    by_entity: dict[str, int] = {}
    seen_ids: set[str] = set()
    projected_bytes = 0
    for entity in sorted(store.ENTITY_KEYS):
        rows = source.read(entity)
        by_entity[entity] = len(rows)
        keyed: list[tuple[str, dict]] = []
        for record in rows:
            if type(record) is not dict:
                raise ReportTruthError(f"{entity} contains a non-object effective record")
            key = store.canonical_key(entity, record)
            if not key:
                raise ReportTruthError(f"{entity} contains an effective record without identity")
            keyed.append((key, record))
        if len({key for key, _ in keyed}) != len(keyed):
            raise ReportTruthError(f"{entity} contains duplicate effective identities")
        for key, source_record in sorted(keyed, key=lambda item: item[0].encode("utf-8")):
            record = _canonical_record(source_record, run_dir)
            if store.canonical_key(entity, record) != key:
                raise ReportTruthError(
                    f"{entity}:{key} changed identity while provenance was canonicalised",
                )
            material_digest = _digest(_canonical_bytes(store.material(entity, record)))
            observation_id = _digest(
                b"quarry.private-observation.v2\0"
                + entity.encode("utf-8") + b"\0" + key.encode("utf-8") + b"\0"
                + material_digest.encode("ascii")
            )
            if observation_id in seen_ids:
                raise ReportTruthError("private observation identity collision")
            seen_ids.add(observation_id)

            source_name = source.store_ref(entity, source_record)
            source_ref = _relative_reference(run_dir, source_name)
            source_names = source.store_refs(entity, source_record)
            if type(source_names) is not list or not source_names:
                raise ReportTruthError(f"{entity}:{key} has no canonical source artifact")
            source_refs = []
            for name in source_names:
                relative = _relative_reference(run_dir, name)
                if relative not in source_refs:
                    source_refs.append(relative)
            if source_ref not in source_refs:
                raise ReportTruthError(f"{entity}:{key} source identity does not reconcile")
            record_refs = _record_reference_roster(record)
            if len(source_refs) + len(record_refs) > MAX_REFERENCES_PER_OBSERVATION:
                raise ReportTruthError(f"{entity}:{key} exceeds the provenance-reference bound")
            source_refs.sort()
            record_refs.sort()
            if set(source_refs).intersection(record_refs):
                raise ReportTruthError(
                    f"{entity}:{key} aliases a canonical source as a record proof",
                )
            refs = sorted(set((*source_refs, *record_refs)))
            try:
                artifacts = [_artifact_record(claims[ref]) for ref in refs]
            except KeyError as exc:
                raise ReportTruthError(
                    f"{entity}:{key} references an unattested artifact {exc.args[0]!r}",
                ) from exc
            if entity == "finding" and not any(
                    path.startswith(("raw/", "revisions/raw/")) for path in record_refs):
                raise ReportTruthError(
                    f"finding {key!r} has no attested raw proof artifact",
                )
            observation = {
                "observation_id": observation_id,
                "entity": entity,
                "key": key,
                "material_digest": material_digest,
                "record": record,
                "source_ref": source_ref,
                "source_refs": source_refs,
                "record_refs": record_refs,
                "artifact_refs": artifacts,
            }
            projected_bytes += len(_canonical_bytes(observation))
            if projected_bytes > MAX_PRIVATE_REPORT_BYTES:
                raise ReportTruthError(
                    f"the private report exceeds the {MAX_PRIVATE_REPORT_BYTES}-byte support envelope",
                )
            observations.append(observation)

    observations.sort(key=lambda row: (row["entity"].encode("utf-8"), row["key"].encode("utf-8")))
    total = sum(by_entity.values())
    if total != len(observations):
        raise ReportTruthError("private-report input/reconciliation count diverged")
    expected_counts = rev.entity_counts if rev.status == "valid" else manifest.document["entity_counts"]
    observed_nonzero = {entity: count for entity, count in by_entity.items() if count}
    if observed_nonzero != expected_counts:
        raise ReportTruthError("private-report rows do not reconcile with the certified entity counts")
    # The original (pre-path-canonicalisation) records were reconciled against
    # revision.entity_digests inside _authenticated_view.  Rehashing the emitted
    # record here would incorrectly make an absolute in-run raw_ref material.
    source_view = {
        "kind": "revision" if rev.status == "valid" else "base",
        "manifest_digest": manifest.digest,
        "revision": rev.revision if rev.status == "valid" else 0,
        "revision_digest": _named_digest(rev.digest) if rev.status == "valid" else None,
        "generated_at": rev.created if rev.status == "valid" else manifest.document["finished"],
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "target": manifest.document["target"],
        "run_id": manifest.document["run_id"],
        "source_view": source_view,
        "counts": {
            "input": total,
            "included": len(observations),
            "omitted": 0,
            "by_entity": by_entity,
        },
        "observations": observations,
        "omissions": [],
    }
    verify_private_report(document)
    if legacy_state_absent != (not os.path.lexists(run_dir / "state.json")):
        raise ReportTruthError("the base lifecycle changed while the private report was built")
    final_manifest = run_manifest.read(
        run_dir / "manifest.json", verify_lifecycle=not legacy_state_absent,
    )
    if final_manifest.digest != manifest.digest:
        raise ReportTruthError("the base manifest changed while the private report was built")
    if staged_revision is None:
        final_revision = revision.read(run_dir)
        if (final_revision.status != rev.status or final_revision.revision != rev.revision
                or final_revision.digest != rev.digest
                or final_revision.pointer_digest != rev.pointer_digest):
            raise ReportTruthError("the revision changed while the private report was built")
    return document


def _group_observations(observations: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in observations:
        grouped.setdefault(row["entity"], []).append(row)
    return grouped


def verify_private_report(document: object, *, expected: dict | None = None) -> dict:
    """Validate exact structural/reconciliation invariants; optionally require a rebuilt document."""
    if type(document) is not dict or set(document) != {
        "schema_version", "target", "run_id", "source_view", "counts", "observations", "omissions",
    }:
        raise ReportTruthError("private report fields do not match v2")
    encoded = canonical_json_bytes(document)
    if len(encoded) > MAX_PRIVATE_REPORT_BYTES:
        raise ReportTruthError(
            f"the private report exceeds the {MAX_PRIVATE_REPORT_BYTES}-byte support envelope",
        )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ReportTruthError("private report schema version is unsupported")
    if type(document["target"]) is not str or not document["target"].strip():
        raise ReportTruthError("private report target is invalid")
    if type(document["run_id"]) is not str or not document["run_id"].strip():
        raise ReportTruthError("private report run_id is invalid")
    source = document["source_view"]
    if type(source) is not dict or set(source) != {
        "kind", "manifest_digest", "revision", "revision_digest", "generated_at",
    } or source["kind"] not in ("base", "revision"):
        raise ReportTruthError("private report source view is invalid")
    _count(source["revision"], "revision")
    _document_digest(source["manifest_digest"], "manifest_digest")
    if source["kind"] == "base" and (source["revision"] != 0 or source["revision_digest"] is not None):
        raise ReportTruthError("base private report carries revision identity")
    if source["kind"] == "revision" and (
            source["revision"] < 1 or type(source["revision_digest"]) is not str):
        raise ReportTruthError("revision private report carries no revision identity")
    if source["kind"] == "revision":
        _document_digest(source["revision_digest"], "revision_digest")
    _timestamp(source["generated_at"])
    counts = document["counts"]
    if type(counts) is not dict or set(counts) != {"input", "included", "omitted", "by_entity"}:
        raise ReportTruthError("private report counts are invalid")
    for field in ("input", "included", "omitted"):
        _count(counts[field], field)
    if type(counts["by_entity"]) is not dict or set(counts["by_entity"]) != set(store.ENTITY_KEYS):
        raise ReportTruthError("private report entity roster is incomplete")
    for entity, value in counts["by_entity"].items():
        _count(value, f"by_entity.{entity}")
    observations, omissions = document["observations"], document["omissions"]
    if type(observations) is not list or type(omissions) is not list:
        raise ReportTruthError("private report observations/omissions are invalid")
    if counts["input"] != counts["included"] + counts["omitted"] \
            or counts["included"] != len(observations) or counts["omitted"] != len(omissions) \
            or counts["input"] != sum(counts["by_entity"].values()):
        raise ReportTruthError("private report counts do not reconcile")
    if omissions:
        raise ReportTruthError("v2 private machine projection may not omit a current-schema observation")
    prior: tuple[bytes, bytes] | None = None
    seen: set[str] = set()
    observed_counts = {entity: 0 for entity in store.ENTITY_KEYS}
    artifact_descriptors: dict[str, tuple[int, int | None, str, str]] = {}
    for row in observations:
        if type(row) is not dict or set(row) != {
            "observation_id", "entity", "key", "material_digest", "record", "source_ref",
            "source_refs", "record_refs", "artifact_refs",
        }:
            raise ReportTruthError("private observation fields are invalid")
        entity, key = row["entity"], row["key"]
        if type(entity) is not str or entity not in store.ENTITY_KEYS \
                or type(key) is not str or not key.strip() or type(row["record"]) is not dict:
            raise ReportTruthError("private observation identity is invalid")
        order = (entity.encode("utf-8"), key.encode("utf-8"))
        if prior is not None and order <= prior:
            raise ReportTruthError("private observations are not in canonical unique order")
        prior = order
        if store.canonical_key(entity, row["record"]) != key:
            raise ReportTruthError("private observation key does not match its record")
        material_digest = _digest(_canonical_bytes(store.material(entity, row["record"])))
        identity = _digest(
            b"quarry.private-observation.v2\0" + entity.encode() + b"\0" + key.encode()
            + b"\0" + material_digest.encode("ascii")
        )
        _document_digest(row["material_digest"], "material_digest")
        _document_digest(row["observation_id"], "observation_id")
        if row["material_digest"] != material_digest or row["observation_id"] != identity \
                or identity in seen:
            raise ReportTruthError("private observation digest/identity is invalid")
        seen.add(identity)
        observed_counts[entity] += 1
        refs = row["artifact_refs"]
        if type(refs) is not list or not refs or len(refs) > MAX_REFERENCES_PER_OBSERVATION:
            raise ReportTruthError("private observation has no artifact references")
        paths = []
        for ref in refs:
            if type(ref) is not dict or set(ref) != {"path", "bytes", "rows", "digest", "media_type"}:
                raise ReportTruthError("private observation artifact reference is invalid")
            _relative_path(ref["path"])
            _count(ref["bytes"], "artifact bytes")
            _document_digest(ref["digest"], "artifact digest")
            if type(ref["media_type"]) is not str or ref["media_type"] not in _MEDIA_TYPES:
                raise ReportTruthError("private observation artifact descriptor is invalid")
            if ref["rows"] is not None:
                _count(ref["rows"], "artifact rows")
            descriptor = (ref["bytes"], ref["rows"], ref["digest"], ref["media_type"])
            previous = artifact_descriptors.setdefault(ref["path"], descriptor)
            if previous != descriptor:
                raise ReportTruthError(
                    "private report carries conflicting descriptors for one artifact path",
                )
            paths.append(ref["path"])
        _relative_path(row["source_ref"])
        source_refs, record_refs = row["source_refs"], row["record_refs"]
        if type(source_refs) is not list or not source_refs \
                or type(record_refs) is not list \
                or len(source_refs) + len(record_refs) > MAX_REFERENCES_PER_OBSERVATION:
            raise ReportTruthError("private observation provenance rosters are invalid")
        for ref in (*source_refs, *record_refs):
            _relative_path(ref)
        base_source = f"normalized/{entity}.jsonl"
        revision_sources = [ref for ref in source_refs if ref != base_source]
        if source["kind"] == "base":
            canonical_source_roster = source_refs == [base_source]
            canonical_source_ref = base_source
        else:
            numbered_sources = []
            for ref in revision_sources:
                match = re.fullmatch(r"revisions/rev(\d{4,})/observations\.jsonl", ref)
                if match is not None:
                    number = int(match.group(1))
                    if ref == f"revisions/{revision._rev_name(number)}/observations.jsonl":
                        numbered_sources.append((number, ref))
            canonical_source_roster = (
                len(numbered_sources) == len(revision_sources)
                and all(1 <= number <= source["revision"] for number, _ref in numbered_sources)
                and len({number for number, _ref in numbered_sources}) == len(numbered_sources)
            )
            canonical_source_ref = (
                max(numbered_sources)[1] if numbered_sources else base_source
            )
        derived_record_refs = _record_reference_roster(row["record"])
        if source_refs != sorted(set(source_refs)) or record_refs != sorted(set(record_refs)) \
                or set(source_refs).intersection(record_refs) \
                or paths != sorted(set((*source_refs, *record_refs))) \
                or not canonical_source_roster \
                or row["source_ref"] != canonical_source_ref \
                or record_refs != derived_record_refs:
            raise ReportTruthError("private observation artifact paths do not reconcile")
        if entity == "finding" and not any(
                path.startswith(("raw/", "revisions/raw/")) for path in record_refs):
            raise ReportTruthError("private finding has no raw proof artifact")
    if observed_counts != counts["by_entity"]:
        raise ReportTruthError("private report per-entity counts do not reconcile")
    # Encoding is part of validation: NaN, surrogates, cycles and non-JSON values fail here.
    if expected is not None and encoded != canonical_json_bytes(expected):
        raise ReportTruthError("private report does not match the authoritative rebuilt projection")
    return document


def published_private_report_current(run) -> bool:
    """Whether the named base report is the exact current authenticated projection.

    This predicate is intentionally semantic, not an existence test.  The
    strict reader refuses symlinks, hard links, loose modes, replacement files,
    unstable names and torn/oversized bodies before comparing canonical bytes.
    """
    try:
        from . import resource_contract
        expected = build_private_report(run)
        raw = resource_contract.read_private_file(
            Path(run.reports) / "private-report.json",
            maximum=MAX_PRIVATE_REPORT_BYTES,
        )
        read_private_report(raw, expected=expected)
        return True
    except Exception:
        return False


def read_private_report(body: bytes, *, expected: dict | None = None) -> dict:
    if type(body) is not bytes:
        raise ReportTruthError("private report body is not bytes")
    if len(body) > MAX_PRIVATE_REPORT_BYTES:
        raise ReportTruthError(
            f"the private report exceeds the {MAX_PRIVATE_REPORT_BYTES}-byte support envelope",
        )
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportTruthError(f"private report is not strict JSON: {type(exc).__name__}: {exc}") from exc
    verify_private_report(document, expected=expected)
    if body != canonical_json_bytes(document):
        raise ReportTruthError("private report bytes are not canonical v2 JSON")
    return document


__all__ = [
    "MAX_PRIVATE_REPORT_BYTES", "MAX_REFERENCES_PER_OBSERVATION", "ReportTruthError", "SCHEMA_VERSION",
    "build_private_report", "canonical_json_bytes", "read_private_report",
    "published_private_report_current", "verify_private_report",
]
