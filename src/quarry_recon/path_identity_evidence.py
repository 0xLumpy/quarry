"""Bounded, non-promoting C-PATH-IDENTITY evidence substrate.

The property corpus in this module is candidate-independent.  The companion
collector invokes the production repository identity, store, campaign and
private-path boundaries in disposable local repositories and records what
actually happened.  Those local observations are useful source evidence, but
they do not authenticate a candidate owner, an H0 isolation interval or a
toolchain.  Consequently this module deliberately emits ``source_substrate``
and is not a release semantic verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import stat
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from . import campaign, privfs, release_evidence as evidence, repository_identity, store


PROPERTY_CORPUS_SCHEMA_VERSION = "quarry.path-identity-property-corpus.v1"
CONTAINMENT_DECISIONS_SCHEMA_VERSION = "quarry.path-identity-containment-decisions.v1"
MAX_BYTES = 2 * 1024 * 1024
MAX_INTEGER = (1 << 63) - 1

INPUT_PATHS = MappingProxyType({
    "path-identity-campaign-runtime": "src/quarry_recon/campaign.py",
    "path-identity-contract-tests": "tests/test_path_identity_contract.py",
    "path-identity-corpus": "release/evidence/path-identity-property-corpus-v1.json",
    "path-identity-corpus-schema":
        "release/evidence/schemas/path-identity-property-corpus-v1.schema.json",
    "path-identity-decisions-schema":
        "release/evidence/schemas/path-identity-containment-decisions-v1.schema.json",
    "path-identity-evidence-runtime": "src/quarry_recon/path_identity_evidence.py",
    "path-identity-privfs-runtime": "src/quarry_recon/privfs.py",
    "path-identity-producer": "scripts/emit_path_identity_evidence.py",
    "path-identity-production-tests": "tests/test_repository_identity.py",
    "path-identity-repository-runtime": "src/quarry_recon/repository_identity.py",
    "path-identity-store-runtime": "src/quarry_recon/store.py",
})


class PathIdentityEvidenceError(evidence.EvidenceError):
    """The bounded property corpus or one local containment decision is invalid."""


def _qualified(kind: type[BaseException]) -> str:
    return f"{kind.__module__}.{kind.__qualname__}"


_INVALID_RUN = _qualified(repository_identity.InvalidRunId)
_INVALID_CAMPAIGN = _qualified(repository_identity.InvalidCampaignId)
_INVALID_ARTIFACT = _qualified(repository_identity.InvalidArtifactComponent)
_PRIVATE_PATH = _qualified(privfs.PrivatePathUnsafe)
_CONTRACT_ERROR = _qualified(store.ContractError)
_INVALID_RUN_IDENTITY = _qualified(store._InvalidRunIdentity)
_NOT_A_DIRECTORY = _qualified(NotADirectoryError)


def _case(
    case_id: str,
    operation: str,
    subject: str,
    kind: str,
    value: object,
    expected_disposition: str,
    expected_exception: str | None,
    *,
    allow_empty: bool | None = None,
) -> dict:
    return {
        "case_id": case_id,
        "operation": operation,
        "subject": subject,
        "input": {"kind": kind, "value": value},
        "options": {"allow_empty": allow_empty},
        "expected_disposition": expected_disposition,
        "expected_exception": expected_exception,
    }


def _property_cases() -> tuple[dict, ...]:
    cases: list[dict] = []
    valid_ids = (
        ("r1", "r1"),
        ("fixed", "fixed"),
        ("timestamp", "20260811-102030-deadbeef"),
        ("upper", "A"),
        ("punctuation", "a.b-c_d"),
        ("max64", "x" * 64),
    )
    invalid_ids = (
        ("none", "none", None),
        ("bytes", "bytes", "base64:cnVu"),
        ("list", "list", []),
        ("mapping", "mapping", {}),
        ("empty", "string", ""),
        ("dot", "string", "."),
        ("dotdot", "string", ".."),
        ("absolute", "string", "/absolute"),
        ("slash", "string", "a/b"),
        ("backslash", "string", "a\\b"),
        ("nul", "string", "a\0b"),
        ("newline", "string", "a\nb"),
        ("non-ascii", "string", "å"),
        ("over64", "string", "x" * 65),
        ("hostile-subclass", "hostile_string", "fixed"),
    )
    for operation, subject, exception in (
        ("validate_run_id", "run", _INVALID_RUN),
        ("validate_campaign_id", "campaign", _INVALID_CAMPAIGN),
    ):
        prefix = "run-id" if subject == "run" else "campaign-id"
        for label, value in valid_ids:
            cases.append(_case(
                f"{prefix}-valid-{label}", operation, subject, "string", value,
                "accepted", None,
            ))
        for label, kind, value in invalid_ids:
            cases.append(_case(
                f"{prefix}-refuse-{label}", operation, subject, kind, value,
                "refused", exception,
            ))
        for reserved in ("state", "campaigns"):
            cases.append(_case(
                f"{prefix}-refuse-reserved-{reserved}", operation, subject,
                "string", reserved, "refused", exception,
            ))

    cases.extend((
        _case("artifact-valid-ipv6-space", "validate_artifact_component", "artifact",
              "string", "2001:db8::1 evidence.json", "accepted", None),
        _case("tool-valid-nuclei", "validate_artifact_component", "tool",
              "string", "nuclei", "accepted", None),
    ))
    invalid_components = (
        ("empty", "string", ""),
        ("dot", "string", "."),
        ("dotdot", "string", ".."),
        ("traversal", "string", "../x"),
        ("slash", "string", "a/b"),
        ("backslash", "string", "a\\b"),
        ("absolute", "string", "/tmp/escape"),
        ("nul", "string", "a\0b"),
        ("newline", "string", "a\nb"),
        ("over255", "string", "x" * 256),
        ("surrogate", "surrogate", "d800"),
        ("hostile-subclass", "hostile_string", "artifact"),
    )
    for label, kind, value in invalid_components:
        cases.append(_case(
            f"artifact-refuse-{label}", "validate_artifact_component", "artifact",
            kind, value, "refused", _INVALID_ARTIFACT,
        ))

    cases.extend((
        _case("store-artifact-valid-raw", "validate_store_artifact", "artifact", "tuple",
              ["raw", "params", "nuclei", "out.json"], "accepted", None),
        _case("store-artifact-refuse-empty", "validate_store_artifact", "artifact", "tuple",
              [], "refused", _CONTRACT_ERROR),
        _case("store-artifact-refuse-list", "validate_store_artifact", "artifact", "list",
              ["raw", "out.json"], "refused", _CONTRACT_ERROR),
        _case("store-artifact-refuse-65-components", "validate_store_artifact", "artifact", "tuple",
              ["raw", *("a" for _ in range(64))], "refused", _CONTRACT_ERROR),
        _case("store-artifact-refuse-foreign-root", "validate_store_artifact", "artifact", "tuple",
              ["exports", "out.json"], "refused", _CONTRACT_ERROR),
        _case("store-artifact-refuse-traversal", "validate_store_artifact", "artifact", "tuple",
              ["raw", "..", "out.json"], "refused", _INVALID_ARTIFACT),
    ))

    relative_cases = (
        ("empty-allowed", "tuple", [], True, "accepted", None),
        ("empty-required", "tuple", [], False, "refused", _PRIVATE_PATH),
        ("one", "tuple", ["a"], False, "accepted", None),
        ("max64-components", "tuple", ["a"] * 64, False, "accepted", None),
        ("over64-components", "tuple", ["a"] * 65, False, "refused", _PRIVATE_PATH),
        ("max255-bytes", "tuple", ["x" * 255], False, "accepted", None),
        ("over255-bytes", "tuple", ["x" * 256], False, "refused", _PRIVATE_PATH),
        ("over4096-total", "tuple", ["x" * 255] * 17, False, "refused", _PRIVATE_PATH),
        ("empty-component", "tuple", [""], False, "refused", _PRIVATE_PATH),
        ("dotdot", "tuple", [".."], False, "refused", _PRIVATE_PATH),
        ("absolute", "tuple", ["/absolute"], False, "refused", _PRIVATE_PATH),
        ("backslash", "tuple", ["a\\b"], False, "refused", _PRIVATE_PATH),
        ("control", "tuple", ["a\nb"], False, "refused", _PRIVATE_PATH),
        ("surrogate", "tuple_surrogate", ["d800"], False, "refused", _PRIVATE_PATH),
        ("hostile-subclass", "tuple_hostile_string", ["safe"], False, "refused", _PRIVATE_PATH),
        ("not-tuple", "list", ["safe"], False, "refused", _PRIVATE_PATH),
    )
    for label, kind, value, allow_empty, disposition, exception in relative_cases:
        cases.append(_case(
            f"private-relative-{label}", "validate_relative_components", "private_path",
            kind, value, disposition, exception, allow_empty=allow_empty,
        ))

    cases.extend((
        _case("entity-refuse-unknown", "validate_entity", "entity", "string", "unknown",
              "refused", _CONTRACT_ERROR),
        _case("entity-refuse-hostile-subclass", "validate_entity", "entity", "hostile_string",
              "subdomain", "refused", _CONTRACT_ERROR),
        _case("project-root-refuse-symlink", "run_create_project_symlink", "project", "string",
              "fixed", "refused", _NOT_A_DIRECTORY),
        _case("run-root-refuse-symlink", "run_open_symlink", "run", "string", "fixed",
              "refused", _CONTRACT_ERROR),
        _case("run-identity-refuse-run-json-symlink", "run_open_identity_symlink", "run",
              "string", "run.json", "refused", _INVALID_RUN_IDENTITY),
        _case("run-identity-refuse-manifest-json-symlink", "run_open_identity_symlink", "run",
              "string", "manifest.json", "refused", _INVALID_RUN_IDENTITY),
        _case("artifact-parent-refuse-symlink", "run_raw_parent_symlink", "artifact", "string",
              "params", "refused", _NOT_A_DIRECTORY),
        _case("tool-route-refuse-before-mutation", "run_raw_tool", "tool", "string",
              "../escape", "refused", _INVALID_ARTIFACT),
        _case("tool-hostile-refuse-before-mutation", "run_raw_tool", "tool", "hostile_string",
              "nuclei", "refused", _INVALID_ARTIFACT),
        _case("campaign-absorb-refuse-outside-repository", "campaign_absorb_outside", "run",
              "string", "fixed", "refused", _CONTRACT_ERROR),
        _case("run-read-refuse-unknown-entity", "run_entity_read", "entity", "string",
              "unknown", "refused", _CONTRACT_ERROR),
        _case("run-read-refuse-hostile-entity", "run_entity_read", "entity", "hostile_string",
              "subdomain", "refused", _CONTRACT_ERROR),
        _case("run-add-refuse-unknown-entity", "run_entity_add", "entity", "string",
              "unknown", "refused", _CONTRACT_ERROR),
        _case("run-add-refuse-hostile-entity", "run_entity_add", "entity", "hostile_string",
              "subdomain", "refused", _CONTRACT_ERROR),
    ))
    return tuple(cases)


PROPERTY_CASES = _property_cases()
CASE_COUNT = len(PROPERTY_CASES)


def property_corpus_document() -> dict:
    """Return the fixed candidate-independent v1 property corpus."""
    return {
        "schema_version": PROPERTY_CORPUS_SCHEMA_VERSION,
        "artifact_type": "path-identity-property-corpus",
        "release": "0.3.10",
        "gate_id": "C-PATH-IDENTITY",
        "name": "property-corpus",
        "disposition": "source_substrate",
        "closure_status": "OPEN",
        "cases": [dict(case) for case in PROPERTY_CASES],
    }


def _canonical_line(document: object) -> bytes:
    try:
        body = evidence.canonical_json_bytes(document) + b"\n"
    except evidence.EvidenceError as exc:
        raise PathIdentityEvidenceError(str(exc)) from exc
    if len(body) > MAX_BYTES:
        raise PathIdentityEvidenceError("path identity evidence exceeds its byte contract")
    return body


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PathIdentityEvidenceError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _bounded_json_integer(raw: str) -> int:
    digits = raw[1:] if raw.startswith("-") else raw
    if not digits or len(digits) > 19:
        raise PathIdentityEvidenceError("path identity JSON integer exceeds its decimal bound")
    try:
        value = int(raw)
    except (ValueError, OverflowError) as exc:
        raise PathIdentityEvidenceError("path identity JSON integer is malformed") from exc
    if not -MAX_INTEGER <= value <= MAX_INTEGER:
        raise PathIdentityEvidenceError("path identity JSON integer exceeds its signed 64-bit bound")
    return value


def _reject_json_float(_raw: str) -> float:
    raise PathIdentityEvidenceError("path identity evidence does not permit JSON floats")


def _reject_json_constant(_raw: str) -> object:
    raise PathIdentityEvidenceError("path identity evidence does not permit non-finite constants")


def _parse(body: bytes, where: str) -> dict:
    if type(body) is not bytes or not body or len(body) > MAX_BYTES or not body.endswith(b"\n"):
        raise PathIdentityEvidenceError(f"{where} is not one bounded canonical JSON line")
    try:
        document = json.loads(
            body[:-1].decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_int=_bounded_json_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError,
        PathIdentityEvidenceError,
    ) as exc:
        if isinstance(exc, PathIdentityEvidenceError):
            raise
        raise PathIdentityEvidenceError(f"{where} is not strict JSON") from exc
    if type(document) is not dict or _canonical_line(document) != body:
        raise PathIdentityEvidenceError(f"{where} is not canonical JSON")
    return document


def read_property_corpus(body: bytes) -> dict:
    """Read only the exact committed canonical property corpus."""
    document = _parse(body, "path identity property corpus")
    expected = property_corpus_document()
    if document != expected:
        raise PathIdentityEvidenceError("path identity property corpus roster or order drifted")
    return document


def canonical_property_corpus_bytes() -> bytes:
    """Return canonical bytes for the one supported property corpus."""
    return _canonical_line(property_corpus_document())


class _HostileString(str):
    def __hash__(self):  # pragma: no cover - execution is a failed invariant, not a branch to accept
        raise AssertionError("path validation executed an untrusted hash hook")

    def __eq__(self, _other):  # pragma: no cover - same fail-closed tripwire
        raise AssertionError("path validation executed an untrusted equality hook")


def _materialize(encoded: dict):
    kind, value = encoded["kind"], encoded["value"]
    if kind == "string":
        return value
    if kind == "none":
        return None
    if kind == "bytes":
        if type(value) is not str or not value.startswith("base64:"):
            raise PathIdentityEvidenceError("property corpus bytes encoding is malformed")
        try:
            return base64.b64decode(value[7:], validate=True)
        except ValueError as exc:
            raise PathIdentityEvidenceError("property corpus bytes encoding is malformed") from exc
    if kind == "list":
        return list(value)
    if kind == "mapping":
        return dict(value)
    if kind == "hostile_string":
        return _HostileString(value)
    if kind == "surrogate":
        return chr(int(value, 16))
    if kind == "tuple":
        return tuple(value)
    if kind == "tuple_surrogate":
        return tuple(chr(int(item, 16)) for item in value)
    if kind == "tuple_hostile_string":
        return tuple(_HostileString(item) for item in value)
    raise PathIdentityEvidenceError("property corpus input kind is unknown")


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, privfs.DIR_MODE)
    return path


def _manual_run(path: Path, *, identity_file: str = "run.json", run_id: str = "fixed") -> Path:
    _private_directory(path)
    identity = {
        "run_id": run_id,
        "target": "acme.example",
        "started": "2026-08-11T10:20:30+00:00",
    }
    destination = path / identity_file
    destination.write_bytes(json.dumps(identity, sort_keys=True).encode("utf-8"))
    os.chmod(destination, privfs.FILE_MODE)
    return path


def _operation(case: dict, root: Path):
    value = _materialize(case["input"])
    operation = case["operation"]
    if operation == "validate_run_id":
        return lambda: repository_identity.validate_run_id(value)
    if operation == "validate_campaign_id":
        return lambda: repository_identity.validate_campaign_id(value)
    if operation == "validate_artifact_component":
        return lambda: repository_identity.validate_artifact_component(value, case["subject"])
    if operation == "validate_store_artifact":
        return lambda: store._validated_artifact_components(value)
    if operation == "validate_relative_components":
        allow_empty = case["options"]["allow_empty"]
        return lambda: privfs.validate_relative_components(value, allow_empty=allow_empty)
    if operation == "validate_entity":
        return lambda: store.validate_entity(value)
    if operation == "run_create_project_symlink":
        outside = _private_directory(root / "outside-project")
        project = root / "project"
        os.symlink(outside, project)
        return lambda: store.Run.create(project, "acme.example", run_id=value)
    if operation == "run_open_symlink":
        outside = _manual_run(root / "outside-run")
        project = _private_directory(root / "project")
        recon = _private_directory(project / "recon")
        os.symlink(outside, recon / value)
        return lambda: store.Run.open(project, "acme.example", value)
    if operation == "run_open_identity_symlink":
        linked = value
        project = _private_directory(root / "project")
        recon = _private_directory(project / "recon")
        run_dir = _private_directory(recon / "fixed")
        safe = "manifest.json" if linked == "run.json" else "run.json"
        _manual_run(run_dir, identity_file=safe)
        external = root / "external-identity.json"
        identity = {
            "run_id": "fixed", "target": "acme.example",
            "started": "2026-08-11T10:20:30+00:00",
        }
        external.write_bytes(json.dumps(identity, sort_keys=True).encode("utf-8"))
        os.chmod(external, privfs.FILE_MODE)
        os.symlink(external, run_dir / linked)
        return lambda: store.Run.open(project, "acme.example", "fixed")
    if operation in {"run_raw_parent_symlink", "run_raw_tool"}:
        project = root / "project"
        run = store.Run.create(project, "acme.example", run_id="fixed")
        if operation == "run_raw_parent_symlink":
            outside = _private_directory(root / "outside-artifact")
            os.symlink(outside, run.raw / value)
            callback = lambda: run.raw_path(value, "nuclei", "out.json")
        else:
            callback = lambda: run.raw_path("params", value, "out.json")
        callback._path_identity_run = run
        return callback
    if operation == "campaign_absorb_outside":
        project = root / "project"
        union = campaign.Union.for_campaign(project, "fixed-campaign", create=True)
        outside = _manual_run(root / "outside" / value, run_id=value)
        return lambda: union.absorb(outside)
    if operation in {"run_entity_read", "run_entity_add"}:
        run = store.Run.create(root / "project", "acme.example", run_id="fixed")
        if operation == "run_entity_read":
            callback = lambda: run.read(value)
        else:
            callback = lambda: run.add(value, {"value": "synthetic"})
        callback._path_identity_run = run
        return callback
    raise PathIdentityEvidenceError(f"unsupported path identity operation {operation!r}")


def _tree_records(root: Path) -> dict[str, dict]:
    records: dict[str, dict] = {}

    def visit(path: Path, relative: str) -> None:
        observed = path.lstat()
        kind = (
            "directory" if stat.S_ISDIR(observed.st_mode) else
            "regular" if stat.S_ISREG(observed.st_mode) else
            "symlink" if stat.S_ISLNK(observed.st_mode) else
            "other"
        )
        record = {
            "kind": kind,
            "mode": stat.S_IMODE(observed.st_mode),
            "uid": observed.st_uid,
            "gid": observed.st_gid,
            "device": observed.st_dev,
            "inode": observed.st_ino,
            "links": observed.st_nlink,
            "size": observed.st_size,
            "mtime_ns": observed.st_mtime_ns,
            "ctime_ns": observed.st_ctime_ns,
            "content": None,
        }
        if kind == "regular":
            record["content"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        elif kind == "symlink":
            record["content"] = "sha256:" + hashlib.sha256(
                os.readlink(path).encode("utf-8", "surrogateescape")
            ).hexdigest()
        records[relative] = record
        if kind == "directory":
            for child in sorted(path.iterdir(), key=lambda item: os.fsencode(item.name)):
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                visit(child, child_relative)

    visit(root, ".")
    return records


def _records_digest(records: object) -> str:
    try:
        raw = json.dumps(
            records, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:  # pragma: no cover - local stat data
        raise PathIdentityEvidenceError("local path signature cannot be encoded") from exc
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _tree_summary(records: dict[str, dict]) -> dict:
    return {"digest": _records_digest(records), "entries": len(records)}


def _identity_summary(records: dict[str, dict]) -> dict:
    identities = {
        path: {
            name: record[name]
            for name in ("kind", "mode", "uid", "gid", "device", "inode", "links")
        }
        for path, record in records.items()
    }
    return {"digest": _records_digest(identities), "entries": len(identities)}


def _relative_cache_path(value: object, root: Path) -> str | None:
    try:
        return Path(os.path.abspath(os.fspath(value))).relative_to(root).as_posix()
    except (TypeError, ValueError, OSError):
        return None


def _application_cache_shape(run: object | None) -> dict:
    if type(run) is not store.Run:
        return {"records": {}, "folded": {}, "counts": {}}
    records = {
        entity: sorted(str(key) for key in values)
        for entity, values in sorted(run._records.items())
    }
    folded = {
        entity: {
            "type": f"{type(value).__module__}.{type(value).__qualname__}",
            "record_count": len(value.records) if type(getattr(value, "records", None)) is dict else None,
        }
        for entity, value in sorted(run._folded.items())
    }
    counts = {
        entity: value
        for entity, value in sorted(run._counts_cache.items())
        if type(value) is int and 0 <= value <= MAX_INTEGER
    }
    return {"records": records, "folded": folded, "counts": counts}


def _cache_signature(root: Path, run: object | None) -> dict:
    with store._RUN_LOCKS_GUARD:
        run_keys = sorted(
            (relative, str(run_id))
            for project, run_id in store._RUN_LOCKS
            if (relative := _relative_cache_path(project, root)) is not None
        )
        project_keys = sorted(
            relative
            for project in store._PROJECT_LOCKS
            if (relative := _relative_cache_path(project, root)) is not None
        )
        active_types = sorted(
            (f"{type(key).__module__}.{type(key).__qualname__}",
             f"{type(value).__module__}.{type(value).__qualname__}")
            for key, value in store._ACQUISITION_ACTIVE.items()
        )
        managed_types = sorted(
            f"{type(value).__module__}.{type(value).__qualname__}"
            for value in store._LIVE_MANAGED_ACQUISITIONS.values()
        )
    projects, runs = store._thread_mutation_ledgers()
    thread_projects = sorted(
        relative
        for project in projects
        if (relative := _relative_cache_path(project, root)) is not None
    )
    thread_runs = sorted(
        (relative, str(run_id))
        for project, run_id in runs
        if (relative := _relative_cache_path(project, root)) is not None
    )
    application = _application_cache_shape(run)
    shape = {
        "run_keys": run_keys,
        "project_keys": project_keys,
        "active_types": active_types,
        "managed_types": managed_types,
        "thread_projects": thread_projects,
        "thread_runs": thread_runs,
        "application": application,
    }
    return {
        "digest": _records_digest(shape),
        "run_locks": len(run_keys),
        "project_locks": len(project_keys),
        "active_acquisitions": len(active_types),
        "live_managed_acquisitions": len(managed_types),
        "thread_projects": len(thread_projects),
        "thread_runs": len(thread_runs),
        "record_entities": len(application["records"]),
        "folded_entities": len(application["folded"]),
        "count_entities": len(application["counts"]),
    }


def _errno(value: object) -> int | None:
    number = getattr(value, "errno", None)
    return number if type(number) is int and 0 <= number <= MAX_INTEGER else None


def _exception_record(error: BaseException) -> dict:
    causes = []
    seen = {id(error)}
    current = error.__cause__ or error.__context__
    while current is not None and id(current) not in seen and len(causes) < 4:
        seen.add(id(current))
        causes.append({"class": _qualified(type(current)), "errno": _errno(current)})
        current = current.__cause__ or current.__context__
    try:
        message = str(error).encode("utf-8", "backslashreplace")
    except BaseException:  # pragma: no cover - production exceptions here have ordinary messages
        message = b"<unprintable>"
    return {
        "class": _qualified(type(error)),
        "errno": _errno(error),
        "message_digest": "sha256:" + hashlib.sha256(message).hexdigest(),
        "causes": causes,
    }


def _return_record(value: object) -> dict:
    if type(value) is str:
        normalized: object = value
    elif type(value) is tuple and all(type(item) is str for item in value):
        normalized = list(value)
    elif type(value) is Path:
        normalized = os.fspath(value)
    elif type(value) in {int, bool, type(None)}:
        normalized = value
    else:
        normalized = {"type": f"{type(value).__module__}.{type(value).__qualname__}"}
    return {
        "type": f"{type(value).__module__}.{type(value).__qualname__}",
        "digest": _records_digest(normalized),
    }


def _mutation_count(before: dict[str, dict], after: dict[str, dict]) -> int:
    names = set(before) | set(after)
    return sum(before.get(name) != after.get(name) for name in names)


def _collect_case(case: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="quarry-cpath-") as temporary:
        root = Path(temporary)
        operation = _operation(case, root)
        run = getattr(operation, "_path_identity_run", None)
        before_records = _tree_records(root)
        before_cache = _cache_signature(root, run)
        returned = None
        caught = None
        try:
            returned = operation()
        except BaseException as exc:  # the exact production refusal is evidence
            caught = exc
        after_cache = _cache_signature(root, run)
        after_records = _tree_records(root)
        actual = "accepted" if caught is None else "refused"
        return {
            "case_id": case["case_id"],
            "operation": case["operation"],
            "subject": case["subject"],
            "expected_disposition": case["expected_disposition"],
            "actual_disposition": actual,
            "exception": None if caught is None else _exception_record(caught),
            "return_value": _return_record(returned) if caught is None else None,
            "tree_before": _tree_summary(before_records),
            "tree_after": _tree_summary(after_records),
            "identity_before": _identity_summary(before_records),
            "identity_after": _identity_summary(after_records),
            "cache_before": before_cache,
            "cache_after": after_cache,
            "mutation_count": _mutation_count(before_records, after_records),
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp() -> str:
    value = _utc_now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise PathIdentityEvidenceError("path identity collection clock is not timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _digest(value: object, where: str) -> str:
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(char not in "0123456789abcdef" for char in value[7:])):
        raise PathIdentityEvidenceError(f"{where} is not a canonical sha256 digest")
    return value


def _verify_local_inputs(input_bodies: Mapping[str, bytes]) -> list[dict]:
    if (not isinstance(input_bodies, Mapping) or set(input_bodies) != set(INPUT_PATHS)
            or any(type(body) is not bytes for body in input_bodies.values())):
        raise PathIdentityEvidenceError("path identity inputs are not the exact bounded set")
    root = Path(__file__).resolve().parents[2]
    bindings = []
    for name, path in sorted(INPUT_PATHS.items()):
        body = input_bodies[name]
        if body != (root / path).read_bytes():
            raise PathIdentityEvidenceError(f"path identity input {name!r} is not the local bound source")
        bindings.append({
            "name": name,
            "path": path,
            "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        })
    read_property_corpus(input_bodies["path-identity-corpus"])
    return bindings


def build_containment_decisions(
    *, candidate_identity_digest: str, input_bodies: Mapping[str, bytes],
) -> dict:
    """Collect candidate-bound local decisions without claiming accepted H0 authority."""
    candidate = _digest(candidate_identity_digest, "candidate_identity_digest")
    bindings = _verify_local_inputs(input_bodies)
    started_at = _timestamp()
    decisions = [_collect_case(case) for case in PROPERTY_CASES]
    finished_at = _timestamp()
    corpus_body = input_bodies["path-identity-corpus"]
    document = {
        "schema_version": CONTAINMENT_DECISIONS_SCHEMA_VERSION,
        "artifact_type": "path-identity-containment-decisions",
        "release": "0.3.10",
        "gate_id": "C-PATH-IDENTITY",
        "name": "containment-decisions",
        "disposition": "source_substrate",
        "closure_status": "OPEN",
        "semantic_promotion": False,
        "candidate_identity_digest": candidate,
        "property_corpus_digest": "sha256:" + hashlib.sha256(corpus_body).hexdigest(),
        "input_bindings": bindings,
        "collection_interval": {"started_at": started_at, "finished_at": finished_at},
        "environment": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "os_name": os.name,
            "platform_system": platform.system(),
            "platform_machine": platform.machine() or "unknown",
            "platform_release": platform.release() or "unknown",
            "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        },
        "attestation": {
            "required_lane": "H0-hermetic",
            "collection_context": "local-unattested",
            "signed": False,
            "h0_isolated": False,
            "candidate_ownership_authenticated": False,
            "collection_interval_authenticated": False,
            "toolchain_authenticated": False,
        },
        "case_count": len(decisions),
        "cases": decisions,
    }
    return verify_containment_decisions(
        document, candidate_identity_digest=candidate, input_bodies=input_bodies,
    )


def _exact(value: object, fields: set[str], where: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise PathIdentityEvidenceError(f"{where} does not carry its exact fields")
    return value


def _integer(value: object, where: str, *, nullable: bool = False) -> int | None:
    if value is None and nullable:
        return None
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise PathIdentityEvidenceError(f"{where} is not a bounded non-negative integer")
    return value


def _text(value: object, where: str, *, limit: int = 4096) -> str:
    if type(value) is not str or not value:
        raise PathIdentityEvidenceError(f"{where} is not bounded non-empty text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PathIdentityEvidenceError(f"{where} is not bounded printable ASCII text") from exc
    if any(byte < 0x20 or byte > 0x7e for byte in encoded):
        raise PathIdentityEvidenceError(f"{where} is not bounded printable ASCII text")
    if len(encoded) > limit:
        raise PathIdentityEvidenceError(f"{where} is not bounded non-empty text")
    return value


def _time(value: object, where: str) -> datetime:
    if type(value) is not str or len(value) != 27 or not value.endswith("Z"):
        raise PathIdentityEvidenceError(f"{where} is not a microsecond UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PathIdentityEvidenceError(f"{where} is not a UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or _timestamp_text(parsed) != value:
        raise PathIdentityEvidenceError(f"{where} is not canonical UTC")
    return parsed


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _signature(value: object, where: str) -> dict:
    row = _exact(value, {"digest", "entries"}, where)
    _digest(row["digest"], f"{where}.digest")
    _integer(row["entries"], f"{where}.entries")
    return row


def _cache(value: object, where: str) -> dict:
    fields = {
        "digest", "run_locks", "project_locks", "active_acquisitions",
        "live_managed_acquisitions", "thread_projects", "thread_runs",
        "record_entities", "folded_entities", "count_entities",
    }
    row = _exact(value, fields, where)
    _digest(row["digest"], f"{where}.digest")
    for name in fields - {"digest"}:
        _integer(row[name], f"{where}.{name}")
    return row


def _verify_exception(value: object, where: str) -> dict:
    row = _exact(value, {"class", "errno", "message_digest", "causes"}, where)
    _text(row["class"], f"{where}.class", limit=512)
    _integer(row["errno"], f"{where}.errno", nullable=True)
    _digest(row["message_digest"], f"{where}.message_digest")
    if type(row["causes"]) is not list or len(row["causes"]) > 4:
        raise PathIdentityEvidenceError(f"{where}.causes is not a bounded array")
    for index, cause in enumerate(row["causes"]):
        item = _exact(cause, {"class", "errno"}, f"{where}.causes[{index}]")
        _text(item["class"], f"{where}.causes[{index}].class", limit=512)
        _integer(item["errno"], f"{where}.causes[{index}].errno", nullable=True)
    return row


def _verify_bindings(value: object, input_bodies: Mapping[str, bytes] | None) -> list[dict]:
    if type(value) is not list or len(value) != len(INPUT_PATHS):
        raise PathIdentityEvidenceError("path identity input bindings are incomplete")
    expected_pairs = list(sorted(INPUT_PATHS.items()))
    actual_pairs = []
    for index, binding in enumerate(value):
        row = _exact(binding, {"name", "path", "digest"}, f"input_bindings[{index}]")
        _digest(row["digest"], f"input_bindings[{index}].digest")
        actual_pairs.append((row["name"], row["path"]))
    if actual_pairs != expected_pairs:
        raise PathIdentityEvidenceError("path identity input bindings are reordered or drifted")
    if input_bodies is not None:
        expected = _verify_local_inputs(input_bodies)
        if value != expected:
            raise PathIdentityEvidenceError("path identity input binding digest drift")
    return value


def verify_containment_decisions(
    document: object,
    *,
    candidate_identity_digest: str | None = None,
    input_bodies: Mapping[str, bytes] | None = None,
) -> dict:
    """Validate exact corpus reconciliation while retaining the OPEN disposition."""
    fields = {
        "schema_version", "artifact_type", "release", "gate_id", "name", "disposition",
        "closure_status", "semantic_promotion", "candidate_identity_digest",
        "property_corpus_digest", "input_bindings", "collection_interval", "environment",
        "attestation", "case_count", "cases",
    }
    doc = _exact(document, fields, "path identity containment decisions")
    identity = (
        doc["schema_version"], doc["artifact_type"], doc["release"], doc["gate_id"], doc["name"],
        doc["disposition"], doc["closure_status"], doc["semantic_promotion"],
    )
    if identity != (
        CONTAINMENT_DECISIONS_SCHEMA_VERSION, "path-identity-containment-decisions", "0.3.10",
        "C-PATH-IDENTITY", "containment-decisions", "source_substrate", "OPEN", False,
    ):
        raise PathIdentityEvidenceError("path identity decisions claim an unsupported disposition")
    candidate = _digest(doc["candidate_identity_digest"], "candidate_identity_digest")
    if candidate_identity_digest is not None and candidate != candidate_identity_digest:
        raise PathIdentityEvidenceError("path identity decisions belong to another candidate")
    _digest(doc["property_corpus_digest"], "property_corpus_digest")
    _verify_bindings(doc["input_bindings"], input_bodies)
    if input_bodies is not None:
        corpus_digest = "sha256:" + hashlib.sha256(input_bodies["path-identity-corpus"]).hexdigest()
        if doc["property_corpus_digest"] != corpus_digest:
            raise PathIdentityEvidenceError("path identity decisions name another property corpus")

    interval = _exact(doc["collection_interval"], {"started_at", "finished_at"}, "collection_interval")
    started = _time(interval["started_at"], "collection_interval.started_at")
    finished = _time(interval["finished_at"], "collection_interval.finished_at")
    if finished < started:
        raise PathIdentityEvidenceError("path identity collection interval is reversed")

    environment = _exact(doc["environment"], {
        "python_implementation", "python_version", "os_name", "platform_system",
        "platform_machine", "platform_release", "effective_uid",
    }, "environment")
    for name in set(environment) - {"effective_uid"}:
        _text(environment[name], f"environment.{name}", limit=512)
    _integer(environment["effective_uid"], "environment.effective_uid", nullable=True)
    attestation = _exact(doc["attestation"], {
        "required_lane", "collection_context", "signed", "h0_isolated",
        "candidate_ownership_authenticated", "collection_interval_authenticated",
        "toolchain_authenticated",
    }, "attestation")
    if attestation != {
        "required_lane": "H0-hermetic",
        "collection_context": "local-unattested",
        "signed": False,
        "h0_isolated": False,
        "candidate_ownership_authenticated": False,
        "collection_interval_authenticated": False,
        "toolchain_authenticated": False,
    }:
        raise PathIdentityEvidenceError("local path decisions may not claim H0 attestation")

    if type(doc["cases"]) is not list or len(doc["cases"]) != CASE_COUNT:
        raise PathIdentityEvidenceError("path identity decisions have incomplete case cardinality")
    if doc["case_count"] != CASE_COUNT or type(doc["case_count"]) is not int:
        raise PathIdentityEvidenceError("path identity case count is not exact")
    case_fields = {
        "case_id", "operation", "subject", "expected_disposition", "actual_disposition",
        "exception", "return_value", "tree_before", "tree_after", "identity_before",
        "identity_after", "cache_before", "cache_after", "mutation_count",
    }
    for index, (value, expected) in enumerate(zip(doc["cases"], PROPERTY_CASES)):
        row = _exact(value, case_fields, f"cases[{index}]")
        for name in ("case_id", "operation", "subject", "expected_disposition"):
            if row[name] != expected[name]:
                raise PathIdentityEvidenceError(f"cases[{index}] does not reconcile with the property corpus")
        if row["actual_disposition"] != expected["expected_disposition"]:
            raise PathIdentityEvidenceError(f"cases[{index}] contradicts its expected disposition")
        before_tree = _signature(row["tree_before"], f"cases[{index}].tree_before")
        after_tree = _signature(row["tree_after"], f"cases[{index}].tree_after")
        before_identity = _signature(row["identity_before"], f"cases[{index}].identity_before")
        after_identity = _signature(row["identity_after"], f"cases[{index}].identity_after")
        before_cache = _cache(row["cache_before"], f"cases[{index}].cache_before")
        after_cache = _cache(row["cache_after"], f"cases[{index}].cache_after")
        if (before_tree != after_tree or before_identity != after_identity
                or before_cache != after_cache or row["mutation_count"] != 0):
            raise PathIdentityEvidenceError(f"cases[{index}] mutated repository or authority state")
        _integer(row["mutation_count"], f"cases[{index}].mutation_count")
        if expected["expected_disposition"] == "accepted":
            if row["exception"] is not None:
                raise PathIdentityEvidenceError(f"cases[{index}] accepted with an exception")
            returned = _exact(row["return_value"], {"type", "digest"}, f"cases[{index}].return_value")
            _text(returned["type"], f"cases[{index}].return_value.type", limit=512)
            _digest(returned["digest"], f"cases[{index}].return_value.digest")
        else:
            if row["return_value"] is not None:
                raise PathIdentityEvidenceError(f"cases[{index}] refused with a return value")
            exception = _verify_exception(row["exception"], f"cases[{index}].exception")
            if exception["class"] != expected["expected_exception"]:
                raise PathIdentityEvidenceError(f"cases[{index}] raised an unexpected exception class")
    return doc


def read_containment_decisions(
    body: bytes,
    *,
    candidate_identity_digest: str | None = None,
    input_bodies: Mapping[str, bytes] | None = None,
) -> dict:
    """Read one canonical local decision artifact and reconcile all bound inputs."""
    document = _parse(body, "path identity containment decisions")
    return verify_containment_decisions(
        document,
        candidate_identity_digest=candidate_identity_digest,
        input_bodies=input_bodies,
    )


def canonical_containment_decisions_bytes(
    document: object,
    *,
    candidate_identity_digest: str | None = None,
    input_bodies: Mapping[str, bytes] | None = None,
) -> bytes:
    """Serialize only a verified containment-decision document."""
    verified = verify_containment_decisions(
        document,
        candidate_identity_digest=candidate_identity_digest,
        input_bodies=input_bodies,
    )
    return _canonical_line(verified)
