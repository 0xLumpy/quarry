"""Strict, versioned truth contract for a committed Quarry run manifest.

The manifest is an authority boundary, not a convenient summary cache.  This
module owns its exact serialized shape, reconciles the verdict and structured
records, and binds every immutable base-evidence file by raw SHA-256.  Callers
either receive one fully validated :class:`RunManifest` or a typed refusal;
there is no partially trusted dictionary result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Iterable, NoReturn


SCHEMA_VERSION = "quarry.run-manifest.v1"
_DIGEST_PREFIX = "sha256:"
_TOP_LEVEL_REQUIRED = frozenset({
    "schema_version", "run_id", "target", "started", "finished", "profile",
    "phases_run", "tool_runs", "entity_counts", "notes", "summary", "envelope",
    "lifecycle", "base_files",
})
_TOP_LEVEL_OPTIONAL = frozenset({
    "envelope_remainder", "envelope_degraded", "metrics", "policy",
    "observability_degraded",
})
_SUMMARY_KEYS = frozenset({
    "verdict", "tool_status", "tools_failed", "failures", "gaps",
    "phase_exceptions", "coverage", "coverage_limits", "remainders", "faults",
    "provider_spend", "provider_limits", "operator_limits",
})
_TOOL_RUN_KEYS = frozenset({
    "phase", "tool", "status", "exit_code", "duration", "stdout_lines", "note",
    "cmd", "stderr_tail", "cpu_s", "peak_rss_mb", "depends_on",
})
_FAULT_KEYS = frozenset({"kind", "where", "detail", "challenges_completeness"})
_COVERAGE_KEYS = frozenset({
    "source_id", "measure", "eligible", "tested", "omitted", "reason", "valid",
    "by_kind", "units", "unknown",
})
_REMAINDER_KEYS = frozenset({
    "lane", "unit", "measure", "model", "retriable", "terminal", "detail",
})
_OUTCOME_KEYS = frozenset({
    "phase", "tool", "status", "kind", "why", "output_lines", "missing_tool",
    "measure", "eligible", "omitted", "omitted_fraction", "priority", "error_class",
    "origin",
})
_SPEND_KEYS = frozenset({"lane", "provider", "measure", "amount", "unknown"})
_LIFECYCLE_KEYS = frozenset({"state_at_commit", "generation"})
_STATE_KEYS = frozenset({
    "schema_version", "run_id", "stages", "state", "generation", "updated", "detail",
})
_STAGE_KEYS = frozenset({"generation", "status", "detail", "updated"})
_FILE_KEYS = frozenset({"path", "bytes", "rows", "digest", "media_type"})
_ENVELOPE_KEYS = frozenset({
    "version", "max_keys_per_entity", "rss_budget_mb", "max_bytes_per_key",
    "max_corpus_bytes_per_entity",
})
_TOOL_STATUSES = frozenset({
    "success", "empty", "partial", "failed", "timed_out", "blocked", "skipped", "limited",
})
_SUPPORTED_ENVELOPE = {
    "version": 3,
    "max_keys_per_entity": 100_000,
    "rss_budget_mb": 160,
    "max_bytes_per_key": 65_536,
    "max_corpus_bytes_per_entity": 32 * 1024 * 1024,
}
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
)
MAX_JSONL_LINE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER = (1 << 63) - 1
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_STRUCTURED_FILE_BYTES = 64 * 1024 * 1024
MAX_BASE_FILES = 100_000
MAX_BASE_TREE_DEPTH = 64
MAX_BASE_INVENTORY_BYTES = 4 * 1024 * 1024 * 1024

_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
              | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
_FILE_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
               | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))


class ManifestError(ValueError):
    """A manifest or one of the immutable files it claims cannot be trusted."""


@dataclass(frozen=True)
class RunManifest:
    """One validated v1 document and the exact raw bytes that carried it."""

    document: dict[str, Any]
    raw: bytes
    # The semantic fold is made while the manifest's run-directory descriptor
    # authority is held.  Keeping that exact snapshot lets strict downstream
    # projectors consume the bytes that were authenticated instead of reopening
    # mutable pathnames after verification (an ABA swap/restore would otherwise
    # be invisible to a final rehash).
    folded_by_entity: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def summary(self) -> dict[str, Any]:
        return self.document["summary"]

    @property
    def digest(self) -> str:
        return _DIGEST_PREFIX + hashlib.sha256(self.raw).hexdigest()


@dataclass(frozen=True)
class LegacyRunManifest:
    """Explicit compatibility view of a versionless pre-v1 commitment.

    It is never relabelled as v1 and is not eligible as release evidence.  The
    same immutable repository facts are nevertheless reopened and reconciled so
    existing 0.3.9 repositories do not become unreadable merely because they
    predate the lifecycle sidecar.
    """

    document: dict[str, Any]
    raw: bytes

    @property
    def summary(self) -> dict[str, Any]:
        return self.document["summary"]


def _fail(message: str) -> NoReturn:
    raise ManifestError(message)


def _exact_keys(value: Any, expected: Iterable[str], where: str) -> dict:
    if type(value) is not dict:
        _fail(f"{where} must be an object")
    expected_set = set(expected)
    if set(value) != expected_set:
        _fail(f"{where} keys must be exactly {sorted(expected_set)!r}")
    if not all(type(key) is str for key in value):
        _fail(f"{where} member names must be strings")
    return value


def _object_with_optional(value: Any, required: Iterable[str], optional: Iterable[str], where: str) -> dict:
    if type(value) is not dict:
        _fail(f"{where} must be an object")
    required_set, optional_set = set(required), set(optional)
    names = set(value)
    missing, extra = required_set - names, names - required_set - optional_set
    if missing or extra or not all(type(key) is str for key in value):
        _fail(f"{where} has missing keys {sorted(missing)!r} or extra keys {sorted(extra)!r}")
    return value


def _string(value: Any, where: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value.strip()):
        _fail(f"{where} must be an exact{' non-empty' if nonempty else ''} string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(f"{where} contains a non-Unicode scalar")
    return value


def _count(value: Any, where: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_JSON_INTEGER:
        _fail(f"{where} must be an exact non-negative integer")
    return value


def _number(value: Any, where: str) -> int | float:
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not 0 <= value <= MAX_JSON_INTEGER):
        _fail(f"{where} must be a finite non-negative number")
    return value


def _validate_status_exit(status_value: Any, exit_code: Any, where: str,
                          *, provider: bool = False) -> None:
    status_value = _string(status_value, f"{where}.status")
    if status_value not in _TOOL_STATUSES:
        _fail(f"{where}.status is unknown")
    if exit_code is not None and type(exit_code) is not int:
        _fail(f"{where}.exit_code must be an integer or null")


def _validate_projection_event(event: dict[str, Any], index: int) -> None:
    """Validate event fields that participate in the committed summary projection.

    The event log predates the strict manifest contract and contains additional
    diagnostic event shapes.  Those remain opaque here.  Fields that drive
    provider terminals or coverage arithmetic, however, may never be coerced,
    discarded, or defaulted from malformed persisted bytes: doing so can turn
    an unknown execution into a clean verdict.
    """
    from . import events

    where = f"events.jsonl row {index}"
    event_name = event.get("event")
    if event_name in {events.TOOL_START, events.TOOL_FINISH} and "provider" in event:
        if type(event["provider"]) is not bool:
            _fail(f"{where}.provider must be an exact boolean")
        if event["provider"] is True:
            _string(event.get("source_id"), f"{where}.source_id")
            work_unit = event.get("work_unit")
            if work_unit is not None:
                _string(work_unit, f"{where}.work_unit")
            if "reset_generation" in event and type(event["reset_generation"]) is not bool:
                _fail(f"{where}.reset_generation must be an exact boolean")
            if event_name == events.TOOL_FINISH:
                _validate_status_exit(
                    event.get("status"), event.get("exit_code"), where, provider=True,
                )

    if event_name == events.COVERAGE_RESET:
        _string(event.get("source_id"), f"{where}.source_id")
        return
    if event_name == "spend":
        for name in ("source_id", "provider", "measure"):
            _string(event.get(name), f"{where}.{name}")
        if "unit" in event:
            _string(event["unit"], f"{where}.unit")
        # An omitted or non-count amount is deliberately projected as
        # ``unknown=1`` rather than zero.  Identity fields, unlike the amount,
        # have no conservative projection and therefore must be exact here.
        return
    if event_name == "remainder":
        _string(event.get("source_id"), f"{where}.source_id")
        _string(event.get("unit"), f"{where}.unit")
        for name in ("measure", "model"):
            if name in event:
                # Semantically malformed remainder payloads are preserved as
                # explicit ``invalid`` records by the projector.  Only their
                # identity must be exact enough to keep that record durable.
                _string(event[name], f"{where}.{name}", nonempty=False)
        if "detail" in event and type(event["detail"]) is not dict:
            _fail(f"{where}.detail must be an object")
        return
    if event_name != events.COVERAGE_PARTIAL:
        return

    kind = event.get("kind")
    if ("tested" in event or "omitted" in event) and event.get("eligible") is None:
        _fail(f"{where} carries tested/omitted coverage without eligible")
    structured = event.get("eligible") is not None or kind == events.COVERAGE_UNKNOWN \
        or "coverage_valid" in event
    if not structured:
        return
    _string(event.get("source_id"), f"{where}.source_id")
    _string(event.get("unit"), f"{where}.unit")
    if "measure" in event:
        _string(event["measure"], f"{where}.measure")
    if "reason" in event:
        _string(event["reason"], f"{where}.reason", nonempty=False)
    known_kinds = {
        events.COVERAGE_SAMPLE,
        events.COVERAGE_PROVIDER,
        events.COVERAGE_CAP,
        events.COVERAGE_TIMEOUT,
        events.COVERAGE_TOOL_OMISSION,
        events.COVERAGE_OWNERSHIP,
        events.COVERAGE_UNKNOWN,
    }
    if kind is not None and kind not in known_kinds:
        _fail(f"{where}.kind is unknown")
    if type(event.get("coverage_valid")) is not bool:
        _fail(f"{where}.coverage_valid must be an exact boolean")
    if kind == events.COVERAGE_UNKNOWN:
        if event["coverage_valid"] is not False:
            _fail(f"{where}.coverage_valid contradicts unknown coverage")
        for name in ("eligible", "tested", "omitted"):
            if name in event:
                _count(event[name], f"{where}.{name}")
        return
    values = tuple(_count(event.get(name), f"{where}.{name}")
                   for name in ("eligible", "tested", "omitted"))
    eligible, tested, omitted = values
    valid = tested + omitted == eligible
    if event["coverage_valid"] is not valid:
        _fail(f"{where}.coverage_valid contradicts its counters")


def validate_state_document(
    value: Any,
    run_id: str,
    *,
    expected_generation: str | None = None,
    sealed_only: bool = False,
) -> dict[str, Any]:
    """Validate the one persisted run-lifecycle representation.

    Ordinary repository readers and committed-manifest reconciliation must not
    disagree about whether a state sidecar is meaningful. ``sealed_only`` is
    used by the manifest authority; live ``Run`` readers also accept the exact
    ``created`` and ``running`` representations written by the state machine.
    """
    document = _exact_keys(value, _STATE_KEYS, "state.json")
    if document["schema_version"] != 1:
        _fail("state.json does not have the supported lifecycle version")
    if document["run_id"] != run_id:
        _fail("state.json belongs to a different run")
    state = document["state"]
    allowed = {"created", "running", "finalizing", "finished", "finalization_failed"}
    if state not in allowed:
        _fail("state.json names an unknown lifecycle state")
    if sealed_only and state not in {"finalizing", "finished", "finalization_failed"}:
        _fail("state.json does not name a sealed lifecycle state")
    generation = document["generation"]
    if type(generation) is not str or re.fullmatch(r"[0-9a-f]{16}", generation) is None:
        _fail("state.json generation is not a canonical content generation")
    if expected_generation is not None and generation != expected_generation:
        _fail("manifest lifecycle generation contradicts state.json")
    _timestamp(document["updated"], "state.json.updated")
    if document["detail"] is not None:
        _string(document["detail"], "state.json.detail", nonempty=False)
    stages = document["stages"]
    if type(stages) is not dict:
        _fail("state.json.stages must be an object")
    if state in {"created", "running"} and stages:
        _fail(f"{state} state.json cannot contain finalization stages")
    failed_stages = 0
    for name, value in stages.items():
        _string(name, "state.json stage name")
        record = _exact_keys(value, _STAGE_KEYS, f"state.json.stages.{name}")
        if record["generation"] != generation:
            _fail(f"state.json.stages.{name}.generation is stale")
        if record["status"] not in {"done", "failed"}:
            _fail(f"state.json.stages.{name}.status is unknown")
        failed_stages += record["status"] == "failed"
        if record["detail"] is not None:
            _string(record["detail"], f"state.json.stages.{name}.detail", nonempty=False)
        _timestamp(record["updated"], f"state.json.stages.{name}.updated")
    if state == "finished" and failed_stages:
        _fail("finished state.json retains a failed finalization stage")
    if (state == "finalization_failed" and not failed_stages
            and not (type(document["detail"]) is str and document["detail"].strip())):
        _fail("finalization_failed state.json has no failed stage or failure detail")
    return document


def _list(value: Any, where: str) -> list:
    if type(value) is not list:
        _fail(f"{where} must be an array")
    return value


def _timestamp(value: Any, where: str) -> datetime:
    value = _string(value, where)
    if _RFC3339.fullmatch(value) is None:
        _fail(f"{where} is not an exact RFC3339 timestamp")
    zone = value[-6:] if value[-1] != "Z" else "+00:00"
    if int(zone[1:3]) > 23 or int(zone[4:6]) > 59:
        _fail(f"{where} has an invalid RFC3339 offset")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(f"{where} is not an RFC3339 timestamp")
    if moment.tzinfo is None:
        _fail(f"{where} must name an absolute instant")
    return moment


def _relative_path(value: Any, where: str) -> str:
    value = _string(value, where)
    path = PurePosixPath(value)
    if (value.startswith("/") or "\\" in value or path.is_absolute()
            or value != path.as_posix() or any(part in ("", ".", "..") for part in path.parts)):
        _fail(f"{where} must be a normalized repository-relative POSIX path")
    return value


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON member {key!r} is duplicated")
        result[key] = value
    return result


def _json_int(token: str) -> int:
    try:
        value = int(token)
    except ValueError as exc:
        raise ManifestError("JSON integer is invalid") from exc
    if not -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER:
        _fail("JSON integer is outside the portable v1 range")
    return value


def _json_float(token: str) -> float:
    try:
        value = float(token)
    except ValueError as exc:
        raise ManifestError("JSON number is invalid") from exc
    if not math.isfinite(value) or not -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER:
        _fail("JSON number is outside the portable v1 range")
    return value


def _parse_json(raw: bytes, where: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_json_pairs,
            parse_int=_json_int,
            parse_float=_json_float,
            parse_constant=lambda token: _fail(f"{where} contains non-finite number {token}"),
        )
    except ManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ManifestError(f"{where} is not strict UTF-8 JSON: {type(exc).__name__}: {exc}") from exc


def _validate_json_value(value: Any, where: str, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        _fail(f"{where} exceeds the JSON nesting bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER:
            _fail(f"{where} integer is outside the portable v1 range")
        return
    if type(value) is float:
        if not math.isfinite(value) or not -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER:
            _fail(f"{where} number is outside the portable v1 range")
        return
    if type(value) is str:
        _string(value, where, nonempty=False)
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_json_value(item, f"{where}[{index}]", depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail(f"{where} has a non-string member name")
            _string(key, f"{where} member name", nonempty=False)
            _validate_json_value(item, f"{where}.{key}", depth + 1)
        return
    _fail(f"{where} contains non-JSON value {type(value).__name__}")


def canonical_json_bytes(document: Any) -> bytes:
    """The exact v1 JSON encoding (one sorted UTF-8 line and one record delimiter)."""
    try:
        encoded = json.dumps(
            document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ManifestError(f"manifest cannot be encoded as canonical JSON: {type(exc).__name__}: {exc}") from exc
    return encoded + b"\n"


def _validate_fault(record: Any, where: str) -> None:
    from .state import ContractError, Fault

    if type(record) is not dict or not {"kind", "challenges_completeness"}.issubset(record) \
            or not set(record).issubset(_FAULT_KEYS):
        _fail(f"{where} is not an exact Fault record")
    _string(record["kind"], f"{where}.kind")
    if type(record["challenges_completeness"]) is not bool:
        _fail(f"{where}.challenges_completeness must be a boolean")
    for name in ("where", "detail"):
        if name in record and record[name] is not None:
            _string(record[name], f"{where}.{name}", nonempty=False)
    try:
        rebuilt = Fault.from_dict(record).to_dict()
    except (ContractError, TypeError, ValueError, KeyError) as exc:
        raise ManifestError(f"{where} is invalid: {exc}") from exc
    if rebuilt != record:
        _fail(f"{where} is not the canonical Fault serialization")


def _validate_coverage(record: Any, where: str) -> None:
    from .state import ContractError, Coverage

    _exact_keys(record, _COVERAGE_KEYS, where)
    _string(record["source_id"], f"{where}.source_id", nonempty=False)
    _string(record["measure"], f"{where}.measure", nonempty=False)
    for name in ("eligible", "tested", "omitted"):
        _count(record[name], f"{where}.{name}")
    if record["reason"] is not None:
        _string(record["reason"], f"{where}.reason", nonempty=False)
    if type(record["valid"]) is not bool:
        _fail(f"{where}.valid must be a boolean")
    if type(record["by_kind"]) is not dict:
        _fail(f"{where}.by_kind must be an object")
    for kind, counters in record["by_kind"].items():
        _string(kind, f"{where}.by_kind member")
        counters = _exact_keys(counters, {"eligible", "tested", "omitted"},
                               f"{where}.by_kind.{kind}")
        for name, value in counters.items():
            _count(value, f"{where}.by_kind.{kind}.{name}")
    for collection, required in (
        ("units", {"unit", "eligible", "tested", "omitted", "kind", "reason"}),
        ("unknown", {"unit", "kind", "reason"}),
    ):
        for index, item in enumerate(_list(record[collection], f"{where}.{collection}")):
            item = _exact_keys(item, required, f"{where}.{collection}[{index}]")
            _string(item["unit"], f"{where}.{collection}[{index}].unit", nonempty=False)
            _string(item["kind"], f"{where}.{collection}[{index}].kind")
            if item["reason"] is not None:
                _string(item["reason"], f"{where}.{collection}[{index}].reason", nonempty=False)
            for name in ("eligible", "tested", "omitted"):
                if name in item:
                    _count(item[name], f"{where}.{collection}[{index}].{name}")
    try:
        rebuilt = Coverage.from_dict(record).to_dict()
    except (AttributeError, ContractError, TypeError, ValueError, KeyError) as exc:
        raise ManifestError(f"{where} is invalid: {exc}") from exc
    if rebuilt != record:
        _fail(f"{where} is not the canonical Coverage serialization")


def _validate_remainder(record: Any, where: str) -> None:
    from .state import ContractError, parse_remainder

    if type(record) is dict and set(record) == {"lane", "unit", "invalid"}:
        _string(record["lane"], f"{where}.lane")
        _string(record["unit"], f"{where}.unit", nonempty=False)
        _string(record["invalid"], f"{where}.invalid")
        return
    _exact_keys(record, _REMAINDER_KEYS, where)
    try:
        rebuilt = parse_remainder(record).as_record()
    except (ContractError, TypeError, ValueError, KeyError) as exc:
        raise ManifestError(f"{where} is invalid: {exc}") from exc
    if rebuilt != record:
        _fail(f"{where} is not the canonical Remainder serialization")


def _validate_outcome(record: Any, where: str, *, spend: bool = False) -> None:
    allowed = _SPEND_KEYS if spend else _OUTCOME_KEYS
    if type(record) is not dict or not set(record).issubset(allowed):
        _fail(f"{where} contains unknown members")
    required = {"lane", "provider", "measure", "amount", "unknown"} if spend else {"phase", "tool", "why"}
    if not required.issubset(record):
        _fail(f"{where} is missing required members")
    for key, value in record.items():
        if key in {"output_lines", "eligible", "omitted", "amount", "unknown"}:
            _count(value, f"{where}.{key}")
        elif key == "omitted_fraction":
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
                _fail(f"{where}.omitted_fraction must be between zero and one")
        elif spend and key in {"lane", "provider", "measure"}:
            _string(value, f"{where}.{key}")
        elif key in {"phase", "tool"}:
            _string(value, f"{where}.{key}")
        elif key == "priority":
            if value not in {"major", "minor"}:
                _fail(f"{where}.priority is unknown")
        elif key == "origin":
            if value not in {"provider", "operator"}:
                _fail(f"{where}.origin is unknown")
        elif value is None and key not in {"measure", "why"}:
            _fail(f"{where}.{key} must not be null")
        elif value is not None:
            _string(value, f"{where}.{key}", nonempty=False)


def validate_summary(summary: Any) -> dict:
    """Validate and reconcile the exact canonical run summary."""
    summary = _exact_keys(summary, _SUMMARY_KEYS, "summary")
    if summary["verdict"] not in {"complete", "complete_with_limits", "complete_with_gaps"}:
        _fail("summary.verdict is unknown")
    status = summary["tool_status"]
    if type(status) is not dict or not all(type(k) is str and k and type(v) is int and v >= 0
                                           for k, v in status.items()):
        _fail("summary.tool_status must map non-empty strings to non-negative integers")
    failures = _list(summary["failures"], "summary.failures")
    gaps = _list(summary["gaps"], "summary.gaps")
    coverage_limits = _list(summary["coverage_limits"], "summary.coverage_limits")
    provider_limits = _list(summary["provider_limits"], "summary.provider_limits")
    operator_limits = _list(summary["operator_limits"], "summary.operator_limits")
    provider_spend = _list(summary["provider_spend"], "summary.provider_spend")
    for name, records in (("failures", failures), ("gaps", gaps),
                          ("coverage_limits", coverage_limits),
                          ("provider_limits", provider_limits),
                          ("operator_limits", operator_limits)):
        for index, record in enumerate(records):
            _validate_outcome(record, f"summary.{name}[{index}]")
    for index, record in enumerate(provider_spend):
        _validate_outcome(record, f"summary.provider_spend[{index}]", spend=True)
    if _count(summary["tools_failed"], "summary.tools_failed") != len(failures):
        _fail("summary.tools_failed does not equal the failure-record count")
    for index, value in enumerate(_list(summary["phase_exceptions"], "summary.phase_exceptions")):
        _string(value, f"summary.phase_exceptions[{index}]")
    for index, record in enumerate(_list(summary["coverage"], "summary.coverage")):
        _validate_coverage(record, f"summary.coverage[{index}]")
    remainders = _list(summary["remainders"], "summary.remainders")
    invalid_remainders = False
    for index, record in enumerate(remainders):
        _validate_remainder(record, f"summary.remainders[{index}]")
        invalid_remainders = invalid_remainders or set(record) == {"lane", "unit", "invalid"}
    if invalid_remainders and not gaps:
        _fail("summary carries an invalid remainder without a named gap")
    faults = _list(summary["faults"], "summary.faults")
    for index, record in enumerate(faults):
        _validate_fault(record, f"summary.faults[{index}]")
    challenged = any(record["challenges_completeness"] for record in faults)
    if failures or gaps or summary["phase_exceptions"] or challenged or invalid_remainders:
        derived = "complete_with_gaps"
    elif coverage_limits or provider_limits or operator_limits:
        derived = "complete_with_limits"
    else:
        derived = "complete"
    if summary["verdict"] != derived:
        _fail(f"summary.verdict {summary['verdict']!r} contradicts derived verdict {derived!r}")
    return summary


def validate_document(document: Any) -> dict:
    """Validate all manifest fields that are independent of repository bytes."""
    _validate_json_value(document, "manifest")
    document = _object_with_optional(document, _TOP_LEVEL_REQUIRED, _TOP_LEVEL_OPTIONAL, "manifest")
    if document["schema_version"] != SCHEMA_VERSION:
        _fail(f"manifest.schema_version must be {SCHEMA_VERSION!r}")
    _string(document["run_id"], "manifest.run_id")
    _string(document["target"], "manifest.target")
    from .repository_identity import validate_run_id
    from .store import validate_target
    try:
        validate_run_id(document["run_id"])
        validate_target(document["target"])
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"manifest identity is invalid: {exc}") from exc
    started = _timestamp(document["started"], "manifest.started")
    finished = _timestamp(document["finished"], "manifest.finished")
    if finished < started:
        _fail("manifest.finished precedes manifest.started")
    if type(document["profile"]) is not dict:
        _fail("manifest.profile must be an object")
    phases = _list(document["phases_run"], "manifest.phases_run")
    if any(type(value) is not str or not value for value in phases) or len(phases) != len(set(phases)):
        _fail("manifest.phases_run must contain unique non-empty strings")
    for index, record in enumerate(_list(document["tool_runs"], "manifest.tool_runs")):
        record = _exact_keys(record, _TOOL_RUN_KEYS, f"manifest.tool_runs[{index}]")
        for key in ("phase", "tool", "cmd"):
            _string(record[key], f"manifest.tool_runs[{index}].{key}")
        for key in ("note", "stderr_tail", "depends_on"):
            _string(record[key], f"manifest.tool_runs[{index}].{key}", nonempty=False)
        _validate_status_exit(
            record["status"], record["exit_code"], f"manifest.tool_runs[{index}]",
        )
        _number(record["duration"], f"manifest.tool_runs[{index}].duration")
        _number(record["cpu_s"], f"manifest.tool_runs[{index}].cpu_s")
        _number(record["peak_rss_mb"], f"manifest.tool_runs[{index}].peak_rss_mb")
        _count(record["stdout_lines"], f"manifest.tool_runs[{index}].stdout_lines")
    from .store import ENTITY_KEYS

    counts = document["entity_counts"]
    if type(counts) is not dict or not set(counts).issubset(ENTITY_KEYS):
        _fail("manifest.entity_counts contains an unknown entity")
    for entity, count in counts.items():
        _count(count, f"manifest.entity_counts.{entity}")
    for index, note in enumerate(_list(document["notes"], "manifest.notes")):
        _string(note, f"manifest.notes[{index}]", nonempty=False)
    validate_summary(document["summary"])
    envelope = _exact_keys(document["envelope"], _ENVELOPE_KEYS, "manifest.envelope")
    for name, value in envelope.items():
        _count(value, f"manifest.envelope.{name}")
    if envelope != _SUPPORTED_ENVELOPE:
        _fail("manifest.envelope does not equal the supported v3 declaration")
    lifecycle = _exact_keys(document["lifecycle"], _LIFECYCLE_KEYS, "manifest.lifecycle")
    if lifecycle["state_at_commit"] != "finalizing":
        _fail("manifest.lifecycle.state_at_commit must be 'finalizing'")
    generation = _string(lifecycle["generation"], "manifest.lifecycle.generation")
    if re.fullmatch(r"[0-9a-f]{16}", generation) is None:
        _fail("manifest.lifecycle.generation must be 16 lowercase hexadecimal characters")
    files = _list(document["base_files"], "manifest.base_files")
    paths: list[str] = []
    for index, record in enumerate(files):
        record = _exact_keys(record, _FILE_KEYS, f"manifest.base_files[{index}]")
        paths.append(_relative_path(record["path"], f"manifest.base_files[{index}].path"))
        _count(record["bytes"], f"manifest.base_files[{index}].bytes")
        if record["rows"] is not None:
            _count(record["rows"], f"manifest.base_files[{index}].rows")
        digest = _string(record["digest"], f"manifest.base_files[{index}].digest")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            _fail(f"manifest.base_files[{index}].digest is not sha256")
        _string(record["media_type"], f"manifest.base_files[{index}].media_type")
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")) or len(paths) != len(set(paths)):
        _fail("manifest.base_files paths must be strictly UTF-8 sorted and unique")
    for name in _TOP_LEVEL_OPTIONAL:
        if name not in document:
            continue
        value = document[name]
        if name == "policy":
            _list(value, f"manifest.{name}")
        elif name == "envelope_degraded":
            if type(value) is not dict or not value:
                _fail("manifest.envelope_degraded must be a non-empty object")
            for cause, detail in value.items():
                _string(cause, "manifest.envelope_degraded cause")
                detail = _string(detail, f"manifest.envelope_degraded.{cause}")
                if not detail.startswith("EXCEPTION:") or not detail.removeprefix("EXCEPTION:").strip():
                    _fail(f"manifest.envelope_degraded.{cause} is not an exception record")
        elif name == "observability_degraded":
            value = _exact_keys(
                value, {"writes_failed", "first_error"}, "manifest.observability_degraded",
            )
            if _count(value["writes_failed"], "manifest.observability_degraded.writes_failed") == 0:
                _fail("manifest.observability_degraded must name at least one failed write")
            _string(value["first_error"], "manifest.observability_degraded.first_error")
        elif type(value) is not dict:
            _fail(f"manifest.{name} must be an object")
    return document


def _stat_identity(observed: os.stat_result) -> tuple[int, ...]:
    return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_nlink,
            observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)


def _verify_private_directory(observed: os.stat_result, where: str) -> None:
    if not stat.S_ISDIR(observed.st_mode):
        _fail(f"{where} is not a directory")
    if observed.st_uid != os.geteuid():
        _fail(f"{where} is not owned by the current user")
    if stat.S_IMODE(observed.st_mode) != 0o700:
        _fail(f"{where} mode must be exactly 0700")


def _verify_private_file(observed: os.stat_result, where: str) -> None:
    if not stat.S_ISREG(observed.st_mode):
        _fail(f"{where} is not a regular file")
    if observed.st_uid != os.geteuid():
        _fail(f"{where} is not owned by the current user")
    if stat.S_IMODE(observed.st_mode) != 0o600:
        _fail(f"{where} mode must be exactly 0600")
    if observed.st_nlink != 1:
        _fail(f"{where} has an unexpected hard link")


@contextmanager
def _run_anchor(run_dir: Path):
    if not all((_DIR_FLAGS & getattr(os, name, 0)) for name in ("O_DIRECTORY", "O_NOFOLLOW")):
        _fail("descriptor-anchored manifest verification is unsupported on this platform")
    try:
        fd = os.open(run_dir, _DIR_FLAGS)
    except OSError as exc:
        raise ManifestError(f"run directory cannot be opened safely: {exc}") from exc
    primary: BaseException | None = None
    try:
        observed = os.fstat(fd)
        _verify_private_directory(observed, "run directory")
        yield fd, _stat_identity(observed)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(fd)
        except BaseException:
            if primary is None:
                raise


def _assert_anchor_name(run_dir: Path, identity: tuple[int, ...]) -> None:
    try:
        observed = os.stat(run_dir, follow_symlinks=False)
    except OSError as exc:
        raise ManifestError(f"run directory name changed during verification: {exc}") from exc
    _verify_private_directory(observed, "run directory")
    if _stat_identity(observed) != identity:
        _fail("run directory name was substituted during verification")


def _components(relative: str) -> tuple[str, ...]:
    normalized = _relative_path(relative, "managed run path")
    return tuple(PurePosixPath(normalized).parts)


def _open_directory_at(root_fd: int, components: tuple[str, ...], where: str) -> int:
    try:
        current = os.dup(root_fd)
        os.set_inheritable(current, False)
    except OSError as exc:
        raise ManifestError(f"{where} anchor cannot be duplicated: {exc}") from exc
    try:
        for component in components:
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=current)
            except OSError as exc:
                raise ManifestError(f"{where} cannot be opened safely: {exc}") from exc
            try:
                _verify_private_directory(os.fstat(child), where)
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        try:
            os.close(current)
        except BaseException:
            pass
        raise


def _open_file_at(root_fd: int, relative: str) -> int:
    components = _components(relative)
    parent = _open_directory_at(root_fd, components[:-1], f"parent of {relative}")
    fd = -1
    try:
        try:
            fd = os.open(components[-1], _FILE_FLAGS, dir_fd=parent)
        except OSError as exc:
            raise ManifestError(f"managed file {relative!r} cannot be opened safely: {exc}") from exc
        _verify_private_file(os.fstat(fd), f"managed file {relative!r}")
        return fd
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except BaseException:
                pass
        raise
    finally:
        os.close(parent)


def _path_kind_at(root_fd: int, relative: str) -> str | None:
    components = _components(relative)
    parent = _open_directory_at(root_fd, components[:-1], f"parent of {relative}")
    try:
        try:
            observed = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ManifestError(f"managed path {relative!r} cannot be inspected: {exc}") from exc
        if stat.S_ISREG(observed.st_mode):
            _verify_private_file(observed, f"managed path {relative!r}")
            return "file"
        if stat.S_ISDIR(observed.st_mode):
            _verify_private_directory(observed, f"managed path {relative!r}")
            return "directory"
        _fail(f"managed path {relative!r} has an unsafe object type")
    finally:
        os.close(parent)


def _descriptor_at(root_fd: int, relative: str) -> dict:
    fd = _open_file_at(root_fd, relative)
    primary: BaseException | None = None
    try:
        before = os.fstat(fd)
        digest = hashlib.sha256()
        total = 0
        structured_jsonl = (
            relative.startswith("normalized/")
            or relative.startswith("envelope-fold-refused/")
            or ("/" not in relative and relative.endswith(".jsonl"))
        )
        structured_json = (
            relative == "run.json"
            or ("/" not in relative and relative.endswith(".json"))
            or (relative.startswith("metrics/") and relative.endswith(".json"))
        )
        rows: int | None = 0 if structured_jsonl else None
        line = bytearray()
        structured_raw = bytearray()
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BASE_INVENTORY_BYTES:
                _fail(f"base evidence {relative} exceeds the inventory byte bound")
            digest.update(chunk)
            if structured_json:
                if total > MAX_STRUCTURED_FILE_BYTES:
                    _fail(f"base evidence {relative} exceeds the structured-file byte bound")
                structured_raw.extend(chunk)
            if rows is not None:
                for byte in chunk:
                    line.append(byte)
                    if len(line) > MAX_JSONL_LINE_BYTES:
                        _fail(f"base evidence {relative} has an oversized JSONL record")
                    if byte == 10:
                        if len(line) == 1:
                            _fail(f"base evidence {relative} has an empty JSONL record")
                        _parse_json(bytes(line[:-1]), f"base evidence {relative} row {rows + 1}")
                        rows += 1
                        line.clear()
        if rows is not None and line:
            _fail(f"base evidence {relative} is missing its final JSONL delimiter")
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after) or total != before.st_size:
            _fail(f"base evidence {relative} changed while it was hashed")
        if structured_json:
            _parse_json(bytes(structured_raw), f"base evidence {relative}")
        media = "application/x-ndjson" if structured_jsonl else (
            "application/json" if structured_json else "application/octet-stream"
        )
        return {"path": relative, "bytes": total, "rows": rows,
                "digest": _DIGEST_PREFIX + digest.hexdigest(), "media_type": media}
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(fd)
        except BaseException:
            if primary is None:
                raise


def _walk_directory_at(directory_fd: int, relative_root: str, *, depth: int,
                       found: list[str]) -> None:
    if depth > MAX_BASE_TREE_DEPTH:
        _fail("base evidence tree exceeds the directory-depth bound")
    try:
        names = os.listdir(directory_fd)
        names.sort(key=lambda name: name.encode("utf-8"))
    except (OSError, UnicodeEncodeError) as exc:
        raise ManifestError(f"base root {relative_root!r} cannot be enumerated: {exc}") from exc
    for name in names:
        _string(name, f"base entry below {relative_root!r}")
        if "/" in name or "\\" in name or name in {".", ".."}:
            _fail(f"base entry below {relative_root!r} is not a safe component")
        relative = f"{relative_root}/{name}"
        try:
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise ManifestError(f"base evidence {relative!r} cannot be inspected: {exc}") from exc
        if stat.S_ISDIR(observed.st_mode):
            _verify_private_directory(observed, f"base evidence directory {relative!r}")
            try:
                child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
            except OSError as exc:
                raise ManifestError(f"base evidence directory {relative!r} cannot be opened: {exc}") from exc
            try:
                _verify_private_directory(
                    os.fstat(child), f"base evidence directory {relative!r}",
                )
                _walk_directory_at(child, relative, depth=depth + 1, found=found)
            finally:
                os.close(child)
        elif stat.S_ISREG(observed.st_mode):
            _verify_private_file(observed, f"base evidence {relative!r}")
            found.append(relative)
            if len(found) > MAX_BASE_FILES:
                _fail("base evidence tree exceeds the file-count bound")
        else:
            _fail(f"base evidence {relative!r} is not a regular file")


def _build_file_inventory_at(root_fd: int) -> list[dict]:
    from .store import _BASE_ARTIFACT_DIRECTORY_ROOTS, _BASE_ARTIFACT_FILE_ROOTS

    found = ["run.json"]
    if _path_kind_at(root_fd, "run.json") != "file":
        _fail("run.json is absent")
    for relative in sorted(_BASE_ARTIFACT_FILE_ROOTS, key=lambda item: item.encode("utf-8")):
        kind = _path_kind_at(root_fd, relative)
        if kind is None:
            continue
        if kind != "file":
            _fail(f"base artifact file root {relative!r} is not a file")
        found.append(relative)
    for relative in sorted(_BASE_ARTIFACT_DIRECTORY_ROOTS, key=lambda item: item.encode("utf-8")):
        kind = _path_kind_at(root_fd, relative)
        if kind is None:
            continue
        if kind != "directory":
            _fail(f"base artifact directory root {relative!r} is not a directory")
        directory = _open_directory_at(root_fd, (relative,), f"base root {relative!r}")
        try:
            _walk_directory_at(directory, relative, depth=1, found=found)
        finally:
            os.close(directory)
    if len(found) != len(set(found)):
        _fail("base evidence inventory contains a duplicate path")
    found.sort(key=lambda item: item.encode("utf-8"))
    descriptors = [_descriptor_at(root_fd, relative) for relative in found]
    if sum(item["bytes"] for item in descriptors) > MAX_BASE_INVENTORY_BYTES:
        _fail("base evidence inventory exceeds the total-byte bound")
    return descriptors


def build_file_inventory(run_dir: Path) -> list[dict]:
    """Hash the exact immutable base-evidence set in canonical path order."""
    try:
        run_dir = Path(run_dir)
        with _run_anchor(run_dir) as (root_fd, identity):
            result = _build_file_inventory_at(root_fd)
            _assert_anchor_name(run_dir, identity)
            return result
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"base evidence cannot be inventoried: {type(exc).__name__}: {exc}") from exc


def _read_file_at(root_fd: int, relative: str, byte_limit: int = MAX_MANIFEST_BYTES) -> bytes:
    fd = _open_file_at(root_fd, relative)
    primary: BaseException | None = None
    try:
        before = os.fstat(fd)
        if before.st_size > byte_limit:
            _fail(f"managed file {relative!r} exceeds {byte_limit} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(fd, min(1024 * 1024, byte_limit + 1 - total))
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > byte_limit:
                _fail(f"managed file {relative!r} exceeds {byte_limit} bytes")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns):
            _fail(f"managed file {relative!r} changed while it was read")
        return b"".join(chunks)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(fd)
        except BaseException:
            if primary is None:
                raise


def _claimed_descriptor(document: dict, relative: str) -> dict:
    claimed = {item["path"]: item for item in document["base_files"]}.get(relative)
    if claimed is None:
        _fail(f"manifest.base_files omits semantic input {relative!r}")
    return claimed


def _assert_raw_descriptor(document: dict, relative: str, raw: bytes) -> None:
    claimed = _claimed_descriptor(document, relative)
    rows = raw.count(b"\n") if claimed["media_type"] == "application/x-ndjson" else None
    observed = {
        "path": relative,
        "bytes": len(raw),
        "rows": rows,
        "digest": _DIGEST_PREFIX + hashlib.sha256(raw).hexdigest(),
        "media_type": claimed["media_type"],
    }
    if observed != claimed:
        _fail(f"semantic input {relative!r} does not match manifest.base_files")


class _MemoryEventPath:
    def __init__(self, raw: bytes | None) -> None:
        self.raw = raw

    def exists(self) -> bool:
        return self.raw is not None

    def read_bytes(self) -> bytes:
        if self.raw is None:
            raise FileNotFoundError("events.jsonl")
        return self.raw

    def read_text(self, *, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self.read_bytes().decode(encoding, errors)


class _MemoryRunDirectory:
    def __init__(self, events_raw: bytes | None) -> None:
        self.events_raw = events_raw

    def __truediv__(self, name: str) -> _MemoryEventPath:
        if name != "events.jsonl":
            raise ManifestError(f"authenticated projector requested unexpected path {name!r}")
        return _MemoryEventPath(self.events_raw)


def _fold_entities_at(root_fd: int, document: dict) -> dict[str, Any]:
    from .store import ENTITY_KEYS, _fold_observation_stream

    normalized_kind = _path_kind_at(root_fd, "normalized")
    if normalized_kind is None:
        return {}
    if normalized_kind != "directory":
        _fail("normalized evidence root is not a directory")
    directory = _open_directory_at(root_fd, ("normalized",), "normalized evidence")
    try:
        try:
            names = os.listdir(directory)
            names.sort(key=lambda name: name.encode("utf-8"))
        except (OSError, UnicodeEncodeError) as exc:
            raise ManifestError(f"normalized evidence cannot be enumerated: {exc}") from exc
    finally:
        os.close(directory)
    allowed = {f"{entity}.jsonl" for entity in ENTITY_KEYS}
    if not set(names).issubset(allowed):
        _fail("normalized evidence contains an unknown entity log")
    folded_by_entity: dict[str, Any] = {}
    for name in names:
        entity = name[:-6]
        relative = f"normalized/{name}"
        fd = _open_file_at(root_fd, relative)
        primary: BaseException | None = None
        try:
            before = os.fstat(fd)
            digest = hashlib.sha256()
            pending = bytearray()
            rows = 0
            total = 0

            def authenticated_lines():
                nonlocal rows, total
                while True:
                    try:
                        chunk = os.read(fd, 1024 * 1024)
                    except InterruptedError:
                        continue
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BASE_INVENTORY_BYTES:
                        _fail(f"base evidence {relative} exceeds the inventory byte bound")
                    digest.update(chunk)
                    pending.extend(chunk)
                    while True:
                        newline = pending.find(b"\n")
                        if newline < 0:
                            break
                        line = bytes(pending[:newline + 1])
                        del pending[:newline + 1]
                        if len(line) == 1:
                            _fail(f"base evidence {relative} has an empty JSONL record")
                        if len(line) > MAX_JSONL_LINE_BYTES:
                            _fail(f"base evidence {relative} has an oversized JSONL record")
                        _parse_json(line[:-1], f"base evidence {relative} row {rows + 1}")
                        rows += 1
                        yield line
                    if len(pending) > MAX_JSONL_LINE_BYTES:
                        _fail(f"base evidence {relative} has an oversized JSONL record")
                if pending:
                    _fail(f"base evidence {relative} is missing its final JSONL delimiter")

            folded = _fold_observation_stream(
                authenticated_lines(), entity,
                max_keys=document["envelope"]["max_keys_per_entity"],
                max_bytes_per_key=document["envelope"]["max_bytes_per_key"],
                max_corpus_bytes=document["envelope"]["max_corpus_bytes_per_entity"],
                on_refused=lambda _key, _kind: None,
                require_newline=True,
            )
            after = os.fstat(fd)
            if _stat_identity(before) != _stat_identity(after) or total != before.st_size:
                _fail(f"base evidence {relative} changed while it was folded")
            observed = {
                "path": relative,
                "bytes": total,
                "rows": rows,
                "digest": _DIGEST_PREFIX + digest.hexdigest(),
                "media_type": "application/x-ndjson",
            }
            if observed != _claimed_descriptor(document, relative):
                _fail(f"normalized entity log {name!r} changed before semantic folding")
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                os.close(fd)
            except BaseException:
                if primary is None:
                    raise
        if folded.status in {"absent", "unusable"}:
            _fail(f"normalized entity log {name!r} cannot be folded")
        folded_by_entity[entity] = folded
    return folded_by_entity


def _generation(document: dict, folded_by_entity: dict[str, Any]) -> str:
    from .store import fingerprint

    digest = hashlib.sha256(document["run_id"].encode("utf-8"))
    for entity in sorted(folded_by_entity):
        records = folded_by_entity[entity].records
        digest.update(f"\n{entity}:{len(records)}".encode("utf-8"))
        for key in sorted(records):
            digest.update(f"\n{key}={fingerprint(entity, records[key])}".encode("utf-8"))
    return digest.hexdigest()[:16]


def _contains_all(actual: list, required: list) -> bool:
    remaining = list(actual)
    for record in required:
        try:
            remaining.remove(record)
        except ValueError:
            return False
    return True


def _reconcile_summary_projection(
    document: dict,
    folded_by_entity: dict[str, Any],
    events_raw: bytes | None,
) -> None:
    """Recompute every durable projection available after reopening the run.

    Explicit in-process Fault/Gap objects are persisted only by the manifest, so
    those two arrays may contain conservative additional records.  Every fact
    derivable from immutable logs must nevertheless be present, and all other
    projections are exact.
    """
    from .store import ENTITY_KEYS, FoldedLog, Run

    try:
        projection = object.__new__(Run)
        projection.dir = _MemoryRunDirectory(events_raw)
        projection.notes = list(document["notes"])
        projection._faults = []
        projection._gaps = []
        projection._verdict_sealed = False
        projection._sealed_summary = None
        projection._folded = {
            entity: folded_by_entity.get(entity, FoldedLog(status="absent"))
            for entity in ENTITY_KEYS
        }
        projection._records = {
            entity: folded.records for entity, folded in projection._folded.items()
        }
        projection.tool_runs = lambda phase=None: [
            record for record in (
                SimpleNamespace(**item) for item in document["tool_runs"]
            ) if phase is None or record.phase == phase
        ]
        projection.envelope_remainder = lambda: document.get("envelope_remainder")
        expected = Run._run_summary(projection)
    except Exception as exc:
        raise ManifestError(f"manifest summary cannot be recomputed: {type(exc).__name__}: {exc}") from exc
    actual = document["summary"]
    exact = (
        "tool_status", "tools_failed", "failures", "coverage", "coverage_limits",
        "remainders", "provider_spend", "provider_limits", "operator_limits",
    )
    for name in exact:
        if actual[name] != expected[name]:
            _fail(f"summary.{name} does not reconcile with immutable run evidence")
    phase_exceptions = [note for note in document["notes"] if "EXCEPTION" in note]
    if actual["phase_exceptions"] != phase_exceptions:
        _fail("summary.phase_exceptions does not reconcile with manifest.notes")
    for name in ("gaps", "faults"):
        if not _contains_all(actual[name], expected[name]):
            _fail(f"summary.{name} omits a fact derived from immutable run evidence")


def _reconcile_repository(
    document: dict,
    root_fd: int,
    *,
    verify_lifecycle: bool,
    state_raw: bytes | None = None,
    folded_by_entity: dict[str, Any] | None = None,
) -> None:
    identity_raw = _read_file_at(root_fd, "run.json")
    _assert_raw_descriptor(document, "run.json", identity_raw)
    identity = _parse_json(identity_raw, "run.json")
    if type(identity) is not dict or any(identity.get(key) != document[key]
                                         for key in ("run_id", "target", "started")):
        _fail("manifest identity contradicts run.json")
    if _path_kind_at(root_fd, "tool-runs.jsonl") is not None:
        raw_tool_ledger = _read_file_at(root_fd, "tool-runs.jsonl", MAX_STRUCTURED_FILE_BYTES)
        _assert_raw_descriptor(document, "tool-runs.jsonl", raw_tool_ledger)
        if raw_tool_ledger and not raw_tool_ledger.endswith(b"\n"):
            _fail("tool-runs.jsonl is torn")
        tool_rows = [
            _parse_json(line, f"tool-runs.jsonl row {index}")
            for index, line in enumerate(raw_tool_ledger.splitlines(), 1)
        ]
    else:
        tool_rows = []
    if document["tool_runs"] != tool_rows:
        _fail("manifest.tool_runs does not reconcile with tool-runs.jsonl")
    if _path_kind_at(root_fd, "events.jsonl") is not None:
        events_raw = _read_file_at(root_fd, "events.jsonl", MAX_STRUCTURED_FILE_BYTES)
        _assert_raw_descriptor(document, "events.jsonl", events_raw)
        if events_raw and not events_raw.endswith(b"\n"):
            _fail("events.jsonl is torn")
        for index, line in enumerate(events_raw.splitlines(), 1):
            event = _parse_json(line, f"events.jsonl row {index}")
            if type(event) is not dict:
                _fail(f"events.jsonl row {index} is not an object")
            _validate_projection_event(event, index)
    else:
        events_raw = None
    for manifest_key, filename in (
        ("envelope_remainder", "envelope-remainder.json"),
        ("envelope_degraded", "envelope-degraded.json"),
    ):
        bound_kind = _path_kind_at(root_fd, filename)
        if bound_kind is not None:
            if bound_kind != "file":
                _fail(f"{filename} is not a regular file")
            if manifest_key not in document:
                _fail(f"manifest omits present {filename}")
            observed_raw = _read_file_at(root_fd, filename)
            _assert_raw_descriptor(document, filename, observed_raw)
            observed_bound = _parse_json(observed_raw, filename)
            marker_stub = (
                manifest_key == "envelope_remainder"
                and observed_bound == {**document["envelope"], "overflow": True}
            )
            degraded_marker = (
                manifest_key == "envelope_degraded"
                and type(observed_bound) is dict
                and set(observed_bound) == {"degraded"}
                and document[manifest_key] == observed_bound["degraded"]
            )
            if document[manifest_key] != observed_bound and not marker_stub and not degraded_marker:
                _fail(f"manifest.{manifest_key} does not reconcile with {filename}")
            if manifest_key == "envelope_degraded":
                missing_notes = [detail for detail in document[manifest_key].values()
                                 if detail not in document["notes"]]
                if missing_notes:
                    _fail("manifest.envelope_degraded is not surfaced in manifest.notes")
        elif manifest_key in document:
            _fail(f"manifest.{manifest_key} names an absent {filename}")
    if _path_kind_at(root_fd, "events.degraded.json") is not None:
        degraded_raw = _read_file_at(root_fd, "events.degraded.json")
        _assert_raw_descriptor(document, "events.degraded.json", degraded_raw)
        degraded = _parse_json(degraded_raw, "events.degraded.json")
        if (type(degraded) is not dict
                or set(degraded) != {"writes_failed", "first_error"}
                or type(degraded["writes_failed"]) is not int
                or degraded["writes_failed"] < 0
                or (degraded["writes_failed"] == 0 and degraded["first_error"] is not None)
                or (degraded["writes_failed"] > 0
                    and (type(degraded["first_error"]) is not str
                         or not degraded["first_error"].strip()))):
            _fail("events.degraded.json has an invalid degradation record")
        active = degraded["writes_failed"] > 0
        if active and document.get("observability_degraded") != degraded:
            _fail("manifest.observability_degraded does not reconcile with events.degraded.json")
        if active:
            required_fault = {
                "kind": "machinery",
                "where": "events.jsonl",
                "detail": (f"{degraded['writes_failed']} event write(s) failed: "
                           f"{degraded['first_error']}"),
                "challenges_completeness": True,
            }
            if required_fault not in document["summary"]["faults"]:
                _fail("events.degraded.json is not surfaced as a completeness-challenging fault")
        if not active and "observability_degraded" in document:
            _fail("manifest claims observability degradation absent from events.degraded.json")
    elif "observability_degraded" in document:
        _fail("manifest.observability_degraded names an absent events.degraded.json")
    if folded_by_entity is None:
        folded_by_entity = _fold_entities_at(root_fd, document)
    observed_counts = {entity: len(folded.records)
                       for entity, folded in folded_by_entity.items()}
    if document["entity_counts"] != observed_counts:
        _fail("manifest.entity_counts does not reconcile with normalized evidence")
    if document["lifecycle"]["generation"] != _generation(document, folded_by_entity):
        _fail("manifest lifecycle generation does not reconcile with normalized evidence")
    _reconcile_summary_projection(document, folded_by_entity, events_raw)
    if not verify_lifecycle:
        return
    if _path_kind_at(root_fd, "state.json") != "file":
        _fail("state.json is absent or unsafe")
    if state_raw is None:
        state_raw = _read_file_at(root_fd, "state.json")
    state_document = _parse_json(state_raw, "state.json")
    validate_state_document(
        state_document,
        document["run_id"],
        expected_generation=document["lifecycle"]["generation"],
        sealed_only=True,
    )


def read(path: Path, *, verify_lifecycle: bool = True) -> RunManifest:
    """Open, strictly validate, and repository-reconcile one v1 manifest."""
    try:
        path = Path(path)
        if path.name != "manifest.json":
            _fail("the committed run-manifest name must be manifest.json")
        run_dir = path.parent
        with _run_anchor(run_dir) as (root_fd, identity):
            raw = _read_file_at(root_fd, "manifest.json")
            document = validate_document(_parse_json(raw, "manifest"))
            if raw != canonical_json_bytes(document):
                _fail("manifest bytes are not the canonical v1 encoding")
            if document["base_files"] != _build_file_inventory_at(root_fd):
                _fail("manifest.base_files does not match the immutable base evidence")
            state_raw = _read_file_at(root_fd, "state.json") if verify_lifecycle else None
            folded_by_entity = _fold_entities_at(root_fd, document)
            _reconcile_repository(
                document,
                root_fd,
                verify_lifecycle=verify_lifecycle,
                state_raw=state_raw,
                folded_by_entity=folded_by_entity,
            )
            if document["base_files"] != _build_file_inventory_at(root_fd):
                _fail("base evidence changed during manifest verification")
            if _read_file_at(root_fd, "manifest.json") != raw:
                _fail("manifest.json changed during verification")
            if state_raw is not None and _read_file_at(root_fd, "state.json") != state_raw:
                _fail("state.json changed during verification")
            _assert_anchor_name(run_dir, identity)
            return RunManifest(
                document=document,
                raw=raw,
                folded_by_entity=folded_by_entity,
            )
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"manifest cannot be verified: {type(exc).__name__}: {exc}") from exc


def validate_prepared_document(run_dir: Path, document: dict) -> None:
    """Authenticate a writer's complete candidate before manifest publication."""
    run_dir = Path(run_dir)
    document = validate_document(document)
    raw = canonical_json_bytes(document)
    if len(raw) > MAX_MANIFEST_BYTES:
        _fail(f"prepared manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    with _run_anchor(run_dir) as (root_fd, identity):
        if document["base_files"] != _build_file_inventory_at(root_fd):
            _fail("prepared manifest.base_files does not match immutable base evidence")
        _reconcile_repository(document, root_fd, verify_lifecycle=False)
        if document["base_files"] != _build_file_inventory_at(root_fd):
            _fail("base evidence changed during prepared-manifest validation")
        _assert_anchor_name(run_dir, identity)


def read_legacy(path: Path) -> LegacyRunManifest:
    """Read a versionless manifest only for the documented no-state legacy path."""
    try:
        path = Path(path)
        if path.name != "manifest.json":
            _fail("the legacy run-manifest name must be manifest.json")
        run_dir = path.parent
        if os.path.lexists(run_dir / "state.json"):
            _fail("a manifest with lifecycle state is not a legacy commitment")
        with _run_anchor(run_dir) as (root_fd, identity):
            raw = _read_file_at(root_fd, "manifest.json")
            legacy = _parse_json(raw, "legacy manifest")
            required = _TOP_LEVEL_REQUIRED - {"schema_version", "lifecycle", "base_files"}
            legacy = _object_with_optional(
                legacy, required, _TOP_LEVEL_OPTIONAL, "legacy manifest",
            )
            if "schema_version" in legacy:
                _fail("a schema-versioned manifest is not legacy")
            if legacy.get("envelope") != _SUPPORTED_ENVELOPE:
                _fail("legacy manifest envelope is not the supported v3 declaration")
            synthetic = dict(legacy)
            synthetic["schema_version"] = SCHEMA_VERSION
            synthetic["base_files"] = _build_file_inventory_at(root_fd)
            folded = _fold_entities_at(root_fd, synthetic)
            synthetic["lifecycle"] = {
                "state_at_commit": "finalizing",
                "generation": _generation(synthetic, folded),
            }
            validate_document(synthetic)
            _reconcile_repository(
                synthetic,
                root_fd,
                verify_lifecycle=False,
                folded_by_entity=folded,
            )
            if synthetic["base_files"] != _build_file_inventory_at(root_fd):
                _fail("legacy base evidence changed during verification")
            if _read_file_at(root_fd, "manifest.json") != raw:
                _fail("legacy manifest.json changed during verification")
            if _path_kind_at(root_fd, "state.json") is not None:
                _fail("legacy lifecycle state appeared during verification")
            _assert_anchor_name(run_dir, identity)
            return LegacyRunManifest(document=legacy, raw=raw)
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"legacy manifest cannot be verified: {type(exc).__name__}: {exc}") from exc


def committed(path: Path, *, verify_lifecycle: bool = True) -> bool:
    """Boolean compatibility predicate backed only by the strict v1 reader."""
    try:
        read(path, verify_lifecycle=verify_lifecycle)
    except (ManifestError, OSError):
        return False
    return True


def legacy_committed(path: Path) -> bool:
    """Whether the exact no-state, versionless compatibility contract is met."""
    try:
        read_legacy(path)
    except (ManifestError, OSError):
        return False
    return True
