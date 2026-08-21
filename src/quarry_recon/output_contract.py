"""Bounded, non-promoting C-OUTPUT-CONTRACT source substrate.

Only the in-process producer consumes runner-sealed repository testimony.  A
serialized raw receipt is deliberately a *shape-only diagnostic*: it has no
authenticated envelope or resolver and must never be treated as evidence or
an accepting release input.  The native Gitleaks rows remain explicitly open
until a pinned, attested fixture execution proves their claimed semantics.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path

from . import release_evidence as evidence
from . import privfs, runner, store


FIXTURE_MANIFEST_SCHEMA = "quarry.c-output-fixture-manifest.v2"
RAW_RECEIPT_SCHEMA = "quarry.c-output-raw-receipt.v2"
CASE_MATRIX_SCHEMA = "quarry.c-output-case-matrix.v2"
TOOL_ATTESTATION_SCHEMA = "quarry.c-output-tool-attestation.v1"
MAX_RECEIPT_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_STREAM_BYTES = 16 * 1024 * 1024
RETAINED_STREAM_CAP_BYTES = 16
SERIALIZED_RECEIPT_DISPOSITION = "unauthenticated-shape-only"
SERIALIZED_RECEIPT_CLAIM = "non-evidence-diagnostic"
SOURCE_SUBSTRATE_DISPOSITION = "source_substrate"
SOURCE_SUBSTRATE_OBSERVATION = "open-native-gitleaks-rows-unavailable"
CASES = (
    "empty", "non_empty", "malformed", "truncated", "non_utf8", "partial",
    "timeout", "signal", "tool_specific_exit",
)
HELPER_CASES = frozenset({
    "empty", "malformed", "truncated", "non_utf8", "partial", "timeout", "signal",
})
GITLEAKS_CASES = frozenset({"non_empty", "tool_specific_exit"})
_HEX = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_UTC_ZERO_OFFSET = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$",
)
_VERSION = re.compile(r"(?:^|\s)(?:gitleaks\s+)?v?(\d+\.\d+\.\d+)(?:\s|$)", re.I)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
FROZEN_FIXTURE_MANIFEST_DIGEST = "sha256:7fce7f2864eaf6cba7e6393de0811b2bcb9b2ccf5ebee5ef6348c0834d738302"
FROZEN_FIXTURE_MANIFEST_INPUT = "c-output-fixture-manifest"
FROZEN_FIXTURE_MANIFEST_PATH = "release/evidence/c-output-fixture-manifest-v2.json"
FROZEN_FIXTURE_MANIFEST_RAW_SHA256 = "a352eb99a3449b0eba36132b1342cce517d8cb4686685f2cbbe942d3411e4821"

_EXPECTED = {
    "empty": {
        "effective_status": "empty", "execution_terminal": "complete", "exit": "zero",
        "native": "none", "parser": {"complete": True, "outcome": "empty", "records": 0},
        "repository_publication": "published", "stderr_terminal": "eof", "stdout_terminal": "eof",
    },
    "non_empty": {
        "effective_status": "unavailable", "execution_terminal": "not_started", "exit": "none",
        "native": "unavailable", "parser": {"complete": False, "outcome": "unavailable", "records": None},
        "repository_publication": "not_requested", "stderr_terminal": "not_started", "stdout_terminal": "not_started",
    },
    "malformed": {
        "effective_status": "partial", "execution_terminal": "complete", "exit": "zero",
        "native": "none", "parser": {"complete": False, "outcome": "malformed", "records": None},
        "repository_publication": "published", "stderr_terminal": "eof", "stdout_terminal": "eof",
    },
    "truncated": {
        "effective_status": "partial", "execution_terminal": "complete", "exit": "zero",
        "native": "none", "parser": {"complete": False, "outcome": "unavailable", "records": None},
        "repository_publication": "fenced", "stderr_terminal": "eof", "stdout_terminal": "capped",
    },
    "non_utf8": {
        "effective_status": "partial", "execution_terminal": "complete", "exit": "zero",
        "native": "none", "parser": {"complete": False, "outcome": "non_utf8", "records": None},
        "repository_publication": "published", "stderr_terminal": "eof", "stdout_terminal": "eof",
    },
    "partial": {
        "effective_status": "partial", "execution_terminal": "complete", "exit": "zero",
        "native": "none", "parser": {"complete": True, "outcome": "empty", "records": 0},
        "repository_publication": "published", "stderr_terminal": "eof", "stdout_terminal": "eof",
    },
    "timeout": {
        "effective_status": "timed_out", "execution_terminal": "timed_out", "exit": "none",
        "native": "none", "parser": {"complete": False, "outcome": "unavailable", "records": None},
        "repository_publication": "fenced", "stderr_terminal": "deadline", "stdout_terminal": "deadline",
    },
    "signal": {
        "effective_status": "failed", "execution_terminal": "complete", "exit": "negative",
        "native": "none", "parser": {"complete": False, "outcome": "unavailable", "records": None},
        "repository_publication": "published", "stderr_terminal": "eof", "stdout_terminal": "eof",
    },
    "tool_specific_exit": {
        "effective_status": "unavailable", "execution_terminal": "not_started", "exit": "none",
        "native": "unavailable", "parser": {"complete": False, "outcome": "unavailable", "records": None},
        "repository_publication": "not_requested", "stderr_terminal": "not_started", "stdout_terminal": "not_started",
    },
}


class OutputContractError(ValueError):
    """C-OUTPUT source evidence is malformed, unbound, or semantically false."""


def _object(value: object, name: str, members: set[str]) -> dict:
    if type(value) is not dict or set(value) != members:
        raise OutputContractError(f"{name} must have exactly {sorted(members)!r}")
    return value


def _array(value: object, name: str, *, maximum: int) -> list:
    if type(value) is not list or len(value) > maximum:
        raise OutputContractError(f"{name} must be a bounded array")
    return value


def _text(value: object, name: str, *, maximum: int = 4096, nonempty: bool = True) -> str:
    if (type(value) is not str or len(value) > maximum or (nonempty and not value)
            or any(ord(char) < 0x20 for char in value)):
        raise OutputContractError(f"{name} must be a bounded control-free string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise OutputContractError(f"{name} is not valid UTF-8") from exc
    return value


def _count(value: object, name: str, *, maximum: int = MAX_STREAM_BYTES) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise OutputContractError(f"{name} must be a bounded non-negative integer")
    return value


def _bare_digest(value: object, name: str) -> str:
    value = _text(value, name, maximum=64)
    if _HEX.fullmatch(value) is None:
        raise OutputContractError(f"{name} must be a bare SHA-256 hex digest")
    return value


def _evidence_digest(value: object, name: str) -> str:
    value = _text(value, name, maximum=71)
    if not value.startswith("sha256:") or _HEX.fullmatch(value[7:]) is None:
        raise OutputContractError(f"{name} must be a sha256: evidence digest")
    return value


def _diagnostic_digest(value: object, name: str) -> str:
    value = _text(value, name, maximum=71)
    if not value.startswith("sha256:") or _HEX.fullmatch(value[7:]) is None:
        raise OutputContractError(f"{name} must be a sha256 shape-diagnostic digest")
    return value


def _timestamp(value: object, name: str) -> str:
    value = _text(value, name, maximum=32)
    if _RFC3339.fullmatch(value) is None:
        raise OutputContractError(f"{name} must be canonical UTC RFC3339 with Z")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OutputContractError(f"{name} must be a real RFC3339 timestamp") from exc
    return value


def _canonical_utc_timestamp(value: object, name: str) -> str:
    """Normalize the repository's exact UTC ``+00:00`` clock form to ``Z``."""
    value = _text(value, name, maximum=32)
    if _UTC_ZERO_OFFSET.fullmatch(value) is None:
        raise OutputContractError(f"{name} must be UTC (+00:00 or Z), never an offset alias")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OutputContractError(f"{name} must be a real UTC timestamp") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise OutputContractError(f"{name} is not UTC")
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z").replace(".000000Z", "Z")


def _timestamp_value(value: str) -> datetime:
    """Return an already-validated canonical UTC timestamp for ordering checks."""
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _safe_relative(value: object, name: str) -> str:
    value = _text(value, name, maximum=512)
    path = Path(value)
    if ("\\" in value or path.is_absolute() or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)):
        raise OutputContractError(f"{name} is not a safe relative path")
    return value


def _component(value: object, name: str) -> str:
    value = _text(value, name, maximum=255)
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise OutputContractError(f"{name} is not a safe artifact component")
    return value


def _canonical_digest(document: object) -> str:
    return evidence.canonical_digest(document)


def _bounded(document: object, name: str, maximum: int = MAX_RECEIPT_BYTES) -> None:
    if len(evidence.canonical_json_bytes(document)) > maximum:
        raise OutputContractError(f"{name} exceeds its canonical byte bound")


def _fixture(value: object, name: str) -> dict:
    item = _object(value, name, {
        "bytes", "candidate_input", "encoding", "path", "sha256",
        "source_bytes", "source_sha256",
    })
    if _TOKEN.fullmatch(_text(item["candidate_input"], f"{name}.candidate_input", maximum=128)) is None:
        raise OutputContractError(f"{name}.candidate_input is invalid")
    _safe_relative(item["path"], f"{name}.path")
    if item["encoding"] not in {"raw", "hex"}:
        raise OutputContractError(f"{name}.encoding is unsupported")
    _count(item["bytes"], f"{name}.bytes")
    _bare_digest(item["sha256"], f"{name}.sha256")
    _count(item["source_bytes"], f"{name}.source_bytes")
    _bare_digest(item["source_sha256"], f"{name}.source_sha256")
    if item["encoding"] == "raw" and (
            item["bytes"] != item["source_bytes"] or item["sha256"] != item["source_sha256"]):
        raise OutputContractError(f"{name}.raw fixture source and payload disagree")
    return item


def _expected(value: object, name: str) -> dict:
    item = _object(value, name, {
        "effective_status", "execution_terminal", "exit", "native", "parser",
        "repository_publication", "stderr_terminal", "stdout_terminal",
    })
    if item["effective_status"] not in {
            "success", "empty", "partial", "failed", "timed_out", "unavailable"}:
        raise OutputContractError(f"{name}.effective_status is invalid")
    if item["execution_terminal"] not in {"complete", "timed_out", "not_started"}:
        raise OutputContractError(f"{name}.execution_terminal is invalid")
    if item["exit"] not in {"zero", "one", "negative", "none"}:
        raise OutputContractError(f"{name}.exit is invalid")
    if item["native"] not in {"none", "committed", "unavailable"}:
        raise OutputContractError(f"{name}.native is invalid")
    if item["repository_publication"] not in {"published", "fenced", "not_requested"}:
        raise OutputContractError(f"{name}.repository_publication is invalid")
    if item["stdout_terminal"] not in {"eof", "capped", "deadline", "not_started"}:
        raise OutputContractError(f"{name}.stdout_terminal is invalid")
    if item["stderr_terminal"] not in {"eof", "deadline", "not_started"}:
        raise OutputContractError(f"{name}.stderr_terminal is invalid")
    parser = _object(item["parser"], f"{name}.parser", {"complete", "outcome", "records"})
    if parser["outcome"] not in {
            "empty", "non_empty", "malformed", "truncated", "non_utf8", "unavailable"}:
        raise OutputContractError(f"{name}.parser.outcome is invalid")
    if (type(parser["complete"]) is not bool
            or (parser["records"] is not None and type(parser["records"]) is not int)
            or (type(parser["records"]) is int and not 0 <= parser["records"] <= MAX_STREAM_BYTES)):
        raise OutputContractError(f"{name}.parser fact is invalid")
    unavailable = item["effective_status"] == "unavailable"
    if unavailable != (item["execution_terminal"] == "not_started"):
        raise OutputContractError(f"{name} unavailable terminal coupling is invalid")
    if unavailable and not (
            item["exit"] == "none" and item["native"] == "unavailable"
            and item["repository_publication"] == "not_requested"
            and item["stdout_terminal"] == item["stderr_terminal"] == "not_started"
            and parser == {"complete": False, "outcome": "unavailable", "records": None}):
        raise OutputContractError(f"{name} unavailable facts are not explicit")
    return item


def validate_fixture_manifest(document: object) -> dict:
    """Validate the frozen real-fixture inventory without accepting a run."""
    doc = _object(document, "fixture manifest", {
        "cases", "disposition", "helper", "retained_stream_cap_bytes", "schema_version",
    })
    if doc["schema_version"] != FIXTURE_MANIFEST_SCHEMA:
        raise OutputContractError("fixture manifest schema version is unsupported")
    if doc["disposition"] != SOURCE_SUBSTRATE_DISPOSITION:
        raise OutputContractError("fixture manifest is not explicitly source substrate")
    if doc["retained_stream_cap_bytes"] != RETAINED_STREAM_CAP_BYTES:
        raise OutputContractError("fixture manifest does not freeze the retained stream cap")
    helper = _object(doc["helper"], "fixture manifest.helper", {"candidate_input", "path", "sha256"})
    if helper["candidate_input"] != "c-output-python-helper":
        raise OutputContractError("fixture helper candidate input is not frozen")
    _safe_relative(helper["path"], "fixture manifest.helper.path")
    _bare_digest(helper["sha256"], "fixture manifest.helper.sha256")
    cases = _array(doc["cases"], "fixture manifest.cases", maximum=len(CASES))
    if len(cases) != len(CASES):
        raise OutputContractError("fixture manifest must enumerate exactly nine cases")
    ids = []
    for index, value in enumerate(cases):
        item = _object(value, f"fixture manifest.cases[{index}]", {
            "availability", "executor", "expected", "fixture", "id", "stderr",
        })
        case_id = _text(item["id"], f"fixture manifest.cases[{index}].id", maximum=32)
        if case_id not in CASES:
            raise OutputContractError("fixture manifest has an unknown case")
        if item["executor"] not in {"candidate-python-helper", "gitleaks"}:
            raise OutputContractError("fixture case executor is unsupported")
        if ((case_id in HELPER_CASES) != (item["executor"] == "candidate-python-helper")
                or (case_id in GITLEAKS_CASES) != (item["executor"] == "gitleaks")):
            raise OutputContractError("fixture case executor does not match its frozen case")
        expected_availability = (
            "measured-helper" if case_id in HELPER_CASES else "unavailable-source-substrate"
        )
        if item["availability"] != expected_availability:
            raise OutputContractError("fixture case availability does not match the source contract")
        if case_id in {"timeout", "signal"}:
            if item["fixture"] is not None:
                raise OutputContractError("terminal helper case must not admit a payload fixture")
        elif item["fixture"] is None:
            raise OutputContractError("fixture case lacks a frozen payload fixture")
        else:
            _fixture(item["fixture"], f"fixture manifest.cases[{index}].fixture")
            if case_id in GITLEAKS_CASES and item["fixture"]["encoding"] != "raw":
                raise OutputContractError("gitleaks fixture must be a raw candidate file")
        if case_id == "partial":
            if item["stderr"] is None:
                raise OutputContractError("partial case lacks a frozen stderr fixture")
            _fixture(item["stderr"], f"fixture manifest.cases[{index}].stderr")
        elif item["stderr"] is not None:
            raise OutputContractError("only partial may emit frozen stderr")
        if _expected(item["expected"], f"fixture manifest.cases[{index}].expected") != _EXPECTED[case_id]:
            raise OutputContractError("fixture expected facts drifted from the fixed contract")
        ids.append(case_id)
    if tuple(ids) != CASES:
        raise OutputContractError("fixture case order is not the frozen nine-case order")
    _bounded(doc, "fixture manifest", MAX_MANIFEST_BYTES)
    if _canonical_digest(doc) != FROZEN_FIXTURE_MANIFEST_DIGEST:
        raise OutputContractError("fixture manifest is not the frozen real-fixture inventory")
    return doc


def fixture_identity_inputs(fixture_manifest: object) -> dict[str, str]:
    """Return every candidate-identity input needed to run the frozen fixtures."""
    manifest = validate_fixture_manifest(fixture_manifest)
    values = {
        FROZEN_FIXTURE_MANIFEST_INPUT: FROZEN_FIXTURE_MANIFEST_PATH,
        manifest["helper"]["candidate_input"]: manifest["helper"]["path"],
    }
    for case in manifest["cases"]:
        for field in ("fixture", "stderr"):
            spec = case[field]
            if spec is None:
                continue
            previous = values.setdefault(spec["candidate_input"], spec["path"])
            if previous != spec["path"]:
                raise OutputContractError("fixture input name maps to more than one path")
    return dict(sorted(values.items()))


def _case(manifest: dict, case_id: str) -> dict:
    try:
        return next(item for item in manifest["cases"] if item["id"] == case_id)
    except StopIteration as exc:
        raise OutputContractError("case is absent from the frozen fixture manifest") from exc


def _candidate_binding(candidate_identity: object) -> dict:
    try:
        return evidence.candidate_summary(candidate_identity)
    except (TypeError, ValueError) as exc:
        raise OutputContractError("candidate identity is not valid release evidence") from exc


def _candidate_document(candidate_identity: object) -> dict:
    try:
        return evidence.validate_candidate_identity(candidate_identity)
    except (TypeError, ValueError) as exc:
        raise OutputContractError("candidate identity is not valid release evidence") from exc


def _run_binding(run: store.Run) -> dict:
    if type(run) is not store.Run:
        raise OutputContractError("receipt producer requires an exact repository Run")
    identity = store.read_run_identity(run.project_dir, run.run_id)
    if (type(identity) is not dict or identity.get("run_id") != run.run_id
            or identity.get("target") != run.target or identity.get("started") != run.started):
        raise OutputContractError("Run owner identity does not reconcile")
    device, inode = run._run_directory_identity
    if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
        raise OutputContractError("Run has no stable directory owner identity")
    return {
        "run_id": run.run_id,
        "target": run.target,
        "started_at": _canonical_utc_timestamp(run.started, "Run.started"),
        "directory_device": device,
        "directory_inode": inode,
    }


def _sealed_testimony(result: runner.RunResult, run: store.Run) -> dict:
    try:
        return runner.repository_execution_testimony(result, repository=run)
    except (TypeError, ValueError) as exc:
        raise OutputContractError("receipt producer refuses unsealed repository testimony") from exc


def _runtime_file(value: object, name: str) -> dict:
    item = _object(value, name, {"bytes", "mode", "path", "role", "sha256"})
    _count(item["bytes"], f"{name}.bytes", maximum=(1 << 63) - 1)
    _count(item["mode"], f"{name}.mode", maximum=0o777)
    _text(item["path"], f"{name}.path", maximum=4096)
    _text(item["role"], f"{name}.role", maximum=128)
    _bare_digest(item["sha256"], f"{name}.sha256")
    return item


def _runtime_closure(value: object, name: str) -> dict | None:
    if value is None:
        return None
    item = _object(value, name, {"bytes", "objects", "sha256"})
    _count(item["bytes"], f"{name}.bytes", maximum=(1 << 63) - 1)
    _count(item["objects"], f"{name}.objects", maximum=(1 << 31) - 1)
    _bare_digest(item["sha256"], f"{name}.sha256")
    return item


def _runtime_identity_row(value: object, name: str) -> dict:
    """Validate the typed, closed identity rows emitted by PreparedLaunch."""
    if type(value) is not dict:
        raise OutputContractError(f"{name} is not an identity object")
    host = {"attestation", "closure", "executable", "identity", "role", "runtime", "runtime_root"}
    managed = host | {"declared_identity", "receipt"}
    browser = host - {"attestation"}
    keys = set(value)
    if keys == host:
        if value["attestation"] != "host-digest" or value["closure"] is not None:
            raise OutputContractError(f"{name} host identity is invalid")
    elif keys == managed:
        if value["attestation"] != "managed-receipt":
            raise OutputContractError(f"{name} managed identity is invalid")
        _runtime_closure(value["closure"], f"{name}.closure")
        receipt = _object(value["receipt"], f"{name}.receipt", {"bytes", "path", "sha256"})
        _count(receipt["bytes"], f"{name}.receipt.bytes", maximum=(1 << 63) - 1)
        _text(receipt["path"], f"{name}.receipt.path", maximum=4096)
        _bare_digest(receipt["sha256"], f"{name}.receipt.sha256")
        _text(value["declared_identity"], f"{name}.declared_identity", maximum=512)
    elif keys == browser:
        _runtime_closure(value["closure"], f"{name}.closure")
    else:
        raise OutputContractError(f"{name} has unknown identity fields")
    if value["role"] not in {
            "adapter", "dependency", "browser", "interpreter", "shebang-interpreter"}:
        raise OutputContractError(f"{name}.role is invalid")
    executable = _runtime_file(value["executable"], f"{name}.executable")
    if executable["role"] not in {"executable", "browser"}:
        raise OutputContractError(f"{name}.executable.role is invalid")
    identity = _text(value["identity"], f"{name}.identity", maximum=512)
    if not (identity.startswith("sha256:") or identity.startswith("distro@sha256:")):
        raise OutputContractError(f"{name}.identity is invalid")
    _text(value["runtime"], f"{name}.runtime", maximum=128)
    _text(value["runtime_root"], f"{name}.runtime_root", maximum=4096)
    return value


def _runtime_identity_record(value: object, name: str) -> dict:
    item = _object(value, name, {
        "argv_items", "credential_environment_keys", "dynamic_closure", "environment_keys",
        "identities", "launch_anchors", "payload_anchors", "private_inputs", "schema_version",
        "selected_executable", "tool",
    })
    if item["schema_version"] != "quarry.runtime-launch.v1":
        raise OutputContractError(f"{name}.schema_version is invalid")
    _text(item["tool"], f"{name}.tool", maximum=128)
    if type(item["argv_items"]) is not int or not 1 <= item["argv_items"] <= 64:
        raise OutputContractError(f"{name}.argv_items is invalid")
    for field in ("environment_keys", "credential_environment_keys"):
        values = _array(item[field], f"{name}.{field}", maximum=128)
        if values != sorted(set(values)):
            raise OutputContractError(f"{name}.{field} is not canonical")
        for index, entry in enumerate(values):
            _text(entry, f"{name}.{field}[{index}]", maximum=128)
    identities = _array(item["identities"], f"{name}.identities", maximum=64)
    if not identities:
        raise OutputContractError(f"{name}.identities is empty")
    for index, identity in enumerate(identities):
        _runtime_identity_row(identity, f"{name}.identities[{index}]")
    selected = _runtime_file(item["selected_executable"], f"{name}.selected_executable")
    if selected["role"] != "selected-executable":
        raise OutputContractError(f"{name}.selected_executable role drifted")
    anchors = _array(item["launch_anchors"], f"{name}.launch_anchors", maximum=64)
    for index, anchor in enumerate(anchors):
        anchor = _object(anchor, f"{name}.launch_anchors[{index}]", {
            "bytes", "mode", "path", "role", "sha256", "source_path",
        })
        _count(anchor["bytes"], f"{name}.launch_anchors[{index}].bytes", maximum=(1 << 63) - 1)
        _count(anchor["mode"], f"{name}.launch_anchors[{index}].mode", maximum=0o777)
        _text(anchor["path"], f"{name}.launch_anchors[{index}].path", maximum=4096)
        _text(anchor["source_path"], f"{name}.launch_anchors[{index}].source_path", maximum=4096)
        _text(anchor["role"], f"{name}.launch_anchors[{index}].role", maximum=128)
        _bare_digest(anchor["sha256"], f"{name}.launch_anchors[{index}].sha256")
    # These collections have heterogeneous rows owned by runtime_identity;
    # their top-level presence stays closed while the C-OUTPUT helper admits none.
    for field in ("payload_anchors", "private_inputs", "dynamic_closure"):
        _array(item[field], f"{name}.{field}", maximum=64)
    return item


def _runtime_launch(testimony: Mapping[str, object]) -> dict:
    required = {
        "runtime_identity", "runtime_identity_ref", "runtime_source_argv",
        "runtime_source_argv_indexes",
    }
    if not required.issubset(testimony):
        raise OutputContractError("receipt producer refuses a non-repository-backed result")
    record = _runtime_identity_record(testimony["runtime_identity"], "runtime identity")
    source_argv = _array(testimony["runtime_source_argv"], "runtime source argv", maximum=64)
    if not source_argv:
        raise OutputContractError("result source argv is not the admitted argv")
    for index, item in enumerate(source_argv):
        _text(item, f"runtime source argv[{index}]", maximum=4096)
    indexes = _array(testimony["runtime_source_argv_indexes"], "runtime source argv indexes", maximum=64)
    if (len(indexes) != len(source_argv) or indexes[0] != 0
            or any(type(item) is not int or item < 0 for item in indexes)
            or indexes != sorted(set(indexes)) or indexes[-1] >= record["argv_items"]):
        raise OutputContractError("result source-to-runtime argv mapping is invalid")
    ref = _safe_relative(testimony["runtime_identity_ref"], "runtime identity reference")
    return {
        "runtime_identity": record,
        "runtime_identity_digest": _canonical_digest(record),
        "runtime_identity_ref": ref,
        "source_argv": list(source_argv),
        "source_argv_indexes": list(indexes),
    }


def _stream(value: object, name: str) -> dict:
    item = _object(value, name, {
        "claim_id", "detail", "lines", "observed_bytes", "observed_sha256",
        "retained_bytes", "retained_sha256", "role", "terminal",
    })
    if item["role"] not in {"stdin", "stdout", "stderr"}:
        raise OutputContractError(f"{name}.role is invalid")
    if item["terminal"] not in {
            "not_started", "complete", "eof", "peer_closed", "cancelled", "deadline",
            "source_error", "sink_error", "capped", "worker_crash",
    }:
        raise OutputContractError(f"{name}.terminal is invalid")
    for field in ("lines", "observed_bytes", "retained_bytes"):
        _count(item[field], f"{name}.{field}")
    if item["retained_bytes"] > item["observed_bytes"]:
        raise OutputContractError(f"{name} retains more bytes than it observed")
    for field in ("observed_sha256", "retained_sha256"):
        if item[field] is not None:
            _bare_digest(item[field], f"{name}.{field}")
    if item["terminal"] == "not_started":
        if any(item[field] not in {0, None} for field in (
                "lines", "observed_bytes", "retained_bytes", "observed_sha256",
                "retained_sha256", "claim_id",
        )):
            raise OutputContractError(f"{name} has activity before start")
    elif item["observed_sha256"] is None:
        raise OutputContractError(f"{name} lacks its observed digest")
    if item["claim_id"] is None:
        if item["retained_bytes"] != 0 or item["retained_sha256"] is not None:
            raise OutputContractError(f"{name} retained bytes without a claim identifier")
    else:
        _text(item["claim_id"], f"{name}.claim_id", maximum=128)
        if item["retained_sha256"] is None:
            raise OutputContractError(f"{name} lacks its retained digest")
    if item["detail"] is not None:
        _text(item["detail"], f"{name}.detail", maximum=256)
    if item["role"] in {"stdout", "stderr"} and item["terminal"] == "eof":
        if (item["retained_bytes"] != item["observed_bytes"]
                or item["retained_sha256"] != item["observed_sha256"]):
            raise OutputContractError(f"{name} EOF retention does not equal the observed stream")
    if item["role"] in {"stdout", "stderr"} and item["terminal"] == "capped":
        if (item["observed_bytes"] <= RETAINED_STREAM_CAP_BYTES
                or item["retained_bytes"] != RETAINED_STREAM_CAP_BYTES
                or item["retained_sha256"] is None):
            raise OutputContractError(f"{name} capped retention does not match the frozen cap")
    return item


def _execution_document(value: object, name: str) -> tuple[dict, list[dict]]:
    settlement = _object(value, name, {
        "detail", "exit_code", "launched", "process_group_settled",
        "process_tree_settled", "request_id", "streams", "terminal", "tool_pid",
        "worker_pid",
    })
    if _REQUEST_ID.fullmatch(_text(settlement["request_id"], f"{name}.request_id", maximum=32)) is None:
        raise OutputContractError(f"{name}.request_id is invalid")
    if settlement["terminal"] not in {
            "complete", "timed_out", "launch_failed", "worker_failed", "cancelled"}:
        raise OutputContractError(f"{name}.terminal is invalid")
    if type(settlement["launched"]) is not bool:
        raise OutputContractError(f"{name}.launched is invalid")
    if settlement["exit_code"] is not None and (
            type(settlement["exit_code"]) is not int
            or not -(1 << 31) <= settlement["exit_code"] <= (1 << 31) - 1):
        raise OutputContractError(f"{name}.exit_code is invalid")
    for field in ("process_group_settled", "process_tree_settled"):
        if type(settlement[field]) is not bool:
            raise OutputContractError(f"{name}.{field} is invalid")
    if settlement["process_group_settled"] is not True:
        raise OutputContractError(f"{name} process group is not settled")
    for field in ("worker_pid", "tool_pid"):
        if settlement[field] is not None:
            _count(settlement[field], f"{name}.{field}", maximum=(1 << 31) - 1)
            if settlement[field] == 0:
                raise OutputContractError(f"{name}.{field} is invalid")
    if settlement["launched"] != (settlement["tool_pid"] is not None):
        raise OutputContractError(f"{name} launch identity disagrees")
    if settlement["terminal"] == "complete" and settlement["exit_code"] is None:
        raise OutputContractError(f"{name} complete execution lacks exit code")
    if settlement["detail"] is not None:
        _text(settlement["detail"], f"{name}.detail", maximum=256)
    records = _array(settlement["streams"], f"{name}.streams", maximum=3)
    if len(records) != 3:
        raise OutputContractError(f"{name} must have exactly three streams")
    streams = [_stream(item, f"{name}.streams[{index}]") for index, item in enumerate(records)]
    if [item["role"] for item in streams] != ["stdin", "stdout", "stderr"]:
        raise OutputContractError(f"{name} stream order is not canonical")
    return settlement, streams


def _settlement(testimony: Mapping[str, object]) -> tuple[dict, list[dict], str]:
    required = {
        "execution_settlement", "execution_request_id", "execution_terminal",
        "process_group_settled", "process_tree_settled", "streams",
        "repository_ownership_settled", "repository_publication",
    }
    if not required.issubset(testimony):
        raise OutputContractError("result lacks authenticated repository settlement")
    settlement, streams = _execution_document(testimony["execution_settlement"], "execution settlement")
    if (settlement["request_id"] != testimony["execution_request_id"]
            or settlement["terminal"] != testimony["execution_terminal"]
            or settlement["process_group_settled"] != testimony["process_group_settled"]
            or settlement["process_tree_settled"] != testimony["process_tree_settled"]):
        raise OutputContractError("flattened execution testimony disagrees with settlement")
    if testimony["repository_ownership_settled"] is not True:
        raise OutputContractError("repository ownership is not settled")
    publication = testimony["repository_publication"]
    if publication not in {"published", "fenced", "not_requested"}:
        raise OutputContractError("repository publication is not terminal")
    projected = testimony["streams"]
    if type(projected) is not dict or [projected.get(role) for role in ("stdin", "stdout", "stderr")] != streams:
        raise OutputContractError("stream projection disagrees with authenticated settlement")
    return settlement, streams, publication


def _native_outputs(testimony: Mapping[str, object], *, require_current_paths: bool = False) -> dict:
    native = testimony.get("native_outputs")
    if type(native) is not dict:
        raise OutputContractError("native output record is missing")
    required = {
        "clean", "policy_count", "committed", "uncertain", "unpublished",
        "cleanup_settled", "claim_retained", "fault_operation", "fault_type",
    }
    allowed = required | {"current_paths"}
    if set(native) != (allowed if require_current_paths else required):
        raise OutputContractError("native receipt has unknown or absent fields")
    if type(native["clean"]) is not bool or native["cleanup_settled"] is not True:
        raise OutputContractError("native receipt cleanup is not settled")
    if native["claim_retained"] is not False:
        raise OutputContractError("native receipt retains a live claim")
    if native["fault_operation"] is not None:
        _text(native["fault_operation"], "native receipt.fault_operation", maximum=128)
    if native["fault_type"] is not None:
        _text(native["fault_type"], "native receipt.fault_type", maximum=128)
    if require_current_paths:
        paths = _array(native["current_paths"], "native receipt.current_paths", maximum=64)
        if any(type(path) is not str or not os.path.isabs(path) for path in paths):
            raise OutputContractError("native receipt current paths are invalid")
    _count(native["policy_count"], "native receipt.policy_count", maximum=64)
    facts = []
    for group in ("committed", "uncertain", "unpublished"):
        records = _array(native[group], f"native receipt.{group}", maximum=64)
        for index, value in enumerate(records):
            item = _object(value, f"native receipt.{group}[{index}]", {
                "components", "kind", "policy_index", "present", "sha256", "size",
            })
            if item["kind"] not in {"file", "tree"} or type(item["present"]) is not bool:
                raise OutputContractError("native fact kind/presence is invalid")
            _count(item["policy_index"], "native fact policy index", maximum=63)
            _count(item["size"], "native fact size")
            components = _array(item["components"], "native fact components", maximum=16)
            if not components:
                raise OutputContractError("native fact has invalid components")
            for component_index, component in enumerate(components):
                _component(component, f"native fact components[{component_index}]")
            if item["present"]:
                _bare_digest(item["sha256"], "native fact sha256")
            elif item["size"] != 0 or item["sha256"] is not None:
                raise OutputContractError("absent native artifact authenticates bytes")
            facts.append(item)
    indexes = [item["policy_index"] for item in facts]
    if (len(facts) != native["policy_count"] or len(indexes) != len(set(indexes))
            or set(indexes) != set(range(native["policy_count"]))):
        raise OutputContractError("native receipt partition is incomplete or overlaps")
    return {key: native[key] for key in required}


def _sealed_artifact_path(
    testimony: Mapping[str, object], run: store.Run, role: str,
) -> tuple[Path, tuple[str, ...]] | None:
    key = f"repository_{role}_path"
    value = testimony.get(key)
    if value is None:
        return None
    if type(value) is not str or not os.path.isabs(value):
        raise OutputContractError(f"sealed {role} path is invalid")
    path = Path(os.path.abspath(os.path.normpath(value)))
    try:
        managed = store.managed_run_for_artifact(path)
    except (OSError, ValueError) as exc:
        raise OutputContractError(f"sealed {role} path cannot be resolved") from exc
    if managed is None:
        raise OutputContractError(f"sealed {role} path is not repository managed")
    owner, components = managed
    expected = Path(os.path.abspath(os.path.normpath(str(run.dir.joinpath(*components)))))
    if (owner._authority_key != run._authority_key
            or owner._run_directory_identity != run._run_directory_identity
            or path != expected):
        raise OutputContractError(f"sealed {role} path belongs to another run")
    return path, components


def _verified_artifact_bytes(
    run: store.Run, components: tuple[str, ...], *, size: int, digest: str, label: str,
) -> bytes:
    """Hash a retained run artifact through the run's strict descriptor authority."""
    run_fd = artifact_fd = -1
    try:
        run_fd = store._open_run_fd(
            run.project_dir, run.run_id, expected_identity=run._run_directory_identity,
        )
        artifact_fd = privfs.open_strict_file_at(run_fd, components)
        before = os.fstat(artifact_fd)
        if before.st_size > MAX_STREAM_BYTES or before.st_size != size:
            raise OutputContractError(f"retained {label} size does not match runner settlement")
        chunks: list[bytes] = []
        total = 0
        digest_state = hashlib.sha256()
        while True:
            chunk = os.read(artifact_fd, min(1024 * 1024, size - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > size:
                raise OutputContractError(f"retained {label} exceeds runner settlement")
            digest_state.update(chunk)
            chunks.append(chunk)
        after = os.fstat(artifact_fd)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
                or total != size or digest_state.hexdigest() != digest):
            raise OutputContractError(f"retained {label} bytes do not match runner settlement")
        body = b"".join(chunks)
    except OutputContractError:
        raise
    except Exception as exc:
        raise OutputContractError(f"cannot open retained {label} through run authority") from exc
    finally:
        for descriptor in (artifact_fd, run_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    return body


def _unavailable(parser: str) -> dict:
    return {
        "complete": False, "input": None, "outcome": "unavailable",
        "parser": parser, "records": None,
    }


def parse_stdout_json(*, run: store.Run, testimony: Mapping[str, object]) -> dict:
    """Parse sealed stdout with explicit zero-byte empty and terminal semantics."""
    settlement, streams, publication = _settlement(testimony)
    stdout = streams[1]
    if stdout["terminal"] == "capped":
        retained = _sealed_artifact_path(testimony, run, "stdout")
        if retained is None or stdout["retained_sha256"] is None:
            return _unavailable("json-array")
        _path, components = retained
        body = _verified_artifact_bytes(
            run, components, size=stdout["retained_bytes"], digest=stdout["retained_sha256"],
            label="capped stdout",
        )
        return {
            # The retained prefix is authenticated in-process, but it cannot
            # prove a complete JSON document.  Do not feed a cap to json.loads.
            "complete": False,
            "input": {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                      "stream": "stdout"},
            "outcome": "truncated",
            "parser": "json-array", "records": None,
        }
    if (settlement["terminal"] != "complete" or settlement["exit_code"] is None
            or settlement["exit_code"] < 0 or stdout["terminal"] != "eof"
            or publication != "published"):
        return _unavailable("json-array")
    retained = _sealed_artifact_path(testimony, run, "stdout")
    if retained is None or stdout["retained_sha256"] is None:
        return _unavailable("json-array")
    _path, components = retained
    body = _verified_artifact_bytes(
        run, components, size=stdout["retained_bytes"], digest=stdout["retained_sha256"],
        label="stdout",
    )
    source = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "stream": "stdout"}
    if not body:
        return {
            "complete": True, "input": source, "outcome": "empty",
            "parser": "json-array", "records": 0,
        }
    try:
        rendered = body.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return {
            "complete": False, "input": source, "outcome": "non_utf8",
            "parser": "json-array", "records": None,
        }
    try:
        parsed = json.loads(rendered)
    except (json.JSONDecodeError, ValueError):
        return {
            "complete": False, "input": source, "outcome": "malformed",
            "parser": "json-array", "records": None,
        }
    if type(parsed) is not list or any(type(item) is not dict for item in parsed):
        return {
            "complete": False, "input": source, "outcome": "malformed",
            "parser": "json-array", "records": None,
        }
    return {
        "complete": True, "input": source,
        "outcome": "empty" if not parsed else "non_empty",
        "parser": "json-array", "records": len(parsed),
    }


def _native_current_path(
    testimony: Mapping[str, object], run: store.Run, fact: dict,
) -> tuple[Path, tuple[str, ...]]:
    path = Path(os.path.abspath(os.path.normpath(str(run.dir.joinpath(*fact["components"])))))
    current = testimony["native_outputs"].get("current_paths")
    if type(current) is not list or str(path) not in current:
        raise OutputContractError("native report is not current for this execution")
    try:
        managed = store.managed_run_for_artifact(path)
    except (OSError, ValueError) as exc:
        raise OutputContractError("native report path cannot be resolved") from exc
    if managed is None:
        raise OutputContractError("native report path is not repository managed")
    owner, _components = managed
    if (owner._authority_key != run._authority_key
            or owner._run_directory_identity != run._run_directory_identity):
        raise OutputContractError("native report belongs to another run")
    return path, tuple(fact["components"])


def parse_gitleaks_native_json(
    *, run: store.Run, testimony: Mapping[str, object], fixture_path: Path,
    expected_components: tuple[str, ...],
) -> dict:
    """Parse one current committed gitleaks report and bind its finding path."""
    settlement, _streams, publication = _settlement(testimony)
    if settlement["terminal"] != "complete" or settlement["exit_code"] != 1:
        return _unavailable("gitleaks-json")
    native = _native_outputs(testimony, require_current_paths=True)
    if (publication != "published" or native["clean"] is not True
            or native["policy_count"] != 1 or len(native["committed"]) != 1
            or native["uncertain"] or native["unpublished"]):
        raise OutputContractError("gitleaks report is not one clean committed native artifact")
    fact = native["committed"][0]
    if (fact["components"] != list(expected_components) or fact["kind"] != "file"
            or fact["policy_index"] != 0):
        raise OutputContractError("gitleaks native artifact does not match its admitted sink")
    if not fact["present"] or fact["sha256"] is None:
        raise OutputContractError("gitleaks native report is absent")
    _path, components = _native_current_path(testimony, run, fact)
    body = _verified_artifact_bytes(
        run, components, size=fact["size"], digest=fact["sha256"], label="native report",
    )
    source = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "stream": "native"}
    try:
        parsed = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {
            "complete": False, "input": source, "outcome": "malformed",
            "parser": "gitleaks-json", "records": None,
        }
    if type(parsed) is not list or any(type(item) is not dict for item in parsed):
        return {
            "complete": False, "input": source, "outcome": "malformed",
            "parser": "gitleaks-json", "records": None,
        }
    expected_file = os.path.abspath(os.path.normpath(str(fixture_path)))
    if any(
            type(item.get("File")) is not str
            or os.path.abspath(os.path.normpath(item["File"])) != expected_file
            for item in parsed):
        raise OutputContractError("gitleaks finding is not bound to the frozen fixture path")
    return {
        "complete": True, "input": source,
        "outcome": "empty" if not parsed else "non_empty",
        "parser": "gitleaks-json", "records": len(parsed),
    }


def _timestamps(testimony: Mapping[str, object], *, run_started_at: str) -> dict:
    started = _timestamp(testimony.get("execution_started_at"), "execution_started_at")
    finished = _timestamp(testimony.get("execution_finished_at"), "execution_finished_at")
    run_started = _timestamp(run_started_at, "run.started_at")
    if not _timestamp_value(run_started) <= _timestamp_value(started) <= _timestamp_value(finished):
        raise OutputContractError("execution timestamps do not bracket the repository run")
    return {"started_at": started, "finished_at": finished}


def _validate_candidate_summary(value: object, name: str) -> dict:
    item = _object(value, name, {
        "dirty", "git_commit", "git_tree", "identity_digest", "package_version",
        "source_tree_digest",
    })
    if item["dirty"] is not False:
        raise OutputContractError(f"{name}.dirty is not false")
    for field in ("git_commit", "git_tree"):
        rendered = _text(item[field], f"{name}.{field}", maximum=64)
        if not re.fullmatch(r"[0-9a-f]{40,64}", rendered):
            raise OutputContractError(f"{name}.{field} is invalid")
    _evidence_digest(item["identity_digest"], f"{name}.identity_digest")
    _evidence_digest(item["source_tree_digest"], f"{name}.source_tree_digest")
    _text(item["package_version"], f"{name}.package_version", maximum=128)
    return item


def _validate_run_binding(value: object, name: str) -> dict:
    item = _object(value, name, {
        "directory_device", "directory_inode", "run_id", "started_at", "target",
    })
    _timestamp(item["started_at"], f"{name}.started_at")
    for field in ("directory_device", "directory_inode"):
        _count(item[field], f"{name}.{field}", maximum=(1 << 63) - 1)
    _text(item["run_id"], f"{name}.run_id", maximum=128)
    _text(item["target"], f"{name}.target", maximum=1024)
    return item


def _validate_launch(value: object, name: str) -> dict:
    launch = _object(value, name, {
        "runtime_identity", "runtime_identity_digest", "runtime_identity_ref",
        "source_argv", "source_argv_indexes",
    })
    if _canonical_digest(launch["runtime_identity"]) != launch["runtime_identity_digest"]:
        raise OutputContractError(f"{name} runtime identity digest disagrees")
    _evidence_digest(launch["runtime_identity_digest"], f"{name}.runtime_identity_digest")
    _safe_relative(launch["runtime_identity_ref"], f"{name}.runtime_identity_ref")
    _runtime_launch({
        "runtime_identity": launch["runtime_identity"],
        "runtime_identity_ref": launch["runtime_identity_ref"],
        "runtime_source_argv": launch["source_argv"],
        "runtime_source_argv_indexes": launch["source_argv_indexes"],
    })
    return launch


def _serialized_helper_launch_shape(case: dict, manifest: dict, launch: dict) -> None:
    """Couple a diagnostic helper row to its admitted, non-PATH source argv.

    This validates only the serialized shape.  ``_helper_tool`` additionally
    no-follow opens and candidate-binds these exact paths before the in-process
    producer creates a diagnostic document.
    """
    identity = launch["runtime_identity"]
    argv = launch["source_argv"]
    helper = manifest["helper"]
    if identity["tool"] != "c-output-python-helper" or len(argv) < 3:
        raise OutputContractError("serialized helper launch is not the C-OUTPUT helper")
    if argv[1:3] != ["--case", case["id"]]:
        raise OutputContractError("serialized helper source argv has the wrong frozen case")
    expected = 3
    if case["fixture"] is not None:
        if (len(argv) < expected + 4 or argv[expected] != "--payload"
                or argv[expected + 2] != "--encoding"
                or argv[expected + 3] != case["fixture"]["encoding"]):
            raise OutputContractError("serialized helper source argv has the wrong fixture mapping")
        expected += 4
    if case["stderr"] is not None:
        if len(argv) < expected + 2 or argv[expected] != "--stderr":
            raise OutputContractError("serialized helper source argv has the wrong stderr mapping")
        expected += 2
    if len(argv) != expected:
        raise OutputContractError("serialized helper source argv has trailing logical arguments")
    matches = [
        item for item in identity["identities"]
        if item["role"] == "adapter"
        and item["executable"]["path"] == argv[0]
        and item["executable"]["sha256"] == helper["sha256"]
    ]
    if len(matches) != 1:
        raise OutputContractError("serialized helper launch does not bind its adapter source identity")


def _validate_timestamps(value: object, name: str, *, run_started_at: str) -> dict:
    item = _object(value, name, {"finished_at", "started_at"})
    started = _timestamp(item["started_at"], f"{name}.started_at")
    finished = _timestamp(item["finished_at"], f"{name}.finished_at")
    run_started = _timestamp(run_started_at, f"{name}.run_started_at")
    if not _timestamp_value(run_started) <= _timestamp_value(started) <= _timestamp_value(finished):
        raise OutputContractError(f"{name} does not bracket the repository run")
    return item


def validate_tool_attestation(document: object) -> dict:
    """Strictly validate a diagnostic gitleaks version attestation."""
    doc = _object(document, "tool attestation", {
        "candidate", "execution", "launch", "run", "schema_version", "stdout",
        "timestamps", "version",
    })
    if doc["schema_version"] != TOOL_ATTESTATION_SCHEMA:
        raise OutputContractError("tool attestation schema is invalid")
    if re.fullmatch(r"v\d+\.\d+\.\d+", _text(doc["version"], "tool attestation.version", maximum=32)) is None:
        raise OutputContractError("tool attestation version is invalid")
    _validate_candidate_summary(doc["candidate"], "tool attestation.candidate")
    run_binding = _validate_run_binding(doc["run"], "tool attestation.run")
    _validate_timestamps(
        doc["timestamps"], "tool attestation.timestamps", run_started_at=run_binding["started_at"],
    )
    launch = _validate_launch(doc["launch"], "tool attestation.launch")
    if launch["runtime_identity"]["tool"] != "gitleaks":
        raise OutputContractError("tool attestation did not prepare gitleaks")
    _execution_document(doc["execution"], "tool attestation.execution")
    stdout = _object(doc["stdout"], "tool attestation.stdout", {"bytes", "sha256"})
    _count(stdout["bytes"], "tool attestation.stdout.bytes")
    _bare_digest(stdout["sha256"], "tool attestation.stdout.sha256")
    _bounded(doc, "tool attestation")
    return doc


def _tool_attestation(*, run: store.Run, candidate_identity: object, result: runner.RunResult) -> dict:
    candidate = _candidate_binding(candidate_identity)
    run_binding = _run_binding(run)
    testimony = _sealed_testimony(result, run)
    launch = _runtime_launch(testimony)
    settlement, streams, publication = _settlement(testimony)
    if (launch["runtime_identity"]["tool"] != "gitleaks"
            or launch["source_argv"] != ["gitleaks", "version"]
            or settlement["terminal"] != "complete" or settlement["exit_code"] != 0
            or publication != "published"):
        raise OutputContractError("gitleaks version run did not complete cleanly")
    stdout = streams[1]
    if stdout["terminal"] != "eof" or stdout["retained_sha256"] is None:
        raise OutputContractError("gitleaks version run has no retained complete stdout")
    retained = _sealed_artifact_path(testimony, run, "stdout")
    if retained is None:
        raise OutputContractError("gitleaks version run has no sealed stdout artifact")
    _path, components = retained
    body = _verified_artifact_bytes(
        run, components, size=stdout["retained_bytes"], digest=stdout["retained_sha256"],
        label="gitleaks version stdout",
    )
    try:
        rendered = body.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise OutputContractError("gitleaks version output is not UTF-8") from exc
    match = _VERSION.search(rendered)
    if match is None:
        raise OutputContractError("gitleaks version output is not parseable")
    return {
        "schema_version": TOOL_ATTESTATION_SCHEMA,
        "candidate": candidate,
        "run": run_binding,
        "timestamps": _timestamps(testimony, run_started_at=run_binding["started_at"]),
        "launch": launch,
        "execution": settlement,
        "stdout": {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()},
        "version": "v" + match.group(1),
    }


def attest_gitleaks_version(*, run: store.Run, candidate_identity: object,
                            result: runner.RunResult) -> dict:
    """Return a diagnostic record; receipt production never accepts it as input."""
    return validate_tool_attestation(
        _tool_attestation(run=run, candidate_identity=candidate_identity, result=result),
    )


def _candidate_root(value: object) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise OutputContractError("candidate_root is not a filesystem path")
    try:
        root = Path(value).resolve(strict=True)
    except OSError as exc:
        raise OutputContractError("candidate_root cannot be resolved") from exc
    if not root.is_dir():
        raise OutputContractError("candidate_root is not a directory")
    return root


def _read_candidate_regular_nofollow(
    root: Path, relative: str, *, label: str, maximum: int = MAX_STREAM_BYTES,
) -> tuple[Path, bytes]:
    """Read one bounded candidate input through no-follow descriptor traversal.

    Candidate identity binds Git blobs, while runtime launch binds executable
    bytes.  This final open closes the remaining worktree-path gap: every
    directory component and the leaf are opened from the resolved candidate
    root with ``O_NOFOLLOW`` and the leaf's identity is stable across the read.
    """
    relative = _safe_relative(relative, f"candidate {label} path")
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, flag) for flag in required_flags) or os.open not in os.supports_dir_fd:
        raise OutputContractError("candidate fixture reads require no-follow descriptor traversal")
    parts = Path(relative).parts
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(os.fspath(root), directory_flags))
        for component in parts[:-1]:
            descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
        descriptors.append(os.open(parts[-1], file_flags, dir_fd=descriptors[-1]))
        descriptor = descriptors[-1]
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OutputContractError(f"candidate {label} is not a regular file")
        if before.st_size > maximum:
            raise OutputContractError(f"candidate {label} exceeds its byte bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise OutputContractError(f"candidate {label} exceeds its byte bound")
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or total != after.st_size):
            raise OutputContractError(f"candidate {label} changed while being read")
        return root.joinpath(*parts), b"".join(chunks)
    except OSError as exc:
        raise OutputContractError(
            f"candidate {label} cannot be opened without following links ({type(exc).__name__})",
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _bound_fixture(
    spec: dict, candidate_document: dict, root: Path, *, label: str,
) -> tuple[Path, bytes]:
    inputs = {item["name"]: item for item in candidate_document["inputs"]}
    bound = inputs.get(spec["candidate_input"])
    if (bound is None or bound["path"] != spec["path"]
            or bound["digest"] != "sha256:" + spec["source_sha256"]):
        raise OutputContractError(f"candidate does not bind frozen {label} source bytes")
    path, source = _read_candidate_regular_nofollow(
        root, spec["path"], label=f"{label} fixture",
    )
    if (len(source) != spec["source_bytes"]
            or hashlib.sha256(source).hexdigest() != spec["source_sha256"]):
        raise OutputContractError(f"candidate {label} source bytes drifted")
    try:
        payload = bytes.fromhex(source.decode("ascii", "strict").strip()) if spec["encoding"] == "hex" else source
    except (UnicodeDecodeError, ValueError) as exc:
        raise OutputContractError(f"candidate {label} fixture encoding is invalid") from exc
    if len(payload) != spec["bytes"] or hashlib.sha256(payload).hexdigest() != spec["sha256"]:
        raise OutputContractError(f"candidate {label} payload bytes drifted")
    return path, payload


def _bound_frozen_fixture_manifest(manifest: dict, candidate_document: dict, root: Path) -> None:
    """Require the candidate to bind and still hold the exact canonical manifest bytes."""
    inputs = {item["name"]: item for item in candidate_document["inputs"]}
    bound = inputs.get(FROZEN_FIXTURE_MANIFEST_INPUT)
    if (bound is None or bound["path"] != FROZEN_FIXTURE_MANIFEST_PATH
            or bound["digest"] != "sha256:" + FROZEN_FIXTURE_MANIFEST_RAW_SHA256):
        raise OutputContractError("candidate does not bind the frozen fixture manifest bytes")
    _path, body = _read_candidate_regular_nofollow(
        root, FROZEN_FIXTURE_MANIFEST_PATH, label="fixture manifest", maximum=MAX_MANIFEST_BYTES,
    )
    if body != evidence.canonical_json_bytes(manifest) + b"\n":
        raise OutputContractError("candidate fixture manifest bytes drifted from the canonical frozen inventory")


def _adapter_identity(launch: dict, *, source_path: Path, digest: str) -> None:
    matches = []
    for value in launch["runtime_identity"]["identities"]:
        if type(value) is not dict or value.get("role") != "adapter":
            continue
        executable = value.get("executable")
        if type(executable) is not dict:
            continue
        if executable.get("path") == str(source_path) and executable.get("sha256") == digest:
            matches.append(value)
    if len(matches) != 1:
        raise OutputContractError("prepared launch does not bind the helper adapter source")


def _helper_tool(
    manifest: dict, case: dict, candidate_identity: object, candidate_root: Path, launch: dict,
) -> tuple[dict, Path | None, Path | None, bytes | None]:
    candidate = _candidate_document(candidate_identity)
    helper = manifest["helper"]
    inputs = {item["name"]: item for item in candidate["inputs"]}
    bound = inputs.get(helper["candidate_input"])
    if (bound is None or bound["path"] != helper["path"]
            or bound["digest"] != "sha256:" + helper["sha256"]):
        raise OutputContractError("candidate does not bind the frozen Python helper source")
    helper_path, helper_source = _read_candidate_regular_nofollow(
        candidate_root, helper["path"], label="helper source",
    )
    if hashlib.sha256(helper_source).hexdigest() != helper["sha256"]:
        raise OutputContractError("candidate helper source bytes drifted")
    _adapter_identity(launch, source_path=helper_path, digest=helper["sha256"])
    fixture_path, fixture_payload = (None, None) if case["fixture"] is None else _bound_fixture(
        case["fixture"], candidate, candidate_root, label="stdout",
    )
    stderr_path, _stderr_payload = (None, None) if case["stderr"] is None else _bound_fixture(
        case["stderr"], candidate, candidate_root, label="stderr",
    )
    expected_argv = [str(helper_path), "--case", case["id"]]
    if fixture_path is not None:
        expected_argv += ["--payload", str(fixture_path), "--encoding", case["fixture"]["encoding"]]
    if stderr_path is not None:
        expected_argv += ["--stderr", str(stderr_path)]
    if launch["runtime_identity"]["tool"] != "c-output-python-helper":
        raise OutputContractError("helper case did not prepare the helper tool identity")
    if launch["source_argv"] != expected_argv:
        raise OutputContractError("helper source argv does not bind the frozen fixture inputs")
    return ({
        "kind": "candidate-python-helper",
        "candidate_input": helper["candidate_input"],
        "adapter_sha256": helper["sha256"],
        "runtime_executable_sha256": launch["runtime_identity"]["selected_executable"]["sha256"],
        "fixture_candidate_input": None if case["fixture"] is None else case["fixture"]["candidate_input"],
        "fixture_sha256": None if case["fixture"] is None else case["fixture"]["sha256"],
        "stderr_candidate_input": None if case["stderr"] is None else case["stderr"]["candidate_input"],
        "stderr_sha256": None if case["stderr"] is None else case["stderr"]["sha256"],
    }, fixture_path, stderr_path, fixture_payload)


def _gitleaks_tool(
    *, case: dict, candidate_identity: object, candidate_root: Path, run: store.Run,
    launch: dict, version_result: runner.RunResult,
) -> tuple[dict, Path]:
    candidate_document = _candidate_document(candidate_identity)
    candidate = _candidate_binding(candidate_document)
    run_binding = _run_binding(run)
    fixture_path, _fixture_payload = _bound_fixture(
        case["fixture"], candidate_document, candidate_root, label="gitleaks",
    )
    native_path = run.dir.joinpath("raw", "c-output-contract", case["id"], "gitleaks.json")
    expected_argv = [
        "gitleaks", "dir", "--no-banner", "--report-path", str(native_path),
        "--report-format", "json", str(fixture_path),
    ]
    if launch["runtime_identity"]["tool"] != "gitleaks" or launch["source_argv"] != expected_argv:
        raise OutputContractError("gitleaks source argv does not bind its fixture and native sink")
    attestation = attest_gitleaks_version(
        run=run, candidate_identity=candidate_document, result=version_result,
    )
    if (attestation["candidate"] != candidate or attestation["run"] != run_binding
            or attestation["version"] != "v8.30.1"):
        raise OutputContractError("gitleaks version attestation is not bound to this candidate/run/version")
    selected = launch["runtime_identity"]["selected_executable"]["sha256"]
    version_selected = attestation["launch"]["runtime_identity"]["selected_executable"]["sha256"]
    if selected != version_selected:
        raise OutputContractError("gitleaks scan and version attestation used different executable bytes")
    return ({
        "kind": "gitleaks",
        "runtime_executable_sha256": selected,
        "version": attestation["version"],
        "version_attestation_digest": _canonical_digest(attestation),
        "fixture_candidate_input": case["fixture"]["candidate_input"],
        "fixture_sha256": case["fixture"]["sha256"],
    }, fixture_path)


def _verified_stderr(case: dict, *, run: store.Run, testimony: Mapping[str, object],
                     streams: list[dict], publication: str) -> bytes:
    stderr = streams[2]
    spec = case["stderr"]
    if spec is None:
        if case["executor"] == "candidate-python-helper" and (
                stderr["observed_bytes"] != 0 or stderr["observed_sha256"] != _EMPTY_SHA256):
            raise OutputContractError("helper case emitted undocumented stderr bytes")
        return b""
    if publication != "published" or stderr["retained_sha256"] is None:
        raise OutputContractError("partial case lacks a retained stderr artifact")
    retained = _sealed_artifact_path(testimony, run, "stderr")
    if retained is None:
        raise OutputContractError("partial case lacks a sealed stderr artifact")
    _path, components = retained
    body = _verified_artifact_bytes(
        run, components, size=stderr["retained_bytes"], digest=stderr["retained_sha256"],
        label="stderr",
    )
    if len(body) != spec["bytes"] or hashlib.sha256(body).hexdigest() != spec["sha256"]:
        raise OutputContractError("partial case stderr bytes drifted from its frozen fixture")
    return body


def _derive_effective_status(
    *, case: dict, settlement: dict, streams: list[dict], parser: dict, stderr_body: bytes,
) -> str:
    """Derive status from sealed facts, never from mutable RunResult.status."""
    if settlement["terminal"] == "timed_out":
        return "timed_out"
    exit_code = settlement["exit_code"]
    if type(exit_code) is int and exit_code < 0:
        return "failed"
    if streams[1]["terminal"] == "capped":
        if (settlement["terminal"] != "complete" or exit_code is None
                or parser["outcome"] not in {"truncated", "unavailable"}
                or parser["complete"]):
            raise OutputContractError("capped stdout does not have a partial terminal shape")
        return "partial"
    if parser["outcome"] in {"malformed", "truncated", "non_utf8"}:
        return "partial"
    if case["stderr"] is not None:
        # Keep the partial fixture honest by using the production status
        # classifier over the exact, sealed diagnostic bytes.  A merely
        # non-empty caller-controlled stderr stream never earns PARTIAL.
        if (settlement["terminal"] != "complete" or exit_code != 0
                or parser["outcome"] != "empty" or not parser["complete"]
                or streams[2]["terminal"] != "eof"):
            raise OutputContractError("partial fixture does not have its valid-empty transport shape")
        folded = stderr_body.lower()
        blocked = any(signature.encode("utf-8") in folded for signature in runner.BLOCK_SIGNATURES)
        transport = any(signature.encode("utf-8") in folded for signature in runner.TRANSPORT_SIGNATURES)
        classified, _note = runner._classify(
            exit_code, streams[1]["observed_bytes"] > 0, blocked, transport, True, (0,),
        )
        if classified is not runner.Status.PARTIAL or blocked or not transport:
            raise OutputContractError("partial stderr does not derive a transport-degraded result")
        return "partial"
    if case["executor"] == "gitleaks":
        if exit_code != 1 or parser["outcome"] != "non_empty" or not parser["complete"]:
            raise OutputContractError("gitleaks exit 1 is not an accepted successful finding result")
        return "success"
    if parser["outcome"] == "empty" and parser["complete"]:
        return "empty"
    if parser["outcome"] == "non_empty" and parser["complete"]:
        return "success"
    raise OutputContractError("sealed execution facts do not derive a contract status")


def _case_invariants(case: dict, receipt: dict, *, fixture_payload: bytes | None = None) -> None:
    expected = case["expected"]
    execution = receipt["execution"]
    stdout = receipt["streams"][1]
    stderr = receipt["streams"][2]
    parser = receipt["parser"]
    if receipt["effective_status"] != expected["effective_status"]:
        raise OutputContractError("case effective status does not match frozen contract")
    if execution["terminal"] != expected["execution_terminal"]:
        raise OutputContractError("case execution terminal does not match frozen contract")
    if receipt["repository_publication"] != expected["repository_publication"]:
        raise OutputContractError("case repository publication does not match frozen contract")
    exit_code = execution["exit_code"]
    if ((expected["exit"] == "zero" and exit_code != 0)
            or (expected["exit"] == "one" and exit_code != 1)
            or (expected["exit"] == "negative" and not (type(exit_code) is int and exit_code < 0))
            or (expected["exit"] == "none" and exit_code is not None)):
        raise OutputContractError("case exit condition does not match frozen contract")
    if stdout["terminal"] != expected["stdout_terminal"] or stderr["terminal"] != expected["stderr_terminal"]:
        raise OutputContractError("case stream terminal does not match frozen contract")
    if {key: parser[key] for key in ("complete", "outcome", "records")} != expected["parser"]:
        raise OutputContractError("case parser fact does not match frozen contract")
    native = receipt["native_outputs"]
    if expected["native"] == "none":
        if not (native["clean"] is True and native["policy_count"] == 0
                and not native["committed"] and not native["uncertain"] and not native["unpublished"]):
            raise OutputContractError("non-native case has native artifact authority")
    elif not (native["clean"] is True and native["policy_count"] == 1
              and len(native["committed"]) == 1 and native["committed"][0]["present"]
              and not native["uncertain"] and not native["unpublished"]):
        raise OutputContractError("native case lacks one clean committed artifact")
    fixture = case["fixture"]
    if case["executor"] == "candidate-python-helper":
        if fixture is None:
            if stdout["observed_bytes"] != 0 or stdout["observed_sha256"] != _EMPTY_SHA256:
                raise OutputContractError("terminal helper case observed undocumented stdout bytes")
        elif (stdout["observed_bytes"] != fixture["bytes"]
              or stdout["observed_sha256"] != fixture["sha256"]):
            raise OutputContractError("helper stdout does not match its frozen fixture payload")
        if stdout["terminal"] == "capped":
            if fixture_payload is not None:
                retained_prefix = fixture_payload[:RETAINED_STREAM_CAP_BYTES]
                if (stdout["retained_bytes"] != len(retained_prefix)
                        or stdout["retained_sha256"] != hashlib.sha256(retained_prefix).hexdigest()):
                    raise OutputContractError("capped helper receipt does not bind the exact retained prefix")
                if parser["outcome"] == "unavailable" and parser["input"] is not None:
                    raise OutputContractError("refused capped parser has an unverified retained input")
        if case["stderr"] is not None and (
                stderr["observed_bytes"] != case["stderr"]["bytes"]
                or stderr["observed_sha256"] != case["stderr"]["sha256"]):
            raise OutputContractError("partial stderr does not match its frozen fixture payload")


def receipt_from_runner(
    *, fixture_manifest: object, case_id: str, run: store.Run,
    candidate_identity: object, candidate_root: str | os.PathLike[str],
    result: runner.RunResult, gitleaks_version_result: runner.RunResult | None = None,
) -> dict:
    """Produce one raw receipt solely from sealed repository execution facts."""
    manifest = validate_fixture_manifest(fixture_manifest)
    if case_id not in CASES:
        raise OutputContractError("receipt producer received an unknown case")
    case = _case(manifest, case_id)
    if case["availability"] != "measured-helper":
        raise OutputContractError(
            "native Gitleaks fixture row is explicitly unavailable in this source substrate",
        )
    root = _candidate_root(candidate_root)
    candidate = _candidate_binding(candidate_identity)
    candidate_document = _candidate_document(candidate_identity)
    _bound_frozen_fixture_manifest(manifest, candidate_document, root)
    run_binding = _run_binding(run)
    testimony = _sealed_testimony(result, run)
    launch = _runtime_launch(testimony)
    settlement, streams, publication = _settlement(testimony)
    native = _native_outputs(testimony, require_current_paths=True)
    if case["executor"] == "candidate-python-helper":
        tool, _fixture_path, _stderr_path, fixture_payload = _helper_tool(
            manifest, case, candidate_identity, root, launch,
        )
        parser = parse_stdout_json(run=run, testimony=testimony)
    else:
        # validate_fixture_manifest makes this unreachable today.  Keep a
        # fail-closed guard if the inventory changes before a real H1 resolver
        # and pinned fixture execution are introduced.
        raise OutputContractError("native Gitleaks receipt production is not available")
    stderr_body = _verified_stderr(
        case, run=run, testimony=testimony, streams=streams, publication=publication,
    )
    receipt = {
        "schema_version": RAW_RECEIPT_SCHEMA,
        "case_id": case_id,
        "fixture_manifest_digest": _canonical_digest(manifest),
        "disposition": SERIALIZED_RECEIPT_DISPOSITION,
        "claim": SERIALIZED_RECEIPT_CLAIM,
        "candidate": candidate,
        "run": run_binding,
        "timestamps": _timestamps(testimony, run_started_at=run_binding["started_at"]),
        "launch": launch,
        "execution": settlement,
        "repository_publication": publication,
        "streams": streams,
        "native_outputs": native,
        "tool": tool,
        "parser": parser,
        "effective_status": _derive_effective_status(
            case=case, settlement=settlement, streams=streams, parser=parser,
            stderr_body=stderr_body,
        ),
    }
    validate_raw_receipt(receipt, fixture_manifest=manifest)
    _case_invariants(case, receipt, fixture_payload=fixture_payload)
    return receipt


def _validate_parser(value: object, name: str, *, streams: list[dict], native: dict) -> dict:
    parser = _object(value, name, {"complete", "input", "outcome", "parser", "records"})
    if parser["parser"] not in {"json-array", "gitleaks-json"}:
        raise OutputContractError(f"{name}.parser is invalid")
    if parser["outcome"] not in {
            "empty", "non_empty", "malformed", "truncated", "non_utf8", "unavailable"}:
        raise OutputContractError(f"{name}.outcome is invalid")
    if type(parser["complete"]) is not bool:
        raise OutputContractError(f"{name}.complete is invalid")
    if parser["complete"] != (parser["records"] is not None):
        raise OutputContractError(f"{name}.records completeness disagrees")
    if parser["records"] is not None:
        _count(parser["records"], f"{name}.records")
    source = parser["input"]
    if source is None:
        return parser
    source = _object(source, f"{name}.input", {"bytes", "sha256", "stream"})
    _count(source["bytes"], f"{name}.input.bytes")
    _bare_digest(source["sha256"], f"{name}.input.sha256")
    if source["stream"] == "stdout":
        stdout = streams[1]
        if (source["bytes"] != stdout["retained_bytes"]
                or source["sha256"] != stdout["retained_sha256"]):
            raise OutputContractError(f"{name} input does not equal retained stdout")
    elif source["stream"] == "native":
        if len(native["committed"]) != 1:
            raise OutputContractError(f"{name} native input lacks one committed artifact")
        fact = native["committed"][0]
        if source["bytes"] != fact["size"] or source["sha256"] != fact["sha256"]:
            raise OutputContractError(f"{name} input does not equal retained native output")
    else:
        raise OutputContractError(f"{name}.input.stream is invalid")
    return parser


def _validate_native_document(value: object) -> dict:
    return _native_outputs({"native_outputs": value})


def validate_raw_receipt(
    document: object, *, fixture_manifest: object, accepting: bool = False,
) -> dict:
    """Validate a serialized *shape-only diagnostic*, never authenticated evidence.

    Raw JSON cannot carry the runner's sealed authority.  Callers asking this
    path to accept evidence fail closed; only ``receipt_from_runner`` has
    access to in-process repository testimony and descriptor-pinned bytes.
    """
    if accepting is not False:
        raise OutputContractError("serialized raw receipts have no authenticated accepting resolver")
    manifest = validate_fixture_manifest(fixture_manifest)
    doc = _object(document, "raw receipt", {
        "candidate", "case_id", "claim", "disposition", "effective_status", "execution", "fixture_manifest_digest",
        "launch", "native_outputs", "parser", "repository_publication", "run",
        "schema_version", "streams", "timestamps", "tool",
    })
    if doc["schema_version"] != RAW_RECEIPT_SCHEMA or doc["case_id"] not in CASES:
        raise OutputContractError("raw receipt schema/case is invalid")
    if (doc["disposition"] != SERIALIZED_RECEIPT_DISPOSITION
            or doc["claim"] != SERIALIZED_RECEIPT_CLAIM):
        raise OutputContractError("serialized raw receipt does not disclose its non-evidence disposition")
    if doc["fixture_manifest_digest"] != _canonical_digest(manifest):
        raise OutputContractError("raw receipt is not bound to this frozen fixture manifest")
    _validate_candidate_summary(doc["candidate"], "raw receipt.candidate")
    run_binding = _validate_run_binding(doc["run"], "raw receipt.run")
    _validate_timestamps(
        doc["timestamps"], "raw receipt.timestamps", run_started_at=run_binding["started_at"],
    )
    _validate_launch(doc["launch"], "raw receipt.launch")
    settlement, settlement_streams = _execution_document(doc["execution"], "raw receipt.execution")
    if not settlement["launched"]:
        raise OutputContractError("raw receipt does not record a launched execution")
    if doc["repository_publication"] not in {"published", "fenced"}:
        raise OutputContractError("raw receipt publication is not terminal")
    streams = _array(doc["streams"], "raw receipt streams", maximum=3)
    if len(streams) != 3 or streams != settlement_streams:
        raise OutputContractError("raw receipt streams do not equal its serialized settlement projection")
    native = _validate_native_document(doc["native_outputs"])
    parser = _validate_parser(doc["parser"], "raw receipt.parser", streams=settlement_streams,
                              native=native)
    case = _case(manifest, doc["case_id"])
    if case["availability"] != "measured-helper":
        raise OutputContractError("serialized native Gitleaks rows are unavailable in this source substrate")
    tool = doc["tool"]
    if case["executor"] == "candidate-python-helper":
        helper_tool = _object(tool, "raw receipt helper tool", {
            "adapter_sha256", "candidate_input", "fixture_candidate_input",
            "fixture_sha256", "kind", "runtime_executable_sha256",
            "stderr_candidate_input", "stderr_sha256",
        })
        if (helper_tool["kind"] != "candidate-python-helper"
                or helper_tool["candidate_input"] != manifest["helper"]["candidate_input"]
                or helper_tool["adapter_sha256"] != manifest["helper"]["sha256"]):
            raise OutputContractError("helper case tool identity is invalid")
        _bare_digest(helper_tool["runtime_executable_sha256"], "raw receipt helper runtime digest")
        _serialized_helper_launch_shape(case, manifest, doc["launch"])
        fixture = case["fixture"]
        if (helper_tool["fixture_candidate_input"] != (None if fixture is None else fixture["candidate_input"])
                or helper_tool["fixture_sha256"] != (None if fixture is None else fixture["sha256"])
                or helper_tool["stderr_candidate_input"] != (
                    None if case["stderr"] is None else case["stderr"]["candidate_input"])
                or helper_tool["stderr_sha256"] != (
                    None if case["stderr"] is None else case["stderr"]["sha256"])):
            raise OutputContractError("helper tool is not bound to this case's frozen fixtures")
    else:  # pragma: no cover - guarded by the frozen source-only manifest above.
        raise OutputContractError("serialized native Gitleaks rows are unavailable")
    if (case["executor"] == "candidate-python-helper" and parser["parser"] != "json-array") or (
            case["executor"] == "gitleaks" and parser["parser"] != "gitleaks-json"):
        raise OutputContractError("raw receipt parser does not match its executor")
    if doc["effective_status"] not in {"success", "empty", "partial", "failed", "timed_out"}:
        raise OutputContractError("raw receipt effective status is invalid")
    _case_invariants(case, doc)
    _bounded(doc, "raw receipt")
    return doc


def diagnostic_receipt_digest(receipt: object, *, fixture_manifest: object) -> str:
    """Return a digest for a validated diagnostic shape, not an evidence digest."""
    validate_raw_receipt(receipt, fixture_manifest=fixture_manifest)
    return _canonical_digest(receipt)


def raw_receipt_digest(receipt: object, *, fixture_manifest: object) -> str:
    """Compatibility spelling for :func:`diagnostic_receipt_digest`."""
    return diagnostic_receipt_digest(receipt, fixture_manifest=fixture_manifest)


def collect_case_matrix(*, fixture_manifest: object, receipts: Sequence[object]) -> dict:
    """Fail closed while the frozen native rows lack a real H1 resolver."""
    manifest = validate_fixture_manifest(fixture_manifest)
    unavailable = [item["id"] for item in manifest["cases"]
                   if item["availability"] != "measured-helper"]
    if unavailable:
        raise OutputContractError(
            "C-OUTPUT remains open: native rows lack pinned attested fixture executions: "
            + ", ".join(unavailable),
        )
    if type(receipts) not in (tuple, list) or len(receipts) != len(CASES):
        raise OutputContractError("collector requires exactly nine raw receipts")
    rows = []
    candidate = run_binding = None
    for expected_case, raw in zip(CASES, receipts):
        receipt = validate_raw_receipt(raw, fixture_manifest=manifest)
        if receipt["case_id"] != expected_case:
            raise OutputContractError("raw receipts are not in frozen case order")
        if candidate is None:
            candidate, run_binding = receipt["candidate"], receipt["run"]
        elif receipt["candidate"] != candidate or receipt["run"] != run_binding:
            raise OutputContractError("raw receipts do not share one candidate and repository run owner")
        rows.append({
            "id": expected_case,
            "availability": "measured-helper",
            "open_reason": None,
            "effective_status": receipt["effective_status"],
            "parser": receipt["parser"],
            "diagnostic_digest": diagnostic_receipt_digest(receipt, fixture_manifest=manifest),
        })
    matrix = {
        "schema_version": CASE_MATRIX_SCHEMA,
        "fixture_manifest_digest": _canonical_digest(manifest),
        "candidate": candidate,
        "run": run_binding,
        "disposition": SOURCE_SUBSTRATE_DISPOSITION,
        "observation": SOURCE_SUBSTRATE_OBSERVATION,
        "cases": rows,
    }
    validate_case_matrix(matrix, fixture_manifest=manifest)
    return matrix


def validate_case_matrix(
    document: object, *, fixture_manifest: object, accepting: bool = False,
) -> dict:
    """Validate a source-only matrix shape; it cannot accept or promote release evidence."""
    if accepting is not False:
        raise OutputContractError("C-OUTPUT source matrices have no accepting semantic verifier")
    manifest = validate_fixture_manifest(fixture_manifest)
    doc = _object(document, "case matrix", {
        "candidate", "cases", "disposition", "fixture_manifest_digest", "observation", "run", "schema_version",
    })
    if (doc["schema_version"] != CASE_MATRIX_SCHEMA
            or doc["disposition"] != SOURCE_SUBSTRATE_DISPOSITION
            or doc["observation"] != SOURCE_SUBSTRATE_OBSERVATION):
        raise OutputContractError("case matrix is not the explicit open source substrate")
    if doc["fixture_manifest_digest"] != _canonical_digest(manifest):
        raise OutputContractError("case matrix fixture binding disagrees")
    _validate_candidate_summary(doc["candidate"], "case matrix.candidate")
    _validate_run_binding(doc["run"], "case matrix.run")
    rows = _array(doc["cases"], "case matrix cases", maximum=len(CASES))
    if len(rows) != len(CASES):
        raise OutputContractError("case matrix must contain exactly nine cases")
    for expected_case, row in zip(CASES, rows):
        item = _object(row, "case matrix row", {
            "availability", "diagnostic_digest", "effective_status", "id", "open_reason", "parser",
        })
        if item["id"] != expected_case:
            raise OutputContractError("case matrix order drifted")
        expected_case_document = _case(manifest, expected_case)
        if item["availability"] != expected_case_document["availability"]:
            raise OutputContractError("case matrix availability drifted from the source manifest")
        if item["availability"] == "measured-helper":
            if item["open_reason"] is not None:
                raise OutputContractError("measured helper matrix row has an open reason")
            _diagnostic_digest(item["diagnostic_digest"], "case matrix diagnostic digest")
        elif not (
                item["open_reason"] == "native-gitleaks-fixture-unavailable"
                and item["diagnostic_digest"] is None):
            raise OutputContractError("unavailable native matrix row lacks its exact open reason")
        parser = _object(item["parser"], "case matrix parser", {
            "complete", "input", "outcome", "parser", "records",
        })
        expected = expected_case_document["expected"]
        if (item["effective_status"] != expected["effective_status"]
                or {key: parser[key] for key in ("complete", "outcome", "records")}
                != expected["parser"]):
            raise OutputContractError("case matrix row no longer matches frozen facts")
    _bounded(doc, "case matrix")
    return doc
