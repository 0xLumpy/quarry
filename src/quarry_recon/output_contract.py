"""Bounded evidence substrate for the C-OUTPUT-CONTRACT gate.

This module deliberately has no adapter or network authority.  A raw receipt is
made only from an already-settled :class:`runner.RunResult` that used the
repository publication seam; the collector then derives the one fixed nine-case
matrix.  Neither shape is a release gate record or a substitute for an attested
H1 execution.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import release_evidence as evidence
from . import runner


FIXTURE_MANIFEST_SCHEMA = "quarry.c-output-fixture-manifest.v1"
RAW_RECEIPT_SCHEMA = "quarry.c-output-raw-receipt.v1"
CASE_MATRIX_SCHEMA = "quarry.c-output-case-matrix.v1"

CASES = (
    "empty", "non_empty", "malformed", "truncated", "non_utf8", "partial",
    "timeout", "signal", "tool_specific_exit",
)
EXPECTED_STATUS = {
    "empty": "empty", "non_empty": "success", "malformed": "partial",
    "truncated": "partial", "non_utf8": "partial", "partial": "partial",
    "timeout": "timed_out", "signal": "failed", "tool_specific_exit": "failed",
}
_DIGEST = "sha256:" + "0" * 64


class OutputContractError(ValueError):
    """One output-contract input is not bounded authenticated evidence."""


def _object(value: object, name: str, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise OutputContractError(f"{name} must have exactly {sorted(keys)!r}")
    return value


def _text(value: object, name: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        raise OutputContractError(f"{name} must be {'a non-empty ' if nonempty else 'a '}string")
    return value


def _digest(value: object, name: str) -> str:
    value = _text(value, name)
    if len(value) != len(_DIGEST) or not value.startswith("sha256:") or any(
        char not in "0123456789abcdef" for char in value[7:]
    ):
        raise OutputContractError(f"{name} must be a sha256 digest")
    return value


def _count(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise OutputContractError(f"{name} must be a bounded non-negative integer")
    return value


def _canonical_bytes(document: object) -> bytes:
    return evidence.canonical_json_bytes(document)


def raw_receipt_digest(receipt: object) -> str:
    """Digest one canonical raw receipt after validating its exact shape."""
    validate_raw_receipt(receipt)
    return "sha256:" + hashlib.sha256(_canonical_bytes(receipt)).hexdigest()


def validate_fixture_manifest(document: object) -> dict:
    doc = _object(document, "fixture manifest", {"cases", "schema_version", "tool"})
    if doc["schema_version"] != FIXTURE_MANIFEST_SCHEMA:
        raise OutputContractError("fixture manifest has an unsupported schema")
    tool = _object(doc["tool"], "fixture manifest.tool", {"argv0", "name", "version", "version_command"})
    if tool["name"] != "gitleaks":
        raise OutputContractError("C-OUTPUT fixture tool must be gitleaks")
    if tool["version"] != "v8.30.1":
        raise OutputContractError("C-OUTPUT fixture tool version drifted")
    for field in tool:
        _text(tool[field], f"fixture manifest.tool.{field}")
    cases = doc["cases"]
    if type(cases) is not list or len(cases) != len(CASES):
        raise OutputContractError("fixture manifest must enumerate exactly nine cases")
    ids = []
    for index, value in enumerate(cases):
        item = _object(value, f"fixture manifest.cases[{index}]", {"id", "parser"})
        case_id = _text(item["id"], f"fixture manifest.cases[{index}].id")
        _text(item["parser"], f"fixture manifest.cases[{index}].parser")
        ids.append(case_id)
    if tuple(ids) != CASES:
        raise OutputContractError("fixture manifest case order is not the frozen nine-case order")
    return doc


def _validate_stream(value: object, name: str) -> dict:
    item = _object(value, name, {
        "lines", "observed_bytes", "observed_sha256", "retained_bytes",
        "retained_sha256", "role", "terminal",
    })
    if item["role"] not in {"stdout", "stderr"}:
        raise OutputContractError(f"{name}.role is not an output role")
    if item["terminal"] not in {"complete", "eof", "capped", "sink_error", "not_started"}:
        raise OutputContractError(f"{name}.terminal is unsupported")
    for field in ("lines", "observed_bytes", "retained_bytes"):
        _count(item[field], f"{name}.{field}")
    if item["retained_bytes"] > item["observed_bytes"]:
        raise OutputContractError(f"{name} retains more bytes than observed")
    for field in ("observed_sha256", "retained_sha256"):
        if item[field] is not None:
            _digest(item[field], f"{name}.{field}")
    if item["terminal"] != "not_started" and item["observed_sha256"] is None:
        raise OutputContractError(f"{name} lacks an authenticated observed digest")
    if item["retained_bytes"] and item["retained_sha256"] is None:
        raise OutputContractError(f"{name} lacks an authenticated retained digest")
    return item


def _validate_native_fact(value: object, name: str) -> dict:
    item = _object(value, name, {"components", "kind", "policy_index", "present", "sha256", "size"})
    if item["kind"] not in {"file", "tree"}:
        raise OutputContractError(f"{name}.kind is unsupported")
    _count(item["policy_index"], f"{name}.policy_index")
    if type(item["components"]) is not list or not item["components"]:
        raise OutputContractError(f"{name}.components must be a non-empty array")
    for index, component in enumerate(item["components"]):
        _text(component, f"{name}.components[{index}]")
    if type(item["present"]) is not bool:
        raise OutputContractError(f"{name}.present must be boolean")
    _count(item["size"], f"{name}.size")
    if item["present"]:
        _digest(item["sha256"], f"{name}.sha256")
    elif item["size"] != 0 or item["sha256"] is not None:
        raise OutputContractError(f"{name} authenticates absent native bytes")
    return item


def validate_raw_receipt(document: object) -> dict:
    """Validate one receipt without interpreting it as an accepted gate result."""
    doc = _object(document, "raw receipt", {
        "case_id", "execution", "fixture_manifest_digest", "native_outputs", "parser",
        "result", "schema_version", "streams", "tool",
    })
    if doc["schema_version"] != RAW_RECEIPT_SCHEMA:
        raise OutputContractError("raw receipt has an unsupported schema")
    if doc["case_id"] not in CASES:
        raise OutputContractError("raw receipt has an unknown case")
    _digest(doc["fixture_manifest_digest"], "raw receipt.fixture_manifest_digest")
    tool = _object(doc["tool"], "raw receipt.tool", {"argv0_sha256", "name", "version"})
    if tool["name"] != "gitleaks":
        raise OutputContractError("raw receipt does not attest gitleaks")
    _digest(tool["argv0_sha256"], "raw receipt.tool.argv0_sha256")
    _text(tool["version"], "raw receipt.tool.version")
    result = _object(doc["result"], "raw receipt.result", {"duration_ms", "exit_code", "status"})
    _count(result["duration_ms"], "raw receipt.result.duration_ms")
    if result["status"] not in {item.value for item in runner.Status}:
        raise OutputContractError("raw receipt has an unknown runner status")
    if result["exit_code"] is not None and type(result["exit_code"]) is not int:
        raise OutputContractError("raw receipt.result.exit_code must be an integer or null")
    execution = _object(doc["execution"], "raw receipt.execution", {
        "process_group_settled", "process_tree_settled", "repository_ownership_settled",
        "repository_publication", "request_id", "terminal",
    })
    if (type(execution["process_group_settled"]) is not bool
            or type(execution["process_tree_settled"]) is not bool
            or execution["process_group_settled"] is not True
            or execution["process_tree_settled"] is not True
            or execution["repository_ownership_settled"] is not True):
        raise OutputContractError("raw receipt lacks settled execution/repository authority")
    if execution["repository_publication"] not in {"published", "not_requested", "fenced", "partial", "committed_with_fault"}:
        raise OutputContractError("raw receipt has an unknown repository publication")
    if type(execution["request_id"]) is not str or len(execution["request_id"]) != 32:
        raise OutputContractError("raw receipt has an invalid execution request id")
    _text(execution["terminal"], "raw receipt.execution.terminal")
    streams = doc["streams"]
    if type(streams) is not list or len(streams) != 2:
        raise OutputContractError("raw receipt must carry stdout and stderr settlements")
    parsed_streams = [_validate_stream(value, f"raw receipt.streams[{index}]") for index, value in enumerate(streams)]
    if [item["role"] for item in parsed_streams] != ["stdout", "stderr"]:
        raise OutputContractError("raw receipt stream order must be stdout then stderr")
    native = _object(doc["native_outputs"], "raw receipt.native_outputs", {
        "claim_retained", "clean", "cleanup_settled", "committed", "policy_count",
        "uncertain", "unpublished",
    })
    if type(native["clean"]) is not bool or type(native["cleanup_settled"]) is not bool or type(native["claim_retained"]) is not bool:
        raise OutputContractError("raw receipt native receipt has invalid flags")
    if native["cleanup_settled"] is not True or native["claim_retained"] is not False:
        raise OutputContractError("raw receipt native output ownership is unsettled")
    _count(native["policy_count"], "raw receipt.native_outputs.policy_count")
    if any(type(native[field]) is not list for field in ("committed", "uncertain", "unpublished")):
        raise OutputContractError("raw receipt native output partitions must be arrays")
    facts = [
        _validate_native_fact(value, f"raw receipt.native_outputs.{group}[{index}]")
        for group in ("committed", "uncertain", "unpublished")
        for index, value in enumerate(native[group])
    ]
    indices = [fact["policy_index"] for fact in facts]
    if (len(facts) != native["policy_count"] or len(indices) != len(set(indices))
            or set(indices) != set(range(native["policy_count"]))):
        raise OutputContractError("raw receipt native output partition is incomplete or overlapping")
    parser = _object(doc["parser"], "raw receipt.parser", {"complete", "outcome", "parser"})
    if type(parser["complete"]) is not bool:
        raise OutputContractError("raw receipt.parser.complete must be boolean")
    _text(parser["parser"], "raw receipt.parser.parser")
    if parser["outcome"] not in {"empty", "non_empty", "malformed", "truncated", "non_utf8", "partial", "unavailable"}:
        raise OutputContractError("raw receipt parser outcome is unsupported")
    return doc


def receipt_from_run_result(*, case_id: str, fixture_manifest_digest: str, tool_version: str,
                            result: runner.RunResult, parser: Mapping[str, object]) -> dict:
    """Produce a raw receipt from runner-owned authenticated facts only.

    This is intentionally the only source producer.  Callers cannot hand-write
    execution or stream fields, and legacy/path-based runner results are refused.
    """
    if case_id not in CASES or type(result) is not runner.RunResult:
        raise OutputContractError("receipt producer requires a known case and RunResult")
    if result.tool != "gitleaks" or not result.cmd or Path(result.cmd[0]).name != "gitleaks":
        raise OutputContractError("receipt producer refuses a non-gitleaks runner invocation")
    meta = result.meta
    required = {"execution_request_id", "execution_terminal", "process_group_settled",
                "process_tree_settled", "repository_publication", "repository_ownership_settled",
                "streams", "native_outputs"}
    if not required.issubset(meta) or not isinstance(meta["streams"], dict):
        raise OutputContractError("receipt producer refuses a non-repository-backed runner result")
    streams = []
    for role in ("stdout", "stderr"):
        source = meta["streams"].get(role)
        if type(source) is not dict:
            raise OutputContractError(f"receipt producer lacks {role} settlement")
        streams.append({key: source[key] for key in (
            "role", "terminal", "observed_bytes", "retained_bytes", "observed_sha256",
            "retained_sha256", "lines",
        )})
    argv0 = result.cmd[0] if result.cmd else ""
    try:
        with open(argv0, "rb") as handle:
            executable_digest = "sha256:" + hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as exc:
        raise OutputContractError("receipt producer cannot attest the executed gitleaks binary") from exc
    native_source = meta["native_outputs"]
    receipt = {
        "schema_version": RAW_RECEIPT_SCHEMA,
        "case_id": case_id,
        "fixture_manifest_digest": fixture_manifest_digest,
        "tool": {"name": "gitleaks", "argv0_sha256": executable_digest, "version": tool_version},
        "result": {"status": result.status.value, "exit_code": result.exit_code,
                   "duration_ms": round(result.duration * 1000)},
        "execution": {
            "request_id": meta["execution_request_id"], "terminal": meta["execution_terminal"],
            "process_group_settled": meta["process_group_settled"],
            "process_tree_settled": meta["process_tree_settled"],
            "repository_publication": meta["repository_publication"],
            "repository_ownership_settled": meta["repository_ownership_settled"],
        },
        "streams": streams,
        "native_outputs": {key: native_source[key] for key in (
            "clean", "policy_count", "committed", "uncertain", "unpublished",
            "cleanup_settled", "claim_retained",
        )},
        "parser": dict(parser),
    }
    validate_raw_receipt(receipt)
    return receipt


def collect_case_matrix(*, fixture_manifest: object, receipts: Sequence[object]) -> dict:
    """Derive the exact, ordered nine-case matrix from source receipts.

    The output records observations only.  Promotion to ``C-OUTPUT-CONTRACT``
    remains the job of an external, candidate-bound H1 collector and signer.
    """
    manifest = validate_fixture_manifest(fixture_manifest)
    if type(receipts) not in (list, tuple) or len(receipts) != len(CASES):
        raise OutputContractError("collector requires exactly nine raw receipts")
    fixture_digest = "sha256:" + hashlib.sha256(_canonical_bytes(manifest)).hexdigest()
    rows = []
    for expected_case, raw in zip(CASES, receipts):
        receipt = validate_raw_receipt(raw)
        if receipt["case_id"] != expected_case:
            raise OutputContractError("raw receipts are not in frozen case order")
        if receipt["fixture_manifest_digest"] != fixture_digest:
            raise OutputContractError("raw receipt is bound to another fixture manifest")
        if receipt["tool"]["version"] != manifest["tool"]["version"]:
            raise OutputContractError("raw receipt does not attest the frozen gitleaks version")
        if receipt["result"]["status"] != EXPECTED_STATUS[expected_case]:
            raise OutputContractError(f"{expected_case} did not produce its documented runner result")
        rows.append({
            "id": expected_case,
            "parser_outcome": receipt["parser"]["outcome"],
            "receipt_digest": raw_receipt_digest(receipt),
            "runner_status": receipt["result"]["status"],
        })
    return {
        "schema_version": CASE_MATRIX_SCHEMA,
        "fixture_manifest_digest": fixture_digest,
        "observation": "h1-attestation-required",
        "cases": rows,
    }


def validate_case_matrix(document: object) -> dict:
    doc = _object(document, "case matrix", {"cases", "fixture_manifest_digest", "observation", "schema_version"})
    if doc["schema_version"] != CASE_MATRIX_SCHEMA or doc["observation"] != "h1-attestation-required":
        raise OutputContractError("case matrix has an unsupported semantic state")
    _digest(doc["fixture_manifest_digest"], "case matrix.fixture_manifest_digest")
    if type(doc["cases"]) is not list or len(doc["cases"]) != len(CASES):
        raise OutputContractError("case matrix must have exactly nine cases")
    for expected, value in zip(CASES, doc["cases"]):
        row = _object(value, "case matrix.case", {"id", "parser_outcome", "receipt_digest", "runner_status"})
        if row["id"] != expected or row["runner_status"] != EXPECTED_STATUS[expected]:
            raise OutputContractError("case matrix case/result mapping drifted")
        _digest(row["receipt_digest"], "case matrix.case.receipt_digest")
        _text(row["parser_outcome"], "case matrix.case.parser_outcome")
    return doc
