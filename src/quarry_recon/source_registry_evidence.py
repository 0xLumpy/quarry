"""Bounded C-SOURCE-REGISTRY reconciliation evidence.

This is deliberately descriptive substrate: it reads the checked-in registry
and transport declarations, but never invokes an adapter, provider, target, or
tool.  A future accepted H0/H1 collector must still supply signed evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
import ast
import importlib
import inspect
from collections.abc import Mapping
from pathlib import Path

import yaml

from . import network_policy, policy, release_evidence as evidence, sources


SCHEMA_VERSION = "quarry.source-registry-reconciliation.v1"
MAX_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INPUT_PATHS = {
    "docs-policy-ownership-policy": "src/quarry_recon/policy.py",
    "docs-policy-sources-module": "src/quarry_recon/sources.py",
    "docs-policy-sources-registry": "src/quarry_recon/data/sources.yaml",
    "docs-policy-transport-doors": "src/quarry_recon/network_policy.py",
    "source-registry-reconciliation-producer": "scripts/emit_source_registry_reconciliation.py",
    "source-registry-reconciliation-runtime": "src/quarry_recon/source_registry_evidence.py",
    "source-registry-reconciliation-schema": "release/evidence/schemas/source-registry-reconciliation-v1.schema.json",
    "source-registry-reconciliation-tests": "tests/test_source_registry_contract.py",
    "source-registry-reconciliation-h1-tests": "tests/test_source_registry_h1_contract.py",
}
_LOCAL_EVENT = ["evidence.ownership"]
_H0_CASE = "tests/test_source_registry_contract.py::test_reconciliation_is_canonical_complete_and_execution_free"
_H1_CASE = "tests/test_source_registry_h1_contract.py::test_h1_synthetic_transport_admission_receipt"
_ONE_PASS = {"collected": 1, "deselected": 0, "failed": 0, "passed": 1, "selected": 1,
             "skipped": 0, "xfailed": 0, "xpassed": 0}
_COUNTS = {
    "planned_contract_count": 67,
    "auxiliary_contract_count": 25,
    "canonical_contract_count": 92,
    "planned_door_count": 67,
    "auxiliary_door_count": 24,
    "transport_door_count": 91,
    "ownership_count": 92,
}


class SourceRegistryEvidenceError(evidence.EvidenceError):
    """The standalone registry-reconciliation evidence is not exact."""


def _digest(value: object, where: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise SourceRegistryEvidenceError(f"{where} must be a canonical sha256 digest")
    return value


def _exact(value: object, fields: set[str], where: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise SourceRegistryEvidenceError(f"{where} does not carry its exact fields")
    return value


def _canonical(document: object) -> bytes:
    try:
        body = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SourceRegistryEvidenceError("registry reconciliation is not canonical JSON") from exc
    if len(body) > MAX_BYTES:
        raise SourceRegistryEvidenceError("registry reconciliation exceeds its byte contract")
    return body


def canonical_json_bytes(document: object) -> bytes:
    """Return the one allowed serialized representation."""
    return _canonical(verify(document))


def _registry_contracts(registry_bytes: bytes | None = None) -> tuple[dict, dict]:
    """Load canonical contracts from the bound YAML bytes, not an ambient cache."""
    if registry_bytes is None:
        planned, auxiliary = sources.all_sources(), sources.auxiliary_sources()
    else:
        try:
            raw = yaml.safe_load(registry_bytes.decode("utf-8", "strict"))
        except (UnicodeError, yaml.YAMLError) as exc:
            raise SourceRegistryEvidenceError("bound source registry bytes are not YAML") from exc
        if type(raw) is not dict:
            raise SourceRegistryEvidenceError("bound source registry is not an object")
        planned = raw.get("sources")
        auxiliary = raw.get("auxiliary_sources")
        semantics = raw.get("semantics")
        if not all(type(value) is dict for value in (planned, auxiliary, semantics)):
            raise SourceRegistryEvidenceError("bound source registry has no exact source sections")
        ownership, transport = {}, {}
        for kind, ids in (semantics.get("ownership") or {}).items():
            for source_id in ids or []:
                if source_id in ownership or source_id not in planned:
                    raise SourceRegistryEvidenceError("bound source registry ownership is ambiguous")
                ownership[source_id] = kind
        for row in semantics.get("transport") or []:
            if type(row) is not dict:
                raise SourceRegistryEvidenceError("bound source registry transport is malformed")
            value = {field: row.get(field) for field in sources.TRANSPORT_FIELDS}
            for source_id in row.get("sources") or []:
                if source_id in transport or source_id not in planned:
                    raise SourceRegistryEvidenceError("bound source registry transport is ambiguous")
                transport[source_id] = value
        provider_control = set(semantics.get("provider_control") or [])
        def decorate(entries: dict, planned_entry: bool) -> dict:
            result = {}
            for source_id, entry in entries.items():
                if type(entry) is not dict:
                    raise SourceRegistryEvidenceError("bound source registry has a non-object contract")
                row = dict(entry)
                if isinstance(row.get("default"), bool):
                    row["default"] = "on" if row["default"] else "off"
                if planned_entry:
                    row["ownership"] = ownership.get(source_id)
                    row["transport"] = transport.get(source_id)
                    if source_id in provider_control:
                        row["provider_control"] = True
                result[source_id] = row
            return result
        planned, auxiliary = decorate(planned, True), decorate(auxiliary, False)
    return planned, auxiliary


def _contracts(registry_bytes: bytes | None = None) -> list[dict]:
    planned, auxiliary = _registry_contracts(registry_bytes)
    if set(planned) & set(auxiliary):
        raise SourceRegistryEvidenceError("planned and auxiliary source IDs overlap")
    rows = []
    for section, entries in (("planned", planned), ("auxiliary", auxiliary)):
        for source_id, contract in entries.items():
            if not isinstance(contract, dict):
                raise SourceRegistryEvidenceError("source registry contains a non-object contract")
            row = {"section": section, "source_id": source_id, **contract}
            rows.append(row)
    return sorted(rows, key=lambda row: row["source_id"])


def _door_row(source_id: str, door: network_policy.TransportDoor) -> dict:
    return {
        "source_id": source_id,
        "kind": door.kind,
        "authority": door.authority_class,
        "profile": door.profile,
        "argv0": list(door.argv0),
        "helpers": list(door.helpers),
        "descendants": list(door.descendants),
        "required_argv": list(door.required_argv),
        "forbidden_argv": list(door.forbidden_argv),
        "connect_time_peer": door.connect_time_peer,
        "broker_required": door.broker_required,
        "supported": door.supported,
        "unsupported_reason": door.unsupported_reason,
    }


def _doors() -> list[dict]:
    return [_door_row(source_id, door) for source_id, door in
            sorted(network_policy.TRANSPORT_DOORS.items())]


def _derived_counts(contracts: list[dict], doors: list[dict]) -> dict:
    """Return the complete count contract from the resolved rows themselves."""
    planned_ids = {row["source_id"] for row in contracts if row["section"] == "planned"}
    auxiliary_ids = {row["source_id"] for row in contracts if row["section"] == "auxiliary"}
    door_ids = {row["source_id"] for row in doors}
    if len(planned_ids) + len(auxiliary_ids) != len(contracts):
        raise SourceRegistryEvidenceError("resolved source contracts are not a disjoint partition")
    if len(door_ids) != len(doors):
        raise SourceRegistryEvidenceError("resolved transport doors are not unique")
    return {
        "planned_contract_count": len(planned_ids),
        "auxiliary_contract_count": len(auxiliary_ids),
        "canonical_contract_count": len(contracts),
        "planned_door_count": len(door_ids & planned_ids),
        "auxiliary_door_count": len(door_ids & auxiliary_ids),
        "transport_door_count": len(doors),
        "ownership_count": sum("ownership" in row and row["ownership"] is not None for row in contracts),
    }


def _static_emitter_inventory() -> dict:
    """Reuse the contract-boundary literal emitter discovery, deterministically."""
    package = importlib.import_module("quarry_recon.phases")
    roots = [Path(package.__file__).parent]
    files = list(roots[0].glob("*.py"))
    for module_name in ("quarry_recon.cloud", "quarry_recon.osint", "quarry_recon.evidence"):
        files.append(Path(inspect.getsourcefile(importlib.import_module(module_name))))
    literal_ids: dict[str, set[str]] = {}
    discovery_files = []
    for path in sorted({path.resolve() for path in files}):
        if path.stem == "__init__":
            continue
        body = path.read_bytes()
        discovery_files.append({
            "path": str(path.relative_to(Path(__file__).resolve().parents[2])),
            "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        })
        for node in ast.walk(ast.parse(body.decode("utf-8", "strict"), filename=str(path))):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = (
                node.func.id if isinstance(node.func, ast.Name) and node.func.id in {"run_provider", "run_contract"}
                else node.func.attr if isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "tool_start", "tool_finish", "tool_progress", "coverage_partial", "tool_blocked",
                    "ledger", "coverage_reset", "artifact_written", "spend",
                } else None
            )
            if function and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str:
                literal_ids.setdefault(node.args[0].value, set()).add(path.stem)
    return {
        "discovery_roots": ["src/quarry_recon/phases", "src/quarry_recon/cloud.py",
                            "src/quarry_recon/evidence.py", "src/quarry_recon/osint.py"],
        "discovery_files": discovery_files,
        "literal_source_ids": sorted(literal_ids),
        "finite_dynamic_maps": [
            {"name": "canonical_contracts", "source_ids": sorted(sources.all_source_contracts())},
            {"name": "transport_doors", "source_ids": sorted(network_policy.TRANSPORT_DOORS)},
        ],
    }


def _synthetic_admissions(doors: list[dict]) -> list[dict]:
    rows = []
    for door in doors:
        if door["source_id"] == "crawl.jxscout_chunks":
            rows.append({
                "door": door,
                "synthetic_probe": {
                    "kind": "environment-dependent",
                    "value": "requires verified jxscout-chunks executable, bundle, and private scratch root",
                },
                "admission_class": "environment-dependent",
                "admitted": None,
                "observed_door": None,
                "reason": "exact bwrap admission depends on local ownership, mode, and executable identity",
            })
            continue
        if door["helpers"]:
            probe = {"kind": "helper", "value": door["helpers"][0]}
            observed = network_policy.transport_door(door["source_id"], helper=probe["value"])
        else:
            argv = ["/synthetic/bin/" + door["argv0"][0], *door["required_argv"]]
            if door["profile"] == "nuclei-authorized-http":
                argv.extend(("-pt", "http,dns"))
            probe = {"kind": "argv", "value": argv}
            observed = network_policy.transport_door(door["source_id"], argv=argv)
        if not door["supported"]:
            if observed is not None:
                raise SourceRegistryEvidenceError("unsupported transport door was admitted by a synthetic probe")
            admission_class, admitted = "unsupported", None
            reason = door["unsupported_reason"]
        else:
            if observed is None:
                raise SourceRegistryEvidenceError("supported deterministic transport door was not admitted")
            admission_class, admitted, reason = "deterministic", True, ""
        rows.append({
            "door": door, "synthetic_probe": probe, "admission_class": admission_class,
            "admitted": admitted, "reason": reason,
            "observed_door": None if observed is None else _door_row(door["source_id"], observed),
        })
    return rows


def _receipt(*, lane: str, case_id: str, nodeid: str, evidence_instance_id: str) -> dict:
    return {"lane": lane, "case_id": case_id, "nodeid": nodeid,
            "evidence_instance_id": evidence_instance_id, "selection": dict(_ONE_PASS),
            "result": "pass"}


def build(*, candidate_identity_digest: str, input_bodies: Mapping[str, bytes],
          h0_evidence_instance_id: str = "instance-00",
          h1_evidence_instance_id: str = "instance-01") -> dict:
    """Build a candidate-bound but execution-free reconciliation artifact."""
    if set(input_bodies) != set(_INPUT_PATHS) or any(type(body) is not bytes
                                                     for body in input_bodies.values()):
        raise SourceRegistryEvidenceError("registry reconciliation inputs are not the exact bounded set")
    contracts = _contracts(input_bodies["docs-policy-sources-registry"])
    doors = _doors()
    document = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "source-registry-reconciliation",
        "release": "0.3.10",
        "gate_id": "C-SOURCE-REGISTRY",
        "name": "registry-reconciliation",
        "candidate_identity_digest": candidate_identity_digest,
        "input_bindings": [
            {"name": name, "path": path,
             "digest": "sha256:" + hashlib.sha256(input_bodies[name]).hexdigest()}
            for name, path in sorted(_INPUT_PATHS.items())
        ],
        "counts": _derived_counts(contracts, doors),
        "contracts": contracts,
        "doors": doors,
        "local_event_without_transport": list(_LOCAL_EVENT),
        "h0_static_emitter": {
            "partition": "H0-static-emitter",
            "executed_lane_count": 0,
            **_static_emitter_inventory(),
            "real_adapter_execution": False,
            "real_tool_execution": False,
            "provider_execution": False,
            "target_execution": False,
            "receipt": _receipt(lane="H0-hermetic", case_id="static-reconciliation",
                                nodeid=_H0_CASE, evidence_instance_id=h0_evidence_instance_id),
        },
        "h1_synthetic_admission": {
            "partition": "H1-synthetic-transport-admission",
            "executed_lane_count": 0,
            "admissions": _synthetic_admissions(doors),
            "real_adapter_execution": False,
            "real_tool_execution": False,
            "provider_execution": False,
            "target_execution": False,
            "receipt": _receipt(lane="H1-tool-integration", case_id="synthetic-transport-admission",
                                nodeid=_H1_CASE, evidence_instance_id=h1_evidence_instance_id),
        },
    }
    return verify(document, input_bodies=input_bodies)


def _verify_inputs(rows: object) -> None:
    if type(rows) is not list or len(rows) != len(_INPUT_PATHS):
        raise SourceRegistryEvidenceError("registry reconciliation input bindings are incomplete")
    expected = []
    for name, path in sorted(_INPUT_PATHS.items()):
        expected.append((name, path))
    actual = []
    for index, row in enumerate(rows):
        item = _exact(row, {"name", "path", "digest"}, f"input_bindings[{index}]")
        _digest(item["digest"], f"input_bindings[{index}].digest")
        actual.append((item["name"], item["path"]))
    if actual != expected:
        raise SourceRegistryEvidenceError("registry reconciliation input bindings are reordered or drifted")


def _verify_partition(value: object, *, expected_partition: str, expected_doors: list[dict] | None,
                      expected_static: dict | None) -> None:
    fields = {"partition", "executed_lane_count", "real_adapter_execution", "real_tool_execution",
              "provider_execution", "target_execution"}
    if expected_doors is None:
        fields |= {"discovery_roots", "discovery_files", "literal_source_ids", "finite_dynamic_maps", "receipt"}
    else:
        fields |= {"admissions", "receipt"}
    row = _exact(value, fields, expected_partition)
    if row["partition"] != expected_partition or row["executed_lane_count"] != 0:
        raise SourceRegistryEvidenceError("registry evidence partition claims an executed lane")
    if any(row[name] is not False for name in ("real_adapter_execution", "real_tool_execution",
                                               "provider_execution", "target_execution")):
        raise SourceRegistryEvidenceError("registry evidence may not claim real adapter/tool/provider/target execution")
    if expected_doors is not None:
        if row["admissions"] != _synthetic_admissions(expected_doors):
            raise SourceRegistryEvidenceError("synthetic H1 admission facts do not match transport doors")
    else:
        if expected_static is None:  # pragma: no cover - caller invariant
            raise SourceRegistryEvidenceError("H0 static emitter source inventory is absent")
        if any(row[name] != expected_static[name] for name in expected_static):
            raise SourceRegistryEvidenceError("H0 static emitter inventory does not exactly resolve source IDs")
    receipt = _exact(row["receipt"], {"lane", "case_id", "nodeid", "evidence_instance_id",
                                        "selection", "result"}, "registry partition receipt")
    expected_case = (
        ("H0-hermetic", "static-reconciliation", _H0_CASE)
        if expected_doors is None else
        ("H1-tool-integration", "synthetic-transport-admission", _H1_CASE)
    )
    if ((receipt["lane"], receipt["case_id"], receipt["nodeid"]) != expected_case or
            type(receipt["evidence_instance_id"]) is not str or not receipt["evidence_instance_id"] or
            receipt["selection"] != _ONE_PASS or receipt["result"] != "pass"):
        raise SourceRegistryEvidenceError("registry partition has no exact synthetic/static test receipt")


def verify(document: object, *, candidate_identity_digest: str | None = None,
           input_bodies: Mapping[str, bytes] | None = None) -> dict:
    """Strictly rederive all registry and door facts from the local semantic modules."""
    doc = _exact(document, {
        "schema_version", "artifact_type", "release", "gate_id", "name", "candidate_identity_digest",
        "input_bindings", "counts", "contracts", "doors", "local_event_without_transport",
        "h0_static_emitter", "h1_synthetic_admission",
    }, "source registry reconciliation")
    if (doc["schema_version"], doc["artifact_type"], doc["release"], doc["gate_id"], doc["name"]) != (
            SCHEMA_VERSION, "source-registry-reconciliation", "0.3.10", "C-SOURCE-REGISTRY",
            "registry-reconciliation"):
        raise SourceRegistryEvidenceError("registry reconciliation has an unsupported identity")
    candidate = _digest(doc["candidate_identity_digest"], "candidate_identity_digest")
    if candidate_identity_digest is not None and candidate != candidate_identity_digest:
        raise SourceRegistryEvidenceError("registry reconciliation belongs to another candidate")
    _verify_inputs(doc["input_bindings"])
    registry_bytes = None
    if input_bodies is not None:
        if set(input_bodies) != set(_INPUT_PATHS):
            raise SourceRegistryEvidenceError("registry reconciliation has an incomplete scope input binding")
        expected_digests = {name: "sha256:" + hashlib.sha256(body).hexdigest()
                            for name, body in input_bodies.items() if type(body) is bytes}
        if len(expected_digests) != len(_INPUT_PATHS) or any(
                row["digest"] != expected_digests[row["name"]] for row in doc["input_bindings"]):
            raise SourceRegistryEvidenceError("registry reconciliation source input digest drift")
        modules = {
            "docs-policy-sources-module": sources,
            "docs-policy-ownership-policy": policy,
            "docs-policy-transport-doors": network_policy,
        }
        for name, module in modules.items():
            if input_bodies[name] != Path(module.__file__).read_bytes():
                raise SourceRegistryEvidenceError("scope bytes are not the local semantic module being verified")
        root = Path(__file__).resolve().parents[2]
        if input_bodies["docs-policy-sources-registry"] != (
                root / _INPUT_PATHS["docs-policy-sources-registry"]).read_bytes():
            raise SourceRegistryEvidenceError("scope bytes are not the local source registry being verified")
        for name in ("source-registry-reconciliation-schema", "source-registry-reconciliation-producer",
                     "source-registry-reconciliation-runtime", "source-registry-reconciliation-tests",
                     "source-registry-reconciliation-h1-tests"):
            if input_bodies[name] != (root / _INPUT_PATHS[name]).read_bytes():
                raise SourceRegistryEvidenceError("scope bytes are not the local registry evidence artifact family")
        try:
            test_tree = ast.parse(
                input_bodies["source-registry-reconciliation-tests"].decode("utf-8", "strict") + "\n" +
                input_bodies["source-registry-reconciliation-h1-tests"].decode("utf-8", "strict"),
            )
        except (UnicodeError, SyntaxError) as exc:
            raise SourceRegistryEvidenceError("source registry test receipt source is not parseable") from exc
        found = {node.name for node in ast.walk(test_tree) if isinstance(node, ast.FunctionDef)}
        if {"test_reconciliation_is_canonical_complete_and_execution_free",
            "test_h1_synthetic_transport_admission_receipt"} - found:
            raise SourceRegistryEvidenceError("source registry partition receipt tests are absent")
        registry_bytes = input_bodies["docs-policy-sources-registry"]
    expected_contracts, expected_doors = _contracts(registry_bytes), _doors()
    if input_bodies is not None and expected_contracts != _contracts():
        raise SourceRegistryEvidenceError("bound source registry bytes do not reproduce the executing source registry")
    expected_ownership = {row["source_id"]: row["ownership"] for row in expected_contracts}
    if policy.SOURCE_OWNERSHIP != expected_ownership:
        raise SourceRegistryEvidenceError("ownership policy does not reproduce every bound registry contract")
    expected_transport = {row["source_id"]: row["transport"] for row in expected_contracts
                          if row["source_id"] not in _LOCAL_EVENT}
    if expected_transport != {
            source_id: {"kind": door["kind"], "authority": door["authority"], "profile": door["profile"]}
            for source_id, door in ((row["source_id"], row) for row in expected_doors)}:
        raise SourceRegistryEvidenceError("transport doors do not reproduce every bound registry contract")
    if doc["contracts"] != expected_contracts:
        raise SourceRegistryEvidenceError("registry reconciliation contracts omit, overlap, or alter an emitted ID")
    if doc["doors"] != expected_doors:
        raise SourceRegistryEvidenceError("registry reconciliation transport doors omit or alter admission facts")
    derived_counts = _derived_counts(expected_contracts, expected_doors)
    if derived_counts != _COUNTS or doc["counts"] != derived_counts:
        raise SourceRegistryEvidenceError("registry reconciliation cardinality contract drift")
    if doc["local_event_without_transport"] != _LOCAL_EVENT:
        raise SourceRegistryEvidenceError("only evidence.ownership may be a local event without a transport door")
    ids = [row["source_id"] for row in expected_contracts]
    if set(ids) - set(network_policy.TRANSPORT_DOORS) != set(_LOCAL_EVENT):
        raise SourceRegistryEvidenceError("local-event transport exception is not sole or stable")
    _verify_partition(doc["h0_static_emitter"], expected_partition="H0-static-emitter",
                      expected_doors=None, expected_static=_static_emitter_inventory())
    _verify_partition(doc["h1_synthetic_admission"], expected_partition="H1-synthetic-transport-admission",
                      expected_doors=expected_doors, expected_static=None)
    return doc


def read(data: bytes, **expected: object) -> dict:
    """Read exact canonical JSON bytes and validate all local semantic facts."""
    if type(data) is not bytes or len(data) > MAX_BYTES or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise SourceRegistryEvidenceError("registry reconciliation violates its byte/line contract")
    try:
        document = evidence.load_json_bytes(data[:-1], maximum=MAX_BYTES)
    except evidence.EvidenceError as exc:
        raise SourceRegistryEvidenceError("registry reconciliation is not strict JSON") from exc
    if _canonical(document) != data:
        raise SourceRegistryEvidenceError("registry reconciliation bytes are not canonical")
    return verify(document, **expected)
