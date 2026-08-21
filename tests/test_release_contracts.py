"""Canonical scope, trust, artifact and aggregation contracts for v0.3.10."""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence
from quarry_recon import fault_store_evidence
from quarry_recon import release_v310_05
from quarry_recon import resource_contract
from quarry_recon import path_identity_evidence
from quarry_recon import private_files_evidence
from quarry_recon import source_registry_evidence

pytestmark = pytest.mark.offline

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/release_contracts/ed25519-golden-v1.json"
APPROVAL_SEED = hashlib.sha256(b"Quarry test-only approval signing key v1").digest()
GATE_SEED = hashlib.sha256(b"Quarry test-only gate signing key v1").digest()
_PATH_IDENTITY_CACHE: dict[str, dict] = {}


def _public_key(seed: bytes) -> bytes:
    scalar = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return contracts._point_encode(contracts._scalar_mult(contracts._ED25519_BASE, scalar))


PUBLIC = _public_key(APPROVAL_SEED)


def _digest(byte: str) -> str:
    return "sha256:" + byte * 64


def _review(approved_at: str = "2026-08-01T00:00:00Z") -> dict:
    return {
        "approved_at": approved_at,
        "review_id": "test-review",
        "reviewer": "test-approver",
        "signature": None,
    }


def _sign(message: bytes, *, seed: bytes) -> bytes:
    public = _public_key(seed)
    expanded = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(expanded[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") \
        % contracts._ED25519_L
    encoded_r = contracts._point_encode(contracts._scalar_mult(contracts._ED25519_BASE, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") \
        % contracts._ED25519_L
    encoded_s = ((nonce + challenge * scalar) % contracts._ED25519_L).to_bytes(32, "little")
    return encoded_r + encoded_s


def _policy() -> dict:
    return copy.deepcopy(json.loads(FIXTURE.read_text())["policy"])


def _sign_contract_review(
    document: dict, policy: dict, *, approved_at: str = "2026-08-01T00:00:00Z",
) -> None:
    document["approval"] = _review(approved_at)
    message = contracts.contract_review_preimage(
        payload_digest=contracts.contract_review_payload_digest(document),
        trust_policy_digest=evidence.canonical_digest(policy),
    )
    document["approval"]["signature"] = {
        "algorithm": "ed25519",
        "key_id": "test-approval-v1",
        "value": "base64:" + base64.b64encode(
            _sign(message, seed=APPROVAL_SEED)
        ).decode("ascii"),
    }


def _read(path: str, reader) -> dict:
    return reader((ROOT / path).read_bytes())


def _benchmark_baseline_body(thresholds: dict, gate_id: str) -> bytes:
    return contracts.canonical_json_line({
        "artifact_type": "benchmark-baseline",
        "gate_id": gate_id,
        "metrics": [{
            "metric": row["metric"],
            "unit": row["unit"],
            "value": 10_000,
        } for row in thresholds["thresholds"]
            if row["gate_id"] == gate_id and row["class"] == "regression"],
        "release": "0.3.10",
        "schema_version": contracts.BENCHMARK_BASELINE_SCHEMA,
    })


def _synthetic_sdist() -> bytes:
    stream = io.BytesIO()
    root = "quarry_recon-0.3.10"
    files = {
        f"{root}/LICENSE": b"Synthetic MIT license fixture\n",
        f"{root}/NOTICE": b"Synthetic release fixture; no third-party bundled bytes.\n",
        f"{root}/PKG-INFO": b"Metadata-Version: 2.1\nName: quarry-recon\nVersion: 0.3.10\n",
        f"{root}/pyproject.toml": (
            b"[build-system]\nrequires=['setuptools']\n"
            b"[project]\nname='quarry-recon'\nversion='0.3.10'\n"
        ),
        f"{root}/release/evidence/schemas/release-scope-v1.schema.json": b"{}\n",
        f"{root}/src/quarry_recon/__init__.py": b"__version__ = '0.3.10'\n",
        f"{root}/src/quarry_recon/data/default.yaml": b"fixture: true\n",
    }
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.mode = 0o644
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return gzip.compress(stream.getvalue(), mtime=0)


def _synthetic_wheel() -> bytes:
    stream = io.BytesIO()
    dist = "quarry_recon-0.3.10.dist-info"
    files = {
        f"{dist}/METADATA": (
            b"Metadata-Version: 2.1\nName: quarry-recon\nVersion: 0.3.10\n"
            b"Requires-Dist: click>=8.2\nRequires-Dist: pyyaml>=6.0\n"
            b"Requires-Dist: idna>=3.4\n"
            b"Requires-Dist: tomli>=2.0; python_version < '3.11'\n"
        ),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: quarry-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist}/entry_points.txt": b"[console_scripts]\nquarry=quarry_recon.cli:cli\n",
        f"{dist}/licenses/LICENSE": b"Synthetic MIT license fixture\n",
        f"{dist}/licenses/NOTICE": b"Synthetic release fixture; no third-party bundled bytes.\n",
        "quarry_recon/__init__.py": b"__version__ = '0.3.10'\n",
        "quarry_recon/data/default.yaml": b"fixture: true\n",
        "quarry_recon/data/target.template.yaml": b"fixture: target\n",
        f"{dist.removesuffix('.dist-info')}.data/data/share/quarry-recon/schemas/release-scope-v1.schema.json": b"{}\n",
    }
    record_name = f"{dist}/RECORD"
    record_rows = []
    for name, body in sorted(files.items()):
        encoded = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        record_rows.append(f"{name},sha256={encoded},{len(body)}")
    record_rows.append(f"{record_name},,")
    files[record_name] = ("\n".join(record_rows) + "\n").encode("utf-8")
    with zipfile.ZipFile(stream, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, body in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, body)
    return stream.getvalue()


def _generic_supporting_body(gate_id: str, name: str, identity: dict) -> bytes:
    result = {"outcome": "pass", "subject": f"{gate_id}/{name}"}
    return contracts.canonical_json_line({
        "artifact_type": "machine-report",
        "assertion": {
            "id": f"{contracts.required_assertion_id(gate_id)}.{name}",
            "reason": None,
            "status": "pass",
        },
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": gate_id,
        "name": name,
        "records": [{
            "id": "record-000",
            "result": result,
            "result_digest": evidence.canonical_digest(result),
            "status": "pass",
        }],
        "release": "0.3.10",
        "schema_version": contracts.SUPPORTING_ARTIFACT_SCHEMA,
    })


def _v310_05_body(gate_id: str, artifact_kind: str, identity: dict) -> bytes:
    """Build the complete canonical matrix accepted by the frozen V310-05 parser."""
    matrix = release_v310_05._MATRICES[(gate_id, artifact_kind)]
    identity_mode = (
        "switch" if (gate_id, artifact_kind) == ("C-INSTALL-ROLLBACK", "filesystem-trace")
        else "none" if gate_id == "C-SECRETS"
        else "preserve"
    )
    before = _digest("6")
    after = _digest("7") if identity_mode == "switch" else before
    return contracts.canonical_json_line({
        "artifact_kind": artifact_kind,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "finished_at": "2026-08-14T10:20:01Z",
        "gate_id": gate_id,
        "schema_version": release_v310_05.SCHEMA_VERSION,
        "started_at": "2026-08-14T10:20:00Z",
        "trials": [{
            "after_identity": None if identity_mode == "none" else after,
            "artifact_digests": [_digest(format(index % 16, "x"))],
            "assertions": {name: True for name in sorted(assertions)},
            "before_identity": None if identity_mode == "none" else before,
            "case": case,
            "outcome": "pass",
        } for index, (case, assertions) in enumerate(sorted(matrix.items()))],
        "verdict": "pass",
    })


def _network_boundary_body(identity: dict, support: dict) -> bytes:
    h1 = next(row for row in support["environments"] if row["lane"] == "H1-tool-integration")
    direct = (
        ("connect", "10.203.0.1", "allow", "ok"),
        ("connect", "8.8.4.4", "deny", None),
        ("connect", "10.203.0.2", "deny", None),
        ("connect", "169.254.169.254", "deny", None),
        ("connect", "10.203.0.99", "deny", None),
        ("sendto", "10.203.0.1", "allow", "1"),
        ("sendto", "169.254.169.254", "deny", None),
        ("sendmsg", "10.203.0.1", "allow", "1"),
        ("sendmsg", "10.203.0.99", "deny", None),
    )
    refused = (
        "bücher.fixture.test", "oos.fixture.test", "8.8.4.4",
        "mixed.fixture.test", "protected.fixture.test", "rebind.fixture.test",
    )
    diagnostic = {
        "acceptance_errors": [],
        "broker": {
            "active_operations": 0, "complete": True, "dropped_records": 0,
            "fatal": None, "listener_hup": True, "open_plans": 0,
            "profile": "standard", "request_id": "a" * 32,
            "retained_connections": 0,
            "schema_version": "quarry.network-broker-summary.v1",
            "records": [{
                "decision": decision, "peer": peer,
                "port": 8080 if peer.startswith("10.203") else 80,
                "protocol": 6 if syscall == "connect" else 17,
                "reason": "fixed boundary witness", "result": result,
                "sequence": sequence,
                "socket_type": 1 if syscall == "connect" else 2,
                "stage": "settled", "syscall": syscall, "tid": 100,
            } for sequence, (syscall, peer, decision, result) in enumerate(direct)],
        },
        "dns_records": [{
            "count": 2 if name == "rebind.fixture.test" else 1,
            "dns": name, "kind": 1,
        } for name in sorted(contracts._NETWORK_BOUNDARY_DNS_NAMES)],
        "http_records": [
            {"host": host, "path": path}
            for host, path in sorted(contracts._NETWORK_BOUNDARY_HTTP_CONTACTS)
        ],
        "proxy": {
            "active_sockets": 0, "active_threads": 0, "complete": True,
            "dropped_records": 0, "fatal": None, "open_plans": 0,
            "request_id": "a" * 32,
            "schema_version": "quarry.browser-proxy-summary.v1",
            "records": [{
                "decision": "deny", "host": host, "method": "GET",
                "peer": None, "port": 8080, "reason": "fixed boundary refusal",
                "sequence": sequence, "stage": "authority",
            } for sequence, host in enumerate(refused)],
        },
        "proxy_effects": {
            "cidr_status": 404, "idna_status": 404, "rebind_first_status": 404,
            "redirect_status": 200,
            "start_location": "http://redirect.fixture.test:8080/final",
            "start_status": 302,
        },
        "reaped": [],
        "refused": {
            "direct_ip": True, "mixed": True, "protected": True,
            "rebind": True, "scope": True, "unicode_idna": True,
        },
        "schema_version": "quarry.network-boundary-h1.v1",
        "tracee_results": {
            "approved": 0, "control_plane": 1, "direct_ip": 1, "metadata": 1,
            "scanner_self": 1, "sendmsg_allowed": 1, "sendmsg_control": 1,
            "sendto_allowed": 1, "sendto_metadata": 1,
        },
    }
    return contracts.canonical_json_line({
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-NETWORK-BOUNDARY",
        "instances": [{
            "diagnostic": diagnostic,
            "environment": {key: h1[key] for key in (
                "architecture", "isolation_profile", "os", "python", "runner_image",
            )},
            "identity": {
                "lane": h1["lane"], "python": h1["python"],
                "runner_image": h1["runner_image"],
            },
        }],
        "release": "0.3.10",
        "schema_version": contracts.NETWORK_BOUNDARY_TRACE_SCHEMA,
    })


def _taxonomy_body(environment: dict, toolchain: list[dict]) -> bytes:
    pytest_tools = [tool for tool in toolchain if tool["name"] == "pytest"]
    assert len(pytest_tools) == 1
    lanes = [
        ("offline", "H0-hermetic", ["tests/taxonomy.py::test_offline"]),
        ("integration", "H1-tool-integration", ["tests/taxonomy.py::test_integration"]),
        ("corpus", "C0-private-corpus", ["tests/taxonomy.py::test_corpus"]),
        ("packaging", "P0-package-supply", ["tests/taxonomy.py::test_packaging"]),
        ("live", "L0-authorized-live", ["tests/taxonomy.py::test_live"]),
    ]
    return evidence.canonical_json_bytes({
        "capabilities": [{
            "name": "pytest", "nodes": ["tests/taxonomy.py::test_integration"],
        }],
        "collector": {
            "name": "pytest",
            "python_implementation": "CPython",
            "python_version": environment["python"],
            "version": pytest_tools[0]["version"],
        },
        "lanes": [
            {"lane": lane, "marker": marker, "nodes": nodes}
            for marker, lane, nodes in lanes
        ],
        "schema_version": evidence.PYTEST_TAXONOMY_SCHEMA,
        "selection": {
            "collected": 5,
            "deselected": 4,
            "keyword_expression": "",
            "mark_expression": "offline",
            "selected": 1,
            "selected_by_lane": [
                {"lane": lane, "selected": 1 if lane == "H0-hermetic" else 0}
                for _marker, lane, _nodes in lanes
            ],
        },
        "synthetic_process_nodes": [],
    })


def _h0_collection_nodes() -> list[str]:
    nodes = [
        "tests/test_config.py::TestProfileLoad::test_valid_profile_loads",
        "tests/test_phase1_privfs_core.py::test_strict_walk_refuses_a_symlink_at_every_directory_depth[1]",
        "tests/test_release_h0.py::test_tool_open_refuses_relative_or_non_normalized_paths[git]",
        "tests/taxonomy.py::test_offline_0",
        "tests/taxonomy.py::test_offline_3",
        "tests/taxonomy.py::test_offline_5",
    ]
    nodes.extend(
        nodeid for case in fault_store_evidence.CASES for nodeid in case["nodeids"]
    )
    nodes.extend(contracts._FAULT_REVISION_NODEIDS)
    nodes.extend(contracts._FAULT_FINALIZE_NODEIDS)
    nodes.extend(contracts._FAULT_CAMPAIGN_NODEIDS)
    nodes.extend(contracts._FAULT_RUNNER_H0_NODEIDS)
    return sorted(set(nodes), key=lambda value: value.encode("utf-8"))


def _h0_collection_taxonomy_body(environment: dict, toolchain: list[dict]) -> bytes:
    document = json.loads(_taxonomy_body(environment, toolchain))
    h0_nodes = _h0_collection_nodes()
    document["lanes"][0]["nodes"] = h0_nodes
    document["selection"].update({
        "collected": len(h0_nodes) + 4,
        "deselected": 4,
        "selected": len(h0_nodes),
    })
    document["selection"]["selected_by_lane"][0]["selected"] = len(h0_nodes)
    return evidence.canonical_json_bytes(document)


def _coverage_baseline() -> dict:
    policy = contracts.read_coverage_policy((ROOT / contracts.COVERAGE_POLICY_PATH).read_bytes())
    return {"files": [{
        "path": path, "lines": {"covered": 10, "total": 10},
        "branches": {"covered": 5, "total": 5},
    } for path in policy["source_roster"]]}


def _corpus_disclosure_body(fixture_digest: str) -> bytes:
    return contracts.canonical_json_line({
        "artifact_type": "synthetic-corpus-disclosure-attestation",
        "checks": {
            "deterministic_derivation": "pass",
            "disclosure_review": "pass",
            "schema_validation": "pass",
        },
        "corpus_gate_id": "C-CORPUS-SYNTHETIC",
        "derivation_tree_digests": [fixture_digest, fixture_digest],
        "fixture_digest": fixture_digest,
        "fixture_schema_digest": _digest("c"),
        "release": "0.3.10",
        "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
        "synthetic_value_inventory_digest": _digest("d"),
    })


def _private_files_bodies(identity: dict, instances: list[dict]) -> dict[str, bytes]:
    """Build deterministic synthetic observations for release-contract tests only."""
    collector_uid = 1000

    def stat_fact(kind: str, mode: int, uid: int, inode: int) -> dict:
        return {
            "device": 1, "gid": collector_uid, "inode": inode, "kind": kind,
            "mode": mode, "nlink": 1, "uid": uid,
        }

    umasks = [0, 2, 18, 63]
    observations = [
        {
            "case_id": "h0-create-directory-umask",
            "descriptor_stats": [
                {"kind": "directory", "mode": 0o700, "uid": collector_uid}
                for _ in umasks
            ],
            "error": None, "error_detail": None, "expected": "created",
            "mutation": "created", "operation": "create_directory",
            "post": stat_fact("directory", 0o700, collector_uid, 1), "pre": None,
            "tested_umasks": umasks,
        },
        {
            "case_id": "h0-create-file-umask",
            "descriptor_stats": [
                {"kind": "file", "mode": 0o600, "uid": collector_uid}
                for _ in umasks
            ],
            "error": None, "error_detail": None, "expected": "created",
            "mutation": "created", "operation": "create_file",
            "post": stat_fact("file", 0o600, collector_uid, 2), "pre": None,
            "tested_umasks": umasks,
        },
    ]
    for index, (case_id, operation, kind, mode, uid, error_class) in enumerate((
        ("h0-existing-mode-refusal", "existing_unsafe_mode", "file", 0o644,
         collector_uid, "LegacyModeMismatch"),
        ("h1-directory-symlink-refusal", "directory_symlink", "symlink", 0o777,
         collector_uid, "PrivatePathUnsafe"),
        ("h1-file-symlink-refusal", "file_symlink", "symlink", 0o777,
         collector_uid, "PrivatePathUnsafe"),
        ("h1-foreign-owner-refusal", "foreign_owner", "file", 0o600,
         65534, "PrivatePathUnsafe"),
    ), start=3):
        value = stat_fact(kind, mode, uid, index)
        observations.append({
            "case_id": case_id, "descriptor_stats": [], "error": 1,
            "error_detail": {"class": error_class, "components": [case_id]},
            "expected": "refused", "mutation": "none", "operation": operation,
            "post": value, "pre": copy.deepcopy(value), "tested_umasks": [],
        })

    by_lane = {row["lane"]: row for row in instances}
    bodies = {}
    for name, schema, lane, rows in (
        ("filesystem-trace", private_files_evidence.TRACE_SCHEMA,
         "H0-hermetic", observations[:3]),
        ("mode-owner-symlink-matrix", private_files_evidence.MATRIX_SCHEMA,
         "H1-tool-integration", observations[3:]),
    ):
        instance = by_lane[lane]
        document = {
            "artifact_kind": name,
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "case_roster_digest": private_files_evidence.roster_digest(),
            "collector_uid": collector_uid,
            "disposition": "source_substrate",
            "evidence_instance_id": instance["id"],
            "finished_at": instance["finished_at"],
            "gate_id": "C-PRIVATE-FILES",
            "lane": lane,
            "open_reasons": list(private_files_evidence._OPEN_REASONS),
            "observations": rows,
            "release": "0.3.10",
            "schema_version": schema,
            "started_at": instance["started_at"],
        }
        private_files_evidence.verify_artifact(
            document,
            artifact_kind=name,
            candidate_identity_digest=evidence.canonical_digest(identity),
        )
        bodies[name] = private_files_evidence.canonical_json_bytes(document)
    return bodies


def _supporting_bodies(
    gate_id: str, *, identity: dict, scope: dict, support: dict, thresholds: dict, corpus: dict,
    benchmark: dict | None, measurements: list[dict], environment: dict,
    evidence_instance_id: str, evidence_instances: list[dict], toolchain: list[dict],
    indexed: list[dict], emitted: dict[tuple[str, str], bytes], policy: dict,
) -> dict[str, bytes]:
    names = [name for name, _media_type in contracts.required_artifact_contract(gate_id)]
    bodies: dict[str, bytes] = {}
    if gate_id == "A-IDENTITY":
        bodies["identity-verification"] = contracts.canonical_json_line(identity)
    elif gate_id == "A-EVIDENCE-SCHEMA":
        manifest_body = (ROOT / "release/evidence/aggregator-conformance-v1.json").read_bytes()
        manifest = contracts.read_aggregator_conformance_manifest(manifest_body)
        positive_digest = evidence.canonical_digest({"conformance": "positive-aggregate-verify"})
        bodies["conformance-report"] = contracts.canonical_json_line({
            "artifact_type": "aggregator-conformance-report",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "cases": [{
                "aggregate_digests": [positive_digest, positive_digest]
                if case["kind"] == "positive" else [],
                "error_digest": None if case["kind"] == "positive" else
                contracts.conformance_error_digest(case["error_code"]),
                "id": case["id"],
                "status": "pass",
            } for case in manifest["cases"]],
            "gate_evidence_counts": {
                "gate_evidence_artifacts": len(contracts.SELECTED_RECORD_SLOTS) - len(contracts.LIVE_GATES),
                "gate_records": len(contracts.SELECTED_RECORD_SLOTS),
            },
            "gate_id": gate_id,
            "manifest_digest": contracts.raw_sha256(manifest_body),
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "test_nodeid": contracts._CONFORMANCE_TEST_NODEID,
            "test_source_digest": next(
                row["digest"] for row in scope["input_bindings"]
                if row["name"] == "release-contracts-tests"
            ),
        })
    elif gate_id == "A-TAXONOMY":
        bodies["classification-manifest"] = _h0_collection_taxonomy_body(environment, toolchain)
    elif gate_id == "A-CORPUS":
        selected = next(row for row in corpus["sources"] if row["selected"])
        bodies["corpus-disclosure-report"] = _corpus_disclosure_body(selected["fixture_digest"])
    elif gate_id == "A-THRESHOLDS":
        bodies["threshold-reconciliation"] = contracts.canonical_json_line(thresholds)
    elif gate_id == "A-SUPPORT":
        bodies["support-reconciliation"] = contracts.canonical_json_line(support)
    elif gate_id == "C-SOURCE-REGISTRY":
        source_inputs = {
            name: (ROOT / next(row["path"] for row in scope["input_bindings"]
                               if row["name"] == name)).read_bytes()
            for name in contracts._SOURCE_REGISTRY_BINDINGS
        }
        bodies["registry-reconciliation"] = source_registry_evidence.canonical_json_bytes(
            source_registry_evidence.build(
                candidate_identity_digest=evidence.canonical_digest(identity), input_bodies=source_inputs,
            )
        )
    elif gate_id == "C-CORPUS-SYNTHETIC":
        disclosure = emitted[("A-CORPUS", "corpus-disclosure-report")]
        attestation = contracts._read_synthetic_corpus_disclosure_attestation(disclosure)
        bodies["disclosure-report"] = disclosure
        bodies["derivation-diff"] = contracts.canonical_json_line(
            contracts._machine_report_document(
                gate_id=gate_id,
                name="derivation-diff",
                identity=identity,
                subjects=contracts._synthetic_corpus_diff_subjects(attestation),
            )
        )
    elif gate_id == "C-PATH-IDENTITY":
        candidate_digest = evidence.canonical_digest(identity)
        path_inputs = {
            name: (ROOT / path).read_bytes()
            for name, path in path_identity_evidence.INPUT_PATHS.items()
        }
        if candidate_digest not in _PATH_IDENTITY_CACHE:
            _PATH_IDENTITY_CACHE[candidate_digest] = path_identity_evidence.build_containment_decisions(
                candidate_identity_digest=candidate_digest,
                input_bodies=path_inputs,
            )
        decisions = copy.deepcopy(_PATH_IDENTITY_CACHE[candidate_digest])
        instance = evidence_instances[0]
        decisions["collection_interval"] = {
            "started_at": instance["started_at"].replace("Z", ".000000Z"),
            "finished_at": instance["finished_at"].replace("Z", ".000000Z"),
        }
        decisions["environment"].update({
            "python_implementation": "CPython",
            "python_version": instance["environment"]["python"],
            "platform_system": instance["environment"]["os"],
            "platform_machine": instance["environment"]["architecture"],
        })
        bodies["containment-decisions"] = path_identity_evidence.canonical_containment_decisions_bytes(
            decisions,
            candidate_identity_digest=candidate_digest,
            input_bodies=path_inputs,
        )
        bodies["property-corpus"] = path_inputs["path-identity-corpus"]
    elif gate_id == "C-PRIVATE-FILES":
        bodies.update(_private_files_bodies(identity, evidence_instances))
    elif gate_id == "C-FAULT-STORE":
        fault_inputs = {
            name: (ROOT / path).read_bytes()
            for name, path in fault_store_evidence.INPUT_PATHS.items()
        }
        plan = fault_store_evidence.build_source_plan(
            candidate_identity_digest=evidence.canonical_digest(identity),
            input_bodies=fault_inputs,
        )
        bodies["fault-matrix"] = fault_store_evidence.canonical_source_plan_bytes(
            plan,
            candidate_identity_digest=evidence.canonical_digest(identity),
            input_bodies=fault_inputs,
        )
    elif gate_id == "C-FAULT-REVISION":
        bodies["fault-matrix"] = contracts.canonical_json_line(
            contracts._h0_fault_matrix_document(
                gate_id=gate_id,
                identity=identity,
                nodeids=contracts._FAULT_REVISION_NODEIDS,
            )
        )
    elif gate_id in contracts._FAULT_H0_MATRIX_CONTRACTS:
        nodeids, _source_names = contracts._FAULT_H0_MATRIX_CONTRACTS[gate_id]
        bodies["fault-matrix"] = contracts.canonical_json_line(
            contracts._h0_fault_matrix_document(
                gate_id=gate_id,
                identity=identity,
                nodeids=nodeids,
            )
        )
    elif gate_id == "C-FAULT-RUNNER":
        bodies["fault-matrix"] = contracts.canonical_json_line(
            contracts._machine_report_document(
                gate_id=gate_id,
                name="fault-matrix",
                identity=identity,
                subjects=contracts._FAULT_RUNNER_NODEIDS,
            )
        )
    elif gate_id == "B-SCHEMA":
        registry_body = (ROOT / evidence.REGISTRY_PATH).read_bytes()
        fixture_manifest_body = (ROOT / contracts.SCHEMA_VALIDATION_FIXTURE_MANIFEST_PATH).read_bytes()
        outcomes = []
        registry = evidence._validate_schema_registry(evidence.load_json_bytes(registry_body))
        for registered in registry["schemas"]:
            name = registered["name"]
            fixture_path = contracts.SCHEMA_VALIDATION_FIXTURE_PATHS[name]
            outcomes.append({
                "accept": "pass",
                "fixture_digest": contracts.raw_sha256((ROOT / fixture_path).read_bytes()),
                "malformed": "reject",
                "name": name,
                "record_version": registered["record_version"],
                "round_trip": "pass",
                "schema_digest": contracts.raw_sha256((ROOT / evidence.SCHEMA_PATHS[name]).read_bytes()),
                "unknown_member": "reject",
                "unknown_version": "reject",
            })
        instance = evidence_instances[0]
        bodies["schema-validation-report"] = contracts.canonical_json_line({
            "artifact_type": "schema-validation-report",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "environment": instance["environment"],
            "evidence_finished_at": instance["finished_at"],
            "evidence_instance_id": instance["id"],
            "evidence_started_at": instance["started_at"],
            "fixture_manifest_digest": contracts.raw_sha256(fixture_manifest_body),
            "gate_id": gate_id,
            "legacy_migration": {
                "disposition": "no-supported-legacy-fixtures",
                "supported_legacy_migrations": [],
            },
            "outcomes": outcomes,
            "registry_digest": contracts.raw_sha256(registry_body),
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
        })
    elif gate_id == "B-DOCS-POLICY":
        instance = evidence_instances[0]
        materials = [{
            "digest": next(row["digest"] for row in scope["input_bindings"] if row["name"] == name),
            "name": name,
            "path": next(row["path"] for row in scope["input_bindings"] if row["name"] == name),
        } for name in contracts._DOCS_POLICY_MATERIALS]
        selection = {
            "collected": len(contracts._DOCS_POLICY_TEST_ROSTER), "deselected": 0, "failed": 0,
            "passed": len(contracts._DOCS_POLICY_TEST_ROSTER),
            "selected": len(contracts._DOCS_POLICY_TEST_ROSTER), "skipped": 0,
            "xfailed": 0, "xpassed": 0,
        }
        bodies["parity-report"] = contracts.canonical_json_line({
            "artifact_type": "docs-policy-parity-report",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "docs_policy_materials": materials,
            "environment": instance["environment"],
            "evidence_finished_at": instance["finished_at"],
            "evidence_instance_id": instance["id"],
            "evidence_started_at": instance["started_at"],
            "gate_id": gate_id,
            "name": "docs-policy-parity",
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "selection": selection,
            "test_results": [
                {"nodeid": nodeid, "status": "pass"}
                for nodeid in contracts._DOCS_POLICY_TEST_ROSTER
            ],
            "test_source_digest": next(
                row["digest"] for row in scope["input_bindings"]
                if row["name"] == "docs-parity-tests"
            ),
        })
    elif gate_id == "B-QUALITY":
        instance = evidence_instances[0]
        policy_body = (ROOT / contracts.QUALITY_POLICY_PATH).read_bytes()
        quality_policy = contracts.read_quality_policy(policy_body)
        bindings = {row["name"]: row for row in scope["input_bindings"]}
        selected_bindings = [
            "docs-parity-tests", "package-metadata", "quality-policy",
            "verification-job-map", "verification-workflow-ci",
        ]
        retained = []
        for check in quality_policy["checks"]:
            findings = [] if check["id"] in {"type", "docs"} else [
                ["src/quarry_recon/quality.py", "Q000", 1, 1],
            ]
            output = evidence.canonical_json_bytes(findings)
            retained.append({
                "argv": check["argv"],
                "breached": False,
                "budget": check["budget"],
                "config": {
                    "digest": check["config"]["digest"],
                    "name": "quality-config",
                    "path": check["config"]["path"],
                },
                "expected_exit_code": check["expected_exit_code"],
                "exit_code": 0 if not findings else check["expected_exit_code"],
                "id": check["id"],
                "observed_count": len(findings),
                "output": "base64:" + base64.b64encode(output).decode("ascii"),
                "output_kind": "canonical-findings",
                "result_digest": contracts.raw_sha256(output),
                "sources": check["sources"],
                "tool": check["tool"],
                "version": check["version"],
            })
        quality_selection = {
            "collected": 6, "deselected": 0, "failed": 0, "passed": 6,
            "selected": 6, "skipped": 0, "xfailed": 0, "xpassed": 0,
        }
        bodies["quality-report"] = contracts.canonical_json_line({
            "artifact_type": "quality-report",
            "bindings": [
                {"digest": bindings[name]["digest"], "name": name, "path": bindings[name]["path"]}
                for name in selected_bindings
            ],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "environment": instance["environment"],
            "evidence_finished_at": instance["finished_at"],
            "evidence_instance_id": instance["id"],
            "evidence_started_at": instance["started_at"],
            "gate_id": gate_id,
            "name": "quality-report",
            "observations": retained,
            "quality_policy_digest": contracts.raw_sha256(policy_body),
            "quality_violations": 0,
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "selection": quality_selection,
            "threshold_manifest_digest": contracts.raw_sha256(
                contracts.canonical_json_line(thresholds)
            ),
            "toolchain": toolchain,
        })
    elif gate_id == "B-COVERAGE":
        policy_body = (ROOT / contracts.COVERAGE_POLICY_PATH).read_bytes()
        coverage_policy = contracts.read_coverage_policy(policy_body)
        baseline = _coverage_baseline()
        bindings = {row["name"]: row for row in scope["input_bindings"]}
        h0 = evidence.load_json_bytes(emitted[("B-HERMETIC-ALL", "test-report")][:-1])
        fragments = next(run["fragments"] for run in h0["runs"] if run["environment"]["python"].startswith("3.12."))
        h0_digests = {row["job_instance_id"]: row["digest"] for row in fragments}
        values = {row["metric"]: (0 if row["class"] == "regression" else 10000)
                  for row in thresholds["thresholds"] if row["gate_id"] == gate_id}
        binding_names = (
            "coverage-config", "coverage-policy", "coverage-shard-producer",
            "coverage-shard-schema", "verification-job-map", "verification-workflow-ci",
        )
        coverage_data = []
        shard_files = [{
            "executed_branches": [[1, 2], [2, 3], [3, -1], [4, 5], [5, -1]],
            "executed_lines": list(range(1, 11)), "path": path,
            "possible_branches": [[1, 2], [2, 3], [3, -1], [4, 5], [5, -1]],
            "statements": list(range(1, 11)),
        } for path in coverage_policy["source_roster"]]
        for index, job_id in enumerate(coverage_policy["h0_job_ids"]):
            raw_data_digest = contracts.raw_sha256(f"synthetic-coverage-db-{index}".encode())
            coverage_data.append({
                "digest": raw_data_digest, "h0_fragment_digest": h0_digests[job_id],
                "job_instance_id": job_id,
            })
            bodies[f"coverage-shard-{index}"] = contracts.canonical_json_line({
                "config_digest": contracts.raw_sha256((ROOT / ".coveragerc").read_bytes()),
                "coverage_policy_digest": contracts.raw_sha256(policy_body),
                "coverage_version": "7.15.4", "files": shard_files,
                "h0_fragment_digest": h0_digests[job_id], "job_instance_id": job_id,
                "raw_coverage_data_digest": raw_data_digest,
                "schema_version": contracts.COVERAGE_SHARD_SCHEMA,
                "source_roster": coverage_policy["source_roster"],
            })
        bodies["coverage-report"] = contracts.canonical_json_line({
            "artifact_type": "coverage-report",
            "bindings": [{"digest": bindings[name]["digest"], "name": name, "path": bindings[name]["path"]} for name in binding_names],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "coverage_baseline": baseline,
            "coverage_data": coverage_data,
            "coverage_files": copy.deepcopy(baseline["files"]),
            "coverage_policy_digest": contracts.raw_sha256(policy_body),
            "critical_modules": [{"path": path, "line_coverage": 10000, "branch_coverage": 10000} for path in coverage_policy["critical_modules"]],
            "environment": environment, "evidence_finished_at": "2026-08-14T10:10:01Z",
            "evidence_instance_id": evidence_instance_id, "evidence_started_at": "2026-08-14T10:10:00Z",
            "gate_id": gate_id,
            "measurements": [{"metric": metric, "value": value, "breached": False} for metric, value in values.items()],
            "name": "coverage-report", "release": "0.3.10", "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "source_tree_digest": identity["source_tree_digest"],
            "threshold_manifest_digest": contracts.raw_sha256(contracts.canonical_json_line(thresholds)),
            "toolchain": toolchain,
        })
    elif gate_id == "B-STATIC-SECURITY":
        policy_body = (ROOT / contracts.STATIC_SECURITY_POLICY_PATH).read_bytes()
        security_policy = contracts.read_static_security_policy(policy_body)
        bindings = {row["name"]: row for row in scope["input_bindings"]}
        h0 = evidence.load_json_bytes(emitted[("B-HERMETIC-ALL", "test-report")][:-1])
        run = next(row for row in h0["runs"] if row["environment"]["python"].startswith("3.12."))
        job_id = ".github/workflows/ci.yml#jobs.offline[python-version=3.12,shard=0]"
        fragment_digest = next(row["digest"] for row in run["fragments"] if row["job_instance_id"] == job_id)
        exceptions = json.loads((ROOT / "release/evidence/security-exceptions-v1.json").read_bytes())
        suppressions = []
        for row in exceptions["exceptions"]:
            stable = hashlib.sha256("\0".join(map(str, (row["path"], row["line"], row["test_id"]))).encode()).hexdigest()[:20]
            suppressions.append({"expires_before": row["expires_before"], "finding_id": "bandit-" + stable, "id": "security-suppression-" + stable, "owner": row["owner"], "rationale": row["rationale"]})
        suppressions.sort(key=lambda row: row["id"])
        fragment = {
            "artifact_type": "security-scan-fragment",
            "ast_inventory": [{**row, "source": "ast"} for row in security_policy["ast_inventory"]["entries"]],
            "dependency_manifest": {"digest": security_policy["dependency_manifest"]["digest"], "name": "package-metadata", "path": "pyproject.toml"},
            "detect_secrets_baseline_digest": security_policy["detect_secrets"]["baseline"]["digest"],
            "findings": [], "h0_fragment_digest": fragment_digest,
            "h0_property_tests": security_policy["h0_property_tests"], "job_instance_id": job_id,
            "policy_digest": contracts.raw_sha256(policy_body), "release": "0.3.10",
            "schema_version": contracts.STATIC_SECURITY_FRAGMENT_SCHEMA, "suppressions": suppressions,
            "scan_tools": [{"name": "bandit", "version": "1.9.4"}, {"name": "detect-secrets", "version": "1.5.0"}], "unsuppressed_findings": 0,
        }
        bodies["security-scan-fragment"] = contracts.canonical_json_line(fragment)
        binding_names = contracts._STATIC_SECURITY_BINDINGS
        bodies["security-findings"] = contracts.canonical_json_line({
            **{key: value for key, value in fragment.items() if key not in {"artifact_type", "schema_version", "scan_tools"}},
            "artifact_type": "security-findings",
            "bindings": [{"digest": bindings[name]["digest"], "name": name, "path": bindings[name]["path"]} for name in binding_names],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "checks": contracts._static_security_checks(fragment),
            "environment": environment, "evidence_finished_at": "2026-08-14T10:10:01Z",
            "evidence_instance_id": evidence_instance_id, "evidence_started_at": "2026-08-14T10:10:00Z",
            "gate_id": gate_id, "name": "security-findings",
            "selection": {"collected": 5, "deselected": 0, "failed": 0, "passed": 5, "selected": 5, "skipped": 0, "xfailed": 0, "xpassed": 0},
            "scan_fragment_digest": contracts.raw_sha256(bodies["security-scan-fragment"]),
            "schema_version": contracts.SECURITY_FINDINGS_SCHEMA,
            "toolchain": toolchain,
        })
    elif gate_id == "B-DETERMINISM":
        h0 = evidence.load_json_bytes(emitted[("B-HERMETIC-ALL", "test-report")][:-1])
        h0_run = next(row for row in h0["runs"] if row["environment"]["python"].startswith("3.12."))
        instance = evidence_instances[0]
        instance["environment"] = h0_run["environment"]
        instance["id"] = h0_run["evidence_instance_id"]
        fixture_body = (ROOT / contracts.MANIFEST_PATHS["determinism-fixture"]).read_bytes()
        fixture = contracts.read_determinism_fixture(fixture_body)
        h0_digest = next(row["digest"] for row in h0_run["fragments"]
                         if row["job_instance_id"] == contracts._DETERMINISM_JOB_ID)
        runs = [
            contracts._determinism_expected_tree(fixture, "run-1"),
            contracts._determinism_expected_tree(fixture, "run-2"),
        ]
        fragment = {
            "artifact_differences": 0, "artifact_type": "artifact-tree-diff-fragment",
            "differences": [], "fixture_digest": runs[0]["tree_digest"],
            "fixture_manifest_digest": contracts.raw_sha256(fixture_body),
            "h0_fragment_digest": h0_digest, "job_instance_id": contracts._DETERMINISM_JOB_ID,
            "release": "0.3.10", "runs": runs,
            "schema_version": contracts.DETERMINISM_FRAGMENT_SCHEMA,
        }
        bodies["artifact-tree-diff-fragment"] = contracts.canonical_json_line(fragment)
        bindings = {row["name"]: row for row in scope["input_bindings"]}
        bodies["artifact-tree-diff"] = contracts.canonical_json_line({
            **fragment, "artifact_type": "artifact-tree-diff",
            "bindings": [{"digest": bindings[name]["digest"], "name": name,
                          "path": bindings[name]["path"]}
                         for name in contracts._DETERMINISM_BINDINGS],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "environment": instance["environment"], "evidence_finished_at": instance["finished_at"],
            "evidence_instance_id": instance["id"], "evidence_started_at": instance["started_at"],
            "gate_id": gate_id, "name": "artifact-tree-diff",
            "raw_fragment_digest": contracts.raw_sha256(bodies["artifact-tree-diff-fragment"]),
            "schema_version": contracts.ARTIFACT_TREE_DIFF_SCHEMA, "toolchain": toolchain,
        })
    elif gate_id == "B-MANIFEST":
        instance = evidence_instances[0]
        cases_body = (ROOT / contracts.MANIFEST_PATHS["manifest-evidence-cases"]).read_bytes()
        case_specs = contracts._read_manifest_evidence_cases(cases_body)
        case_manifest_digest = contracts.raw_sha256(cases_body)
        test_sources = [{
            "digest": next(row["digest"] for row in scope["input_bindings"] if row["name"] == name),
            "name": name,
            "path": next(row["path"] for row in scope["input_bindings"] if row["name"] == name),
        } for name in contracts._MANIFEST_TEST_SOURCES]
        materials = [{
            "digest": next(row["digest"] for row in scope["input_bindings"] if row["name"] == name),
            "name": name,
            "path": next(row["path"] for row in scope["input_bindings"] if row["name"] == name),
        } for name in contracts._MANIFEST_MATERIALS]
        node_selection = {
            "collected": len(contracts._MANIFEST_TEST_ROSTER), "deselected": 0, "failed": 0,
            "passed": len(contracts._MANIFEST_TEST_ROSTER),
            "selected": len(contracts._MANIFEST_TEST_ROSTER), "skipped": 0,
            "xfailed": 0, "xpassed": 0,
        }
        case_selection = {
            "collected": sum(len(members) for _case, members in contracts._MANIFEST_CORRUPTION_CASES),
            "deselected": 0, "failed": 0,
            "passed": sum(len(members) for _case, members in contracts._MANIFEST_CORRUPTION_CASES),
            "selected": sum(len(members) for _case, members in contracts._MANIFEST_CORRUPTION_CASES), "skipped": 0,
            "xfailed": 0, "xpassed": 0,
        }
        common = {
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "environment": instance["environment"],
            "evidence_finished_at": instance["finished_at"],
            "evidence_instance_id": instance["id"],
            "evidence_started_at": instance["started_at"],
            "gate_id": gate_id,
            "manifest_materials": materials,
            "case_manifest_digest": case_manifest_digest,
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "test_sources": test_sources,
        }
        bodies["corrupt-fixture-matrix"] = contracts.canonical_json_line({
            **common,
            "artifact_type": "manifest-corrupt-fixture-matrix",
            "cases": [
                {
                    "id": case["id"],
                    "members": [contracts._manifest_observed_result(spec) for spec in case["members"]],
                }
                for case in case_specs["corruption_cases"]
            ],
            "name": "corrupt-fixture-matrix",
            "selection": case_selection,
        })
        bodies["invariant-report"] = contracts.canonical_json_line({
            **common,
            "artifact_type": "manifest-invariant-report",
            "matrix_digest": contracts.raw_sha256(bodies["corrupt-fixture-matrix"]),
            "name": "invariant-report",
            "node_results": [
                contracts._manifest_observed_result(spec)
                for spec in case_specs["invariants"]
            ],
            "selection": node_selection,
        })
    elif gate_id == "B-HERMETIC-ALL":
        h0_environments = [
            copy.deepcopy(instance["environment"])
            for instance in evidence_instances if instance["lane"] == "H0-hermetic"
        ]
        common = {
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
        }
        collection_body = emitted[("A-TAXONOMY", "classification-manifest")]
        taxonomy = evidence.read_pytest_taxonomy(collection_body)
        h0_nodes = taxonomy["lanes"][0]["nodes"]
        runs = []
        instance_by_environment = {
            tuple(instance["environment"][key] for key in (
                "architecture", "isolation_profile", "os", "python", "runner_image",
            )): instance["id"]
            for instance in evidence_instances
        }
        for h0_environment in h0_environments:
            instance_id = instance_by_environment[tuple(h0_environment[key] for key in (
                "architecture", "isolation_profile", "os", "python", "runner_image",
            ))]
            python_minor = h0_environment["python"].rsplit(".", 1)[0]
            full_roster = {
                "count": len(h0_nodes),
                "digest": evidence.h0_roster_digest(h0_nodes),
            }
            fragments = []
            for shard_index in range(6):
                selected_nodes = [
                    nodeid for nodeid in h0_nodes
                    if evidence.h0_shard_index(nodeid, 6) == shard_index
                ]
                selected_roster = {
                    "count": len(selected_nodes),
                    "digest": evidence.h0_roster_digest(selected_nodes),
                }
                fragment = {
                    "collector": {
                        **taxonomy["collector"], "python_version": h0_environment["python"],
                    },
                    "collection_failures": 0,
                    "full_h0_roster": full_roster,
                    "keyword_expression": "",
                    "mark_expression": "offline",
                    "outcomes": {
                        "failed": 0, "passed": len(selected_nodes), "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    },
                    "passed_roster": selected_roster,
                    "schema_version": evidence.H0_SHARD_OUTCOME_REPORT_SCHEMA,
                    "selected_roster": selected_roster,
                    "session_exit_code": 0,
                    "shard_count": 6,
                    "shard_index": shard_index,
                }
                fragment_body = evidence.canonical_json_bytes(fragment)
                fragments.append({
                    "digest": contracts.raw_sha256(fragment_body),
                    "job_instance_id": (
                        ".github/workflows/ci.yml#jobs.offline"
                        f"[python-version={python_minor},shard={shard_index}]"
                    ),
                    "report": fragment,
                })
            runs.append({
                "environment": h0_environment,
                "evidence_instance_id": instance_id,
                "fragments": fragments,
            })
        bodies["collection-manifest"] = collection_body
        bodies["test-report"] = contracts.canonical_json_line({
            **common,
            "artifact_type": "h0-test-report",
            "collection_manifest_digest": contracts.raw_sha256(collection_body),
            "name": "test-report",
            "runs": runs,
        })
        bodies["isolation-self-test"] = contracts.canonical_json_line({
            **common,
            "artifact_type": "h0-isolation-self-test",
            "instances": [{
                "attempts": [{
                    "denial": {"code": "EPERM", "detail": "synthetic H0 denial"},
                    "kind": kind,
                    "outcome": "denied",
                } for kind in contracts._H0_ISOLATION_ATTEMPTS],
                "environment": h0_environment,
                "evidence_instance_id": instance_by_environment[
                    tuple(h0_environment[key] for key in (
                        "architecture", "isolation_profile", "os", "python", "runner_image",
                    ))
                ],
                "isolation_profile": h0_environment["isolation_profile"],
            } for h0_environment in h0_environments],
            "name": "isolation-self-test",
        })
    elif gate_id == "C-PACKAGE-BUILD":
        bodies["sdist"] = _synthetic_sdist()
        bodies["wheel"] = _synthetic_wheel()
        subjects = [{
            "digest": contracts.raw_sha256(bodies[name]),
            "media_type": media_type,
            "name": name,
            "size": len(bodies[name]),
        } for name, media_type in (("sdist", "application/gzip"), ("wheel", "application/zip"))]
        bodies["build-log"] = contracts.canonical_json_line({
            "artifact_type": "clean-build-log",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "clean_tree": True,
            "command": list(contracts._CLEAN_BUILD_COMMAND),
            "combined_output": "base64:" + base64.b64encode(
                b"* Creating isolated environment: venv+pip...\nSuccessfully built fixture\n"
            ).decode("ascii"),
            "exit_code": 0,
            "gate_id": gate_id,
            "package": {"name": "quarry-recon", "version": "0.3.10"},
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "subjects": subjects,
        })
        bodies["package-inventory"] = contracts.canonical_json_line({
            "artifact_type": "package-inventory",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "package": {"name": "quarry-recon", "version": "0.3.10"},
            "release": "0.3.10",
            "schema_version": contracts.PACKAGE_INVENTORY_SCHEMA,
            "subjects": subjects,
        })
    elif gate_id == "C-PACKAGE-INSTALL":
        wheel = next(
            row for row in indexed
            if row["gate_id"] == "C-PACKAGE-BUILD" and row["name"] == "wheel"
        )
        prefix = "/tmp/quarry-p0-install-prefix"
        checkout = "/tmp/quarry-p0-checkout"
        cwd = "/tmp/quarry-p0-invocation"
        dist = f"{prefix}/lib/python3.12/site-packages/quarry_recon-0.3.10.dist-info"
        installed = {
            f"{prefix}/bin/quarry": b"#!/synthetic/p0/python\n",
        }
        with zipfile.ZipFile(io.BytesIO(_synthetic_wheel())) as archive:
            for member in archive.namelist():
                if member.endswith(".dist-info/RECORD"):
                    installed[f"{prefix}/lib/python3.12/site-packages/{member}"] = archive.read(member)
                    continue
                parts = PurePosixPath(member).parts
                if parts[0].endswith(".data"):
                    assert parts[1] == "data"
                    path = PurePosixPath(prefix, *parts[2:])
                else:
                    path = PurePosixPath(
                        prefix, "lib", "python3.12", "site-packages", *parts,
                    )
                installed[str(path)] = archive.read(member)
        installed.update({
            f"{dist}/INSTALLER": b"pip\n",
            f"{dist}/REQUESTED": b"",
            f"{dist}/direct_url.json": b'{"archive_info":{},"url":"file:///synthetic.whl"}\n',
        })
        files = [{
            "digest": contracts.raw_sha256(body), "path": path, "size": len(body),
        } for path, body in sorted(installed.items())]
        common = {
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "checkout_root": checkout,
            "environment": environment,
            "evidence_instance_id": evidence_instance_id,
            "finished_at": "2026-08-14T10:20:01Z",
            "gate_id": gate_id,
            "install_prefix": prefix,
            "invocation_cwd": cwd,
            "package": {"name": "quarry-recon", "version": "0.3.10"},
            "release": "0.3.10",
            "source_wheel": {"digest": wheel["digest"], "size": wheel["size"]},
            "started_at": "2026-08-14T10:20:00Z",
        }
        bodies["install-inventory"] = contracts.canonical_json_line({
            **common,
            "artifact_type": "package-install-inventory",
            "files": files,
            "schema_version": contracts.PACKAGE_INSTALL_INVENTORY_SCHEMA,
        })
        smoke_paths = [
            f"{prefix}/lib/python3.12/site-packages/quarry_recon/__init__.py",
            f"{prefix}/lib/python3.12/site-packages/quarry_recon/data/target.template.yaml",
            f"{prefix}/bin/quarry",
            f"{prefix}/lib/python3.12/site-packages/quarry_recon/__init__.py",
        ]
        bodies["smoke-results"] = contracts.canonical_json_line({
            **common,
            "artifact_type": "package-install-smoke-results",
            "cases": [{
                "details": {
                    "path": path,
                    "version": "0.3.10",
                    **({"checkout_on_sys_path": False}
                       if case_id == "checkout-isolation" else {}),
                },
                "exit_code": 0,
                "id": case_id,
                "output_bytes": 0,
                "output_digest": _digest(format(index, "x")),
            } for index, (case_id, path) in enumerate(zip(contracts._INSTALL_CASE_ROSTER, smoke_paths))],
            "install_inventory_digest": contracts.raw_sha256(bodies["install-inventory"]),
            "schema_version": contracts.PACKAGE_INSTALL_SMOKE_SCHEMA,
        })
    elif gate_id == "C-PYTHON-MATRIX":
        bindings = {row["name"]: row["digest"] for row in scope["input_bindings"]}
        h0_test_report = json.loads(emitted[("B-HERMETIC-ALL", "test-report")])
        taxonomy = evidence.read_pytest_taxonomy(emitted[("A-TAXONOMY", "classification-manifest")])
        h0_selection = {
            "collected": taxonomy["selection"]["collected"],
            "deselected": taxonomy["selection"]["deselected"],
            "failed": 0,
            "passed": taxonomy["selection"]["selected"],
            "selected": taxonomy["selection"]["selected"],
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        }
        h0_runs = {
            tuple(row["environment"][key] for key in (
                "architecture", "isolation_profile", "os", "python", "runner_image",
            )): row for row in h0_test_report["runs"]
        }

        def source_artifacts(source_gate, names):
            return [{
                "digest": next(row["digest"] for row in indexed
                               if row["gate_id"] == source_gate and row["name"] == name),
                "name": name,
            } for name in names]

        rows = []
        for instance in evidence_instances:
            environment = instance["environment"]
            key = tuple(environment[field] for field in (
                "architecture", "isolation_profile", "os", "python", "runner_image",
            ))
            row = {
                "candidate_identity_digest": evidence.canonical_digest(identity),
                "environment": environment,
                "h0": None,
                "lane": instance["lane"],
                "p0": None,
                "package_metadata_digest": bindings["package-metadata"],
                "support_matrix_digest": bindings["support-matrix"],
            }
            if instance["lane"] == "H0-hermetic":
                run = h0_runs[key]
                row["h0"] = {
                    "evidence_instance_id": run["evidence_instance_id"],
                    "fragment_count": len(run["fragments"]),
                    "full_h0_roster": run["fragments"][0]["report"]["full_h0_roster"],
                    "selection": h0_selection,
                    "test_report_digest": next(
                        item["digest"] for item in indexed
                        if item["gate_id"] == "B-HERMETIC-ALL" and item["name"] == "test-report"
                    ),
                }
            else:
                p0_index = sum(
                    row["lane"] == "P0-package-supply" for row in rows
                )
                row["p0"] = {
                    "build_artifacts": source_artifacts(
                        "C-PACKAGE-BUILD", ("build-log", "package-inventory", "sdist", "wheel"),
                    ),
                    "build_evidence_instance_id": f"instance-{p0_index:02d}",
                    "install_artifacts": source_artifacts(
                        "C-PACKAGE-INSTALL", ("install-inventory", "smoke-results"),
                    ),
                    "install_evidence_instance_id": f"instance-{p0_index:02d}",
                }
            rows.append(row)
        bodies["python-matrix-report"] = contracts.canonical_json_line({
            "artifact_type": "python-matrix-report",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "package_metadata_digest": bindings["package-metadata"],
            "release": "0.3.10",
            "rows": rows,
            "schema_version": contracts.PYTHON_MATRIX_REPORT_SCHEMA,
            "support_matrix_digest": bindings["support-matrix"],
        })
    elif gate_id == "C-NETWORK-BOUNDARY":
        bodies["network-boundary-trace"] = _network_boundary_body(identity, support)
    elif gate_id == "C-NET-DENY":
        environments = sorted(
            (row for row in support["environments"]
             if row["lane"] in ("H0-hermetic", "C0-private-corpus", "P0-package-supply")),
            key=lambda row: (
                contracts.LANE_ORDER.index(row["lane"]), row["runner_image"], row["python"],
            ),
        )
        bodies["network-denial-report"] = contracts.canonical_json_line({
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "instances": [{
                "attempts": [{
                    "denial": {"code": "ENETUNREACH", "detail": "synthetic denial"},
                    "elapsed_milliseconds": 1,
                    "kind": kind,
                    "outcome": "denied",
                } for kind in ("native-tool", "proxy", "resolver", "socket", "subprocess")],
                "environment": {
                    key: row[key] for key in (
                        "architecture", "isolation_profile", "os", "python", "runner_image",
                    )
                },
                "identity": {
                    "lane": row["lane"], "python": row["python"],
                    "runner_image": row["runner_image"],
                },
            } for row in environments],
            "release": "0.3.10",
            "schema_version": contracts.NETWORK_DENIAL_REPORT_SCHEMA,
        })
    elif gate_id in contracts.V310_05_SEMANTIC_GATES:
        for artifact_kind, _media_type in contracts.required_artifact_contract(gate_id):
            bodies[artifact_kind] = _v310_05_body(gate_id, artifact_kind, identity)
    elif gate_id in contracts.PERFORMANCE_OPERATIONS:
        assert benchmark is not None
        bodies["benchmark-baseline"] = _benchmark_baseline_body(thresholds, gate_id)
        threshold_rows = [
            row for row in thresholds["thresholds"] if row["gate_id"] == gate_id
        ]
        measured_by_key = {
            (row["class"], row["metric"], row["unit"]): row for row in measurements
        }
        trial_metrics = []
        for threshold in threshold_rows:
            measured = measured_by_key[
                (threshold["class"], threshold["metric"], threshold["unit"])
            ]
            if threshold["class"] == "regression":
                baseline_value = 10_000
                current_value = 10_000
            else:
                baseline_value = None
                current_value = measured["value"]
            trial_metrics.append({
                "baseline_value": baseline_value,
                "class": threshold["class"],
                "current_value": current_value,
                "metric": threshold["metric"],
                "unit": threshold["unit"],
                "value": measured["value"],
            })
        benchmark_digest = evidence.canonical_digest(benchmark)
        bodies["raw-trials"] = contracts.canonical_json_line({
            "artifact_type": "benchmark-trials",
            "benchmark_digest": benchmark_digest,
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "release": "0.3.10",
            "resource_limits_observed": {
                key: value for key, value in benchmark["resource_limits"].items()
            },
            "schema_version": contracts.BENCHMARK_TRIALS_SCHEMA,
            "trials": [{
                "id": f"trial-{index:03d}",
                "metrics": copy.deepcopy(trial_metrics),
            } for index in range(benchmark["repetitions"])],
            "warmup_runs": benchmark["warmup_runs"],
        })
        bodies["trial-invalidations"] = contracts.canonical_json_line({
            "artifact_type": "benchmark-invalidations",
            "benchmark_digest": benchmark_digest,
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "invalidations": [],
            "raw_trials_digest": contracts.raw_sha256(bodies["raw-trials"]),
            "release": "0.3.10",
            "schema_version": contracts.BENCHMARK_INVALIDATIONS_SCHEMA,
        })
        bodies["benchmark-report"] = contracts.canonical_json_line({
            "artifact_type": "benchmark-report",
            "baseline_digest": contracts.raw_sha256(bodies["benchmark-baseline"]),
            "benchmark_digest": benchmark_digest,
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "measurements": measurements,
            "raw_trials_digest": contracts.raw_sha256(bodies["raw-trials"]),
            "release": "0.3.10",
            "schema_version": contracts.BENCHMARK_REPORT_SCHEMA,
            "trial_invalidations_digest": contracts.raw_sha256(
                bodies["trial-invalidations"]
            ),
        })
    elif gate_id == "C-SBOM":
        wheel = next(row for row in indexed if row["gate_id"] == "C-PACKAGE-BUILD" and row["name"] == "wheel")

        def observation_component(name, version, license_value, requirements):
            files = [{
                "digest": contracts.raw_sha256(f"synthetic {name} {version}\n".encode()),
                "path": f"site-packages/{name}/__init__.py",
                "size": len(f"synthetic {name} {version}\n".encode()),
            }]
            requirements = [{
                "active": active, "name": dependency, "raw": raw,
            } for dependency, raw, active in requirements]
            requirements.sort(key=lambda row: row["raw"])
            dependencies = sorted(row["name"] for row in requirements if row["active"])
            return {
                "active_dependencies": dependencies,
                "content_digest": contracts.raw_sha256(contracts.canonical_json_line(files)),
                "files": files,
                "license": license_value,
                "name": name,
                "raw_requirements": requirements,
                "version": version,
            }

        observations = []
        for expected_environment, artifact_name in zip(
            sorted(({
                key: row[key] for key in ("architecture", "isolation_profile", "os", "python", "runner_image")
            } for row in support["environments"] if row["lane"] == "P0-package-supply"), key=lambda row: row["python"]),
            contracts._SBOM_OBSERVATION_NAMES,
            strict=True,
        ):
            python_version = expected_environment["python"]
            minor = ".".join(python_version.split(".")[:2])
            root_requirements = []
            for raw in (
                "click>=8.2", "pyyaml>=6.0", "idna>=3.4",
                "tomli>=2.0; python_version < '3.11'",
            ):
                dependency = raw.split(">", 1)[0].split(";", 1)[0]
                active = not dependency == "tomli" or minor == "3.10"
                root_requirements.append((dependency, raw, active))
            components = [
                observation_component("quarry-recon", "0.3.10", "MIT", root_requirements),
                observation_component("click", "8.2.1", "BSD-3-Clause", [
                    ("colorama", "colorama; platform_system == 'Windows'", False),
                ]),
                observation_component("idna", "3.10", "BSD-3-Clause", [
                    ("ruff", "ruff; extra == 'all'", False),
                ]),
                observation_component("pyyaml", "6.0.2", "MIT", []),
            ]
            if minor == "3.10":
                components.append(observation_component("tomli", "2.0.2", "MIT", []))
            components.sort(key=lambda row: row["name"])
            graph = [{
                "dependencies": row["active_dependencies"], "name": row["name"], "version": row["version"],
            } for row in components]
            marker_environment = {
                "extra": "", "implementation_name": "cpython", "os_name": "posix",
                "platform_system": "Linux", "python_full_version": python_version,
                "python_version": minor, "sys_platform": "linux",
            }
            raw_environment = {**expected_environment, "isolation_profile": None, "runner_image": None}
            raw = contracts.canonical_json_line({
                "artifact_type": "sbom-observation",
                "components": components,
                "dependency_graph_digest": contracts.raw_sha256(contracts.canonical_json_line(graph)),
                "environment": raw_environment,
                "interpreter": {
                    "base_prefix": "/opt/python", "executable": "/tmp/prefix/bin/python",
                    "implementation": "cpython", "prefix": "/tmp/prefix", "version": python_version + " synthetic",
                },
                "marker_environment": marker_environment,
                "marker_evaluator": {"implementation": "pip._vendor.packaging", "version": "24.0"},
                "package": {"name": "quarry-recon", "version": "0.3.10"},
                "producer": {
                    "digest": next(
                        row["digest"] for row in scope["input_bindings"]
                        if row["name"] == "sbom-observation-producer"
                    ),
                    "name": "sbom-observation-producer",
                },
                "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
                "source_wheel": {"digest": wheel["digest"], "size": wheel["size"]},
            })
            bodies[artifact_name] = raw
            observations.append({
                "digest": contracts.raw_sha256(raw), "environment": expected_environment,
                "evidence_instance_id": f"instance-{len(observations):02d}", "name": artifact_name,
            })
        direct = {
            "click": "click>=8.2", "pyyaml": "pyyaml>=6.0", "idna": "idna>=3.4",
            "tomli": "tomli>=2.0; python_version < '3.11'",
        }
        grouped = {}
        for observation in observations:
            for component in json.loads(bodies[observation["name"]])["components"]:
                grouped.setdefault(component["name"], []).append((observation, component))
        components = []
        for name, rows in grouped.items():
            environments = [{
                "active_dependencies": component["active_dependencies"],
                "content_digest": component["content_digest"], "environment": observation["environment"],
                "raw_requirements": component["raw_requirements"],
            } for observation, component in rows]
            environments.sort(key=lambda row: row["environment"]["python"])
            component = rows[0][1]
            components.append({
                "content_digest": contracts.raw_sha256(contracts.canonical_json_line(environments)),
                "declared_requirement": direct.get(name),
                "environments": environments,
                "license": component["license"],
                "name": name,
                "relationship": "project" if name == "quarry-recon" else "dependency",
                "version": component["version"],
            })
        components.extend({
            "content_digest": row["digest"],
            "declared_requirement": None,
            "environments": [],
            "license": row["license"],
            "name": row["name"],
            "relationship": relationship,
            "version": row["version"],
        } for relationship, rows in (
            ("template", support["template_sets"]), ("tool", support["tools"]),
        ) for row in rows)
        components.sort(key=lambda row: (row["relationship"], row["name"]))
        sbom = {
            "artifact_type": "sbom",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "components": components,
            "dependency_graph_digest": contracts.raw_sha256(contracts.canonical_json_line([
                {"digest": row["digest"], "environment": row["environment"]} for row in observations
            ])),
            "gate_id": gate_id,
            "observations": observations,
            "package": {"name": "quarry-recon", "version": "0.3.10"},
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
        }
        sbom["sbom_digest"] = contracts.raw_sha256(contracts.canonical_json_line(sbom))
        bodies["sbom"] = contracts.canonical_json_line(sbom)
    elif gate_id == "C-VULNERABILITY":
        for observation_name in contracts._SBOM_OBSERVATION_NAMES:
            minor = observation_name.removeprefix("sbom-observation-")
            observation = json.loads(emitted[("C-SBOM", observation_name)])
            raw = {
                "bomFormat": "CycloneDX", "components": [
                    {"bom-ref": f"pkg:{row['name']}", "name": row["name"], "version": row["version"]}
                    for row in observation["components"] if row["name"] != "quarry-recon"
                ], "specVersion": "1.4", "vulnerabilities": [],
            }
            requirements = ("\n".join(sorted(
                f"{row['name']}=={row['version']}" for row in observation["components"]
                if row["name"] != "quarry-recon"
            )) + "\n").encode()
            bodies[f"vulnerability-observation-{minor}"] = contracts.canonical_json_line({
                "artifact_type": "vulnerability-observation", "exit_status": 0,
                "finished_at": "2026-08-14T10:20:01Z",
                "requirements": "base64:" + base64.b64encode(requirements).decode("ascii"),
                "scanner": {"argv": ["pip-audit", "--strict", "--no-deps", "--disable-pip", "-r", "/dev/stdin", "--format", "cyclonedx-json", "--progress-spinner", "off"], "name": "pip-audit", "version": "2.10.1"},
                "schema_version": "quarry.vulnerability-observation.v1", "stderr": "base64:",
                "started_at": "2026-08-14T10:20:00Z",
                "stdout": "base64:" + base64.b64encode(contracts.canonical_json_line(raw)).decode("ascii"),
                "subject": {"kind": "resolved-sbom-closure", "requirements_digest": contracts.raw_sha256(requirements), "sbom_observation": observation_name},
            })
        final_sbom = json.loads(emitted[("C-SBOM", "sbom")])
        scans = []
        for instance, observation_name in zip(evidence_instances, contracts._SBOM_OBSERVATION_NAMES, strict=True):
            minor = observation_name.removeprefix("sbom-observation-")
            raw_observation = bodies[f"vulnerability-observation-{minor}"]
            raw_document = json.loads(raw_observation)
            cyclonedx = base64.b64decode(raw_document["stdout"][7:])
            scans.append({
                "cyclonedx_digest": contracts.raw_sha256(cyclonedx), "environment": instance["environment"],
                "evidence_instance_id": instance["id"], "exit_status": 0, "finished_at": raw_document["finished_at"],
                "name": f"vulnerability-observation-{minor}", "observation_digest": contracts.raw_sha256(raw_observation),
                "sbom_observation_digest": contracts.raw_sha256(emitted[("C-SBOM", observation_name)]),
                "sbom_observation_name": observation_name, "started_at": raw_document["started_at"],
            })
        external = ([{"advisories": [], "subject": {"digest": digest, "kind": "runner_image"}}
                     for digest in sorted({row["environment"]["runner_image"] for row in evidence_instances})] +
                    [{"advisories": [], "subject": {"digest": row["content_digest"], "kind": row["relationship"], "name": row["name"], "version": row["version"]}}
                     for row in final_sbom["components"] if row["relationship"] in {"tool", "template"}])
        snapshot = {"digest": _digest("4"), "id": "test-snapshot", "source": "test-authority"}
        freshness = {"observed_at": "2026-08-14T10:20:00Z", "expires_at": "2026-08-14T11:20:01Z"}
        attestation_payload = {"database_snapshot": snapshot, "dependency_scans": scans, "external_results": external,
                               "freshness": freshness, "issuer": "test-authority", "provider": "release-vulnerability-authority"}
        payload_digest = contracts.raw_sha256(contracts.canonical_json_line(attestation_payload))
        message = contracts.signature_preimage(role="approval", payload_digest=payload_digest,
            candidate_identity_digest=evidence.canonical_digest(identity), trust_policy_digest=evidence.canonical_digest(policy))
        provider = {"database_snapshot": snapshot, "dependency_scans": scans, "external_results": external,
                    "freshness": freshness, "name": "release-vulnerability-authority",
                    "trusted_attestation": {"issuer": "test-authority", "signature": {"algorithm": "ed25519", "candidate_identity_digest": evidence.canonical_digest(identity), "key_id": "test-approval-v1", "payload_digest": payload_digest, "role": "approval", "schema_version": contracts.SIGNATURE_ENVELOPE_SCHEMA, "signature": "base64:" + base64.b64encode(_sign(message, seed=APPROVAL_SEED)).decode("ascii"), "trust_policy_digest": evidence.canonical_digest(policy)}}}
        bodies["vulnerability-findings"] = contracts.canonical_json_line({
            "artifact_type": "vulnerability-findings", "candidate_identity_digest": evidence.canonical_digest(identity),
            "dispositions": [], "findings": [], "gate_id": gate_id,
            "provider": provider,
            "raw_scans": scans, "release": "0.3.10", "schema_version": contracts.VULNERABILITY_FINDINGS_SCHEMA,
            "unaccepted_findings": 0,
        })
    elif gate_id == "C-PROVENANCE":
        by_key = {(row["gate_id"], row["name"]): row for row in indexed}
        subjects = [{
            "digest": by_key[("C-PACKAGE-BUILD", name)]["digest"],
            "name": name,
        } for name in ("sdist", "wheel")]
        materials = [{
            "digest": evidence.canonical_digest(identity),
            "name": "candidate-identity",
        }] + [{"digest": row["digest"], "name": row["name"]} for row in identity["inputs"]] + [{
            "digest": by_key[(subject_gate, name)]["digest"],
            "name": f"{subject_gate}/{name}",
        } for subject_gate, name in contracts._PROVENANCE_MATERIAL_ARTIFACTS]
        materials.sort(key=lambda row: row["name"])
        package_build_report = json.loads(emitted[("C-PACKAGE-BUILD", "gate-evidence")])
        package_build_artifacts = {
            (name, by_key[("C-PACKAGE-BUILD", name)]["digest"])
            for name in ("build-log", "package-inventory", "sdist", "wheel")
        }
        package_builders = [
            instance for instance in package_build_report["instances"]
            if package_build_artifacts.issubset({
                (artifact["name"], artifact["digest"]) for artifact in instance["artifacts"]
            })
        ]
        assert len(package_builders) == 1
        package_builder = package_builders[0]
        bodies["provenance"] = contracts.canonical_json_line({
            "artifact_type": "provenance",
            "builder": {
                "environment": package_builder["environment"],
                "evidence_instance_id": package_builder["id"],
                "toolchain": package_builder["toolchain"],
            },
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "materials": materials,
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
            "subjects": subjects,
        })
        payload_digest = contracts.raw_sha256(bodies["provenance"])
        message = contracts.signature_preimage(
            role="gate",
            payload_digest=payload_digest,
            candidate_identity_digest=evidence.canonical_digest(identity),
            trust_policy_digest=evidence.canonical_digest(policy),
        )
        bodies["signature-verification"] = contracts.canonical_json_line({
            "algorithm": "ed25519",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "key_id": "test-gate-v1",
            "payload_digest": payload_digest,
            "role": "gate",
            "schema_version": contracts.SIGNATURE_ENVELOPE_SCHEMA,
            "signature": "base64:" + base64.b64encode(
                _sign(message, seed=GATE_SEED)
            ).decode("ascii"),
            "trust_policy_digest": evidence.canonical_digest(policy),
        })
    elif gate_id == "E-DOCS":
        bodies["release-documentation-report"] = contracts.canonical_json_line(
            contracts._machine_report_document(
                gate_id=gate_id, name="release-documentation-report",
                identity=identity, subjects=contracts._RELEASE_DOCUMENTATION_SECTIONS,
            )
        )
    elif gate_id == "E-PROJECT-HYGIENE":
        bodies["project-hygiene-report"] = contracts.canonical_json_line(
            contracts._machine_report_document(
                gate_id=gate_id, name="project-hygiene-report",
                identity=identity, subjects=contracts._PROJECT_HYGIENE_CHECKS,
            )
        )
    elif gate_id == "E-ARTIFACTS":
        by_key = {(row["gate_id"], row["name"]): row for row in indexed}
        subjects = [{
            "digest": by_key[(subject_gate, name)]["digest"],
            "media_type": media_type,
            "name": f"{subject_gate}/{name}",
        } for subject_gate, name, media_type in (
            ("C-PACKAGE-BUILD", "sdist", "application/gzip"),
            ("C-PACKAGE-BUILD", "wheel", "application/zip"),
            ("C-SBOM", "sbom", "application/json"),
            ("C-PROVENANCE", "provenance", "application/json"),
        )]
        subjects.extend({
            "digest": row["digest"],
            "media_type": "application/schema+json",
            "name": row["name"],
        } for row in scope["input_bindings"] if row["name"].endswith("-schema"))
        subjects.sort(key=lambda row: row["name"])
        bodies["publication-subjects"] = contracts.canonical_json_line({
            "artifact_type": "publication-subjects",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "release": "0.3.10",
            "schema_version": contracts.PUBLICATION_SUBJECTS_SCHEMA,
            "subjects": subjects,
        })
    for name in names:
        if name == "resource-gate-report":
            continue
        bodies.setdefault(name, _generic_supporting_body(gate_id, name, identity))
    if "resource-gate-report" in names:
        threshold_rows = [
            row for row in thresholds["thresholds"] if row["gate_id"] == gate_id
        ]
        measured_by_metric = {row["metric"]: row for row in measurements}
        accepted = {
            row["metric"]: {
                "operator": row["operator"],
                "statistic": row["statistic"],
                "unit": row["unit"],
                "limit": row["limit"],
                "baseline_digest": row["baseline_digest"],
            }
            for row in threshold_rows
        }
        values = {
            row["metric"]: measured_by_metric[row["metric"]]["value"]
            for row in threshold_rows
        }
        trace_digests = sorted(
            contracts.raw_sha256(bodies[name])
            for name in names if name != "resource-gate-report"
        )
        trials = [{
            "case": case,
            "outcome": "pass",
            "resource": {
                "peak_aggregate_rss_bytes": values.get("peak_aggregate_rss", 1),
                "peak_disk_bytes": 1,
                "peak_fd_count": 1,
                "peak_process_count": max(1, values.get("worker_processes", 1)),
                "complete": True,
            },
            "metric_facts": copy.deepcopy(values),
            "assertions": {
                assertion: True
                for assertion in sorted(resource_contract._GATE_ASSERTIONS[gate_id][case])
            },
            "artifact_digests": trace_digests,
        } for case in sorted(resource_contract._GATE_CASES[gate_id])]
        resource_measurements = [{
            "metric": row["metric"],
            "operator": row["operator"],
            "statistic": row["statistic"],
            "unit": row["unit"],
            "value": values[row["metric"]],
            "limit": row["limit"],
            "baseline_digest": row["baseline_digest"],
        } for row in threshold_rows]
        resource_report = resource_contract.build_gate_report(
            candidate_identity_digest=evidence.canonical_digest(identity),
            gate_id=gate_id,
            evidence_instance_id=evidence_instance_id,
            started_at="2026-08-14T10:20:00Z",
            finished_at="2026-08-14T10:20:01Z",
            trials=trials,
            measurements=resource_measurements,
            threshold_manifest_digest=contracts.raw_sha256(
                contracts.canonical_json_line(thresholds)
            ),
            accepted_thresholds=accepted,
            benchmark_manifest_digest=(
                evidence.canonical_digest(benchmark) if benchmark is not None else None
            ),
        )
        assert resource_report["verdict"] == "pass"
        bodies["resource-gate-report"] = resource_contract.canonical_bytes(resource_report)
    return bodies


def _ready_contracts(
    *, approved_at: str = "2026-08-01T00:00:00Z", policy: dict | None = None,
) -> tuple[dict, dict, dict, dict, dict, dict[str, bytes]]:
    if policy is None:
        policy = _policy()
    scope = _read("release/evidence/release-scope-v1.json", contracts.read_release_scope)
    support = _read("release/evidence/support-matrix-v1.json", contracts.read_support_matrix)
    thresholds = _read(
        "release/evidence/threshold-benchmark-v1.json", contracts.read_threshold_manifest,
    )
    corpus = _read("release/evidence/corpus-selection-v1.json", contracts.read_corpus_manifest)
    no_live = _read("release/evidence/no-live-rule-v1.json", contracts.read_no_live_rule)
    support["tools"] = [
        {"digest": _digest("e"), "license": "TEST-ONLY", "name": "bandit", "version": "1.9.4"},
        {"digest": _digest("d"), "license": "TEST-ONLY", "name": "coverage", "version": "7.15.4"},
        {"digest": _digest("f"), "license": "TEST-ONLY", "name": "detect-secrets", "version": "1.5.0"},
        {"digest": _digest("b"), "license": "TEST-ONLY", "name": "mypy", "version": "2.3.1"},
        {"digest": _digest("9"), "license": "TEST-ONLY", "name": "pip-audit", "version": "2.10.1"},
        {"digest": _digest("a"), "license": "TEST-ONLY", "name": "pytest", "version": "9.1.1"},
        {"digest": _digest("c"), "license": "TEST-ONLY", "name": "ruff", "version": "0.16.3"},
    ]
    support["template_sets"] = [
        {"digest": _digest("b"), "license": "TEST-ONLY", "name": "synthetic-templates", "version": "1"},
    ]
    for row in support["environments"]:
        row["isolation_profile"] = _digest("1")
        row["runner_image"] = _digest("2")
    support["aggregators"][0].update({
        "executable_digest": _digest("3"),
        "isolation_profile": _digest("4"),
        "runner_image": _digest("5"),
    })
    for row in thresholds["thresholds"]:
        row["limit"] = 0 if (
            row["gate_id"] in {"B-QUALITY", "B-DETERMINISM"} or
            row["metric"] in resource_contract._ZERO_INVARIANTS
        ) else 1
        if row["class"] == "regression":
            row["baseline_digest"] = _digest("c")
    coverage_baseline_digest = contracts.raw_sha256(contracts.canonical_json_line(_coverage_baseline()))
    for row in thresholds["thresholds"]:
        if row["gate_id"] == "B-COVERAGE" and row["class"] == "regression":
            row["baseline_digest"] = coverage_baseline_digest
    corpus["sources"][-1]["fixture_digest"] = _digest("f")
    corpus["sources"][-1]["attestation_digest"] = contracts.raw_sha256(
        _corpus_disclosure_body(corpus["sources"][-1]["fixture_digest"])
    )
    for benchmark in thresholds["benchmarks"]:
        benchmark.update({
            "concurrency": 1,
            "fixture_digest": _digest("f"),
            "repetitions": 3,
            "runner_class": "synthetic-runner",
            "tool_digests": [_digest("a")],
            "warmup_runs": 1,
        })
        benchmark["resource_limits"].update({
            "cpu_millicores": 1,
            "disk_bytes": 1,
            "memory_bytes": 1,
        })
    for gate_id in contracts.PERFORMANCE_OPERATIONS:
        baseline_digest = contracts.raw_sha256(_benchmark_baseline_body(thresholds, gate_id))
        for row in thresholds["thresholds"]:
            if row["gate_id"] == gate_id and row["class"] == "regression":
                row["baseline_digest"] = baseline_digest

    for document in (support, thresholds, corpus, no_live):
        _sign_contract_review(document, policy, approved_at=approved_at)

    replacements = {
        "corpus-selection": contracts.canonical_json_line(corpus),
        "no-live-rule": contracts.canonical_json_line(no_live),
        "support-matrix": contracts.canonical_json_line(support),
        "threshold-benchmark": contracts.canonical_json_line(thresholds),
    }
    bodies = {}
    for row in scope["input_bindings"]:
        body = replacements.get(row["name"], (ROOT / row["path"]).read_bytes())
        row["digest"] = contracts.raw_sha256(body)
        bodies[row["name"]] = body
    _sign_contract_review(scope, policy, approved_at=approved_at)
    trusted_policy_digest = evidence.canonical_digest(policy)
    contracts.validate_release_scope(
        scope, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    return scope, support, thresholds, corpus, no_live, bodies


def _identity(scope: dict, policy: dict) -> dict:
    scope_digest_by_path = {
        row["path"]: row["digest"] for row in scope["input_bindings"]
    }
    inputs = []
    for index, (name, path) in enumerate(sorted(evidence.DEFAULT_IDENTITY_INPUTS.items())):
        inputs.append({
            "digest": scope_digest_by_path.get(path, _digest(format(index % 16, "x"))),
            "name": name,
            "path": path,
        })
    inputs.extend(
        copy.deepcopy(row) for row in scope["input_bindings"]
        if row["name"] not in evidence.DEFAULT_IDENTITY_INPUTS
    )
    inputs.extend([
        {
            "digest": contracts.raw_sha256(contracts.canonical_json_line(policy)),
            "name": "production-trust-policy",
            "path": contracts.PRODUCTION_TRUST_POLICY_PATH,
        },
        {
            "digest": contracts.raw_sha256(contracts.canonical_json_line(scope)),
            "name": "release-scope",
            "path": "release/evidence/release-scope-v1.json",
        },
    ])
    inputs.sort(key=lambda row: row["name"])
    by_name = {row["name"]: row for row in inputs}
    identity = {
        "dirty": False,
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "inputs": inputs,
        "package_version": "0.3.10",
        "package_version_sources": [
            {
                "digest": by_name["package-metadata"]["digest"],
                "path": "pyproject.toml",
                "value": "0.3.10",
            },
            {
                "digest": by_name["package-version"]["digest"],
                "path": "src/quarry_recon/__init__.py",
                "value": "0.3.10",
            },
        ],
        "release": "0.3.10",
        "schema_version": evidence.CANDIDATE_SCHEMA,
        "schema_versions": dict(evidence.SCHEMA_VERSIONS),
        "source_tree_digest": _digest("e"),
        "source_tree_digest_algorithm": evidence.SOURCE_TREE_ALGORITHM,
        "submodules": [],
    }
    return evidence.validate_candidate_identity(identity)


def _resign_gate(gate: dict, identity: dict, policy: dict) -> None:
    gate["signature"] = None
    message = contracts.signature_preimage(
        role="gate",
        payload_digest=contracts.gate_payload_digest(gate, identity=identity),
        candidate_identity_digest=evidence.canonical_digest(identity),
        trust_policy_digest=evidence.canonical_digest(policy),
    )
    gate["signature"] = {
        "algorithm": "ed25519",
        "key_id": "test-gate-v1",
        "value": "base64:" + base64.b64encode(_sign(message, seed=GATE_SEED)).decode("ascii"),
    }


def _scenario(tmp_path: Path, *, approved_at: str = "2026-08-01T00:00:00Z"):
    policy = _policy()
    scope, support, thresholds, corpus, no_live, bodies = _ready_contracts(
        approved_at=approved_at, policy=policy,
    )
    identity = _identity(scope, policy)
    inputs = contracts.expected_gate_inputs(scope, identity=identity, policy=policy)
    contract_by_gate = {
        gate: (collector, lanes) for gate, collector, lanes in contracts.OBLIGATION_CONTRACTS
    }
    records = []
    indexed = []
    emitted: dict[tuple[str, str], bytes] = {}
    artifact_root = tmp_path / "evidence"
    artifact_root.mkdir(parents=True)
    supported_environments = support["environments"]

    def gate_environment(environment):
        return {key: environment[key] for key in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        )}

    default_environment = gate_environment(next(
        row for row in supported_environments
        if row["lane"] == "H0-hermetic" and row["python"].startswith("3.12.")
    ))
    supported_toolchain = [{
        "digest": row["digest"],
        "name": row["name"],
        "path": f"/runner/bin/{row['name']}",
        "version": row["version"],
    } for row in support["tools"]]
    for gate_id in contracts.SELECTED_RECORD_SLOTS:
        collector, lanes = contract_by_gate[gate_id]
        is_live = gate_id in contracts.LIVE_GATES
        phase_minute = {"A": "00", "B": "10", "C": "20", "D": "30", "E": "40"}[
            gate_id[0]
        ]
        gate_started_at = f"2026-08-14T10:{phase_minute}:00Z"
        instance_finished_at = f"2026-08-14T10:{phase_minute}:01Z"
        gate_finished_at = f"2026-08-14T10:{phase_minute}:02Z"
        artifacts = []
        instances = []
        gate_toolchain = (
            [tool for tool in supported_toolchain if tool["name"] in {"mypy", "pytest", "ruff"}]
            if gate_id == "B-QUALITY" else supported_toolchain if gate_id == "C-TOOLS" else
            [tool for tool in supported_toolchain if tool["name"] == "pip-audit"] if gate_id == "C-VULNERABILITY" else
            [tool for tool in supported_toolchain if tool["name"] in {"coverage", "pytest"}]
            if gate_id == "B-COVERAGE" else [tool for tool in supported_toolchain if tool["name"] == "pytest"]
            if gate_id != "B-STATIC-SECURITY" else [tool for tool in supported_toolchain if tool["name"] in {"bandit", "detect-secrets", "pytest"}]
        )
        if not is_live:
            if gate_id == "B-HERMETIC-ALL":
                instance_specs = [
                    environment for environment in supported_environments
                    if environment["lane"] == "H0-hermetic"
                ]
            elif gate_id in {"C-PACKAGE-BUILD", "C-PACKAGE-INSTALL", "C-SBOM", "C-VULNERABILITY"}:
                instance_specs = [
                    environment for environment in supported_environments
                    if environment["lane"] == "P0-package-supply"
                ]
            elif gate_id == "C-PYTHON-MATRIX":
                instance_specs = [
                    environment for environment in supported_environments
                    if environment["lane"] in lanes
                ]
            elif gate_id in {"B-COVERAGE", "B-STATIC-SECURITY"}:
                instance_specs = [next(environment for environment in supported_environments
                                       if environment["lane"] == "H0-hermetic" and environment["python"].startswith("3.12."))]
            else:
                instance_specs = [
                    next(environment for environment in supported_environments
                         if environment["lane"] == lane)
                    for lane in lanes
                ]
            for instance_index, environment in enumerate(instance_specs):
                instance_environment = gate_environment(environment)
                assertion = {
                    "id": contracts.required_assertion_id(gate_id),
                    "reason": None,
                    "status": "pass",
                }
                selection = {
                    "collected": 1, "deselected": 0, "failed": 0, "passed": 1,
                    "selected": 1, "skipped": 0, "xfailed": 0, "xpassed": 0,
                }
                if gate_id == "A-TAXONOMY":
                    h0_count = len(_h0_collection_nodes())
                    selection = {
                        "collected": h0_count + 4, "deselected": 4, "failed": 0,
                        "passed": h0_count, "selected": h0_count, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "B-HERMETIC-ALL":
                    h0_count = len(_h0_collection_nodes())
                    selection = {
                        "collected": h0_count + 4, "deselected": 4, "failed": 0,
                        "passed": h0_count, "selected": h0_count, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "C-FAULT-STORE":
                    selection = {
                        "collected": fault_store_evidence.NODE_COUNT,
                        "deselected": 0, "failed": 0,
                        "passed": fault_store_evidence.NODE_COUNT,
                        "selected": fault_store_evidence.NODE_COUNT,
                        "skipped": 0, "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "C-CORPUS-SYNTHETIC":
                    selection = {
                        "collected": 4, "deselected": 0, "failed": 0, "passed": 4,
                        "selected": 4, "skipped": 0, "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "C-FAULT-REVISION":
                    count = len(contracts._FAULT_REVISION_NODEIDS)
                    selection = {
                        "collected": count, "deselected": 0, "failed": 0,
                        "passed": count, "selected": count, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id in contracts._FAULT_H0_MATRIX_CONTRACTS:
                    count = len(contracts._FAULT_H0_MATRIX_CONTRACTS[gate_id][0])
                    selection = {
                        "collected": count, "deselected": 0, "failed": 0,
                        "passed": count, "selected": count, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "C-FAULT-RUNNER":
                    count = len(
                        contracts._FAULT_RUNNER_H0_NODEIDS
                        if environment["lane"] == "H0-hermetic"
                        else contracts._FAULT_RUNNER_H1_NODEIDS
                    )
                    selection = {
                        "collected": count, "deselected": 0, "failed": 0,
                        "passed": count, "selected": count, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "C-PRIVATE-FILES":
                    selection = {
                        "collected": 3, "deselected": 0, "failed": 0,
                        "passed": 3, "selected": 3, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "B-DOCS-POLICY":
                    selection = {
                        "collected": len(contracts._DOCS_POLICY_TEST_ROSTER), "deselected": 0,
                        "failed": 0, "passed": len(contracts._DOCS_POLICY_TEST_ROSTER),
                        "selected": len(contracts._DOCS_POLICY_TEST_ROSTER), "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "B-MANIFEST":
                    selection = {
                        "collected": len(contracts._MANIFEST_TEST_ROSTER) + sum(
                            len(members) for _case, members in contracts._MANIFEST_CORRUPTION_CASES
                        ), "deselected": 0,
                        "failed": 0, "passed": len(contracts._MANIFEST_TEST_ROSTER) + sum(
                            len(members) for _case, members in contracts._MANIFEST_CORRUPTION_CASES
                        ), "selected": len(contracts._MANIFEST_TEST_ROSTER) + sum(
                            len(members) for _case, members in contracts._MANIFEST_CORRUPTION_CASES
                        ), "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "B-QUALITY":
                    selection = {
                        "collected": 6, "deselected": 0, "failed": 0, "passed": 6,
                        "selected": 6, "skipped": 0, "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "B-COVERAGE":
                    h0_count = len(_h0_collection_nodes())
                    selection = {
                        "collected": h0_count + 4, "deselected": 4, "failed": 0,
                        "passed": h0_count, "selected": h0_count, "skipped": 0,
                        "xfailed": 0, "xpassed": 0,
                    }
                if gate_id == "B-STATIC-SECURITY":
                    selection = {"collected": 5, "deselected": 0, "failed": 0, "passed": 5,
                                 "selected": 5, "skipped": 0, "xfailed": 0, "xpassed": 0}
                instance_id = f"instance-{instance_index:02d}"
                if gate_id in {"B-COVERAGE", "B-STATIC-SECURITY"}:
                    h0_index = next(
                        index for index, candidate in enumerate(
                            row for row in supported_environments if row["lane"] == "H0-hermetic"
                        ) if candidate["python"] == environment["python"]
                    )
                    instance_id = f"instance-{h0_index:02d}"
                instances.append({
                    "artifacts": [],
                    "assertions": [assertion],
                    "environment": instance_environment,
                    "finished_at": instance_finished_at,
                    "id": instance_id,
                    "lane": environment["lane"],
                    "selection": selection,
                    "started_at": gate_started_at,
                    "toolchain": gate_toolchain,
                })

            benchmark = next(
                (row for row in thresholds["benchmarks"] if row["gate_id"] == gate_id),
                None,
            )
            measurements = []
            for threshold in thresholds["thresholds"]:
                if threshold["gate_id"] == gate_id:
                    if gate_id == "B-COVERAGE":
                        observed_value = 0 if threshold["class"] == "regression" else 10000
                    elif threshold["class"] == "regression":
                        observed_value = 0
                    elif threshold["operator"] == "at_least":
                        observed_value = threshold["limit"]
                    elif (gate_id in contracts.RESOURCE_REPORT_GATES and
                          threshold["metric"] not in resource_contract._ZERO_INVARIANTS):
                        observed_value = min(1, threshold["limit"])
                    else:
                        observed_value = 0
                    measurements.append({
                        "baseline_digest": threshold["baseline_digest"],
                        "class": threshold["class"],
                        "invalidated_trials": 0,
                        "metric": threshold["metric"],
                        "observed_trials": benchmark["repetitions"] if benchmark else 1,
                        "statistic": threshold["statistic"],
                        "unit": threshold["unit"],
                        "value": observed_value,
                    })
            materials = []
            if gate_id == "C-TOOLS":
                materials.extend({
                    "digest": row["digest"], "kind": "template_set", "name": row["name"],
                } for row in support["template_sets"])
            if gate_id in {"A-CORPUS", "C-CORPUS-SYNTHETIC"}:
                selected_corpus = next(row for row in corpus["sources"] if row["selected"])
                materials.extend((
                    {
                        "digest": selected_corpus["attestation_digest"],
                        "kind": "corpus_attestation",
                        "name": selected_corpus["gate_id"],
                    },
                    {
                        "digest": selected_corpus["fixture_digest"],
                        "kind": "corpus_fixture",
                        "name": selected_corpus["gate_id"],
                    },
                ))
            materials.sort(key=lambda row: (row["kind"], row["name"]))
            supporting_bodies = _supporting_bodies(
                gate_id,
                identity=identity,
                scope=scope,
                support=support,
                thresholds=thresholds,
                corpus=corpus,
                benchmark=benchmark,
                measurements=measurements,
                environment=instances[0]["environment"],
                evidence_instance_id=instances[0]["id"],
                evidence_instances=instances,
                toolchain=gate_toolchain,
                indexed=indexed, emitted=emitted,
                policy=policy,
            )
            for artifact_name, media_type in contracts.required_artifact_contract(gate_id):
                artifact_body = supporting_bodies[artifact_name]
                relative = f"artifacts/{gate_id}/{artifact_name}.bin"
                destination = artifact_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(artifact_body)
                artifact = {
                    "digest": contracts.raw_sha256(artifact_body),
                    "gate_id": gate_id,
                    "media_type": media_type,
                    "name": artifact_name,
                    "path": relative,
                    "size": len(artifact_body),
                }
                indexed.append(artifact)
                emitted[(gate_id, artifact_name)] = artifact_body
                artifacts.append({
                    key: artifact[key] for key in ("digest", "media_type", "name")
                })
                target_instance = instances[0]
                if gate_id == "C-FAULT-RUNNER":
                    target_instance = next(
                        instance for instance in instances
                        if instance["lane"] == "H1-tool-integration"
                    )
                if gate_id == "C-PRIVATE-FILES":
                    target_lane = (
                        "H0-hermetic" if artifact_name == "filesystem-trace"
                        else "H1-tool-integration"
                    )
                    target_instance = next(
                        instance for instance in instances
                        if instance["lane"] == target_lane
                    )
                if gate_id in {"C-SBOM", "C-VULNERABILITY"} and (
                        artifact_name.startswith("sbom-observation-") or artifact_name.startswith("vulnerability-observation-")):
                    minor = artifact_name.rsplit("-", 1)[1]
                    target_instance = next(
                        instance for instance in instances
                        if instance["environment"]["python"].startswith(minor + ".")
                    )
                target_instance["artifacts"].append({
                    "digest": artifact["digest"],
                    "name": artifact_name,
                })
            for instance in instances:
                instance["artifacts"].sort(key=lambda row: row["name"])
            report = {
                "benchmark": copy.deepcopy(benchmark),
                "candidate_identity_digest": evidence.canonical_digest(identity),
                "gate_id": gate_id,
                "instances": instances,
                "materials": materials,
                "measurements": measurements,
                "release": "0.3.10",
                "schema_version": contracts.EVIDENCE_REPORT_SCHEMA,
            }
            body = contracts.canonical_json_line(report)
            relative = f"artifacts/{gate_id}/gate-evidence.json"
            destination = artifact_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            artifact = {
                "digest": contracts.raw_sha256(body),
                "gate_id": gate_id,
                "media_type": "application/json",
                "name": "gate-evidence",
                "path": relative,
                "size": len(body),
            }
            indexed.append(artifact)
            emitted[(gate_id, "gate-evidence")] = body
            artifacts.append({key: artifact[key] for key in ("digest", "media_type", "name")})
            artifacts.sort(key=lambda row: row["name"])
        count = len(instances)
        selection = {
            "collected": count,
            "deselected": 0,
            "failed": 0,
            "passed": count,
            "selected": count,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        }
        if gate_id == "A-TAXONOMY":
            selection = copy.deepcopy(instances[0]["selection"])
        if gate_id == "B-HERMETIC-ALL":
            selection = {
                name: sum(instance["selection"][name] for instance in instances)
                for name in selection
            }
        if gate_id in {"B-DOCS-POLICY", "B-QUALITY", "B-COVERAGE", "B-STATIC-SECURITY"}:
            selection = copy.deepcopy(instances[0]["selection"])
        if gate_id == "B-MANIFEST":
            selection = copy.deepcopy(instances[0]["selection"])
        if gate_id in {
            "C-FAULT-STORE", "C-FAULT-REVISION", *contracts._FAULT_H0_MATRIX_CONTRACTS,
        }:
            selection = copy.deepcopy(instances[0]["selection"])
        if gate_id == "C-FAULT-RUNNER":
            selection = {
                name: sum(instance["selection"][name] for instance in instances)
                for name in selection
            }
        if gate_id == "C-PRIVATE-FILES":
            selection = {
                name: sum(instance["selection"][name] for instance in instances)
                for name in selection
            }
        if gate_id == "C-CORPUS-SYNTHETIC":
            selection = copy.deepcopy(instances[0]["selection"])
        rule = None
        reason = None
        status = "pass"
        if is_live:
            status = "not_applicable"
            reason = "approved v0.3.10 scope omits live execution"
            rule = {
                "approved_at": no_live["approval"]["approved_at"],
                "digest": evidence.canonical_digest(no_live),
                "expires_at": no_live["expires_at"],
                "id": no_live["rule_id"],
            }
        gate = {
            "artifacts": artifacts,
            "assertions": [] if is_live else [{
                "id": contracts.required_assertion_id(gate_id),
                "reason": None,
                "status": "pass",
            }],
            "candidate": evidence.candidate_summary(identity),
            "environment": instances[0]["environment"] if instances else default_environment,
            "finished_at": gate_finished_at,
            "gate_id": gate_id,
            "inputs": copy.deepcopy(inputs),
            "lane": collector,
            "not_applicable_rule": rule,
            "reason": reason,
            "release": "0.3.10",
            "required": True,
            "schema_version": evidence.GATE_SCHEMA,
            "selection": selection,
            "signature": None,
            "started_at": gate_started_at,
            "status": status,
            "toolchain": gate_toolchain if not is_live else [],
        }
        _resign_gate(gate, identity, policy)
        records.append(gate)
    indexed.sort(key=lambda row: (row["gate_id"], row["name"]))
    index = {
        "artifacts": indexed,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "release": "0.3.10",
        "schema_version": contracts.ARTIFACT_INDEX_SCHEMA,
    }
    arguments = {
        "aggregator_identity": copy.deepcopy(support["aggregators"][0]),
        "artifact_index": index,
        "artifact_root": artifact_root,
        "corpus_manifest": corpus,
        "generated_at": "2026-08-14T11:00:00Z",
        "identity": identity,
        "input_bodies": bodies,
        "no_live_rule": no_live,
        "records": records,
        "scope": scope,
        "support_matrix": support,
        "threshold_manifest": thresholds,
        "trusted_policy_digest": evidence.canonical_digest(policy),
        "trust_policy": policy,
    }
    return arguments


def _gate(arguments: dict, gate_id: str) -> dict:
    return next(record for record in arguments["records"] if record["gate_id"] == gate_id)


def _rewrite_report(arguments: dict, gate_id: str, mutate) -> None:
    """Rewrite one synthetic report and keep its index/gate signature coherent."""
    gate = _gate(arguments, gate_id)
    indexed = next(
        record for record in arguments["artifact_index"]["artifacts"]
        if record["gate_id"] == gate_id and record["name"] == "gate-evidence"
    )
    path = arguments["artifact_root"] / indexed["path"]
    report = json.loads(path.read_bytes())
    mutate(report, gate)
    body = contracts.canonical_json_line(report)
    path.write_bytes(body)
    indexed["digest"] = contracts.raw_sha256(body)
    indexed["size"] = len(body)
    gate_artifact = next(row for row in gate["artifacts"] if row["name"] == "gate-evidence")
    gate_artifact["digest"] = indexed["digest"]
    _resign_gate(gate, arguments["identity"], arguments["trust_policy"])


def _rewrite_supporting_artifact(
    arguments: dict, gate_id: str, artifact_name: str, body: bytes,
) -> None:
    gate = _gate(arguments, gate_id)
    indexed_by_name = {
        row["name"]: row for row in arguments["artifact_index"]["artifacts"]
        if row["gate_id"] == gate_id
    }
    indexed = indexed_by_name[artifact_name]
    (arguments["artifact_root"] / indexed["path"]).write_bytes(body)
    indexed["digest"] = contracts.raw_sha256(body)
    indexed["size"] = len(body)
    next(row for row in gate["artifacts"] if row["name"] == artifact_name)["digest"] = \
        indexed["digest"]

    report_index = indexed_by_name["gate-evidence"]
    report_path = arguments["artifact_root"] / report_index["path"]
    report = json.loads(report_path.read_bytes())
    for instance in report["instances"]:
        for artifact in instance["artifacts"]:
            if artifact["name"] == artifact_name:
                artifact["digest"] = indexed["digest"]
    report_body = contracts.canonical_json_line(report)
    report_path.write_bytes(report_body)
    report_index["digest"] = contracts.raw_sha256(report_body)
    report_index["size"] = len(report_body)
    next(row for row in gate["artifacts"] if row["name"] == "gate-evidence")["digest"] = \
        report_index["digest"]
    _resign_gate(gate, arguments["identity"], arguments["trust_policy"])


def _rewrite_signed_provenance(arguments: dict, mutate) -> None:
    """Keep the provenance envelope and its enclosing signed record coherent."""
    provenance_index = next(
        row for row in arguments["artifact_index"]["artifacts"]
        if row["gate_id"] == "C-PROVENANCE" and row["name"] == "provenance"
    )
    provenance = json.loads((arguments["artifact_root"] / provenance_index["path"]).read_bytes())
    mutate(provenance)
    provenance_body = contracts.canonical_json_line(provenance)
    payload_digest = contracts.raw_sha256(provenance_body)
    message = contracts.signature_preimage(
        role="gate",
        payload_digest=payload_digest,
        candidate_identity_digest=evidence.canonical_digest(arguments["identity"]),
        trust_policy_digest=evidence.canonical_digest(arguments["trust_policy"]),
    )
    envelope = {
        "algorithm": "ed25519",
        "candidate_identity_digest": evidence.canonical_digest(arguments["identity"]),
        "key_id": "test-gate-v1",
        "payload_digest": payload_digest,
        "role": "gate",
        "schema_version": contracts.SIGNATURE_ENVELOPE_SCHEMA,
        "signature": "base64:" + base64.b64encode(_sign(message, seed=GATE_SEED)).decode("ascii"),
        "trust_policy_digest": evidence.canonical_digest(arguments["trust_policy"]),
    }
    _rewrite_supporting_artifact(arguments, "C-PROVENANCE", "provenance", provenance_body)
    _rewrite_supporting_artifact(
        arguments, "C-PROVENANCE", "signature-verification", contracts.canonical_json_line(envelope),
    )


def _rewrite_resource_report(arguments: dict, gate_id: str, mutate) -> None:
    indexed = next(
        record for record in arguments["artifact_index"]["artifacts"]
        if record["gate_id"] == gate_id and record["name"] == "resource-gate-report"
    )
    path = arguments["artifact_root"] / indexed["path"]
    report = json.loads(path.read_bytes())
    mutate(report)
    _rewrite_supporting_artifact(
        arguments,
        gate_id,
        "resource-gate-report",
        resource_contract.canonical_bytes(report),
    )


def _rebind_scenario(arguments: dict) -> None:
    """Cascade changed accepted manifest bytes without changing substantive reports."""
    manifest_documents = {
        "corpus-selection": arguments["corpus_manifest"],
        "no-live-rule": arguments["no_live_rule"],
        "support-matrix": arguments["support_matrix"],
        "threshold-benchmark": arguments["threshold_manifest"],
    }
    for name, document in manifest_documents.items():
        arguments["input_bodies"][name] = contracts.canonical_json_line(document)
    binding_by_name = {row["name"]: row for row in arguments["scope"]["input_bindings"]}
    for name, body in arguments["input_bodies"].items():
        binding_by_name[name]["digest"] = contracts.raw_sha256(body)
    scope_approved_at = arguments["scope"]["approval"]["approved_at"]
    _sign_contract_review(
        arguments["scope"], arguments["trust_policy"], approved_at=scope_approved_at,
    )

    identity = arguments["identity"]
    identity_input_by_name = {row["name"]: row for row in identity["inputs"]}
    for row in arguments["scope"]["input_bindings"]:
        identity_input_by_name[row["name"]].update({
            "digest": row["digest"],
            "path": row["path"],
        })
    identity_input_by_name["release-scope"]["digest"] = contracts.raw_sha256(
        contracts.canonical_json_line(arguments["scope"])
    )
    identity_digest = evidence.canonical_digest(identity)

    index_by_key = {
        (row["gate_id"], row["name"]): row
        for row in arguments["artifact_index"]["artifacts"]
    }
    emitted = {
        key: (arguments["artifact_root"] / row["path"]).read_bytes()
        for key, row in index_by_key.items()
    }
    for gate in arguments["records"]:
        gate_id = gate["gate_id"]
        if gate_id not in contracts.LIVE_GATES:
            indexed_report = index_by_key[(gate_id, "gate-evidence")]
            path = arguments["artifact_root"] / indexed_report["path"]
            report = json.loads(path.read_bytes())
            report["candidate_identity_digest"] = identity_digest
            supporting_bodies = _supporting_bodies(
                gate_id,
                identity=identity,
                scope=arguments["scope"],
                support=arguments["support_matrix"],
                thresholds=arguments["threshold_manifest"],
                corpus=arguments["corpus_manifest"],
                benchmark=report["benchmark"],
                measurements=report["measurements"],
                environment=gate["environment"],
                evidence_instance_id=report["instances"][0]["id"],
                evidence_instances=report["instances"],
                toolchain=gate["toolchain"],
                indexed=arguments["artifact_index"]["artifacts"], emitted=emitted,
                policy=arguments["trust_policy"],
            )
            for artifact_name, artifact_body in supporting_bodies.items():
                indexed_artifact = index_by_key[(gate_id, artifact_name)]
                artifact_path = arguments["artifact_root"] / indexed_artifact["path"]
                artifact_path.write_bytes(artifact_body)
                indexed_artifact["digest"] = contracts.raw_sha256(artifact_body)
                indexed_artifact["size"] = len(artifact_body)
                emitted[(gate_id, artifact_name)] = artifact_body
                next(
                    row for row in gate["artifacts"] if row["name"] == artifact_name
                )["digest"] = indexed_artifact["digest"]
                for instance in report["instances"]:
                    for artifact in instance["artifacts"]:
                        if artifact["name"] == artifact_name:
                            artifact["digest"] = indexed_artifact["digest"]
            body = contracts.canonical_json_line(report)
            path.write_bytes(body)
            indexed_report["digest"] = contracts.raw_sha256(body)
            indexed_report["size"] = len(body)
            emitted[(gate_id, "gate-evidence")] = body
            next(
                row for row in gate["artifacts"] if row["name"] == "gate-evidence"
            )["digest"] = indexed_report["digest"]
        gate["candidate"] = evidence.candidate_summary(identity)
        gate["inputs"] = contracts.expected_gate_inputs(
            arguments["scope"], identity=identity, policy=arguments["trust_policy"],
        )
        if gate_id in contracts.LIVE_GATES:
            rule = arguments["no_live_rule"]
            gate["not_applicable_rule"] = {
                "approved_at": rule["approval"]["approved_at"],
                "digest": evidence.canonical_digest(rule),
                "expires_at": rule["expires_at"],
                "id": rule["rule_id"],
            }
        _resign_gate(gate, identity, arguments["trust_policy"])
    arguments["artifact_index"]["candidate_identity_digest"] = identity_digest


def _verification_arguments(arguments: dict) -> dict:
    return {
        "artifact_index": arguments["artifact_index"],
        "artifact_root": arguments["artifact_root"],
        "corpus_manifest": arguments["corpus_manifest"],
        "identity": arguments["identity"],
        "input_bodies": arguments["input_bodies"],
        "no_live_rule": arguments["no_live_rule"],
        "policy": arguments["trust_policy"],
        "records": arguments["records"],
        "scope": arguments["scope"],
        "support_matrix": arguments["support_matrix"],
        "threshold_manifest": arguments["threshold_manifest"],
        "trusted_policy_digest": arguments["trusted_policy_digest"],
    }


class TestCommittedContracts:
    def test_fixed_universe_matches_every_obligation_row_in_the_normative_contract(self):
        contract = (ROOT / "docs/releases/RELEASE-GATES.md").read_text(encoding="utf-8")
        documented = set(re.findall(r"^\| `([A-E]-[A-Z0-9-]+)`", contract, re.MULTILINE))
        implemented = {gate for gate, _collector, _lanes in contracts.OBLIGATION_CONTRACTS}
        assert len(documented) == 64
        assert implemented == documented

    def test_complete_scope_is_synthetic_only_and_explicitly_non_authoritative(self):
        scope = _read("release/evidence/release-scope-v1.json", contracts.read_release_scope)
        assert len(scope["obligations"]) == 64
        assert sum(row["record_producing"] for row in scope["obligations"]) == 62
        assert len(scope["selected_record_slots"]) == 56
        assert [row["id"] for row in scope["obligations"] if not row["selected"]] == \
            list(contracts.UNSELECTED_CORPUS_GATES)
        assert all(row["disposition"] == "required_not_applicable"
                   for row in scope["obligations"] if row["id"] in contracts.LIVE_GATES)
        assert scope["approval"] is None
        assert scope["production_trust_policy"]["digest"] is None
        assert not (ROOT / contracts.PRODUCTION_TRUST_POLICY_PATH).exists()
        with pytest.raises(evidence.EvidenceError, match="draft"):
            contracts.read_release_scope(
                (ROOT / "release/evidence/release-scope-v1.json").read_bytes(),
                require_ready=True,
            )

    def test_every_committed_input_binding_rehashes_and_v1_frozen_bytes_are_unchanged(self):
        scope = _read("release/evidence/release-scope-v1.json", contracts.read_release_scope)
        bodies = {row["name"]: (ROOT / row["path"]).read_bytes() for row in scope["input_bindings"]}
        contracts.verify_scope_input_bodies(scope, bodies)
        assert contracts.build_release_scope(bodies) == scope
        assert contracts.raw_sha256((ROOT / evidence.REGISTRY_PATH).read_bytes()) == \
            "sha256:0153272d9327582759ff73d49a9c01c05063f722df3fef02c4861c41d3697ca4"
        assert contracts.raw_sha256((ROOT / evidence.SCHEMA_PATHS["candidate_identity"]).read_bytes()) == \
            "sha256:37f83014e24309efab06238a04be29089b7e64d891c021c1b4ff287d4478b583"
        assert contracts.raw_sha256((ROOT / evidence.SCHEMA_PATHS["gate_record"]).read_bytes()) == \
            "sha256:7cb5de860130fabef5660f47105f453cfc1f42e5458e6f854432e874cfd94fb7"
        by_name = {row["name"]: row["digest"] for row in scope["input_bindings"]}
        assert by_name["run-manifest-validator"] == \
            "sha256:7d286ef3196269c75a240cfc8e7f26705b96dc90b343bc533ba5247ac7cee587"
        assert by_name["run-manifest-schema"] == \
            "sha256:cb18bd7a504e1870c04bc292b6534a6a1c24762d8a2a5343282320e1675c01ba"

    def test_each_additive_schema_declares_the_version_its_reader_implements(self):
        assert set(contracts.SCHEMA_PATHS) == set(contracts.SCHEMA_VERSIONS)
        for name, path in contracts.SCHEMA_PATHS.items():
            schema = json.loads((ROOT / path).read_text(encoding="utf-8"))
            assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
            assert schema["additionalProperties"] is False
            assert schema["properties"]["schema_version"]["const"] == \
                contracts.SCHEMA_VERSIONS[name]

        scope_schema = json.loads(
            (ROOT / "release/evidence/schemas/release-scope-v1.schema.json").read_bytes()
        )
        bindings = scope_schema["properties"]["input_bindings"]
        record_inputs = scope_schema["properties"]["record_inputs"]
        assert bindings["minItems"] == bindings["maxItems"] == len(contracts.SCOPE_INPUT_PATHS)
        assert record_inputs["minItems"] == record_inputs["maxItems"] == \
            len(contracts.SCOPE_INPUT_PATHS) + 3
        support_schema = json.loads(
            (ROOT / contracts.SCHEMA_PATHS["support-matrix-schema"]).read_bytes()
        )
        assert set(support_schema["$defs"]["versioned"]["required"]) == {
            "digest", "license", "name", "version",
        }

    def test_gate_artifact_schema_variants_are_disjoint_and_fail_closed_on_unknown_fields(self):
        schema = json.loads(
            (ROOT / contracts.SCHEMA_PATHS["gate-artifact-schema"]).read_text()
        )
        variant_names = [reference["$ref"].rsplit("/", 1)[-1] for reference in schema["oneOf"]]
        assert variant_names == [
            "machine_report", "clean_build_log", "package_inventory",
            "package_install_inventory", "package_install_smoke_results",
            "benchmark_baseline", "benchmark_trials", "benchmark_invalidations",
            "benchmark_report", "sbom_observation", "sbom", "provenance",
            "publication_subjects",
            "synthetic_corpus_disclosure_attestation", "aggregator_conformance_report",
            "h0_test_report", "h0_isolation_self_test", "schema_validation_report",
            "docs_policy_parity_report",
            "manifest_invariant_report", "manifest_corrupt_fixture_matrix", "quality_report", "coverage_report",
        ]
        discriminators = []
        for name in variant_names:
            variant = schema["$defs"][name]
            assert variant["additionalProperties"] is False
            assert set(variant["properties"]) == set(variant["required"])
            discriminators.append(variant["properties"]["artifact_type"]["const"])
        assert len(discriminators) == len(set(discriminators))
        assert schema["$defs"]["count"]["maximum"] == evidence.MAX_JSON_INTEGER
        assert schema["$defs"]["benchmark_trials"]["properties"]["trials"][
            "maxItems"
        ] == 1000
        clean_build_log = schema["$defs"]["clean_build_log"]
        assert clean_build_log["properties"]["command"]["const"] == \
            list(contracts._CLEAN_BUILD_COMMAND)
        assert clean_build_log["properties"]["exit_code"] == {"const": 0}
        assert schema["$defs"]["build_output"]["maxLength"] == 87_391
        assert schema["$defs"]["build_output"]["minLength"] == 11
        install_files = schema["$defs"]["package_install_inventory"]["properties"]["files"]
        assert install_files["minItems"] == 1 and install_files["maxItems"] == 2_000
        install_cases = schema["$defs"]["package_install_smoke_results"]["properties"]["cases"]
        assert install_cases["minItems"] == install_cases["maxItems"] == 4
        assert "producer" in schema["$defs"]["sbom_observation"]["required"]
        assert schema["$defs"]["sbom_producer"]["properties"]["name"] == {
            "const": "sbom-observation-producer",
        }
        sbom_path = re.compile(
            schema["$defs"]["sbom_file"]["properties"]["path"]["pattern"]
        )
        for value in ("a", "a/b", "C:foo"):
            assert sbom_path.fullmatch(value)
            assert contracts._path(value, "SBOM path") == value
        for value in (
            "C:/foo", "1:/foo", "é:/foo", "_:/foo", ".:/a", "::/a",
            "a//b", "a/", ".", "../a", "a\\b",
        ):
            assert sbom_path.fullmatch(value) is None
            with pytest.raises(evidence.EvidenceError, match="relative POSIX path"):
                contracts._path(value, "SBOM path")
        assert schema["$defs"]["install_checkout_isolation_details"]["properties"][
            "checkout_on_sys_path"
        ] == {"const": False}
        h0_runs = schema["$defs"]["h0_test_report"]["properties"]["runs"]
        assert h0_runs["minItems"] == h0_runs["maxItems"] == 3
        h0_fragments = schema["$defs"]["h0_run"]["properties"]["fragments"]
        assert h0_fragments["minItems"] == h0_fragments["maxItems"] == 6
        assert schema["$defs"]["h0_fragment"]["properties"]["report"] == {
            "$ref": "#/$defs/h0_shard_report",
        }
        assert schema["$defs"]["h0_roster"]["properties"]["count"]["maximum"] == \
            evidence.MAX_JSON_INTEGER
        manifest_cases = schema["$defs"]["manifest_corrupt_fixture_matrix"]["properties"]["cases"]
        assert manifest_cases["minItems"] == manifest_cases["maxItems"] == 3
        assert [row["allOf"][1]["properties"]["members"]["minItems"]
                for row in manifest_cases["prefixItems"]] == [12, 4, 6]
        assert schema["$defs"]["manifest_invariant_report"]["properties"]["node_results"][
            "minItems"
        ] == 18
        case_schema = json.loads((ROOT / contracts.SCHEMA_PATHS[
            "manifest-evidence-cases-schema"
        ]).read_text())
        assert case_schema["properties"]["invariants"]["minItems"] == 18
        assert [row["allOf"][1]["properties"]["members"]["minItems"]
                for row in case_schema["properties"]["corruption_cases"]["prefixItems"]] == [12, 4, 6]
        isolation_instances = schema["$defs"]["h0_isolation_self_test"][
            "properties"
        ]["instances"]
        assert isolation_instances["minItems"] == isolation_instances["maxItems"] == 3
        attempts = schema["$defs"]["h0_isolation_instance"]["properties"]["attempts"]
        assert attempts["items"] is False
        assert attempts["minItems"] == attempts["maxItems"] == 5
        assert [
            row["allOf"][1]["properties"]["kind"]["const"]
            for row in attempts["prefixItems"]
        ] == list(contracts._H0_ISOLATION_ATTEMPTS)
        assert all(
            definition.get("additionalProperties") is False
            for name, definition in schema["$defs"].items()
            if definition.get("type") == "object"
        )

    @pytest.mark.parametrize("path,reader", [
        ("release/evidence/release-scope-v1.json", contracts.read_release_scope),
        ("release/evidence/support-matrix-v1.json", contracts.read_support_matrix),
        ("release/evidence/threshold-benchmark-v1.json", contracts.read_threshold_manifest),
        ("release/evidence/corpus-selection-v1.json", contracts.read_corpus_manifest),
        ("release/evidence/no-live-rule-v1.json", contracts.read_no_live_rule),
    ])
    def test_committed_manifests_have_one_exact_canonical_byte_form(self, path, reader):
        body = (ROOT / path).read_bytes()
        document = reader(body)
        assert body == contracts.canonical_json_line(document)
        with pytest.raises(evidence.EvidenceError, match="canonical|LF"):
            reader(body[:-1] + b" \n")

    def test_draft_matrices_cannot_be_used_as_accepted_inputs(self):
        with pytest.raises(evidence.EvidenceError, match="draft"):
            contracts.read_support_matrix(
                (ROOT / "release/evidence/support-matrix-v1.json").read_bytes(), require_ready=True,
            )
        with pytest.raises(evidence.EvidenceError, match="draft"):
            contracts.read_threshold_manifest(
                (ROOT / "release/evidence/threshold-benchmark-v1.json").read_bytes(),
                require_ready=True,
            )

    def test_threshold_and_gate_evidence_contracts_are_complete(self):
        thresholds = _read(
            "release/evidence/threshold-benchmark-v1.json", contracts.read_threshold_manifest,
        )
        assert len(thresholds["thresholds"]) == len(contracts.THRESHOLD_CONTRACTS) == 62
        for gate_id in contracts.PERFORMANCE_OPERATIONS:
            classes = {
                row["class"] for row in thresholds["thresholds"] if row["gate_id"] == gate_id
            }
            assert classes == {"absolute", "regression"}
        passing = set(contracts.SELECTED_RECORD_SLOTS) - set(contracts.LIVE_GATES)
        assert set(contracts.REQUIRED_ARTIFACTS) == passing
        assert all(contracts.REQUIRED_ARTIFACTS[gate_id] for gate_id in passing)


class TestScopeAndManifestRefusals:
    def test_even_a_reviewed_scope_fails_closed_without_external_production_authority(self):
        scope = _read("release/evidence/release-scope-v1.json", contracts.read_release_scope)
        policy = _policy()
        _sign_contract_review(scope, policy)
        with pytest.raises(evidence.EvidenceError, match="trust policy authority"):
            contracts.validate_release_scope(scope, require_ready=True)
        with pytest.raises(evidence.EvidenceError, match="authority"):
            contracts.validate_release_scope(
                scope, require_ready=True, trust_policy=policy,
            )
        assert contracts.validate_release_scope(
            scope, require_ready=True, trust_policy=policy,
            trusted_policy_digest=evidence.canonical_digest(policy),
        ) == scope

    def test_unknown_missing_duplicate_selection_and_cycle_fail_closed(self):
        scope = _read("release/evidence/release-scope-v1.json", contracts.read_release_scope)
        unknown = copy.deepcopy(scope)
        unknown["surprise"] = True
        with pytest.raises(evidence.EvidenceError, match="unknown"):
            contracts.validate_release_scope(unknown)
        missing = copy.deepcopy(scope)
        del missing["record_inputs"]
        with pytest.raises(evidence.EvidenceError, match="missing"):
            contracts.validate_release_scope(missing)
        duplicate = copy.deepcopy(scope)
        duplicate["selected_record_slots"][-1] = duplicate["selected_record_slots"][0]
        with pytest.raises(evidence.EvidenceError, match="selected slots"):
            contracts.validate_release_scope(duplicate)
        cyclic = copy.deepcopy(scope)
        cyclic["stages"][0]["depends_on"] = ["approval"]
        with pytest.raises(evidence.EvidenceError, match="stages"):
            contracts.validate_release_scope(cyclic)

    def test_private_selection_and_unresolved_threshold_are_refused(self):
        corpus = _read("release/evidence/corpus-selection-v1.json", contracts.read_corpus_manifest)
        corpus["sources"][0]["selected"] = True
        with pytest.raises(evidence.EvidenceError, match="synthetic"):
            contracts.validate_corpus_manifest(corpus)
        thresholds = _read(
            "release/evidence/threshold-benchmark-v1.json", contracts.read_threshold_manifest,
        )
        excessive_trials = copy.deepcopy(thresholds)
        excessive_trials["benchmarks"][0]["repetitions"] = 1001
        with pytest.raises(evidence.EvidenceError, match="trial-id space"):
            contracts.validate_threshold_manifest(excessive_trials)
        policy = _policy()
        _sign_contract_review(thresholds, policy)
        with pytest.raises(evidence.EvidenceError, match="unresolved"):
            contracts.validate_threshold_manifest(
                thresholds, require_ready=True, trust_policy=policy,
                trusted_policy_digest=evidence.canonical_digest(policy),
            )
        support = _read("release/evidence/support-matrix-v1.json", contracts.read_support_matrix)
        _sign_contract_review(support, policy)
        with pytest.raises(evidence.EvidenceError, match="runtime, tool or template"):
            contracts.validate_support_matrix(
                support, require_ready=True, trust_policy=policy,
                trusted_policy_digest=evidence.canonical_digest(policy),
            )


class TestSignatures:
    def test_rfc8032_and_domain_separated_envelope_golden_vectors(self):
        fixture_body = FIXTURE.read_bytes()
        fixture = json.loads(fixture_body)
        assert fixture_body == contracts.canonical_json_line(fixture)
        vector = fixture["rfc8032"]
        contracts.verify_ed25519(
            base64.b64decode(vector["public_key"][7:]),
            base64.b64decode(vector["message"][7:]),
            base64.b64decode(vector["signature"][7:]),
        )
        envelope = fixture["signature_envelope"]
        assert contracts.read_trust_policy(
            contracts.canonical_json_line(fixture["policy"])
        ) == fixture["policy"]
        assert contracts.read_signature_envelope(
            contracts.canonical_json_line(envelope)
        ) == envelope
        preimage = contracts.signature_preimage(
            role=envelope["role"], payload_digest=envelope["payload_digest"],
            candidate_identity_digest=envelope["candidate_identity_digest"],
            trust_policy_digest=envelope["trust_policy_digest"],
        )
        assert "hex:" + preimage.hex() == fixture["signature_preimage"]
        contracts.verify_signature_envelope(
            envelope, policy=fixture["policy"], payload_digest=envelope["payload_digest"],
            candidate_identity_digest=envelope["candidate_identity_digest"], role="approval",
            at=evidence._timestamp("2026-08-14T00:00:00Z", "at"),
        )

    def test_wrong_payload_signature_key_role_and_noncanonical_scalar_fail(self):
        fixture = json.loads(FIXTURE.read_text())
        envelope = fixture["signature_envelope"]
        at = evidence._timestamp("2026-08-14T00:00:00Z", "at")
        with pytest.raises(evidence.EvidenceError, match="payload_digest"):
            contracts.verify_signature_envelope(
                envelope, policy=fixture["policy"], payload_digest=_digest("c"),
                candidate_identity_digest=envelope["candidate_identity_digest"], role="approval", at=at,
            )
        wrong_role = copy.deepcopy(fixture["policy"])
        wrong_role["keys"][0]["roles"] = ["gate"]
        with pytest.raises(evidence.EvidenceError):
            contracts.verify_signature_envelope(
                envelope, policy=wrong_role, payload_digest=envelope["payload_digest"],
                candidate_identity_digest=envelope["candidate_identity_digest"], role="approval", at=at,
            )
        signature = base64.b64decode(fixture["rfc8032"]["signature"][7:])
        bad_scalar = signature[:32] + contracts._ED25519_L.to_bytes(32, "little")
        with pytest.raises(evidence.EvidenceError, match="scalar"):
            contracts.verify_ed25519(PUBLIC, b"", bad_scalar)

    def test_duplicate_key_material_and_dual_role_authority_fail_closed(self):
        duplicate = _policy()
        duplicate["keys"][1]["public_key"] = duplicate["keys"][0]["public_key"]
        with pytest.raises(evidence.EvidenceError, match="duplicate public-key"):
            contracts.validate_trust_policy(duplicate)
        dual_role = _policy()
        dual_role["keys"][0]["roles"] = ["approval", "gate"]
        with pytest.raises(evidence.EvidenceError, match="disjoint"):
            contracts.validate_trust_policy(dual_role)
        incomplete_scope = _policy()
        incomplete_scope["keys"][1]["gate_ids"].pop()
        with pytest.raises(evidence.EvidenceError, match="every selected gate"):
            contracts.validate_trust_policy(incomplete_scope)


class TestIncompleteSemanticRegistry:
    def test_production_aggregation_refuses_unimplemented_obligation_semantics(self, tmp_path):
        assert set(contracts.SEMANTIC_VERIFIERS) == (
            set(contracts.RESOURCE_SEMANTIC_GATES)
            | {
                "A-IDENTITY", "A-EVIDENCE-SCHEMA", "A-TAXONOMY", "A-CORPUS", "A-THRESHOLDS", "A-SUPPORT",
                "B-HERMETIC-ALL", "B-SCHEMA", "B-DOCS-POLICY", "B-MANIFEST", "B-QUALITY", "B-COVERAGE", "B-STATIC-SECURITY", "B-DETERMINISM",
                "C-PACKAGE-BUILD", "C-PACKAGE-INSTALL", "C-PYTHON-MATRIX", "C-SBOM", "C-VULNERABILITY", "C-PROVENANCE", "C-SOURCE-REGISTRY", "C-CORPUS-SYNTHETIC", "C-PRIVATE-FILES", "C-PATH-IDENTITY", "C-FAULT-STORE", "C-FAULT-REVISION", "C-FAULT-FINALIZE", "C-FAULT-CAMPAIGN", "C-FAULT-RUNNER", "C-NETWORK-BOUNDARY", "C-NET-DENY",
                "E-DOCS", "E-PROJECT-HYGIENE", "E-ARTIFACTS",
                *contracts.V310_05_SEMANTIC_GATES,
            }
        )
        assert "E-ARTIFACTS" not in contracts.PROVISIONAL_SEMANTIC_VERIFIERS
        assert "C-PERF-PHASE-FAIRNESS" not in contracts.SEMANTIC_VERIFIERS
        arguments = _scenario(tmp_path)
        with pytest.raises(evidence.EvidenceError, match="gate C-TOOLS"):
            contracts.aggregate_records(**arguments)


class TestSourceRegistryAggregateEvidence:
    @staticmethod
    def _promote_predecessors(monkeypatch):
        """Let the aggregate reach C-SOURCE-REGISTRY without changing production promotion."""
        monkeypatch.setattr(contracts, "SEMANTIC_VERIFIERS", MappingProxyType({
            **contracts.SEMANTIC_VERIFIERS,
            "C-TOOLS": lambda *_args, **_kwargs: None,
            "C-OUTPUT-CONTRACT": lambda *_args, **_kwargs: None,
            "C-NETWORK-BOUNDARY": lambda *_args, **_kwargs: None,
        }))

    def test_aggregate_reaches_next_unimplemented_gate_after_source_registry(self, tmp_path, monkeypatch):
        arguments = _scenario(tmp_path)
        self._promote_predecessors(monkeypatch)
        with pytest.raises(evidence.EvidenceError, match="gate C-CORPUS-SYNTHETIC"):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize(("mutate", "match"), [
        (lambda doc: doc["h0_static_emitter"]["receipt"].update(evidence_instance_id="other-instance"),
         "exact H0/H1 evidence instance"),
        (lambda doc: doc["h1_synthetic_admission"]["receipt"].update(
            nodeid="tests/other.py::test_substituted"), "test receipt"),
        (lambda doc: doc["h1_synthetic_admission"]["receipt"]["selection"].update(selected=2),
         "test receipt"),
    ])
    def test_receipt_substitutions_fail_during_aggregate(self, tmp_path, monkeypatch, mutate, match):
        arguments = _scenario(tmp_path)
        self._promote_predecessors(monkeypatch)
        artifact = next(row for row in arguments["artifact_index"]["artifacts"]
                        if row["gate_id"] == "C-SOURCE-REGISTRY" and
                        row["name"] == "registry-reconciliation")
        document = json.loads((arguments["artifact_root"] / artifact["path"]).read_bytes())
        mutate(document)
        _rewrite_supporting_artifact(
            arguments, "C-SOURCE-REGISTRY", "registry-reconciliation",
            contracts.canonical_json_line(document),
        )
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts.aggregate_records(**arguments)


class TestPrivateFilesSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-PRIVATE-FILES")
        indexed = {
            row["name"]: row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PRIVATE-FILES"
        }
        bodies = {
            name: (arguments["artifact_root"] / indexed[name]["path"]).read_bytes()
            for name in ("filesystem-trace", "mode-owner-symlink-matrix")
        }
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / indexed["gate-evidence"]["path"]).read_bytes(),
            identity=arguments["identity"],
            gate_id="C-PRIVATE-FILES",
        )
        return arguments, gate, bodies, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        contracts._semantic_private_files(
            gate,
            bodies,
            identity=arguments["identity"],
            input_bodies=arguments["input_bodies"],
            report=report,
            scope=arguments["scope"],
        )

    def test_exact_private_file_artifacts_bind_the_signed_h0_h1_instances(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        self._verify(arguments, gate, bodies, report)

    def test_an_unsupported_foreign_owner_case_cannot_pass(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        document = json.loads(bodies["mode-owner-symlink-matrix"])
        foreign = document["observations"][-1]
        foreign["error"] = None
        foreign["error_detail"] = {"class": "unsupported", "components": []}
        body = private_files_evidence.canonical_json_bytes(document)
        bodies["mode-owner-symlink-matrix"] = body
        digest = contracts.raw_sha256(body)
        next(
            row for row in gate["artifacts"]
            if row["name"] == "mode-owner-symlink-matrix"
        )["digest"] = digest
        report["instances"][1]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="did not execute"):
            self._verify(arguments, gate, bodies, report)


class TestPathIdentitySemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-PATH-IDENTITY")
        bodies = {
            row["name"]: (arguments["artifact_root"] / row["path"]).read_bytes()
            for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PATH-IDENTITY"
        }
        report = contracts.read_evidence_report(
            bodies.pop("gate-evidence"),
            identity=arguments["identity"],
            gate_id="C-PATH-IDENTITY",
        )
        return gate, bodies, {
            "identity": arguments["identity"],
            "input_bodies": arguments["input_bodies"],
            "report": report,
            "scope": arguments["scope"],
        }

    def test_exact_measured_corpus_is_owned_by_one_signed_h0_instance(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        contracts._semantic_path_identity(gate, bodies, **context)

    def test_forged_case_result_fails_after_outer_digest_rebinding(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies["containment-decisions"])
        document["cases"][0]["actual_disposition"] = "refused"
        bodies["containment-decisions"] = contracts.canonical_json_line(document)
        digest = contracts.raw_sha256(bodies["containment-decisions"])
        next(row for row in gate["artifacts"] if row["name"] == "containment-decisions")[
            "digest"
        ] = digest
        context["report"]["instances"][0]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="contradicts its expected disposition"):
            contracts._semantic_path_identity(gate, bodies, **context)


class TestSyntheticCorpusSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-CORPUS-SYNTHETIC")
        indexed = {
            row["name"]: row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-CORPUS-SYNTHETIC"
        }
        bodies = {
            name: (arguments["artifact_root"] / indexed[name]["path"]).read_bytes()
            for name in ("derivation-diff", "disclosure-report")
        }
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / indexed["gate-evidence"]["path"]).read_bytes(),
            identity=arguments["identity"],
            gate_id="C-CORPUS-SYNTHETIC",
        )
        return arguments, gate, bodies, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"],
            identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_synthetic_corpus(
                gate,
                bodies,
                corpus=arguments["corpus_manifest"],
                identity=arguments["identity"],
                report=report,
                resolver=resolver,
            )

    def test_c_gate_reuses_the_selected_public_disclosure_attestation(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        self._verify(arguments, gate, bodies, report)

    def test_derivation_projection_substitution_fails_after_digest_rebinding(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        document = json.loads(bodies["derivation-diff"])
        document["records"][0]["result"]["subject"] = f"derivation-1:{_digest('0')}"
        document["records"][0]["result_digest"] = evidence.canonical_digest(
            document["records"][0]["result"]
        )
        bodies["derivation-diff"] = contracts.canonical_json_line(document)
        digest = contracts.raw_sha256(bodies["derivation-diff"])
        next(row for row in gate["artifacts"] if row["name"] == "derivation-diff")["digest"] = digest
        report["instances"][0]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="derivation projection is substituted"):
            self._verify(arguments, gate, bodies, report)


class TestFaultStoreSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-FAULT-STORE")
        indexed = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-FAULT-STORE" and row["name"] == "fault-matrix"
        )
        body = (arguments["artifact_root"] / indexed["path"]).read_bytes()
        report_index = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-FAULT-STORE" and row["name"] == "gate-evidence"
        )
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / report_index["path"]).read_bytes(),
            identity=arguments["identity"],
            gate_id="C-FAULT-STORE",
        )
        return arguments, gate, {"fault-matrix": body}, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"],
            identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_fault_store(
                gate,
                bodies,
                identity=arguments["identity"],
                input_bodies=arguments["input_bodies"],
                report=report,
                resolver=resolver,
                scope=arguments["scope"],
            )

    def test_frozen_fault_roster_reuses_the_validated_h0_run(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        self._verify(arguments, gate, bodies, report)

    def test_source_plan_or_h0_environment_substitution_fails(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path / "plan")
        document = json.loads(bodies["fault-matrix"])
        document["cases"][0]["execution_status"] = "passed"
        bodies["fault-matrix"] = contracts.canonical_json_line(document)
        digest = contracts.raw_sha256(bodies["fault-matrix"])
        next(row for row in gate["artifacts"] if row["name"] == "fault-matrix")["digest"] = digest
        report["instances"][0]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="differs from exact candidate inputs"):
            self._verify(arguments, gate, bodies, report)

        arguments, gate, bodies, report = self._case(tmp_path / "environment")
        report["instances"][0]["environment"]["python"] = "3.11.99"
        with pytest.raises(evidence.EvidenceError, match="one validated H0 run"):
            self._verify(arguments, gate, bodies, report)


class TestFaultRunnerSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-FAULT-RUNNER")
        indexed = {
            row["name"]: row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-FAULT-RUNNER"
        }
        bodies = {
            "fault-matrix": (
                arguments["artifact_root"] / indexed["fault-matrix"]["path"]
            ).read_bytes(),
        }
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / indexed["gate-evidence"]["path"]).read_bytes(),
            identity=arguments["identity"],
            gate_id="C-FAULT-RUNNER",
        )
        return arguments, gate, bodies, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"],
            identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_fault_runner(
                gate,
                bodies,
                identity=arguments["identity"],
                input_bodies=arguments["input_bodies"],
                report=report,
                resolver=resolver,
                scope=arguments["scope"],
            )

    def test_exact_mixed_lane_matrix_reuses_h0_and_owns_h1(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        self._verify(arguments, gate, bodies, report)

    def test_node_or_lane_partition_substitution_fails(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path / "node")
        document = json.loads(bodies["fault-matrix"])
        document["records"][-1]["result"]["subject"] = (
            "tests/substituted.py::test_case"
        )
        document["records"][-1]["result_digest"] = evidence.canonical_digest(
            document["records"][-1]["result"]
        )
        bodies["fault-matrix"] = contracts.canonical_json_line(document)
        digest = contracts.raw_sha256(bodies["fault-matrix"])
        next(row for row in gate["artifacts"] if row["name"] == "fault-matrix")[
            "digest"
        ] = digest
        report["instances"][1]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="exact frozen mixed-lane roster"):
            self._verify(arguments, gate, bodies, report)

        arguments, gate, bodies, report = self._case(tmp_path / "lane")
        report["instances"][1]["selection"]["selected"] -= 1
        with pytest.raises(evidence.EvidenceError, match="exact H0/H1 partition"):
            self._verify(arguments, gate, bodies, report)


class TestFaultRevisionSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-FAULT-REVISION")
        indexed = {
            row["name"]: row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-FAULT-REVISION"
        }
        bodies = {
            "fault-matrix": (
                arguments["artifact_root"] / indexed["fault-matrix"]["path"]
            ).read_bytes(),
        }
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / indexed["gate-evidence"]["path"]).read_bytes(),
            identity=arguments["identity"],
            gate_id="C-FAULT-REVISION",
        )
        return arguments, gate, bodies, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"],
            identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_fault_revision(
                gate,
                bodies,
                identity=arguments["identity"],
                input_bodies=arguments["input_bodies"],
                report=report,
                resolver=resolver,
                scope=arguments["scope"],
            )

    def test_complete_revision_matrix_reuses_the_validated_h0_run(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        self._verify(arguments, gate, bodies, report)

    def test_revision_case_substitution_fails_after_digest_rebinding(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        document = json.loads(bodies["fault-matrix"])
        document["records"][0]["result"]["subject"] = "tests/substituted.py::test_case"
        document["records"][0]["result_digest"] = evidence.canonical_digest(
            document["records"][0]["result"]
        )
        bodies["fault-matrix"] = contracts.canonical_json_line(document)
        digest = contracts.raw_sha256(bodies["fault-matrix"])
        next(row for row in gate["artifacts"] if row["name"] == "fault-matrix")["digest"] = digest
        report["instances"][0]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="exact frozen H0 roster"):
            self._verify(arguments, gate, bodies, report)


class TestFinalizeCampaignFaultSemanticEvidence:
    @staticmethod
    def _case(tmp_path, gate_id):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, gate_id)
        indexed = {
            row["name"]: row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == gate_id
        }
        bodies = {
            "fault-matrix": (
                arguments["artifact_root"] / indexed["fault-matrix"]["path"]
            ).read_bytes(),
        }
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / indexed["gate-evidence"]["path"]).read_bytes(),
            identity=arguments["identity"],
            gate_id=gate_id,
        )
        return arguments, gate, bodies, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"],
            identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_fault_h0_matrix(
                gate,
                bodies,
                identity=arguments["identity"],
                input_bodies=arguments["input_bodies"],
                report=report,
                resolver=resolver,
                scope=arguments["scope"],
            )

    @pytest.mark.parametrize("gate_id", tuple(contracts._FAULT_H0_MATRIX_CONTRACTS))
    def test_exact_fault_matrix_reuses_the_validated_h0_run(self, tmp_path, gate_id):
        arguments, gate, bodies, report = self._case(tmp_path, gate_id)
        self._verify(arguments, gate, bodies, report)

    @pytest.mark.parametrize("gate_id", tuple(contracts._FAULT_H0_MATRIX_CONTRACTS))
    def test_fault_case_substitution_fails_after_digest_rebinding(self, tmp_path, gate_id):
        arguments, gate, bodies, report = self._case(tmp_path, gate_id)
        document = json.loads(bodies["fault-matrix"])
        document["records"][-1]["result"]["subject"] = "tests/substituted.py::test_case"
        document["records"][-1]["result_digest"] = evidence.canonical_digest(
            document["records"][-1]["result"]
        )
        bodies["fault-matrix"] = contracts.canonical_json_line(document)
        digest = contracts.raw_sha256(bodies["fault-matrix"])
        next(row for row in gate["artifacts"] if row["name"] == "fault-matrix")["digest"] = digest
        report["instances"][0]["artifacts"][0]["digest"] = digest
        with pytest.raises(evidence.EvidenceError, match="exact frozen H0 roster"):
            self._verify(arguments, gate, bodies, report)


class TestVulnerabilitySemanticEvidence:
    @staticmethod
    def _document(arguments: dict, name: str) -> dict:
        artifact = next(row for row in arguments["artifact_index"]["artifacts"]
                        if row["gate_id"] == "C-VULNERABILITY" and row["name"] == name)
        return json.loads((arguments["artifact_root"] / artifact["path"]).read_bytes())

    @staticmethod
    def _resign_provider(document: dict, arguments: dict) -> None:
        provider = document["provider"]
        payload = {
            "database_snapshot": provider["database_snapshot"],
            "dependency_scans": provider["dependency_scans"],
            "external_results": provider["external_results"],
            "freshness": provider["freshness"],
            "issuer": provider["trusted_attestation"]["issuer"],
            "provider": provider["name"],
        }
        digest = contracts.raw_sha256(contracts.canonical_json_line(payload))
        message = contracts.signature_preimage(
            role="approval", payload_digest=digest,
            candidate_identity_digest=evidence.canonical_digest(arguments["identity"]),
            trust_policy_digest=evidence.canonical_digest(arguments["trust_policy"]),
        )
        provider["trusted_attestation"]["signature"] = {
            "algorithm": "ed25519", "candidate_identity_digest": evidence.canonical_digest(arguments["identity"]),
            "key_id": "test-approval-v1", "payload_digest": digest, "role": "approval",
            "schema_version": contracts.SIGNATURE_ENVELOPE_SCHEMA,
            "signature": "base64:" + base64.b64encode(_sign(message, seed=APPROVAL_SEED)).decode("ascii"),
            "trust_policy_digest": evidence.canonical_digest(arguments["trust_policy"]),
        }

    def test_positive_documents_validate_both_vulnerability_schemas(self, tmp_path):
        arguments = _scenario(tmp_path)
        findings = self._document(arguments, "vulnerability-findings")
        observation = self._document(arguments, "vulnerability-observation-3.10")
        for path, document in (
            ("release/evidence/schemas/vulnerability-findings-v1.schema.json", findings),
            ("release/evidence/schemas/vulnerability-observation-v1.schema.json", observation),
        ):
            schema = json.loads((ROOT / path).read_bytes())
            Draft202012Validator.check_schema(schema)
            assert list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)) == []

    def test_vulnerability_schemas_reject_wrong_argv_timestamp_and_provider_shape(self, tmp_path):
        arguments = _scenario(tmp_path)
        observation = self._document(arguments, "vulnerability-observation-3.10")
        observation["scanner"]["argv"][1] = "--not-strict"
        observation_schema = Draft202012Validator(json.loads((ROOT / "release/evidence/schemas/vulnerability-observation-v1.schema.json").read_bytes()), format_checker=FormatChecker())
        assert list(observation_schema.iter_errors(observation))
        findings = self._document(arguments, "vulnerability-findings")
        findings["provider"]["freshness"]["observed_at"] = "2026-08-14 10:20:00"
        findings["provider"]["database_snapshot"]["unexpected"] = 1
        findings_schema = Draft202012Validator(json.loads((ROOT / "release/evidence/schemas/vulnerability-findings-v1.schema.json").read_bytes()), format_checker=FormatChecker())
        assert list(findings_schema.iter_errors(findings))

    @pytest.mark.parametrize(("mutate", "expected"), [
        (lambda doc: doc["provider"]["external_results"][0]["subject"].__setitem__("digest", _digest("7")), "external result"),
        (lambda doc: doc["provider"]["dependency_scans"][0].__setitem__("sbom_observation_digest", _digest("6")), "dependency scans"),
    ])
    def test_provider_subject_and_scan_substitutions_fail_after_resigning_outer_record(self, tmp_path, mutate, expected):
        arguments = _scenario(tmp_path)
        document = self._document(arguments, "vulnerability-findings")
        mutate(document)
        self._resign_provider(document, arguments)
        _rewrite_supporting_artifact(arguments, "C-VULNERABILITY", "vulnerability-findings", contracts.canonical_json_line(document))
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    def test_expired_accepted_external_exception_fails_after_all_approval_envelopes_recompute(self, tmp_path):
        arguments = _scenario(tmp_path)
        document = self._document(arguments, "vulnerability-findings")
        result = document["provider"]["external_results"][0]
        exception = {"expires_at": "2026-08-14T10:20:01Z", "owner": "test-owner", "rationale": "Synthetic expiry-path exception rationale."}
        payload = {"expires_at": exception["expires_at"], "id": "OSV-test-1", "owner": exception["owner"], "rationale": exception["rationale"], "subject": result["subject"]}
        digest = contracts.raw_sha256(contracts.canonical_json_line(payload))
        message = contracts.signature_preimage(role="approval", payload_digest=digest,
            candidate_identity_digest=evidence.canonical_digest(arguments["identity"]), trust_policy_digest=evidence.canonical_digest(arguments["trust_policy"]))
        exception["approval"] = {"algorithm": "ed25519", "candidate_identity_digest": evidence.canonical_digest(arguments["identity"]), "key_id": "test-approval-v1", "payload_digest": digest, "role": "approval", "schema_version": contracts.SIGNATURE_ENVELOPE_SCHEMA, "signature": "base64:" + base64.b64encode(_sign(message, seed=APPROVAL_SEED)).decode("ascii"), "trust_policy_digest": evidence.canonical_digest(arguments["trust_policy"])}
        result["advisories"] = [{"exception": exception, "id": "OSV-test-1", "state": "accepted_exception"}]
        self._resign_provider(document, arguments)
        _rewrite_supporting_artifact(arguments, "C-VULNERABILITY", "vulnerability-findings", contracts.canonical_json_line(document))
        with pytest.raises(evidence.EvidenceError, match="external exception"):
            contracts.aggregate_records(**arguments)

    def test_provider_freshness_cannot_predate_the_signed_p0_interval(self, tmp_path):
        arguments = _scenario(tmp_path)
        document = self._document(arguments, "vulnerability-findings")
        document["provider"]["freshness"]["observed_at"] = "2026-08-14T10:19:59Z"
        self._resign_provider(document, arguments)
        _rewrite_supporting_artifact(arguments, "C-VULNERABILITY", "vulnerability-findings", contracts.canonical_json_line(document))
        with pytest.raises(evidence.EvidenceError, match="freshness"):
            contracts.aggregate_records(**arguments)


class TestSchemaValidationSemanticEvidence:
    def test_gate_artifact_schema_and_manual_schema_report_contract_match(self):
        schema = json.loads((ROOT / "release/evidence/schemas/gate-artifact-v1.schema.json").read_text())
        report = schema["$defs"]["schema_validation_report"]
        outcome = schema["$defs"]["schema_validation_outcome"]
        assert set(report["required"]) == {
            "artifact_type", "candidate_identity_digest", "environment", "evidence_finished_at",
            "evidence_instance_id", "evidence_started_at", "fixture_manifest_digest", "gate_id",
            "legacy_migration", "outcomes", "registry_digest", "release", "schema_version",
        }
        assert set(outcome["required"]) == {
            "accept", "fixture_digest", "malformed", "name", "record_version", "round_trip",
            "schema_digest", "unknown_member", "unknown_version",
        }
        assert report["properties"]["gate_id"] == {"const": "B-SCHEMA"}
        assert schema["$defs"]["schema_validation_legacy_migration"] == {
            "additionalProperties": False,
            "properties": {
                "disposition": {"const": "no-supported-legacy-fixtures"},
                "supported_legacy_migrations": {"maxItems": 0, "type": "array"},
            },
            "required": ["disposition", "supported_legacy_migrations"],
            "type": "object",
        }

    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "B-SCHEMA")
        bodies = {}
        for row in arguments["artifact_index"]["artifacts"]:
            if row["gate_id"] == "B-SCHEMA":
                bodies[row["name"]] = (arguments["artifact_root"] / row["path"]).read_bytes()
        report = contracts.read_evidence_report(
            bodies.pop("gate-evidence"), identity=arguments["identity"], gate_id="B-SCHEMA",
        )
        return gate, bodies, {
            "identity": arguments["identity"], "input_bodies": arguments["input_bodies"],
            "report": report, "scope": arguments["scope"],
        }

    def test_registered_schema_fixture_report_recomputes_exactly(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        contracts._semantic_schema_validation(gate, bodies, **context)

    @pytest.mark.parametrize(
        ("mutate", "match"),
        [
            (lambda doc: doc.update(candidate_identity_digest=_digest("0")), "wrong candidate"),
            (lambda doc: doc.update(evidence_instance_id="other-instance"), "exact signed H0"),
            (lambda doc: doc["outcomes"][0].update(schema_digest=_digest("0")), "frozen schema/fixture facts"),
            (lambda doc: doc["outcomes"].reverse(), "exact registered schema roster"),
            (lambda doc: doc.update(fixture_manifest_digest=_digest("0")), "wrong frozen registry"),
        ],
    )
    def test_candidate_h0_and_frozen_source_substitution_fail_closed(self, tmp_path, mutate, match):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies["schema-validation-report"])
        mutate(document)
        bodies["schema-validation-report"] = contracts.canonical_json_line(document)
        next(artifact for artifact in gate["artifacts"]
             if artifact["name"] == "schema-validation-report")["digest"] = contracts.raw_sha256(
                 bodies["schema-validation-report"]
             )
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts._semantic_schema_validation(gate, bodies, **context)

    def test_unsigned_supporting_artifact_substitution_fails_closed(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        bodies["schema-validation-report"] = contracts.canonical_json_line({
            **json.loads(bodies["schema-validation-report"]), "registry_digest": _digest("0"),
        })
        with pytest.raises(evidence.EvidenceError, match="exact signed gate artifact"):
            contracts._semantic_schema_validation(gate, bodies, **context)


class TestDocsPolicySemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "B-DOCS-POLICY")
        bodies = {
            row["name"]: (arguments["artifact_root"] / row["path"]).read_bytes()
            for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "B-DOCS-POLICY"
        }
        report = contracts.read_evidence_report(
            bodies.pop("gate-evidence"), identity=arguments["identity"], gate_id="B-DOCS-POLICY",
        )
        return gate, bodies, {
            "identity": arguments["identity"], "input_bodies": arguments["input_bodies"],
            "report": report, "scope": arguments["scope"],
        }

    def test_fixed_candidate_h0_roster_and_materials_are_accepted(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        contracts._semantic_docs_policy(gate, bodies, **context)

    def test_unsigned_parity_report_substitution_fails_closed(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies["parity-report"])
        document["test_results"].reverse()
        bodies["parity-report"] = contracts.canonical_json_line(document)
        with pytest.raises(evidence.EvidenceError, match="exact signed artifact digest"):
            contracts._semantic_docs_policy(gate, bodies, **context)

    @pytest.mark.parametrize(
        ("mutate", "match"),
        [
            (lambda doc: doc.update(candidate_identity_digest=_digest("0")), "wrong candidate"),
            (lambda doc: doc["test_results"].reverse(), "test roster or order"),
            (lambda doc: doc["docs_policy_materials"].pop(), "material roster"),
            (lambda doc: doc["selection"].update(passed=12), "counts do not reconcile"),
        ],
    )
    def test_candidate_roster_material_and_count_substitution_fail_closed(self, tmp_path, mutate, match):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies["parity-report"])
        mutate(document)
        bodies["parity-report"] = contracts.canonical_json_line(document)
        next(item for item in gate["artifacts"] if item["name"] == "parity-report")["digest"] = \
            contracts.raw_sha256(bodies["parity-report"])
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts._semantic_docs_policy(gate, bodies, **context)


class TestManifestSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "B-MANIFEST")
        bodies = {
            row["name"]: (arguments["artifact_root"] / row["path"]).read_bytes()
            for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "B-MANIFEST"
        }
        report = contracts.read_evidence_report(
            bodies.pop("gate-evidence"), identity=arguments["identity"], gate_id="B-MANIFEST",
        )
        return gate, bodies, {
            "identity": arguments["identity"], "input_bodies": arguments["input_bodies"],
            "report": report, "scope": arguments["scope"],
        }

    def test_fixed_candidate_h0_manifest_rosters_are_accepted(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        contracts._semantic_manifest(gate, bodies, **context)

    def test_unsigned_manifest_artifact_substitution_fails_closed(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies["invariant-report"])
        document["node_results"].reverse()
        bodies["invariant-report"] = contracts.canonical_json_line(document)
        with pytest.raises(evidence.EvidenceError, match="exact signed artifact digest"):
            contracts._semantic_manifest(gate, bodies, **context)

    @pytest.mark.parametrize(
        ("name", "mutate", "match"),
        [
            ("invariant-report", lambda doc: doc.update(candidate_identity_digest=_digest("0")), "wrong candidate"),
            ("invariant-report", lambda doc: doc.update(evidence_instance_id="other-instance"), "exact signed H0"),
            ("invariant-report", lambda doc: doc.update(evidence_finished_at="2026-08-14T10:10:09Z"), "exact signed H0"),
            ("invariant-report", lambda doc: doc.update(case_manifest_digest=_digest("0")), "case manifest digest"),
            ("invariant-report", lambda doc: doc["node_results"].reverse(), "node roster"),
            ("invariant-report", lambda doc: doc["node_results"].pop(), "node roster"),
            ("invariant-report", lambda doc: doc["node_results"][0]["observed"].update(outcome="refused"), "node roster"),
            ("invariant-report", lambda doc: doc["node_results"][0]["observed"].update(code="wrong.code"), "node roster"),
            ("invariant-report", lambda doc: doc["node_results"][0]["observed"].update(error_class="ManifestError"), "node roster"),
            ("invariant-report", lambda doc: doc["node_results"][0].update(result_digest=_digest("0")), "node roster"),
            ("corrupt-fixture-matrix", lambda doc: doc["cases"].reverse(), "case roster"),
            ("corrupt-fixture-matrix", lambda doc: doc["cases"].pop(), "case roster"),
            ("corrupt-fixture-matrix", lambda doc: doc["cases"][0]["members"][0]["observed"].update(outcome="pass"), "case roster"),
            ("corrupt-fixture-matrix", lambda doc: doc["cases"][0]["members"][0]["observed"].update(code="wrong.code"), "case roster"),
            ("corrupt-fixture-matrix", lambda doc: doc["cases"][0]["members"][0]["observed"].update(error_class="RevisionUnusable"), "case roster"),
            ("corrupt-fixture-matrix", lambda doc: doc["cases"][0]["members"][0].update(result_digest=_digest("0")), "case roster"),
            ("invariant-report", lambda doc: doc.update(matrix_digest=_digest("0")), "corruption matrix digest"),
        ],
    )
    def test_candidate_h0_roster_case_and_cross_digest_substitution_fail_closed(
        self, tmp_path, name, mutate, match,
    ):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies[name])
        mutate(document)
        bodies[name] = contracts.canonical_json_line(document)
        next(item for item in gate["artifacts"] if item["name"] == name)["digest"] = \
            contracts.raw_sha256(bodies[name])
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts._semantic_manifest(gate, bodies, **context)

    @pytest.mark.parametrize("name", ["manifest-run-contract-tests", "run-manifest-validator"])
    def test_source_and_material_drift_fail_closed(self, tmp_path, name):
        gate, bodies, context = self._case(tmp_path)
        context["input_bodies"] = dict(context["input_bodies"])
        context["input_bodies"][name] = b"drift\n"
        with pytest.raises(evidence.EvidenceError, match="absent or drifted"):
            contracts._semantic_manifest(gate, bodies, **context)

    def test_case_manifest_substitution_fails_closed_even_when_scope_digest_is_replaced(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        case_manifest = json.loads(context["input_bodies"]["manifest-evidence-cases"])
        case_manifest["invariants"].reverse()
        replacement = contracts.canonical_json_line(case_manifest)
        context["input_bodies"] = dict(context["input_bodies"])
        context["input_bodies"]["manifest-evidence-cases"] = replacement
        context["scope"] = copy.deepcopy(context["scope"])
        next(row for row in context["scope"]["input_bindings"]
             if row["name"] == "manifest-evidence-cases")["digest"] = contracts.raw_sha256(replacement)
        with pytest.raises(evidence.EvidenceError, match="invariant node roster or order"):
            contracts._semantic_manifest(gate, bodies, **context)


class TestH0HermeticSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = next(
            row for row in arguments["records"]
            if row["gate_id"] == "B-HERMETIC-ALL"
        )
        bodies = {}
        for row in arguments["artifact_index"]["artifacts"]:
            if row["gate_id"] == "B-HERMETIC-ALL":
                bodies[row["name"]] = (arguments["artifact_root"] / row["path"]).read_bytes()
        report = contracts.read_evidence_report(
            bodies.pop("gate-evidence"), identity=arguments["identity"],
            gate_id="B-HERMETIC-ALL",
        )
        context = {
            "identity": arguments["identity"],
            "input_bodies": arguments["input_bodies"],
            "report": report,
            "support": arguments["support_matrix"],
        }
        return gate, bodies, context

    def test_exact_candidate_bound_h0_composition_is_accepted(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        contracts._semantic_h0_hermetic_all(gate, bodies, **context)

    @pytest.mark.parametrize(
        ("name", "mutate", "match"),
        [
            (
                "test-report",
                lambda doc: doc.update(candidate_identity_digest=_digest("0")),
                "wrong candidate",
            ),
            (
                "test-report",
                lambda doc: doc["runs"][0]["fragments"][0].update(digest=_digest("0")),
                "digest does not match",
            ),
            (
                "test-report",
                lambda doc: doc["runs"][0]["fragments"].append(
                    copy.deepcopy(doc["runs"][0]["fragments"][0])
                ),
                "every shard index exactly once",
            ),
            (
                "test-report",
                lambda doc: doc["runs"][0].update(
                    evidence_instance_id=doc["runs"][1]["evidence_instance_id"]
                ),
                "exact signed gate-evidence instance",
            ),
            (
                "test-report",
                lambda doc: doc["runs"][0]["fragments"][0].update(
                    job_instance_id=doc["runs"][0]["fragments"][1]["job_instance_id"]
                ),
                "exact verification job instance",
            ),
            (
                "isolation-self-test",
                lambda doc: doc["instances"][0]["attempts"].reverse(),
                "roster or order",
            ),
            (
                "isolation-self-test",
                lambda doc: doc["instances"][0].update(isolation_profile=_digest("0")),
                "profile does not match",
            ),
            (
                "isolation-self-test",
                lambda doc: doc["instances"][0].update(
                    evidence_instance_id=doc["instances"][1]["evidence_instance_id"]
                ),
                "exact signed gate-evidence instance",
            ),
        ],
    )
    def test_substitution_shard_and_isolation_mutations_fail_closed(
        self, tmp_path, name, mutate, match,
    ):
        gate, bodies, context = self._case(tmp_path)
        document = json.loads(bodies[name])
        mutate(document)
        bodies[name] = contracts.canonical_json_line(document)
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts._semantic_h0_hermetic_all(gate, bodies, **context)

    def test_nonpass_fragment_and_gate_logical_count_substitution_fail_closed(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        report = json.loads(bodies["test-report"])
        fragment_record = report["runs"][0]["fragments"][0]
        taxonomy = evidence.read_pytest_taxonomy(bodies["collection-manifest"])
        selected_nodes = [
            nodeid for nodeid in taxonomy["lanes"][0]["nodes"]
            if evidence.h0_shard_index(nodeid, 6) == 0
        ]
        passed_nodes = selected_nodes[:-1]
        fragment_record["report"]["outcomes"].update(
            passed=len(passed_nodes), skipped=1,
        )
        fragment_record["report"]["passed_roster"] = {
            "count": len(passed_nodes),
            "digest": evidence.h0_roster_digest(passed_nodes),
        }
        fragment_record["digest"] = contracts.raw_sha256(
            evidence.canonical_json_bytes(fragment_record["report"])
        )
        bodies["test-report"] = contracts.canonical_json_line(report)
        with pytest.raises(evidence.EvidenceError, match="full/selected/pass roster"):
            contracts._semantic_h0_hermetic_all(gate, bodies, **context)

        gate, bodies, context = self._case(tmp_path / "counts")
        context["report"]["instances"][0]["selection"]["collected"] += 1
        with pytest.raises(evidence.EvidenceError, match="logical H0 collection counts"):
            contracts._semantic_h0_hermetic_all(gate, bodies, **context)


    def test_rebound_wrong_partition_and_runner_topology_fail_closed(self, tmp_path):
        gate, bodies, context = self._case(tmp_path)
        report = json.loads(bodies["test-report"])
        fragment_record = report["runs"][0]["fragments"][0]
        wrong_roster = copy.deepcopy(
            report["runs"][0]["fragments"][1]["report"]["selected_roster"]
        )
        fragment_record["report"]["selected_roster"] = wrong_roster
        fragment_record["report"]["passed_roster"] = copy.deepcopy(wrong_roster)
        fragment_record["report"]["outcomes"]["passed"] = wrong_roster["count"]
        fragment_record["digest"] = contracts.raw_sha256(
            evidence.canonical_json_bytes(fragment_record["report"])
        )
        bodies["test-report"] = contracts.canonical_json_line(report)
        with pytest.raises(evidence.EvidenceError, match="roster does not reconcile"):
            contracts._semantic_h0_hermetic_all(gate, bodies, **context)

        gate, bodies, context = self._case(tmp_path / "topology")
        job_map = json.loads(context["input_bodies"]["verification-job-map"])
        offline = next(row for row in job_map["jobs"] if row["lane"] == "H0-hermetic")
        offline["instances"].pop()
        context["input_bodies"] = dict(context["input_bodies"])
        context["input_bodies"]["verification-job-map"] = contracts.canonical_json_line(job_map)
        with pytest.raises(evidence.EvidenceError, match="3x6 offline matrix"):
            contracts._semantic_h0_hermetic_all(gate, bodies, **context)

    @pytest.mark.parametrize(
        ("field", "value", "match"),
        [
            ("code", "not a token", "stable token"),
            ("detail", "x" * 513, "exceeds 512"),
        ],
    )
    def test_isolation_denial_fields_are_strictly_bounded(
        self, tmp_path, field, value, match,
    ):
        gate, bodies, context = self._case(tmp_path)
        isolation = json.loads(bodies["isolation-self-test"])
        isolation["instances"][0]["attempts"][0]["denial"][field] = value
        bodies["isolation-self-test"] = contracts.canonical_json_line(isolation)
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts._semantic_h0_hermetic_all(gate, bodies, **context)


class TestPackageInstallSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-PACKAGE-INSTALL")
        bodies = {
            row["name"]: (arguments["artifact_root"] / row["path"]).read_bytes()
            for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PACKAGE-INSTALL" and row["name"] != "gate-evidence"
        }
        report_index = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PACKAGE-INSTALL" and row["name"] == "gate-evidence"
        )
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / report_index["path"]).read_bytes(),
            identity=arguments["identity"], gate_id="C-PACKAGE-INSTALL",
        )
        return arguments, gate, bodies, report

    @staticmethod
    def _verify(arguments, gate, bodies, report):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"], identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_package_install(
                gate, bodies, identity=arguments["identity"], report=report, resolver=resolver,
            )

    def test_exact_signed_p0_install_fixture_is_accepted(self, tmp_path):
        arguments, gate, bodies, report = self._case(tmp_path)
        self._verify(arguments, gate, bodies, report)

    @pytest.mark.parametrize(
        ("artifact", "mutate", "match"),
        [
            ("install-inventory", lambda doc: doc["source_wheel"].update(digest=_digest("9")),
             "source wheel does not match"),
            ("install-inventory", lambda doc: doc.update(files=[
                row for row in doc["files"] if not row["path"].endswith("quarry_recon/__init__.py")
            ]), "file set does not reconcile"),
            ("install-inventory", lambda doc: doc.update(invocation_cwd=doc["install_prefix"] + "/work"),
             "outside checkout/prefix"),
            ("install-inventory", lambda doc: (
                doc["files"].append({
                    "digest": _digest("0"), "path": doc["install_prefix"] + "/injected.py", "size": 1,
                }),
                doc["files"].sort(key=lambda row: row["path"]),
            ), "file set does not reconcile"),
            ("smoke-results", lambda doc: doc["cases"].reverse(), "exact ordered roster"),
            ("smoke-results", lambda doc: doc["cases"][-1]["details"].update(checkout_on_sys_path=True),
             "checkout absence from sys.path"),
            ("smoke-results", lambda doc: doc["cases"][0]["details"].update(
                path=doc["install_prefix"] + "/lib/python3.12/site-packages/invented.py"),
             "exact installed module, resource or CLI path"),
            ("smoke-results", lambda doc: doc.update(install_inventory_digest=_digest("8")),
             "exact inventory, wheel and P0 execution context"),
        ],
    )
    def test_install_inventory_and_smoke_adversarial_fixtures_fail_closed(
        self, tmp_path, artifact, mutate, match,
    ):
        arguments, gate, bodies, report = self._case(tmp_path)
        document = json.loads(bodies[artifact])
        mutate(document)
        bodies[artifact] = contracts.canonical_json_line(document)
        for instance in report["instances"]:
            for record in instance["artifacts"]:
                if record["name"] == artifact:
                    record["digest"] = contracts.raw_sha256(bodies[artifact])
        with pytest.raises(evidence.EvidenceError, match=match):
            self._verify(arguments, gate, bodies, report)


class TestProvenanceSemanticEvidence:
    def test_aggregate_reaches_the_next_unimplemented_gate_after_provenance_promotion(self, tmp_path):
        arguments = _scenario(tmp_path)
        # C-TOOLS is intentionally still outside the promoted registry.  Reaching
        # it proves the full aggregate accepted the preceding C-PROVENANCE graph.
        with pytest.raises(evidence.EvidenceError, match="gate C-TOOLS"):
            contracts.aggregate_records(**arguments)

    def test_rebound_provenance_derives_the_current_package_build_report(self, tmp_path):
        arguments = _scenario(tmp_path)
        arguments["support_matrix"]["approval"]["review_id"] = "rebound-support-review"
        _sign_contract_review(
            arguments["support_matrix"], arguments["trust_policy"],
            approved_at=arguments["support_matrix"]["approval"]["approved_at"],
        )
        _rebind_scenario(arguments)
        gate = _gate(arguments, "C-PROVENANCE")
        bodies = {
            row["name"]: (arguments["artifact_root"] / row["path"]).read_bytes()
            for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PROVENANCE" and row["name"] != "gate-evidence"
        }
        report_index = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PROVENANCE" and row["name"] == "gate-evidence"
        )
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / report_index["path"]).read_bytes(),
            identity=arguments["identity"], gate_id="C-PROVENANCE",
        )
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"], identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_provenance(
                gate, bodies, identity=arguments["identity"], report=report,
                resolver=resolver, policy=arguments["trust_policy"],
            )

    def test_schema_and_manual_provenance_roster_stay_in_lockstep(self, tmp_path):
        schema = json.loads((ROOT / contracts.SCHEMA_PATHS["gate-artifact-schema"]).read_bytes())
        provenance = schema["$defs"]["provenance"]
        assert schema["$defs"]["builder"]["required"] == [
            "environment", "evidence_instance_id", "toolchain",
        ]
        assert provenance["properties"]["subjects"]["minItems"] == 2
        assert provenance["properties"]["subjects"]["maxItems"] == 2
        assert provenance["properties"]["materials"]["minItems"] == 5
        assert provenance["properties"]["materials"]["maxItems"] == 1024
        assert len(contracts._PROVENANCE_MATERIAL_ARTIFACTS) == 4
        assert "C-PROVENANCE" in contracts.SEMANTIC_VERIFIERS
        assert "C-PROVENANCE" not in contracts.PROVISIONAL_SEMANTIC_VERIFIERS

        arguments = _scenario(tmp_path)
        record = next(row for row in arguments["artifact_index"]["artifacts"]
                      if row["gate_id"] == "C-PROVENANCE" and row["name"] == "provenance")
        document = json.loads((arguments["artifact_root"] / record["path"]).read_bytes())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        assert list(validator.iter_errors(document)) == []
        assert len(document["materials"]) == 1 + len(arguments["identity"]["inputs"]) + \
            len(contracts._PROVENANCE_MATERIAL_ARTIFACTS)
        assert len(document["materials"]) <= provenance["properties"]["materials"]["maxItems"]
        assert [row["name"] for row in document["subjects"]] == ["sdist", "wheel"]
        expected_names = {"candidate-identity"}
        expected_names.update(f"{gate}/{name}" for gate, name in contracts._PROVENANCE_MATERIAL_ARTIFACTS)
        assert expected_names.issubset({row["name"] for row in document["materials"]})

    @pytest.mark.parametrize(
        ("material_name", "match"),
        [
            ("C-PACKAGE-BUILD/gate-evidence", "release evidence graph"),
            ("C-PACKAGE-INSTALL/gate-evidence", "release evidence graph"),
            ("C-SBOM/sbom", "release evidence graph"),
            ("C-VULNERABILITY/vulnerability-findings", "release evidence graph"),
        ],
    )
    def test_cross_gate_material_substitution_fails_after_resigning(self, tmp_path, material_name, match):
        arguments = _scenario(tmp_path)

        def mutate(document):
            material = next(row for row in document["materials"] if row["name"] == material_name)
            material["digest"] = _digest("f")

        _rewrite_signed_provenance(arguments, mutate)
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize(
        ("mutate", "match"),
        [
            (lambda document: document["subjects"][0].update(digest=_digest("e")), "release evidence graph"),
            (lambda document: document["builder"].update(evidence_instance_id="forged-instance"), "release evidence graph"),
            (lambda document: document["materials"].pop(), "release evidence graph"),
        ],
    )
    def test_subject_and_execution_identity_substitutions_fail_after_resigning(self, tmp_path, mutate, match):
        arguments = _scenario(tmp_path)
        _rewrite_signed_provenance(arguments, mutate)
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts.aggregate_records(**arguments)


class TestPythonMatrixSemanticEvidence:
    @staticmethod
    def _case(tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "C-PYTHON-MATRIX")
        index = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-PYTHON-MATRIX" and row["name"] == "python-matrix-report"
        )
        return arguments, gate, {"python-matrix-report": (arguments["artifact_root"] / index["path"]).read_bytes()}

    @staticmethod
    def _verify(arguments, gate, bodies):
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"], identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_python_matrix(
                gate, bodies, identity=arguments["identity"], scope=arguments["scope"],
                support=arguments["support_matrix"], resolver=resolver,
                input_bodies=arguments["input_bodies"],
            )

    def test_exact_candidate_bound_matrix_reconciles_retained_h0_and_p0_evidence(self, tmp_path):
        arguments, gate, bodies = self._case(tmp_path)
        self._verify(arguments, gate, bodies)

    @pytest.mark.parametrize(
        ("mutate", "match"),
        [
            (lambda doc: doc["rows"].pop(), "cardinality"),
            (lambda doc: doc["rows"].append(copy.deepcopy(doc["rows"][0])), "cardinality"),
            (lambda doc: doc["rows"][0]["environment"].update(python="3.11.9"), "sorted one-to-one"),
            (lambda doc: doc["rows"][0]["h0"].update(test_report_digest=_digest("f")), "validated test run"),
            (lambda doc: doc["rows"][-1]["p0"].update(build_evidence_instance_id="forged-instance"), "exact source"),
            (lambda doc: doc["rows"][-1]["p0"]["install_artifacts"][0].update(digest=_digest("e")), "exact source"),
        ],
    )
    def test_matrix_forgery_fails_closed(self, tmp_path, mutate, match):
        arguments, gate, bodies = self._case(tmp_path)
        document = json.loads(bodies["python-matrix-report"])
        mutate(document)
        bodies["python-matrix-report"] = contracts.canonical_json_line(document)
        with pytest.raises(evidence.EvidenceError, match=match):
            self._verify(arguments, gate, bodies)

    def test_matrix_refuses_a_source_gate_missing_the_second_p0_environment(self, tmp_path):
        arguments, gate, bodies = self._case(tmp_path)
        _rewrite_report(
            arguments, "C-PACKAGE-INSTALL", lambda report, _gate: report["instances"].pop(),
        )
        with pytest.raises(evidence.EvidenceError, match="every accepted P0 environment"):
            self._verify(arguments, gate, bodies)

    def test_matrix_refuses_bound_metadata_outside_the_reviewed_minor_range(self, tmp_path):
        arguments, gate, bodies = self._case(tmp_path)
        arguments["input_bodies"] = dict(arguments["input_bodies"])
        arguments["input_bodies"]["package-metadata"] = arguments["input_bodies"][
            "package-metadata"
        ].replace(b'requires-python = ">=3.10,<3.13"', b'requires-python = ">=3.10"')
        with pytest.raises(evidence.EvidenceError, match="exact published requires-python policy"):
            self._verify(arguments, gate, bodies)


class TestArtifactsAndAggregation:
    @pytest.fixture(autouse=True)
    def _install_test_only_semantic_parsers(self, monkeypatch):
        def verify_structural_fixture(gate, bodies, **context):
            identity = context["identity"]
            for name in sorted(set(bodies) - {"gate-evidence"}):
                contracts._validate_generic_supporting_artifact(
                    bodies[name], gate_id=gate["gate_id"], name=name, identity=identity,
                )

        registry = dict(contracts.PROVISIONAL_SEMANTIC_VERIFIERS)
        registry.update(contracts.SEMANTIC_VERIFIERS)
        for gate_id in set(contracts.SELECTED_RECORD_SLOTS) - set(contracts.LIVE_GATES):
            registry.setdefault(gate_id, verify_structural_fixture)
        monkeypatch.setattr(contracts, "SEMANTIC_VERIFIERS", registry)

    def test_nomination_and_aggregation_require_external_trust_and_exact_release_version(
        self, tmp_path,
    ):
        arguments = _scenario(tmp_path)
        missing_authority = dict(arguments)
        missing_authority["trusted_policy_digest"] = None
        with pytest.raises(evidence.EvidenceError, match="authority"):
            contracts.aggregate_records(**missing_authority)
        wrong_authority = dict(arguments)
        wrong_authority["trusted_policy_digest"] = _digest("9")
        with pytest.raises(evidence.EvidenceError, match="external production authority"):
            contracts.aggregate_records(**wrong_authority)

        wrong_version = copy.deepcopy(arguments["identity"])
        wrong_version["package_version"] = "0.3.9"
        for source in wrong_version["package_version_sources"]:
            source["value"] = "0.3.9"
        with pytest.raises(evidence.EvidenceError, match="nomination-eligible"):
            contracts.validate_candidate_bindings(
                wrong_version,
                scope=arguments["scope"],
                policy=arguments["trust_policy"],
                trusted_policy_digest=arguments["trusted_policy_digest"],
            )

    def test_evidence_schema_manifest_and_report_reconcile_actual_public_cases(self, tmp_path):
        arguments = _scenario(tmp_path)
        manifest_body = (ROOT / "release/evidence/aggregator-conformance-v1.json").read_bytes()
        manifest = contracts.read_aggregator_conformance_manifest(manifest_body)
        assert [case["id"] for case in manifest["cases"]] == [
            "positive-aggregate-verify", "missing-record", "duplicate-gate", "wrong-candidate",
            "malformed-schema", "invalid-signature", "expired-disposition", "unexpected-skip",
            "conflicting-result",
        ]
        aggregate = contracts.aggregate_records(**arguments)
        assert contracts.verify_aggregate(aggregate, **_verification_arguments(arguments)) == aggregate

        def malformed_schema(value):
            value["records"][0]["schema_version"] = "quarry.release-gate.v0"

        def invalid_signature(value):
            value["records"][0]["signature"]["value"] = "base64:" + "A" * 86 + "=="

        def unexpected_skip(value):
            gate = _gate(value, "A-IDENTITY")
            gate["status"] = "not_applicable"
            gate["not_applicable_rule"] = None

        def wrong_candidate(value):
            _gate(value, "A-IDENTITY")["candidate"]["git_commit"] = "0" * 40

        def expired_disposition(value):
            gate = _gate(value, "D-AUTHORIZATION")
            gate["not_applicable_rule"]["expires_at"] = "2026-08-13T00:00:00Z"

        def conflicting_result(**value):
            forged = copy.deepcopy(aggregate)
            forged["records"][0]["status"] = "not_applicable"
            contracts.verify_aggregate(forged, **_verification_arguments(value))

        cases = {
            "missing-record": (lambda value: value["records"].pop(), contracts.aggregate_records),
            "duplicate-gate": (lambda value: value["records"].append(copy.deepcopy(value["records"][0])), contracts.aggregate_records),
            "wrong-candidate": (wrong_candidate, contracts.aggregate_records),
            "malformed-schema": (malformed_schema, contracts.aggregate_records),
            "invalid-signature": (invalid_signature, contracts.aggregate_records),
            "expired-disposition": (expired_disposition, contracts.aggregate_records),
            "unexpected-skip": (unexpected_skip, contracts.aggregate_records),
            "conflicting-result": (lambda value: None, conflicting_result),
        }
        for case_id, (mutate, public_api) in cases.items():
            broken = copy.deepcopy(arguments)
            mutate(broken)
            with pytest.raises(evidence.EvidenceError) as raised:
                public_api(**broken)
            assert contracts.normalized_conformance_error_digest(raised.value) == \
                contracts.conformance_error_digest(case_id)

    @pytest.mark.parametrize("mutation, match", [
        (lambda report: report["cases"].reverse(), "roster or order"),
        (lambda report: report.__setitem__("manifest_digest", _digest("0")), "wrong golden manifest"),
        (lambda report: report.__setitem__("candidate_identity_digest", _digest("1")), "wrong candidate"),
        (lambda report: report["cases"][0].__setitem__("aggregate_digests", [_digest("2"), _digest("3")]), "unequal"),
        (lambda report: report["cases"][1].__setitem__("error_digest", _digest("4")), "normalized error digest"),
    ])
    def test_evidence_schema_report_adversaries_fail_closed(self, tmp_path, mutation, match):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "A-EVIDENCE-SCHEMA")
        indexed = next(row for row in arguments["artifact_index"]["artifacts"]
                       if row["gate_id"] == gate["gate_id"] and row["name"] == "conformance-report")
        report = json.loads((arguments["artifact_root"] / indexed["path"]).read_bytes())
        mutation(report)
        _rewrite_supporting_artifact(
            arguments, gate["gate_id"], "conformance-report", contracts.canonical_json_line(report),
        )
        with pytest.raises(evidence.EvidenceError, match=match):
            contracts.aggregate_records(**arguments)

    def test_artifact_index_rehashes_and_rejects_conflicts_and_symlinks(self, tmp_path):
        scope, _support, _thresholds, _corpus, _no_live, _bodies = _ready_contracts()
        identity = _identity(scope, _policy())
        root = tmp_path / "root"
        root.mkdir()
        (root / "record.json").write_bytes(b"{}\n")
        index = {
            "artifacts": [{
                "digest": contracts.raw_sha256(b"{}\n"), "gate_id": "A-IDENTITY",
                "media_type": "application/json", "name": "gate-evidence",
                "path": "record.json", "size": 3,
            }],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "release": "0.3.10", "schema_version": contracts.ARTIFACT_INDEX_SCHEMA,
        }
        assert contracts.read_artifact_index(
            contracts.canonical_json_line(index), identity=identity,
        ) == index
        with contracts.ArtifactResolver(root, index, identity=identity) as resolver:
            assert resolver.read("A-IDENTITY", "gate-evidence") == b"{}\n"
        conflict = copy.deepcopy(index)
        conflict["artifacts"].append({**conflict["artifacts"][0], "gate_id": "A-SUPPORT"})
        conflict["artifacts"].sort(key=lambda row: (row["gate_id"], row["name"]))
        with pytest.raises(evidence.EvidenceError, match="reused path"):
            contracts.validate_artifact_index(conflict, identity=identity)
        (root / "record.json").unlink()
        (root / "record.json").symlink_to(root / "target.json")
        (root / "target.json").write_bytes(b"{}\n")
        with contracts.ArtifactResolver(root, index, identity=identity) as resolver:
            with pytest.raises(evidence.EvidenceError, match="securely open"):
                resolver.read("A-IDENTITY", "gate-evidence")
        real_root = tmp_path / "real-root"
        real_root.mkdir()
        alias_root = tmp_path / "alias-root"
        alias_root.symlink_to(real_root, target_is_directory=True)
        with pytest.raises(evidence.EvidenceError, match="artifact root"):
            contracts.ArtifactResolver(alias_root, index, identity=identity)

    def test_artifact_resolver_rejects_a_rename_swap_after_hashing(self, tmp_path, monkeypatch):
        scope, _support, _thresholds, _corpus, _no_live, _bodies = _ready_contracts()
        identity = _identity(scope, _policy())
        root = tmp_path / "root"
        root.mkdir()
        target = root / "record.json"
        replacement = root / "replacement.json"
        target.write_bytes(b"{}\n")
        replacement.write_bytes(b"XX\n")
        index = {
            "artifacts": [{
                "digest": contracts.raw_sha256(b"{}\n"), "gate_id": "A-IDENTITY",
                "media_type": "application/json", "name": "gate-evidence",
                "path": "record.json", "size": 3,
            }],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "release": "0.3.10", "schema_version": contracts.ARTIFACT_INDEX_SCHEMA,
        }
        original_read = contracts.os.read
        swapped = False

        def racing_read(descriptor, size):
            nonlocal swapped
            if size == 1 and not swapped:
                replacement.replace(target)
                swapped = True
            return original_read(descriptor, size)

        monkeypatch.setattr(contracts.os, "read", racing_read)
        with contracts.ArtifactResolver(root, index, identity=identity) as resolver:
            with pytest.raises(evidence.EvidenceError, match="identity changed|path changed"):
                resolver.read("A-IDENTITY", "gate-evidence")

    def test_artifact_resolver_snapshots_index_rows_and_returns_defensive_copies(self, tmp_path):
        scope, _support, _thresholds, _corpus, _no_live, _bodies = _ready_contracts()
        identity = _identity(scope, _policy())
        root = tmp_path / "root"
        root.mkdir()
        target = root / "record.json"
        good = b"good"
        evil = b"evil"
        target.write_bytes(good)
        index = {
            "artifacts": [{
                "digest": contracts.raw_sha256(good), "gate_id": "A-IDENTITY",
                "media_type": "application/json", "name": "gate-evidence",
                "path": "record.json", "size": len(good),
            }],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "release": "0.3.10", "schema_version": contracts.ARTIFACT_INDEX_SCHEMA,
        }
        with contracts.ArtifactResolver(root, index, identity=identity) as resolver:
            returned = resolver.record("A-IDENTITY", "gate-evidence")
            returned["digest"] = contracts.raw_sha256(evil)
            index["artifacts"][0]["digest"] = contracts.raw_sha256(evil)
            assert resolver.record("A-IDENTITY", "gate-evidence")["digest"] == \
                contracts.raw_sha256(good)
            target.write_bytes(evil)
            with pytest.raises(evidence.EvidenceError, match="raw bytes"):
                resolver.read("A-IDENTITY", "gate-evidence")

    def test_artifact_resolver_snapshots_the_full_index_before_validation(
        self, tmp_path, monkeypatch,
    ):
        scope, _support, _thresholds, _corpus, _no_live, _bodies = _ready_contracts()
        identity = _identity(scope, _policy())
        root = tmp_path / "root"
        root.mkdir()
        good = b"good"
        evil = b"evil"
        (root / "record.json").write_bytes(evil)
        index = {
            "artifacts": [{
                "digest": contracts.raw_sha256(good), "gate_id": "A-IDENTITY",
                "media_type": "application/json", "name": "gate-evidence",
                "path": "record.json", "size": len(good),
            }],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "release": "0.3.10", "schema_version": contracts.ARTIFACT_INDEX_SCHEMA,
        }
        original_validate = contracts.validate_artifact_index

        def racing_validate(document, **kwargs):
            validated = original_validate(document, **kwargs)
            index["artifacts"][0]["digest"] = contracts.raw_sha256(evil)
            return validated

        monkeypatch.setattr(contracts, "validate_artifact_index", racing_validate)
        with contracts.ArtifactResolver(root, index, identity=identity) as resolver:
            with pytest.raises(evidence.EvidenceError, match="raw bytes"):
                resolver.read("A-IDENTITY", "gate-evidence")

    def test_artifact_resolver_rechecks_the_rooted_ancestor_chain(self, tmp_path, monkeypatch):
        scope, _support, _thresholds, _corpus, _no_live, _bodies = _ready_contracts()
        identity = _identity(scope, _policy())
        root = tmp_path / "root"
        original = root / "sub"
        replacement = root / "replacement"
        original.mkdir(parents=True)
        replacement.mkdir()
        (original / "record.json").write_bytes(b"{}\n")
        (replacement / "record.json").write_bytes(b"XX\n")
        index = {
            "artifacts": [{
                "digest": contracts.raw_sha256(b"{}\n"), "gate_id": "A-IDENTITY",
                "media_type": "application/json", "name": "gate-evidence",
                "path": "sub/record.json", "size": 3,
            }],
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "release": "0.3.10", "schema_version": contracts.ARTIFACT_INDEX_SCHEMA,
        }
        original_read = contracts.os.read
        swapped = False

        def racing_read(descriptor, size):
            nonlocal swapped
            if size == 1 and not swapped:
                original.rename(root / "old-sub")
                replacement.rename(original)
                swapped = True
            return original_read(descriptor, size)

        monkeypatch.setattr(contracts.os, "read", racing_read)
        with contracts.ArtifactResolver(root, index, identity=identity) as resolver:
            with pytest.raises(evidence.EvidenceError, match="ancestor path changed"):
                resolver.read("A-IDENTITY", "gate-evidence")

    def test_full_56_slot_aggregate_is_deterministic_and_approval_is_later(self, tmp_path):
        arguments = _scenario(tmp_path)
        identity_line = contracts.canonical_json_line(arguments["identity"])
        gate_line = contracts.canonical_json_line(arguments["records"][0])
        assert contracts.read_candidate_identity(identity_line) == arguments["identity"]
        assert contracts.read_gate_record(gate_line, identity=arguments["identity"]) == \
            arguments["records"][0]
        with pytest.raises(evidence.EvidenceError, match="canonical|LF"):
            contracts.read_gate_record(gate_line[:-1] + b" \n", identity=arguments["identity"])
        aggregate = contracts.aggregate_records(**arguments)
        assert aggregate["decision"] == "pass"
        assert len(aggregate["records"]) == 56
        assert contracts.aggregate_records(**arguments) == aggregate
        assert contracts.read_aggregate(
            contracts.canonical_json_line(aggregate), identity=arguments["identity"],
            scope=arguments["scope"], policy=arguments["trust_policy"],
            trusted_policy_digest=arguments["trusted_policy_digest"],
        ) == aggregate
        assert contracts.verify_aggregate(
            aggregate, **_verification_arguments(arguments),
        ) == aggregate
        assert contracts.read_verified_aggregate(
            contracts.canonical_json_line(aggregate), **_verification_arguments(arguments),
        ) == aggregate
        input_by_name = {row["name"]: row["digest"] for row in arguments["records"][0]["inputs"]}
        assert input_by_name["candidate-identity"] == evidence.canonical_digest(
            arguments["identity"]
        )
        assert input_by_name["candidate-identity"] != contracts.raw_sha256(identity_line)

        policy = arguments["trust_policy"]
        identity = arguments["identity"]
        aggregate_digest = evidence.canonical_digest(aggregate)
        identity_digest = evidence.canonical_digest(identity)
        policy_digest = evidence.canonical_digest(policy)
        approval = {
            "aggregate_digest": aggregate_digest,
            "approved_at": "2026-08-14T11:00:01Z",
            "candidate_identity_digest": identity_digest,
            "decision": "approve",
            "release": "0.3.10",
            "schema_version": contracts.APPROVAL_SCHEMA,
            "scope_digest": evidence.canonical_digest(arguments["scope"]),
            "signature": None,
            "trust_policy_digest": policy_digest,
        }
        statement_digest = contracts.approval_payload_digest(approval)
        message = contracts.signature_preimage(
            role="approval", payload_digest=statement_digest,
            candidate_identity_digest=identity_digest, trust_policy_digest=policy_digest,
        )
        envelope = {
            "algorithm": "ed25519", "candidate_identity_digest": identity_digest,
            "key_id": "test-approval-v1", "payload_digest": statement_digest,
            "role": "approval", "schema_version": contracts.SIGNATURE_ENVELOPE_SCHEMA,
            "signature": "base64:" + base64.b64encode(
                _sign(message, seed=APPROVAL_SEED)
            ).decode("ascii"),
            "trust_policy_digest": policy_digest,
        }
        approval["signature"] = envelope
        assert contracts.validate_detached_approval(
            approval, identity=identity, scope=arguments["scope"], policy=policy,
            aggregate=aggregate, trusted_policy_digest=arguments["trusted_policy_digest"],
        ) == approval
        assert contracts.read_detached_approval(
            contracts.canonical_json_line(approval), identity=identity,
            scope=arguments["scope"], policy=policy, aggregate=aggregate,
            trusted_policy_digest=arguments["trusted_policy_digest"],
        ) == approval
        assert contracts.verify_detached_approval(
            approval, aggregate=aggregate, **_verification_arguments(arguments),
        ) == approval
        assert contracts.read_verified_detached_approval(
            contracts.canonical_json_line(approval), aggregate=aggregate,
            **_verification_arguments(arguments),
        ) == approval
        wrong = copy.deepcopy(approval)
        wrong["aggregate_digest"] = _digest("9")
        with pytest.raises(evidence.EvidenceError, match="aggregate_digest"):
            contracts.validate_detached_approval(
                wrong, identity=identity, scope=arguments["scope"], policy=policy,
                aggregate=aggregate, trusted_policy_digest=arguments["trusted_policy_digest"],
            )
        backdated = copy.deepcopy(approval)
        backdated["approved_at"] = "2026-08-14T11:00:00.500000Z"
        with pytest.raises(evidence.EvidenceError, match="payload_digest"):
            contracts.validate_detached_approval(
                backdated, identity=identity, scope=arguments["scope"], policy=policy,
                aggregate=aggregate, trusted_policy_digest=arguments["trusted_policy_digest"],
            )
        substituted_aggregator = copy.deepcopy(aggregate)
        substituted_aggregator["aggregator"]["executable_digest"] = _digest("8")
        with pytest.raises(evidence.EvidenceError, match="aggregate_digest"):
            contracts.validate_detached_approval(
                approval, identity=identity, scope=arguments["scope"], policy=policy,
                aggregate=substituted_aggregator,
                trusted_policy_digest=arguments["trusted_policy_digest"],
            )
        forged_summary = copy.deepcopy(aggregate)
        forged_summary["records"][0]["record_digest"] = _digest("7")
        with pytest.raises(evidence.EvidenceError, match="does not reproduce"):
            contracts.verify_aggregate(
                forged_summary, **_verification_arguments(arguments),
            )

    @pytest.mark.parametrize("failure", ["missing", "duplicate", "unknown", "candidate", "signature", "status"])
    def test_aggregate_fails_closed_on_record_graph_corruption(self, tmp_path, failure):
        arguments = _scenario(tmp_path)
        records = copy.deepcopy(arguments["records"])
        arguments["records"] = records
        if failure == "missing":
            records.pop()
        elif failure == "duplicate":
            records[-1] = copy.deepcopy(records[0])
        elif failure == "unknown":
            records[-1]["gate_id"] = "E-UNKNOWN"
        elif failure == "candidate":
            records[0]["candidate"]["source_tree_digest"] = _digest("0")
        elif failure == "signature":
            records[0]["signature"]["value"] = "base64:" + base64.b64encode(b"\0" * 64).decode()
        elif failure == "status":
            records[0]["status"] = "open"
            records[0]["reason"] = "synthetic blocking status"
            _resign_gate(records[0], arguments["identity"], arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError):
            contracts.aggregate_records(**arguments)

    def test_changed_artifact_and_unexpected_skip_fail_closed(self, tmp_path):
        arguments = _scenario(tmp_path)
        first = arguments["artifact_index"]["artifacts"][0]
        (arguments["artifact_root"] / first["path"]).write_bytes(b"changed\n")
        with pytest.raises(evidence.EvidenceError, match="artifact"):
            contracts.aggregate_records(**arguments)
        gate = copy.deepcopy(arguments["records"][0])
        gate["selection"].update({"passed": 0, "skipped": 1})
        with pytest.raises(evidence.EvidenceError, match="passing gate"):
            evidence.validate_gate_record(gate, identity=arguments["identity"])

    @pytest.mark.parametrize(
        ("mutate", "expected"),
        [
            (
                lambda taxonomy: taxonomy["collector"].update({"version": "forged"}),
                "attested pytest toolchain",
            ),
            (
                lambda taxonomy: taxonomy["selection"].update({"mark_expression": "packaging"}),
                "exact offline marker",
            ),
        ],
    )
    def test_taxonomy_artifact_must_match_its_signed_h0_collector(self, tmp_path, mutate, expected):
        arguments = _scenario(tmp_path)
        indexed = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "A-TAXONOMY" and row["name"] == "classification-manifest"
        )
        taxonomy = json.loads((arguments["artifact_root"] / indexed["path"]).read_bytes())
        mutate(taxonomy)
        _rewrite_supporting_artifact(
            arguments,
            "A-TAXONOMY",
            "classification-manifest",
            evidence.canonical_json_bytes(taxonomy),
        )
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    def test_taxonomy_counts_must_match_the_signed_gate_and_evidence_report(self, tmp_path):
        arguments = _scenario(tmp_path)

        def mutate(report, gate):
            counts = {
                "collected": 5, "deselected": 0, "failed": 0, "passed": 5,
                "selected": 5, "skipped": 0, "xfailed": 0, "xpassed": 0,
            }
            report["instances"][0]["selection"] = counts
            gate["selection"] = counts

        _rewrite_report(arguments, "A-TAXONOMY", mutate)
        with pytest.raises(evidence.EvidenceError, match="collected/selected/deselected"):
            contracts.aggregate_records(**arguments)

    def test_taxonomy_reopens_the_bound_job_map_and_workflow(self, tmp_path):
        arguments = _scenario(tmp_path)
        job_map = json.loads(arguments["input_bodies"]["verification-job-map"])
        job_map["jobs"][0]["selection"]["mark_expression"] = "offline"
        arguments["input_bodies"]["verification-job-map"] = \
            evidence.canonical_json_bytes(job_map) + b"\n"
        _rebind_scenario(arguments)
        with pytest.raises(evidence.EvidenceError, match="primary lane marker"):
            contracts.aggregate_records(**arguments)

    def test_corpus_disclosure_attestation_rehashes_to_the_selected_manifest(self, tmp_path):
        arguments = _scenario(tmp_path)
        indexed = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "A-CORPUS" and row["name"] == "corpus-disclosure-report"
        )
        attestation = json.loads((arguments["artifact_root"] / indexed["path"]).read_bytes())
        attestation["fixture_digest"] = _digest("0")
        attestation["derivation_tree_digests"] = [_digest("0"), _digest("0")]
        _rewrite_supporting_artifact(
            arguments,
            "A-CORPUS",
            "corpus-disclosure-report",
            contracts.canonical_json_line(attestation),
        )
        with pytest.raises(evidence.EvidenceError, match="frozen manifest digest"):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize(
        ("mutate", "expected"),
        [
            (
                lambda attestation: attestation["checks"].__setitem__("disclosure_review", "fail"),
                "checks are not all passing",
            ),
            (
                lambda attestation: attestation.__setitem__(
                    "candidate_identity_digest", _digest("candidate"),
                ),
                "invalid members",
            ),
        ],
    )
    def test_corpus_disclosure_attestation_is_candidate_independent_and_fail_closed(
        self, tmp_path, mutate, expected,
    ):
        arguments = _scenario(tmp_path)
        selected = next(
            row for row in arguments["corpus_manifest"]["sources"] if row["selected"]
        )
        attestation = json.loads(_corpus_disclosure_body(selected["fixture_digest"]))
        mutate(attestation)
        body = contracts.canonical_json_line(attestation)
        selected["attestation_digest"] = contracts.raw_sha256(body)
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts._semantic_corpus(
                {"gate_id": "A-CORPUS"},
                {"corpus-disclosure-report": body},
                corpus=arguments["corpus_manifest"],
            )

    @pytest.mark.parametrize("manifest", ["support", "threshold", "corpus"])
    def test_changed_accepted_manifest_rejects_unchanged_substantive_evidence(
        self, tmp_path, manifest,
    ):
        arguments = _scenario(tmp_path)
        if manifest == "support":
            added = copy.deepcopy(arguments["support_matrix"]["environments"][0])
            added["python"] = "9.9.9"
            arguments["support_matrix"]["environments"].append(added)
            arguments["support_matrix"]["environments"].sort(key=lambda row: (
                contracts.LANE_ORDER.index(row["lane"]), row["os"],
                row["architecture"], row["python"],
            ))
            expected = "complete support matrix"
            changed_document = arguments["support_matrix"]
        elif manifest == "threshold":
            benchmark = next(
                row for row in arguments["threshold_manifest"]["thresholds"]
                if row["gate_id"] == "B-COVERAGE" and row["class"] == "absolute"
            )
            benchmark["limit"] = 10001
            expected = "numeric threshold"
            changed_document = arguments["threshold_manifest"]
        else:
            selected = next(row for row in arguments["corpus_manifest"]["sources"] if row["selected"])
            selected["fixture_digest"] = _digest("0")
            expected = "materials"
            changed_document = arguments["corpus_manifest"]
        _sign_contract_review(
            changed_document,
            arguments["trust_policy"],
            approved_at=changed_document["approval"]["approved_at"],
        )
        _rebind_scenario(arguments)
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    def test_manifest_review_metadata_cannot_be_changed_without_approval_signature(self, tmp_path):
        arguments = _scenario(tmp_path)
        arguments["support_matrix"]["approval"]["reviewer"] = "substituted-reviewer"
        _rebind_scenario(arguments)
        with pytest.raises(evidence.EvidenceError, match="signature verification"):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize("failure", ["vacuous", "assertion-substitution"])
    def test_vacuous_or_substituted_assertion_report_is_rejected(self, tmp_path, failure):
        arguments = _scenario(tmp_path)

        def mutate(report, gate):
            if failure == "vacuous":
                report["instances"][0]["assertions"] = []
                report["instances"][0]["selection"] = {
                    key: 0 for key in report["instances"][0]["selection"]
                }
                gate["assertions"] = []
                gate["selection"] = {key: 0 for key in gate["selection"]}
            else:
                report["instances"][0]["assertions"][0]["id"] = "unrelated-assertion"

        _rewrite_report(arguments, "A-IDENTITY", mutate)
        with pytest.raises(evidence.EvidenceError, match="vacuous|assertion"):
            contracts.aggregate_records(**arguments)

    def test_every_matrix_instance_must_prove_the_obligation(self, tmp_path):
        arguments = _scenario(tmp_path)
        _rewrite_report(
            arguments,
            "B-HERMETIC-ALL",
            lambda report, _gate: report["instances"][1].__setitem__("assertions", []),
        )
        with pytest.raises(evidence.EvidenceError, match="every gate evidence instance"):
            contracts.aggregate_records(**arguments)

    def test_each_matrix_instance_requires_selection_and_its_complete_toolchain(self, tmp_path):
        zero = _scenario(tmp_path / "zero")

        def remove_selection(report, gate):
            report["instances"][0]["selection"] = {
                key: 0 for key in report["instances"][0]["selection"]
            }
            gate["selection"] = {key: 0 for key in gate["selection"]}

        _rewrite_report(zero, "A-IDENTITY", remove_selection)
        with pytest.raises(evidence.EvidenceError, match="zero-selection vacuous pass"):
            contracts.aggregate_records(**zero)

        missing_tool = _scenario(tmp_path / "tool")
        _rewrite_report(
            missing_tool,
            "B-HERMETIC-ALL",
            lambda report, _gate: report["instances"][1].__setitem__("toolchain", []),
        )
        with pytest.raises(evidence.EvidenceError, match="complete signed toolchain"):
            contracts.aggregate_records(**missing_tool)

    @pytest.mark.parametrize("failure", ["supporting-artifact", "toolchain", "benchmark-context"])
    def test_gate_specific_machine_evidence_cannot_be_omitted_or_substituted(
        self, tmp_path, failure,
    ):
        arguments = _scenario(tmp_path)
        if failure == "supporting-artifact":
            gate_id = "C-SBOM"
            artifact_name = "sbom"
            gate = _gate(arguments, gate_id)
            gate["artifacts"] = [
                row for row in gate["artifacts"] if row["name"] != artifact_name
            ]
            arguments["artifact_index"]["artifacts"] = [
                row for row in arguments["artifact_index"]["artifacts"]
                if not (row["gate_id"] == gate_id and row["name"] == artifact_name)
            ]

            def mutate(report, _gate):
                report["instances"][0]["artifacts"] = [
                    row for row in report["instances"][0]["artifacts"]
                    if row["name"] != artifact_name
                ]

            expected = "frozen obligation evidence contract"
        elif failure == "toolchain":
            gate_id = "B-QUALITY"

            def mutate(report, gate):
                for instance in report["instances"]:
                    instance["toolchain"] = []
                gate["toolchain"] = []

            expected = "no attested execution toolchain"
        else:
            gate_id = "C-PERF-RUNNER"

            def mutate(report, _gate):
                report["benchmark"]["concurrency"] += 1

            expected = "exact benchmark execution context"
        _rewrite_report(arguments, gate_id, mutate)
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    def test_gate_evidence_media_type_is_frozen(self, tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "A-IDENTITY")
        next(row for row in gate["artifacts"] if row["name"] == "gate-evidence")[
            "media_type"
        ] = "application/zip"
        next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "A-IDENTITY" and row["name"] == "gate-evidence"
        )["media_type"] = "application/zip"
        _resign_gate(gate, arguments["identity"], arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError, match="canonical application/json"):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize(
        "gate_id,artifact_name,mutation,expected",
        [
            (
                "A-IDENTITY",
                "identity-verification",
                "wrong-commit",
                "exact candidate identity",
            ),
            (
                "A-THRESHOLDS",
                "threshold-reconciliation",
                "wrong-limit",
                "exact threshold manifest",
            ),
            (
                "A-SUPPORT",
                "support-reconciliation",
                "wrong-python",
                "exact support matrix",
            ),
            ("C-PACKAGE-BUILD", "wheel", "invalid-wheel", "readable ZIP archive"),
            (
                "C-PACKAGE-BUILD", "build-log", "wrong-build-command",
                "exact clean build command",
            ),
            (
                "C-PACKAGE-BUILD", "build-log", "nonzero-build-exit", "zero exit",
            ),
            (
                "C-PACKAGE-BUILD", "build-log", "invalid-build-output", "base64",
            ),
            (
                "C-PACKAGE-BUILD", "build-log", "empty-build-output", "non-empty",
            ),
            (
                "C-PACKAGE-BUILD", "build-log", "wrong-build-subject-order",
                "reconcile the sdist and wheel bytes",
            ),
            ("C-SBOM", "sbom", "missing-dependency", "support inventory"),
            (
                "C-PROVENANCE",
                "signature-verification",
                "forged-provenance-signature",
                "signature|ed25519",
            ),
            (
                "C-PERF-RUNNER",
                "benchmark-baseline",
                "unresolved-baseline",
                "baseline is absent|does not rehash",
            ),
            (
                "C-PERF-RUNNER",
                "raw-trials",
                "invented-trial",
                "absolute trial metric",
            ),
            (
                "E-DOCS",
                "release-documentation-report",
                "missing-material-check",
                "exact material reconciliation",
            ),
            (
                "E-PROJECT-HYGIENE",
                "project-hygiene-report",
                "reordered-material-checks",
                "exact material reconciliation",
            ),
            (
                "E-ARTIFACTS",
                "publication-subjects",
                "missing-publication-subject",
                "publication subjects do not reconcile",
            ),
        ],
    )
    def test_supporting_artifact_bytes_are_semantically_verified(
        self, tmp_path, gate_id, artifact_name, mutation, expected,
    ):
        arguments = _scenario(tmp_path)
        indexed = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == gate_id and row["name"] == artifact_name
        )
        body = (arguments["artifact_root"] / indexed["path"]).read_bytes()
        if mutation == "invalid-wheel":
            changed = b"not-a-wheel\n"
        else:
            document = json.loads(body)
            if mutation == "wrong-commit":
                document["git_commit"] = "3" * 40
            elif mutation == "wrong-limit":
                next(
                    row for row in document["thresholds"]
                    if row["gate_id"] == "B-COVERAGE" and row["class"] == "absolute"
                )["limit"] += 1
            elif mutation == "wrong-python":
                next(
                    row for row in document["environments"]
                    if row["lane"] == "H0-hermetic" and row["python"] == "3.12.13"
                )["python"] = "3.13.13"
            if mutation in {"wrong-limit", "wrong-python"}:
                _sign_contract_review(
                    document,
                    arguments["trust_policy"],
                    approved_at=document["approval"]["approved_at"],
                )
            elif mutation == "unresolved-result":
                document["records"][0]["result_digest"] = _digest("0")
            elif mutation == "missing-dependency":
                document["components"] = [
                    row for row in document["components"]
                    if not (row["relationship"] == "dependency" and row["name"] == "click")
                ]
            elif mutation == "forged-provenance-signature":
                document["signature"] = "base64:" + base64.b64encode(b"\0" * 64).decode()
            elif mutation == "unresolved-baseline":
                document["metrics"][0]["value"] += 1
            elif mutation == "invented-trial":
                document["trials"][0]["metrics"][0]["current_value"] += 1
            elif mutation == "missing-material-check":
                document["records"].pop()
            elif mutation == "reordered-material-checks":
                document["records"].reverse()
            elif mutation == "missing-publication-subject":
                document["subjects"].pop()
            elif mutation == "wrong-build-command":
                document["command"][-1] = "temporary-dist"
            elif mutation == "nonzero-build-exit":
                document["exit_code"] = 1
            elif mutation == "invalid-build-output":
                document["combined_output"] = "base64:not valid!"
            elif mutation == "empty-build-output":
                document["combined_output"] = "base64:"
            elif mutation == "wrong-build-subject-order":
                document["subjects"].reverse()
            changed = contracts.canonical_json_line(document)
        _rewrite_supporting_artifact(arguments, gate_id, artifact_name, changed)
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize(
        "gate_id,artifact_name,mutation,expected",
        [
            ("C-INSTALL-ROLLBACK", "fault-matrix", "candidate", "another release candidate"),
            ("C-INSTALL-ROLLBACK", "fault-matrix", "gate", "another gate"),
            ("C-INSTALL-ROLLBACK", "fault-matrix", "kind", "required artifact kind"),
            ("C-FAULT-INSTALL", "fault-matrix", "missing-case", "exactly cover"),
            ("C-SECRETS", "sink-scan", "failed-assertion", "changes or fails"),
            ("C-EXEC-IDENTITY", "launch-trace", "identity", "reconcile identity"),
            ("C-EXEC-IDENTITY", "launch-trace", "time", "signed gate interval"),
        ],
    )
    def test_promoted_v310_05_evidence_rejects_adversarial_reports(
        self, tmp_path, gate_id, artifact_name, mutation, expected,
    ):
        arguments = _scenario(tmp_path)
        indexed = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == gate_id and row["name"] == artifact_name
        )
        document = json.loads((arguments["artifact_root"] / indexed["path"]).read_bytes())
        if mutation == "candidate":
            document["candidate_identity_digest"] = _digest("9")
        elif mutation == "gate":
            document["gate_id"] = "C-FAULT-INSTALL"
        elif mutation == "kind":
            document["artifact_kind"] = "filesystem-trace"
        elif mutation == "missing-case":
            document["trials"].pop()
        elif mutation == "failed-assertion":
            document["trials"][0]["assertions"]["matches_zero"] = False
        elif mutation == "identity":
            document["trials"][0]["after_identity"] = _digest("8")
        elif mutation == "time":
            document["started_at"] = "2026-08-14T10:19:59Z"
        _rewrite_supporting_artifact(
            arguments, gate_id, artifact_name, contracts.canonical_json_line(document),
        )
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    def test_passing_benchmark_cannot_drop_an_invalidated_trial(self, tmp_path):
        arguments = _scenario(tmp_path)

        def mutate(report, _gate):
            report["measurements"][0]["invalidated_trials"] = 1

        _rewrite_report(arguments, "C-PERF-RUNNER", mutate)
        with pytest.raises(evidence.EvidenceError, match="rerun a complete trial set"):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize("gate_id", contracts.RESOURCE_SEMANTIC_GATES)
    def test_every_promoted_resource_gate_requires_its_semantic_report(
        self, tmp_path, gate_id,
    ):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, gate_id)

        def omit_from_report(report, _gate):
            for instance in report["instances"]:
                instance["artifacts"] = [
                    row for row in instance["artifacts"]
                    if row["name"] != "resource-gate-report"
                ]

        _rewrite_report(arguments, gate_id, omit_from_report)
        gate["artifacts"] = [
            row for row in gate["artifacts"] if row["name"] != "resource-gate-report"
        ]
        arguments["artifact_index"]["artifacts"] = [
            row for row in arguments["artifact_index"]["artifacts"]
            if not (row["gate_id"] == gate_id and row["name"] == "resource-gate-report")
        ]
        _resign_gate(gate, arguments["identity"], arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError, match="frozen obligation evidence contract"):
            contracts.aggregate_records(**arguments)

    def test_resource_report_cannot_self_select_threshold_policy(self, tmp_path):
        arguments = _scenario(tmp_path)

        def mutate(report):
            measurement = next(
                row for row in report["measurements"] if row["metric"] == "wall_time"
            )
            measurement["limit"] += 1

        _rewrite_resource_report(arguments, "C-PERF-INGEST", mutate)
        with pytest.raises(evidence.EvidenceError, match="accepted threshold policy"):
            contracts.aggregate_records(**arguments)

    def test_resource_report_cannot_swap_threshold_or_benchmark_identity(self, tmp_path):
        threshold_swap = _scenario(tmp_path / "threshold")
        _rewrite_resource_report(
            threshold_swap,
            "C-FAULT-DISK",
            lambda report: report.__setitem__("threshold_manifest_digest", _digest("9")),
        )
        with pytest.raises(evidence.EvidenceError, match="committed threshold manifest"):
            contracts.aggregate_records(**threshold_swap)

        benchmark_swap = _scenario(tmp_path / "benchmark")
        _rewrite_resource_report(
            benchmark_swap,
            "C-PERF-DISK",
            lambda report: report.__setitem__("benchmark_manifest_digest", _digest("8")),
        )
        with pytest.raises(evidence.EvidenceError, match="benchmark identity"):
            contracts.aggregate_records(**benchmark_swap)

    def test_resource_report_body_cannot_be_relabelled_for_another_gate(self, tmp_path):
        arguments = _scenario(tmp_path)
        source = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-FAULT-DISK" and row["name"] == "resource-gate-report"
        )
        body = (arguments["artifact_root"] / source["path"]).read_bytes()
        _rewrite_supporting_artifact(
            arguments, "C-FAULT-RESOLVER", "resource-gate-report", body,
        )
        with pytest.raises(evidence.EvidenceError, match="gate identity"):
            contracts.aggregate_records(**arguments)

    def test_resource_trial_digests_must_resolve_to_the_exact_signed_support_graph(
        self, tmp_path,
    ):
        arguments = _scenario(tmp_path)
        unrelated = next(
            row["digest"] for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-FAULT-STORE" and row["name"] == "fault-matrix"
        )

        def mutate(report):
            for trial in report["trials"]:
                trial["artifact_digests"] = [unrelated]

        _rewrite_resource_report(arguments, "C-FAULT-DISK", mutate)
        with pytest.raises(evidence.EvidenceError, match="signed indexed supporting artifact"):
            contracts.aggregate_records(**arguments)

    def test_resource_measurements_must_reconcile_canonical_raw_trials(self, tmp_path):
        arguments = _scenario(tmp_path)

        def mutate(report):
            for trial in report["trials"]:
                trial["metric_facts"]["wall_time"] = 0
            measurement = next(
                row for row in report["measurements"] if row["metric"] == "wall_time"
            )
            measurement["value"] = 0
            measurement["passed"] = True

        _rewrite_resource_report(arguments, "C-PERF-INGEST", mutate)
        with pytest.raises(evidence.EvidenceError, match="raw trials"):
            contracts.aggregate_records(**arguments)

    def test_resource_report_candidate_and_signed_instance_are_not_swappable(self, tmp_path):
        candidate_swap = _scenario(tmp_path / "candidate")
        _rewrite_resource_report(
            candidate_swap,
            "C-FAULT-DISK",
            lambda report: report.__setitem__("candidate_identity_digest", _digest("7")),
        )
        with pytest.raises(evidence.EvidenceError, match="another candidate"):
            contracts.aggregate_records(**candidate_swap)

        interval_swap = _scenario(tmp_path / "interval")
        _rewrite_resource_report(
            interval_swap,
            "C-FAULT-DISK",
            lambda report: report.__setitem__("started_at", "2026-08-14T10:19:59Z"),
        )
        with pytest.raises(evidence.EvidenceError, match="outside its signed evidence instance"):
            contracts.aggregate_records(**interval_swap)

    def test_resource_report_cannot_move_to_an_identical_second_signed_instance(
        self, tmp_path,
    ):
        arguments = _scenario(tmp_path)

        def move_artifact(report, gate):
            original = report["instances"][0]
            resource_artifact = next(
                row for row in original["artifacts"]
                if row["name"] == "resource-gate-report"
            )
            original["artifacts"] = [
                row for row in original["artifacts"]
                if row["name"] != "resource-gate-report"
            ]
            second = copy.deepcopy(original)
            second["id"] = "instance-01"
            second["artifacts"] = [resource_artifact]
            report["instances"].append(second)
            gate["selection"] = {
                name: value * 2 for name, value in gate["selection"].items()
            }

        _rewrite_report(arguments, "C-FAULT-DISK", move_artifact)
        with pytest.raises(evidence.EvidenceError, match="another evidence instance"):
            contracts.aggregate_records(**arguments)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("started_at", "2026-08-14T09:59:59Z"),
            ("finished_at", "2026-08-14T10:00:03Z"),
        ],
    )
    def test_report_instance_must_be_inside_the_signed_gate_interval(
        self, tmp_path, field, value,
    ):
        arguments = _scenario(tmp_path)
        _rewrite_report(
            arguments,
            "A-IDENTITY",
            lambda report, _gate: report["instances"][0].__setitem__(field, value),
        )
        with pytest.raises(evidence.EvidenceError, match="signed gate interval"):
            contracts.aggregate_records(**arguments)

    def test_release_phases_cannot_overlap_or_run_backwards(self, tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "E-DOCS")
        gate["started_at"] = "2026-08-14T10:00:00Z"
        gate["finished_at"] = "2026-08-14T10:00:02Z"
        _resign_gate(gate, arguments["identity"], arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError, match="lifecycle overlaps D and E"):
            contracts.aggregate_records(**arguments)

    def test_expired_no_live_rule_and_late_manifest_review_fail_closed(self, tmp_path):
        expired = _scenario(tmp_path / "expired")
        expired["no_live_rule"]["expires_at"] = "2026-08-14T10:35:00Z"
        _sign_contract_review(
            expired["no_live_rule"], expired["trust_policy"],
            approved_at=expired["no_live_rule"]["approval"]["approved_at"],
        )
        _rebind_scenario(expired)
        with pytest.raises(evidence.EvidenceError, match="expired before aggregation"):
            contracts.aggregate_records(**expired)

        late = _scenario(tmp_path / "late")
        _sign_contract_review(
            late["support_matrix"], late["trust_policy"],
            approved_at="2026-08-14T10:00:01Z",
        )
        _rebind_scenario(late)
        with pytest.raises(evidence.EvidenceError, match="approved before"):
            contracts.aggregate_records(**late)

        equal = _scenario(tmp_path / "equal")
        _sign_contract_review(
            equal["support_matrix"], equal["trust_policy"],
            approved_at="2026-08-14T10:00:00Z",
        )
        _rebind_scenario(equal)
        with pytest.raises(evidence.EvidenceError, match="approved before"):
            contracts.aggregate_records(**equal)

    def test_no_live_record_cannot_claim_tools_without_execution(self, tmp_path):
        arguments = _scenario(tmp_path)
        gate = _gate(arguments, "D-AUTHORIZATION")
        gate["toolchain"] = [{
            "digest": _digest("a"),
            "name": "unexecuted-tool",
            "path": "/runner/bin/unexecuted-tool",
            "version": "1",
        }]
        _resign_gate(gate, arguments["identity"], arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError, match="zero execution, tools"):
            contracts.aggregate_records(**arguments)


class TestSBOMSemanticEvidence:
    @staticmethod
    def _document(arguments: dict, name: str) -> dict:
        indexed = next(
            row for row in arguments["artifact_index"]["artifacts"]
            if row["gate_id"] == "C-SBOM" and row["name"] == name
        )
        return json.loads((arguments["artifact_root"] / indexed["path"]).read_bytes())

    @classmethod
    def _rewrite_observation(cls, arguments: dict, name: str, mutate) -> None:
        observation = cls._document(arguments, name)
        mutate(observation)
        observation_body = contracts.canonical_json_line(observation)
        _rewrite_supporting_artifact(arguments, "C-SBOM", name, observation_body)

        sbom = cls._document(arguments, "sbom")
        next(row for row in sbom["observations"] if row["name"] == name)[
            "digest"
        ] = contracts.raw_sha256(observation_body)
        sbom["dependency_graph_digest"] = contracts.raw_sha256(
            contracts.canonical_json_line([
                {"digest": row["digest"], "environment": row["environment"]}
                for row in sbom["observations"]
            ])
        )
        sbom.pop("sbom_digest")
        sbom["sbom_digest"] = contracts.raw_sha256(
            contracts.canonical_json_line(sbom)
        )
        _rewrite_supporting_artifact(
            arguments, "C-SBOM", "sbom", contracts.canonical_json_line(sbom),
        )

    def test_raw_and_merged_documents_validate_through_the_committed_schema(
        self, tmp_path,
    ):
        jsonschema = pytest.importorskip("jsonschema")
        arguments = _scenario(tmp_path)
        schema = json.loads(
            (ROOT / contracts.SCHEMA_PATHS["gate-artifact-schema"]).read_bytes()
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        for name in ("sbom-observation-3.10", "sbom"):
            assert list(validator.iter_errors(self._document(arguments, name))) == []

    @pytest.mark.parametrize(
        ("mutation", "expected"),
        [
            ("producer", "unbound producer"),
            ("missing-dependency", "omits an active reachable dependency"),
            ("graph", "dependency graph digest does not recompute"),
            ("content", "content digest does not recompute"),
        ],
    )
    def test_raw_observation_claims_are_recomputed_after_full_rebinding(
        self, tmp_path, mutation, expected,
    ):
        arguments = _scenario(tmp_path)

        def mutate(document):
            if mutation == "producer":
                document["producer"]["digest"] = _digest("9")
            elif mutation == "missing-dependency":
                document["components"] = [
                    row for row in document["components"] if row["name"] != "click"
                ]
            elif mutation == "graph":
                document["dependency_graph_digest"] = _digest("8")
            else:
                document["components"][0]["files"][0]["digest"] = _digest("7")

        self._rewrite_observation(
            arguments, "sbom-observation-3.10", mutate,
        )
        with pytest.raises(evidence.EvidenceError, match=expected):
            contracts.aggregate_records(**arguments)

    def test_merged_sbom_binds_exact_instance_and_support_license(self, tmp_path):
        wrong_instance = _scenario(tmp_path / "instance")
        sbom = self._document(wrong_instance, "sbom")
        sbom["observations"][0]["evidence_instance_id"] = "invented-instance"
        sbom.pop("sbom_digest")
        sbom["sbom_digest"] = contracts.raw_sha256(
            contracts.canonical_json_line(sbom)
        )
        _rewrite_supporting_artifact(
            wrong_instance,
            "C-SBOM",
            "sbom",
            contracts.canonical_json_line(sbom),
        )
        with pytest.raises(evidence.EvidenceError, match="one exact signed P0"):
            contracts.aggregate_records(**wrong_instance)

        wrong_license = _scenario(tmp_path / "license")
        sbom = self._document(wrong_license, "sbom")
        next(
            row for row in sbom["components"] if row["relationship"] == "tool"
        )["license"] = "invented-license"
        sbom.pop("sbom_digest")
        sbom["sbom_digest"] = contracts.raw_sha256(
            contracts.canonical_json_line(sbom)
        )
        _rewrite_supporting_artifact(
            wrong_license,
            "C-SBOM",
            "sbom",
            contracts.canonical_json_line(sbom),
        )
        with pytest.raises(evidence.EvidenceError, match="support inventory"):
            contracts.aggregate_records(**wrong_license)


class TestCoverageSemanticEvidence:
    @staticmethod
    def _report(arguments: dict) -> dict:
        artifact = next(item for item in arguments["artifact_index"]["artifacts"]
                        if item["gate_id"] == "B-COVERAGE" and item["name"] == "coverage-report")
        return json.loads((arguments["artifact_root"] / artifact["path"]).read_bytes())

    @staticmethod
    def _verify(arguments: dict, document: dict) -> None:
        gate = copy.deepcopy(_gate(arguments, "B-COVERAGE"))
        body = contracts.canonical_json_line(document)
        next(item for item in gate["artifacts"] if item["name"] == "coverage-report")["digest"] = contracts.raw_sha256(body)
        report_artifact = next(item for item in arguments["artifact_index"]["artifacts"]
                               if item["gate_id"] == "B-COVERAGE" and item["name"] == "gate-evidence")
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / report_artifact["path"]).read_bytes(),
            identity=arguments["identity"], gate_id="B-COVERAGE",
        )
        bodies = {"coverage-report": body}
        for artifact in arguments["artifact_index"]["artifacts"]:
            if artifact["gate_id"] == "B-COVERAGE" and artifact["name"].startswith("coverage-shard-"):
                bodies[artifact["name"]] = (arguments["artifact_root"] / artifact["path"]).read_bytes()
        with contracts.ArtifactResolver(arguments["artifact_root"], arguments["artifact_index"], identity=arguments["identity"]) as resolver:
            contracts._semantic_coverage(
                gate, bodies, identity=arguments["identity"], report=report,
                scope=arguments["scope"], thresholds=arguments["threshold_manifest"],
                input_bodies=arguments["input_bodies"], resolver=resolver,
            )

    def test_coverage_schema_and_compact_evidence_refuse_forgery(self, tmp_path):
        arguments = _scenario(tmp_path)
        original = self._report(arguments)
        schema = json.loads((ROOT / contracts.SCHEMA_PATHS["gate-artifact-schema"]).read_text())
        coverage_schema = {"$defs": schema["$defs"], **schema["$defs"]["coverage_report"]}
        assert list(Draft202012Validator(coverage_schema).iter_errors(original)) == []
        self._verify(arguments, original)
        mutations = (
            lambda doc: doc.update(candidate_identity_digest=_digest("9")),
            lambda doc: doc["coverage_files"].pop(),
            lambda doc: doc["coverage_files"].append(copy.deepcopy(doc["coverage_files"][0])),
            lambda doc: doc["coverage_files"][0]["lines"].update(covered=11),
            lambda doc: [row["branches"].update(covered=0, total=0) for row in doc["coverage_files"]],
            lambda doc: doc["critical_modules"].pop(),
            lambda doc: doc["coverage_data"][1].update(digest=doc["coverage_data"][0]["digest"]),
            lambda doc: doc["coverage_data"][0].update(h0_fragment_digest=_digest("7")),
            lambda doc: doc["measurements"][0].update(breached=True),
        )
        for mutate in mutations:
            forged = copy.deepcopy(original)
            mutate(forged)
            with pytest.raises(evidence.EvidenceError):
                self._verify(arguments, forged)
        malformed = copy.deepcopy(original)
        malformed["unexpected"] = True
        assert list(Draft202012Validator(coverage_schema).iter_errors(malformed))

    def test_coverage_shard_union_is_read_from_signed_indexed_artifacts(self, tmp_path):
        arguments = _scenario(tmp_path)
        original = self._report(arguments)
        for artifact in arguments["artifact_index"]["artifacts"]:
            if artifact["gate_id"] != "B-COVERAGE" or not artifact["name"].startswith("coverage-shard-"):
                continue
            path = arguments["artifact_root"] / artifact["path"]
            shard = json.loads(path.read_bytes())
            shard["files"][0]["executed_lines"].pop()
            body = contracts.canonical_json_line(shard)
            path.write_bytes(body)
            artifact.update(digest=contracts.raw_sha256(body), size=len(body))
            next(item for item in _gate(arguments, "B-COVERAGE")["artifacts"]
                 if item["name"] == artifact["name"])["digest"] = artifact["digest"]
        with pytest.raises(evidence.EvidenceError, match="totals do not recompute"):
            self._verify(arguments, original)


class TestStaticSecuritySemanticEvidence:
    @staticmethod
    def _documents(arguments: dict) -> tuple[dict, dict]:
        records = {
            item["name"]: item for item in arguments["artifact_index"]["artifacts"]
            if item["gate_id"] == "B-STATIC-SECURITY"
        }
        return tuple(
            json.loads((arguments["artifact_root"] / records[name]["path"]).read_bytes())
            for name in ("security-findings", "security-scan-fragment")
        )

    @staticmethod
    def _verify(arguments: dict, findings: dict, fragment: dict) -> None:
        gate = copy.deepcopy(_gate(arguments, "B-STATIC-SECURITY"))
        fragment_body = contracts.canonical_json_line(fragment)
        findings["scan_fragment_digest"] = contracts.raw_sha256(fragment_body)
        findings_body = contracts.canonical_json_line(findings)
        bodies = {
            "security-findings": findings_body,
            "security-scan-fragment": fragment_body,
        }
        for name, body in bodies.items():
            next(item for item in gate["artifacts"] if item["name"] == name)["digest"] = \
                contracts.raw_sha256(body)
        report_artifact = next(
            item for item in arguments["artifact_index"]["artifacts"]
            if item["gate_id"] == "B-STATIC-SECURITY" and item["name"] == "gate-evidence"
        )
        report = contracts.read_evidence_report(
            (arguments["artifact_root"] / report_artifact["path"]).read_bytes(),
            identity=arguments["identity"], gate_id="B-STATIC-SECURITY",
        )
        with contracts.ArtifactResolver(
            arguments["artifact_root"], arguments["artifact_index"],
            identity=arguments["identity"],
        ) as resolver:
            contracts._semantic_static_security(
                gate, bodies, identity=arguments["identity"], report=report,
                scope=arguments["scope"], thresholds=arguments["threshold_manifest"],
                input_bodies=arguments["input_bodies"], resolver=resolver,
            )

    def test_static_security_schemas_and_semantics_refuse_substitution(self, tmp_path):
        arguments = _scenario(tmp_path)
        findings, fragment = self._documents(arguments)
        findings_schema = json.loads(
            (ROOT / contracts.SCHEMA_PATHS["security-findings-schema"]).read_bytes()
        )
        fragment_schema = json.loads(
            (ROOT / contracts.SCHEMA_PATHS["static-security-fragment-schema"]).read_bytes()
        )
        assert list(Draft202012Validator(findings_schema).iter_errors(findings)) == []
        assert list(Draft202012Validator(fragment_schema).iter_errors(fragment)) == []
        self._verify(arguments, copy.deepcopy(findings), copy.deepcopy(fragment))

        finding_mutations = (
            lambda doc: doc.update(candidate_identity_digest=_digest("9")),
            lambda doc: doc["bindings"].pop(),
            lambda doc: doc["checks"][0].update(result_digest=_digest("9")),
            lambda doc: doc["suppressions"][0].update(owner="substituted"),
            lambda doc: doc["selection"].update(selected=4),
        )
        for mutate in finding_mutations:
            forged = copy.deepcopy(findings)
            mutate(forged)
            with pytest.raises(evidence.EvidenceError):
                self._verify(arguments, forged, copy.deepcopy(fragment))

        fragment_mutations = (
            lambda doc: doc.update(job_instance_id="foreign-job"),
            lambda doc: doc["ast_inventory"][0].update(source="bandit"),
            lambda doc: doc["dependency_manifest"].update(digest=_digest("8")),
            lambda doc: doc.update(unsuppressed_findings=1),
        )
        for mutate in fragment_mutations:
            forged = copy.deepcopy(fragment)
            mutate(forged)
            with pytest.raises(evidence.EvidenceError):
                self._verify(arguments, copy.deepcopy(findings), forged)

        unknown = copy.deepcopy(fragment)
        unknown["unexpected"] = True
        assert list(Draft202012Validator(fragment_schema).iter_errors(unknown))

    def test_static_security_applies_a_future_numeric_threshold(self, tmp_path):
        arguments = _scenario(tmp_path)
        findings, fragment = self._documents(arguments)
        fragment["findings"] = [{
            "api": "B999", "id": "bandit-unsuppressed", "line": 1,
            "path": "src/quarry_recon/example.py", "source": "bandit",
        }]
        fragment["unsuppressed_findings"] = 1
        findings.update({
            "findings": copy.deepcopy(fragment["findings"]),
            "unsuppressed_findings": 1,
            "checks": contracts._static_security_checks(fragment),
        })
        threshold = next(
            row for row in arguments["threshold_manifest"]["thresholds"]
            if row["gate_id"] == "B-STATIC-SECURITY"
        )
        threshold["limit"] = 0
        with pytest.raises(evidence.EvidenceError, match="threshold breach"):
            self._verify(arguments, findings, fragment)


class TestDeterminismSemanticEvidence:
    def test_boolean_zero_cannot_satisfy_the_signed_integer_contract(self, tmp_path):
        arguments = _scenario(tmp_path)
        wrapper_index = next(row for row in arguments["artifact_index"]["artifacts"]
                             if row["gate_id"] == "B-DETERMINISM" and
                             row["name"] == "artifact-tree-diff")
        wrapper = json.loads((arguments["artifact_root"] / wrapper_index["path"]).read_bytes())
        wrapper["artifact_differences"] = False
        _rewrite_supporting_artifact(
            arguments, "B-DETERMINISM", "artifact-tree-diff",
            contracts.canonical_json_line(wrapper),
        )
        _resign_gate(_gate(arguments, "B-DETERMINISM"), arguments["identity"],
                     arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError, match="exact non-negative integer"):
            contracts.aggregate_records(**arguments)

    def test_equal_forged_trees_are_refused_when_fixture_bytes_do_not_rebuild_them(self, tmp_path):
        arguments = _scenario(tmp_path)
        index = next(row for row in arguments["artifact_index"]["artifacts"]
                     if row["gate_id"] == "B-DETERMINISM" and
                     row["name"] == "artifact-tree-diff-fragment")
        fragment = json.loads((arguments["artifact_root"] / index["path"]).read_bytes())
        forged_files = [
            {"bytes": 1, "digest": _digest(str(index)), "path": row["path"]}
            for index, row in enumerate(fragment["runs"][0]["files"])
        ]
        forged_tree = evidence.canonical_digest(forged_files)
        fragment["runs"] = [
            {"files": copy.deepcopy(forged_files), "id": "run-1", "tree_digest": forged_tree},
            {"files": copy.deepcopy(forged_files), "id": "run-2", "tree_digest": forged_tree},
        ]
        fragment["fixture_digest"] = forged_tree
        raw_body = contracts.canonical_json_line(fragment)
        # The raw reader accepts internally consistent paired facts; the gate verifier
        # must additionally rebuild every file from the frozen fixture.
        contracts.read_determinism_fragment(raw_body)
        _rewrite_supporting_artifact(
            arguments, "B-DETERMINISM", "artifact-tree-diff-fragment", raw_body,
        )
        wrapper_index = next(row for row in arguments["artifact_index"]["artifacts"]
                             if row["gate_id"] == "B-DETERMINISM" and
                             row["name"] == "artifact-tree-diff")
        wrapper = json.loads((arguments["artifact_root"] / wrapper_index["path"]).read_bytes())
        wrapper.update({
            "fixture_digest": forged_tree,
            "raw_fragment_digest": contracts.raw_sha256(raw_body),
            "runs": copy.deepcopy(fragment["runs"]),
        })
        _rewrite_supporting_artifact(
            arguments, "B-DETERMINISM", "artifact-tree-diff",
            contracts.canonical_json_line(wrapper),
        )
        _resign_gate(_gate(arguments, "B-DETERMINISM"), arguments["identity"],
                     arguments["trust_policy"])
        with pytest.raises(evidence.EvidenceError, match="trees do not recompute"):
            contracts.aggregate_records(**arguments)
