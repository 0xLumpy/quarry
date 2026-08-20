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
from pathlib import Path

import pytest

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence
from quarry_recon import resource_contract

pytestmark = pytest.mark.offline

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/release_contracts/ed25519-golden-v1.json"
APPROVAL_SEED = hashlib.sha256(b"Quarry test-only approval signing key v1").digest()
GATE_SEED = hashlib.sha256(b"Quarry test-only gate signing key v1").digest()


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
        "quarry_recon/__init__.py": b"__version__ = '0.3.10'\n",
        "quarry_recon/data/default.yaml": b"fixture: true\n",
        "quarry_recon/data/release-scope-v1.schema.json": b"{}\n",
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


def _supporting_bodies(
    gate_id: str, *, identity: dict, scope: dict, support: dict, thresholds: dict,
    benchmark: dict | None, measurements: list[dict], environment: dict,
    evidence_instance_id: str, toolchain: list[dict], indexed: list[dict], policy: dict,
) -> dict[str, bytes]:
    names = [name for name, _media_type in contracts.required_artifact_contract(gate_id)]
    bodies: dict[str, bytes] = {}
    if gate_id == "A-IDENTITY":
        bodies["identity-verification"] = contracts.canonical_json_line(identity)
    elif gate_id == "C-PACKAGE-BUILD":
        bodies["sdist"] = _synthetic_sdist()
        bodies["wheel"] = _synthetic_wheel()
        bodies["package-inventory"] = contracts.canonical_json_line({
            "artifact_type": "package-inventory",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "gate_id": gate_id,
            "package": {"name": "quarry-recon", "version": "0.3.10"},
            "release": "0.3.10",
            "schema_version": contracts.PACKAGE_INVENTORY_SCHEMA,
            "subjects": [{
                "digest": contracts.raw_sha256(bodies[name]),
                "media_type": media_type,
                "name": name,
                "size": len(bodies[name]),
            } for name, media_type in (("sdist", "application/gzip"), ("wheel", "application/zip"))],
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
        components = [{
            "content_digest": identity["source_tree_digest"],
            "declared_requirement": None,
            "license": "MIT",
            "name": "quarry-recon",
            "relationship": "project",
            "version": "0.3.10",
        }]
        components.extend({
            "content_digest": row["digest"],
            "declared_requirement": None,
            "license": "TEST-ONLY",
            "name": row["name"],
            "relationship": relationship,
            "version": row["version"],
        } for relationship, rows in (
            ("template", support["template_sets"]), ("tool", support["tools"]),
        ) for row in rows)
        requirements = {
            "click": "click>=8.2",
            "idna": "idna>=3.4",
            "pyyaml": "pyyaml>=6.0",
            "tomli": "tomli>=2.0; python_version < '3.11'",
        }
        components.extend({
            "content_digest": "sha256:" + hashlib.sha256(name.encode()).hexdigest(),
            "declared_requirement": requirement,
            "license": "SYNTHETIC-RESOLVED-LICENSE",
            "name": name,
            "relationship": "dependency",
            "version": "synthetic-resolved-1",
        } for name, requirement in requirements.items())
        components.sort(key=lambda row: (row["relationship"], row["name"]))
        bodies["sbom"] = contracts.canonical_json_line({
            "artifact_type": "sbom",
            "candidate_identity_digest": evidence.canonical_digest(identity),
            "components": components,
            "dependency_graph_digest": "sha256:" + hashlib.sha256(
                contracts.canonical_json_line(components)
            ).hexdigest(),
            "gate_id": gate_id,
            "package": {"name": "quarry-recon", "version": "0.3.10"},
            "release": "0.3.10",
            "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
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
        }] + [{"digest": row["digest"], "name": row["name"]} for row in identity["inputs"]]
        materials.sort(key=lambda row: row["name"])
        bodies["provenance"] = contracts.canonical_json_line({
            "artifact_type": "provenance",
            "builder": {"environment": environment, "toolchain": toolchain},
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
    support["tools"] = [{"digest": _digest("a"), "name": "synthetic-tool", "version": "1"}]
    support["template_sets"] = [
        {"digest": _digest("b"), "name": "synthetic-templates", "version": "1"},
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
        row["limit"] = (
            0 if row["metric"] in resource_contract._ZERO_INVARIANTS else 1
        )
        if row["class"] == "regression":
            row["baseline_digest"] = _digest("c")
    corpus["sources"][-1]["attestation_digest"] = _digest("e")
    corpus["sources"][-1]["fixture_digest"] = _digest("f")
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
    inputs = []
    for index, (name, path) in enumerate(sorted(evidence.DEFAULT_IDENTITY_INPUTS.items())):
        inputs.append({"digest": _digest(format(index % 16, "x")), "name": name, "path": path})
    inputs.extend(copy.deepcopy(scope["input_bindings"]))
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
        if not is_live:
            if gate_id == "B-HERMETIC-ALL":
                instance_specs = [
                    environment for environment in supported_environments
                    if environment["lane"] == "H0-hermetic"
                ]
            elif gate_id == "C-PYTHON-MATRIX":
                instance_specs = [
                    environment for environment in supported_environments
                    if environment["lane"] in lanes
                ]
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
                instances.append({
                    "artifacts": [],
                    "assertions": [assertion],
                    "environment": instance_environment,
                    "finished_at": instance_finished_at,
                    "id": f"instance-{instance_index:02d}",
                    "lane": environment["lane"],
                    "selection": {
                        "collected": 1, "deselected": 0, "failed": 0, "passed": 1,
                        "selected": 1, "skipped": 0, "xfailed": 0, "xpassed": 0,
                    },
                    "started_at": gate_started_at,
                    "toolchain": supported_toolchain,
                })

            benchmark = next(
                (row for row in thresholds["benchmarks"] if row["gate_id"] == gate_id),
                None,
            )
            measurements = []
            for threshold in thresholds["thresholds"]:
                if threshold["gate_id"] == gate_id:
                    if threshold["class"] == "regression":
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
            if gate_id == "C-CORPUS-SYNTHETIC":
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
                benchmark=benchmark,
                measurements=measurements,
                environment=instances[0]["environment"],
                evidence_instance_id=instances[0]["id"],
                toolchain=supported_toolchain,
                indexed=indexed,
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
                artifacts.append({
                    key: artifact[key] for key in ("digest", "media_type", "name")
                })
                instances[0]["artifacts"].append({
                    "digest": artifact["digest"],
                    "name": artifact_name,
                })
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
            "toolchain": supported_toolchain if not is_live else [],
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
                benchmark=report["benchmark"],
                measurements=report["measurements"],
                environment=gate["environment"],
                evidence_instance_id=report["instances"][0]["id"],
                toolchain=gate["toolchain"],
                indexed=arguments["artifact_index"]["artifacts"],
                policy=arguments["trust_policy"],
            )
            for artifact_name, artifact_body in supporting_bodies.items():
                indexed_artifact = index_by_key[(gate_id, artifact_name)]
                artifact_path = arguments["artifact_root"] / indexed_artifact["path"]
                artifact_path.write_bytes(artifact_body)
                indexed_artifact["digest"] = contracts.raw_sha256(artifact_body)
                indexed_artifact["size"] = len(artifact_body)
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

    def test_gate_artifact_schema_variants_are_disjoint_and_fail_closed_on_unknown_fields(self):
        schema = json.loads(
            (ROOT / contracts.SCHEMA_PATHS["gate-artifact-schema"]).read_text()
        )
        variant_names = [reference["$ref"].rsplit("/", 1)[-1] for reference in schema["oneOf"]]
        assert variant_names == [
            "machine_report", "package_inventory", "benchmark_baseline",
            "benchmark_trials", "benchmark_invalidations", "benchmark_report", "sbom",
            "provenance", "publication_subjects",
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
        assert len(thresholds["thresholds"]) == len(contracts.THRESHOLD_CONTRACTS) == 56
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
            | {"A-IDENTITY", "C-NETWORK-BOUNDARY", "C-NET-DENY"}
        )
        assert "C-PERF-PHASE-FAIRNESS" not in contracts.SEMANTIC_VERIFIERS
        arguments = _scenario(tmp_path)
        with pytest.raises(
            evidence.EvidenceError,
            match="A-TAXONOMY has no registered obligation-specific semantic verifier",
        ):
            contracts.aggregate_records(**arguments)


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
            benchmark["limit"] = 2
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
            ("C-PACKAGE-BUILD", "wheel", "invalid-wheel", "readable ZIP archive"),
            ("C-SBOM", "sbom", "missing-dependency", "declared direct dependency"),
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
            elif mutation == "missing-publication-subject":
                document["subjects"].pop()
            changed = contracts.canonical_json_line(document)
        _rewrite_supporting_artifact(arguments, gate_id, artifact_name, changed)
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
