"""Strict, additive contracts for v0.3.10 release-evidence aggregation.

The v1 candidate and gate record formats remain owned by :mod:`release_evidence`.
This module supplies the object graph around those frozen formats: scope and
matrix manifests, content-addressed artifact resolution, trust verification,
deterministic aggregation, and detached approval.  It deliberately performs no
repository mutation and never treats tracked development manifests as accepted
release authority.
"""
from __future__ import annotations

import base64
import binascii
import csv
import errno
import hashlib
import io
import os
import re
import stat
import tarfile
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType

from . import release_evidence as evidence
from . import release_v310_05
from . import resource_contract


RELEASE_SCOPE_SCHEMA = "quarry.release-scope.v1"
SUPPORT_MATRIX_SCHEMA = "quarry.support-matrix.v1"
THRESHOLD_MANIFEST_SCHEMA = "quarry.threshold-benchmark-manifest.v1"
CORPUS_MANIFEST_SCHEMA = "quarry.corpus-selection.v1"
NO_LIVE_RULE_SCHEMA = "quarry.no-live-rule.v1"
ARTIFACT_INDEX_SCHEMA = "quarry.release-artifact-index.v1"
TRUST_POLICY_SCHEMA = "quarry.release-trust-policy.v1"
SIGNATURE_ENVELOPE_SCHEMA = "quarry.release-signature-envelope.v1"
EVIDENCE_REPORT_SCHEMA = "quarry.gate-evidence-report.v1"
CONFORMANCE_MANIFEST_SCHEMA = "quarry.aggregator-conformance-manifest.v1"
GATE_ARTIFACT_SCHEMA = "quarry.gate-artifact.v1"
SUPPORTING_ARTIFACT_SCHEMA = GATE_ARTIFACT_SCHEMA
PACKAGE_INVENTORY_SCHEMA = GATE_ARTIFACT_SCHEMA
PACKAGE_INSTALL_INVENTORY_SCHEMA = GATE_ARTIFACT_SCHEMA
PACKAGE_INSTALL_SMOKE_SCHEMA = GATE_ARTIFACT_SCHEMA
BENCHMARK_TRIALS_SCHEMA = GATE_ARTIFACT_SCHEMA
BENCHMARK_INVALIDATIONS_SCHEMA = GATE_ARTIFACT_SCHEMA
BENCHMARK_BASELINE_SCHEMA = GATE_ARTIFACT_SCHEMA
BENCHMARK_REPORT_SCHEMA = GATE_ARTIFACT_SCHEMA
RESOURCE_GATE_REPORT_SCHEMA = resource_contract.SCHEMA_VERSION
NETWORK_BOUNDARY_TRACE_SCHEMA = "quarry.network-boundary-trace.v1"
NETWORK_DENIAL_REPORT_SCHEMA = "quarry.network-denial-report.v1"
PUBLICATION_SUBJECTS_SCHEMA = GATE_ARTIFACT_SCHEMA
AGGREGATE_SCHEMA = "quarry.release-aggregate.v1"
APPROVAL_SCHEMA = "quarry.detached-release-approval.v1"

RELEASE = evidence.RELEASE_SCOPE
LANE_ORDER = (
    "H0-hermetic",
    "H1-tool-integration",
    "C0-private-corpus",
    "P0-package-supply",
    "L0-authorized-live",
)
ROLE_ORDER = ("approval", "gate")
CORPUS_GATES = (
    "C-CORPUS-ATTEST",
    "C-CORPUS-RICH",
    "C-CORPUS-INTERRUPTED",
    "C-CORPUS-LEGACY",
    "C-CORPUS-ORPHAN",
    "C-CORPUS-EVOLUTION",
    "C-CORPUS-SYNTHETIC",
)
LIVE_GATES = (
    "D-AUTHORIZATION",
    "D-RANGE-IDENTITY",
    "D-LIVE-CONTRACT",
    "D-CLEANUP",
)

# (obligation id, collector lane, required evidence lanes).  ``None`` marks a
# staged operation rather than a gate-record slot.  This is the fixed 64-row
# universe from RELEASE-GATES.md, not a caller-extensible registry.
OBLIGATION_CONTRACTS = (
    ("A-IDENTITY", "H0-hermetic", ("H0-hermetic",)),
    ("A-TAXONOMY", "H0-hermetic", ("H0-hermetic",)),
    ("A-EVIDENCE-SCHEMA", "H0-hermetic", ("H0-hermetic",)),
    ("A-CORPUS", "H0-hermetic", ("H0-hermetic",)),
    ("A-THRESHOLDS", "H0-hermetic", ("H0-hermetic",)),
    ("A-SUPPORT", "H0-hermetic", ("H0-hermetic",)),
    ("B-HERMETIC-ALL", "H0-hermetic", ("H0-hermetic",)),
    ("B-SCHEMA", "H0-hermetic", ("H0-hermetic",)),
    ("B-MANIFEST", "H0-hermetic", ("H0-hermetic",)),
    ("B-QUALITY", "H0-hermetic", ("H0-hermetic",)),
    ("B-COVERAGE", "H0-hermetic", ("H0-hermetic",)),
    ("B-STATIC-SECURITY", "H0-hermetic", ("H0-hermetic",)),
    ("B-DETERMINISM", "H0-hermetic", ("H0-hermetic",)),
    ("B-DOCS-POLICY", "H0-hermetic", ("H0-hermetic",)),
    ("C-PACKAGE-BUILD", "P0-package-supply", ("P0-package-supply",)),
    ("C-PACKAGE-INSTALL", "P0-package-supply", ("P0-package-supply",)),
    ("C-PYTHON-MATRIX", "H0-hermetic", ("H0-hermetic", "P0-package-supply")),
    ("C-SBOM", "P0-package-supply", ("P0-package-supply",)),
    ("C-VULNERABILITY", "P0-package-supply", ("P0-package-supply",)),
    ("C-PROVENANCE", "P0-package-supply", ("P0-package-supply",)),
    ("C-INSTALL-ROLLBACK", "P0-package-supply", ("H1-tool-integration", "P0-package-supply")),
    ("C-TOOLS", "H1-tool-integration", ("H1-tool-integration",)),
    ("C-OUTPUT-CONTRACT", "H1-tool-integration", ("H1-tool-integration",)),
    ("C-NETWORK-BOUNDARY", "H1-tool-integration", ("H1-tool-integration",)),
    ("C-SOURCE-REGISTRY", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-CORPUS-ATTEST", "C0-private-corpus", ("C0-private-corpus",)),
    ("C-CORPUS-RICH", "C0-private-corpus", ("C0-private-corpus",)),
    ("C-CORPUS-INTERRUPTED", "C0-private-corpus", ("C0-private-corpus",)),
    ("C-CORPUS-LEGACY", "C0-private-corpus", ("C0-private-corpus",)),
    ("C-CORPUS-ORPHAN", "C0-private-corpus", ("C0-private-corpus",)),
    ("C-CORPUS-EVOLUTION", "C0-private-corpus", ("C0-private-corpus",)),
    ("C-CORPUS-SYNTHETIC", "H0-hermetic", ("H0-hermetic",)),
    ("C-PRIVATE-FILES", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-PATH-IDENTITY", "H0-hermetic", ("H0-hermetic",)),
    ("C-SECRETS", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-EXEC-IDENTITY", "H1-tool-integration", ("H1-tool-integration",)),
    ("C-ARCHIVE-FETCH", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-NET-DENY", "H0-hermetic", ("H0-hermetic", "C0-private-corpus", "P0-package-supply")),
    ("C-POLICY-TRACE", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-FAULT-RUNNER", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-FAULT-STORE", "H0-hermetic", ("H0-hermetic",)),
    ("C-FAULT-REVISION", "H0-hermetic", ("H0-hermetic",)),
    ("C-FAULT-FINALIZE", "H0-hermetic", ("H0-hermetic",)),
    ("C-FAULT-CAMPAIGN", "H0-hermetic", ("H0-hermetic",)),
    ("C-FAULT-INSTALL", "H1-tool-integration", ("H1-tool-integration", "P0-package-supply")),
    ("C-FAULT-DISK", "H0-hermetic", ("H0-hermetic",)),
    ("C-FAULT-RESOLVER", "H0-hermetic", ("H0-hermetic",)),
    ("C-FAULT-INTERRUPT", "H0-hermetic", ("H0-hermetic", "H1-tool-integration")),
    ("C-PERF-RUNNER", "H1-tool-integration", ("H1-tool-integration",)),
    ("C-PERF-INGEST", "H0-hermetic", ("H0-hermetic",)),
    ("C-PERF-REPORT", "H0-hermetic", ("H0-hermetic",)),
    ("C-PERF-CAMPAIGN", "H0-hermetic", ("H0-hermetic",)),
    ("C-PERF-DISK", "H0-hermetic", ("H0-hermetic",)),
    ("C-PERF-RESOLVER", "H0-hermetic", ("H0-hermetic",)),
    ("C-PERF-PHASE-FAIRNESS", "H1-tool-integration", ("H1-tool-integration",)),
    ("D-AUTHORIZATION", "H0-hermetic", ()),
    ("D-RANGE-IDENTITY", "H0-hermetic", ()),
    ("D-LIVE-CONTRACT", "H0-hermetic", ()),
    ("D-CLEANUP", "H0-hermetic", ()),
    ("E-AGGREGATE", None, ()),
    ("E-DOCS", "H0-hermetic", ("H0-hermetic",)),
    ("E-PROJECT-HYGIENE", "H0-hermetic", ("H0-hermetic",)),
    ("E-ARTIFACTS", "H0-hermetic", ("H0-hermetic",)),
    ("E-APPROVAL", None, ()),
)

SELECTED_CORPUS_GATES = ("C-CORPUS-SYNTHETIC",)
UNSELECTED_CORPUS_GATES = tuple(gate for gate in CORPUS_GATES if gate not in SELECTED_CORPUS_GATES)
RECORD_UNIVERSE = tuple(gate for gate, lane, _lanes in OBLIGATION_CONTRACTS if lane is not None)
SELECTED_RECORD_SLOTS = tuple(
    gate for gate in RECORD_UNIVERSE if gate not in UNSELECTED_CORPUS_GATES
)
QUALITY_THRESHOLD_CONTRACTS = (
    ("B-HERMETIC-ALL", "absolute", "unexpected_outcomes", "at_most", "maximum", "count"),
    ("B-QUALITY", "absolute", "quality_violations", "at_most", "maximum", "count"),
    ("B-COVERAGE", "absolute", "line_coverage", "at_least", "minimum", "basis_points"),
    ("B-COVERAGE", "regression", "line_coverage_loss", "at_most", "maximum", "basis_points"),
    ("B-STATIC-SECURITY", "absolute", "unsuppressed_findings", "at_most", "maximum", "count"),
    ("B-DETERMINISM", "absolute", "artifact_differences", "at_most", "maximum", "count"),
    ("C-VULNERABILITY", "absolute", "unaccepted_findings", "at_most", "maximum", "count"),
)
RESOURCE_FAULT_THRESHOLD_CONTRACTS = (
    ("C-FAULT-DISK", "absolute", "reserve_overshoot", "at_most", "maximum", "bytes"),
    ("C-FAULT-DISK", "absolute", "destination_corruptions", "at_most", "maximum", "count"),
    ("C-FAULT-DISK", "absolute", "lost_reservations", "at_most", "maximum", "count"),
    ("C-FAULT-DISK", "absolute", "untruthful_remainders", "at_most", "maximum", "count"),
    ("C-FAULT-DISK", "absolute", "lease_leaks", "at_most", "maximum", "count"),
    ("C-FAULT-RESOLVER", "absolute", "worker_leaks", "at_most", "maximum", "count"),
    ("C-FAULT-RESOLVER", "absolute", "late_mutations", "at_most", "maximum", "count"),
    ("C-FAULT-RESOLVER", "absolute", "lost_remainders", "at_most", "maximum", "count"),
    ("C-FAULT-RESOLVER", "absolute", "deadline_overshoot", "at_most", "maximum", "milliseconds"),
    ("C-FAULT-RESOLVER", "absolute", "unbounded_queue_observations", "at_most", "maximum", "count"),
)
PERFORMANCE_OPERATIONS = {
    "C-PERF-RUNNER": "streaming-runner",
    "C-PERF-INGEST": "observation-ingest",
    "C-PERF-REPORT": "report-projection",
    "C-PERF-CAMPAIGN": "campaign-settlement",
    "C-PERF-DISK": "concurrent-disk-governor",
    "C-PERF-RESOLVER": "mixed-resolution-corpus",
    "C-PERF-PHASE-FAIRNESS": "phase-fairness",
}
RESOURCE_REPORT_GATES = (
    "C-FAULT-DISK",
    "C-FAULT-RESOLVER",
    "C-PERF-INGEST",
    "C-PERF-DISK",
    "C-PERF-RESOLVER",
    "C-PERF-PHASE-FAIRNESS",
)
# Phase-fairness aggregate counts cannot prove the required per-obligation
# disposition roster.  Its report remains a supported diagnostic artifact, but
# cannot close the gate until C-POLICY-TRACE has a typed, cross-reconciled body.
RESOURCE_SEMANTIC_GATES = tuple(
    gate_id for gate_id in RESOURCE_REPORT_GATES
    if gate_id != "C-PERF-PHASE-FAIRNESS"
)
V310_05_SEMANTIC_GATES = (
    "C-INSTALL-ROLLBACK",
    "C-FAULT-INSTALL",
    "C-SECRETS",
    "C-EXEC-IDENTITY",
)
PERFORMANCE_THRESHOLD_CONTRACTS = (
    ("C-PERF-RUNNER", "absolute", "peak_aggregate_rss", "at_most", "p95", "bytes"),
    ("C-PERF-RUNNER", "absolute", "wall_deadline", "at_most", "maximum", "milliseconds"),
    ("C-PERF-RUNNER", "absolute", "disk_bytes", "at_most", "p95", "bytes"),
    ("C-PERF-RUNNER", "absolute", "leaked_fds", "at_most", "maximum", "count"),
    ("C-PERF-RUNNER", "absolute", "leaked_processes", "at_most", "maximum", "count"),
    ("C-PERF-RUNNER", "absolute", "evidence_byte_mismatches", "at_most", "maximum", "count"),
    ("C-PERF-RUNNER", "regression", "wall_time_delta", "at_most", "median", "basis_points"),
    ("C-PERF-INGEST", "absolute", "peak_aggregate_rss", "at_most", "p95", "bytes"),
    ("C-PERF-INGEST", "absolute", "wall_time", "at_most", "p95", "milliseconds"),
    ("C-PERF-INGEST", "absolute", "write_amplification", "at_most", "maximum", "basis_points"),
    ("C-PERF-INGEST", "absolute", "disk_growth", "at_most", "maximum", "bytes"),
    ("C-PERF-INGEST", "absolute", "refused_remainders", "at_most", "maximum", "count"),
    ("C-PERF-INGEST", "regression", "wall_time_delta", "at_most", "median", "basis_points"),
    ("C-PERF-REPORT", "absolute", "peak_aggregate_rss", "at_most", "p95", "bytes"),
    ("C-PERF-REPORT", "absolute", "artifact_size", "at_most", "maximum", "bytes"),
    ("C-PERF-REPORT", "absolute", "wall_time", "at_most", "p95", "milliseconds"),
    ("C-PERF-REPORT", "absolute", "artifact_differences", "at_most", "maximum", "count"),
    ("C-PERF-REPORT", "absolute", "observation_coverage", "at_least", "minimum", "basis_points"),
    ("C-PERF-REPORT", "regression", "wall_time_delta", "at_most", "median", "basis_points"),
    ("C-PERF-CAMPAIGN", "absolute", "peak_aggregate_rss", "at_most", "p95", "bytes"),
    ("C-PERF-CAMPAIGN", "absolute", "peak_disk", "at_most", "p95", "bytes"),
    ("C-PERF-CAMPAIGN", "absolute", "decision_latency", "at_most", "p95", "milliseconds"),
    ("C-PERF-CAMPAIGN", "absolute", "full_corpus_duplications", "at_most", "maximum", "count"),
    ("C-PERF-CAMPAIGN", "regression", "decision_latency_delta", "at_most", "median", "basis_points"),
    ("C-PERF-DISK", "absolute", "reserve_overshoot", "at_most", "maximum", "bytes"),
    ("C-PERF-DISK", "absolute", "fairness", "at_least", "minimum", "basis_points"),
    ("C-PERF-DISK", "absolute", "destination_corruptions", "at_most", "maximum", "count"),
    ("C-PERF-DISK", "absolute", "lost_reservations", "at_most", "maximum", "count"),
    ("C-PERF-DISK", "regression", "throughput_delta", "at_most", "median", "basis_points"),
    ("C-PERF-RESOLVER", "absolute", "corpus_deadline", "at_most", "maximum", "milliseconds"),
    ("C-PERF-RESOLVER", "absolute", "worker_processes", "at_most", "maximum", "count"),
    ("C-PERF-RESOLVER", "absolute", "outstanding_queue", "at_most", "maximum", "count"),
    ("C-PERF-RESOLVER", "absolute", "lost_remainders", "at_most", "maximum", "count"),
    ("C-PERF-RESOLVER", "absolute", "late_mutations", "at_most", "maximum", "count"),
    ("C-PERF-RESOLVER", "regression", "deadline_delta", "at_most", "median", "basis_points"),
    ("C-PERF-PHASE-FAIRNESS", "absolute", "terminal_obligations", "at_least", "minimum", "count"),
    ("C-PERF-PHASE-FAIRNESS", "absolute", "silent_starvation", "at_most", "maximum", "count"),
    ("C-PERF-PHASE-FAIRNESS", "absolute", "unstarted_obligations", "at_most", "maximum", "count"),
    ("C-PERF-PHASE-FAIRNESS", "regression", "completion_time_delta", "at_most", "median", "basis_points"),
)
THRESHOLD_CONTRACTS = (
    QUALITY_THRESHOLD_CONTRACTS
    + RESOURCE_FAULT_THRESHOLD_CONTRACTS
    + PERFORMANCE_THRESHOLD_CONTRACTS
)
THRESHOLD_GATES = (
    "B-HERMETIC-ALL",
    "B-QUALITY",
    "B-COVERAGE",
    "B-STATIC-SECURITY",
    "B-DETERMINISM",
    "C-VULNERABILITY",
    "C-FAULT-DISK",
    "C-FAULT-RESOLVER",
    "C-PERF-RUNNER",
    "C-PERF-INGEST",
    "C-PERF-REPORT",
    "C-PERF-CAMPAIGN",
    "C-PERF-DISK",
    "C-PERF-RESOLVER",
    "C-PERF-PHASE-FAIRNESS",
)

# Every passing obligation has a frozen machine-evidence inventory in addition
# to the canonical ``gate-evidence`` reconciliation report.  The verifier opens
# and rehashes each named object; a signer cannot substitute an opaque root
# assertion for the obligation's documented evidence class.
REQUIRED_ARTIFACTS = {
    "A-IDENTITY": (("identity-verification", "application/json"),),
    "A-TAXONOMY": (("classification-manifest", "application/json"),),
    "A-EVIDENCE-SCHEMA": (
        ("conformance-report", "application/json"),
        ("golden-vectors", "application/json"),
    ),
    "A-CORPUS": (("corpus-disclosure-report", "application/json"),),
    "A-THRESHOLDS": (("threshold-reconciliation", "application/json"),),
    "A-SUPPORT": (("support-reconciliation", "application/json"),),
    "B-HERMETIC-ALL": (
        ("collection-manifest", "application/json"),
        ("isolation-self-test", "application/json"),
        ("test-report", "application/json"),
    ),
    "B-SCHEMA": (("schema-validation-report", "application/json"),),
    "B-MANIFEST": (
        ("corrupt-fixture-matrix", "application/json"),
        ("invariant-report", "application/json"),
    ),
    "B-QUALITY": (("quality-report", "application/json"),),
    "B-COVERAGE": (("coverage-report", "application/json"),),
    "B-STATIC-SECURITY": (("security-findings", "application/json"),),
    "B-DETERMINISM": (("artifact-tree-diff", "application/json"),),
    "B-DOCS-POLICY": (("parity-report", "application/json"),),
    "C-PACKAGE-BUILD": (
        ("build-log", "application/json"),
        ("package-inventory", "application/json"),
        ("sdist", "application/gzip"),
        ("wheel", "application/zip"),
    ),
    "C-PACKAGE-INSTALL": (
        ("install-inventory", "application/json"),
        ("smoke-results", "application/json"),
    ),
    "C-PYTHON-MATRIX": (("python-matrix-report", "application/json"),),
    "C-SBOM": (("sbom", "application/json"),),
    "C-VULNERABILITY": (("vulnerability-findings", "application/json"),),
    "C-PROVENANCE": (
        ("provenance", "application/json"),
        ("signature-verification", "application/json"),
    ),
    "C-INSTALL-ROLLBACK": (
        ("fault-matrix", "application/json"),
        ("filesystem-trace", "application/json"),
    ),
    "C-TOOLS": (("adapter-matrix", "application/json"),),
    "C-OUTPUT-CONTRACT": (("case-matrix", "application/json"),),
    "C-NETWORK-BOUNDARY": (("network-boundary-trace", "application/json"),),
    "C-SOURCE-REGISTRY": (("registry-reconciliation", "application/json"),),
    "C-CORPUS-SYNTHETIC": (
        ("derivation-diff", "application/json"),
        ("disclosure-report", "application/json"),
    ),
    "C-PRIVATE-FILES": (
        ("filesystem-trace", "application/json"),
        ("mode-owner-symlink-matrix", "application/json"),
    ),
    "C-PATH-IDENTITY": (
        ("containment-decisions", "application/json"),
        ("property-corpus", "application/json"),
    ),
    "C-SECRETS": (("canary-matrix", "application/json"), ("sink-scan", "application/json")),
    "C-EXEC-IDENTITY": (
        ("launch-trace", "application/json"),
        ("receipt-reconciliation", "application/json"),
    ),
    "C-ARCHIVE-FETCH": (
        ("activation-trace", "application/json"),
        ("adversarial-matrix", "application/json"),
    ),
    "C-NET-DENY": (("network-denial-report", "application/json"),),
    "C-POLICY-TRACE": (("obligation-reconciliation", "application/json"),),
    "C-FAULT-RUNNER": (("fault-matrix", "application/json"),),
    "C-FAULT-STORE": (("fault-matrix", "application/json"),),
    "C-FAULT-REVISION": (("fault-matrix", "application/json"),),
    "C-FAULT-FINALIZE": (("fault-matrix", "application/json"),),
    "C-FAULT-CAMPAIGN": (("fault-matrix", "application/json"),),
    "C-FAULT-INSTALL": (("fault-matrix", "application/json"),),
    "C-FAULT-DISK": (
        ("fault-matrix", "application/json"),
        ("resource-gate-report", "application/json"),
    ),
    "C-FAULT-RESOLVER": (
        ("fault-matrix", "application/json"),
        ("resource-gate-report", "application/json"),
    ),
    "C-FAULT-INTERRUPT": (("fault-matrix", "application/json"),),
    **{
        gate_id: (
            ("benchmark-baseline", "application/json"),
            ("benchmark-report", "application/json"),
            ("raw-trials", "application/json"),
            *(
                (("resource-gate-report", "application/json"),)
                if gate_id in RESOURCE_REPORT_GATES
                else ()
            ),
            ("trial-invalidations", "application/json"),
        )
        for gate_id in PERFORMANCE_OPERATIONS
    },
    "E-DOCS": (("release-documentation-report", "application/json"),),
    "E-PROJECT-HYGIENE": (("project-hygiene-report", "application/json"),),
    "E-ARTIFACTS": (("publication-subjects", "application/json"),),
}

SCHEMA_PATHS = {
    "aggregate-schema": "release/evidence/schemas/release-aggregate-v1.schema.json",
    "artifact-index-schema": "release/evidence/schemas/artifact-index-v1.schema.json",
    "corpus-selection-schema": "release/evidence/schemas/corpus-selection-v1.schema.json",
    "detached-approval-schema": "release/evidence/schemas/detached-approval-v1.schema.json",
    "gate-artifact-schema": "release/evidence/schemas/gate-artifact-v1.schema.json",
    "aggregator-conformance-manifest-schema": "release/evidence/schemas/aggregator-conformance-manifest-v1.schema.json",
    "gate-evidence-report-schema": "release/evidence/schemas/gate-evidence-report-v1.schema.json",
    "no-live-rule-schema": "release/evidence/schemas/no-live-rule-v1.schema.json",
    "network-boundary-trace-schema": "release/evidence/schemas/network-boundary-trace-v1.schema.json",
    "network-denial-report-schema": "release/evidence/schemas/network-denial-report-v1.schema.json",
    "release-scope-schema": "release/evidence/schemas/release-scope-v1.schema.json",
    "resource-gate-report-schema": "release/evidence/schemas/resource-gate-report-v1.schema.json",
    "signature-envelope-schema": "release/evidence/schemas/signature-envelope-v1.schema.json",
    "support-matrix-schema": "release/evidence/schemas/support-matrix-v1.schema.json",
    "threshold-benchmark-schema": "release/evidence/schemas/threshold-benchmark-v1.schema.json",
    "trust-policy-schema": "release/evidence/schemas/trust-policy-v1.schema.json",
}
SCHEMA_VERSIONS = {
    "aggregate-schema": AGGREGATE_SCHEMA,
    "artifact-index-schema": ARTIFACT_INDEX_SCHEMA,
    "corpus-selection-schema": CORPUS_MANIFEST_SCHEMA,
    "detached-approval-schema": APPROVAL_SCHEMA,
    "gate-artifact-schema": GATE_ARTIFACT_SCHEMA,
    "aggregator-conformance-manifest-schema": CONFORMANCE_MANIFEST_SCHEMA,
    "gate-evidence-report-schema": EVIDENCE_REPORT_SCHEMA,
    "no-live-rule-schema": NO_LIVE_RULE_SCHEMA,
    "network-boundary-trace-schema": NETWORK_BOUNDARY_TRACE_SCHEMA,
    "network-denial-report-schema": NETWORK_DENIAL_REPORT_SCHEMA,
    "release-scope-schema": RELEASE_SCOPE_SCHEMA,
    "resource-gate-report-schema": RESOURCE_GATE_REPORT_SCHEMA,
    "signature-envelope-schema": SIGNATURE_ENVELOPE_SCHEMA,
    "support-matrix-schema": SUPPORT_MATRIX_SCHEMA,
    "threshold-benchmark-schema": THRESHOLD_MANIFEST_SCHEMA,
    "trust-policy-schema": TRUST_POLICY_SCHEMA,
}
MANIFEST_PATHS = {
    "aggregator-conformance-manifest": "release/evidence/aggregator-conformance-v1.json",
    "corpus-selection": "release/evidence/corpus-selection-v1.json",
    "no-live-rule": "release/evidence/no-live-rule-v1.json",
    "support-matrix": "release/evidence/support-matrix-v1.json",
    "threshold-benchmark": "release/evidence/threshold-benchmark-v1.json",
}
SCHEMA_VALIDATION_FIXTURE_MANIFEST_PATH = "release/evidence/schema-validation-fixtures-v1.json"
SCHEMA_VALIDATION_FIXTURE_PATHS = {
    "candidate_identity": "release/evidence/schema-fixtures/candidate-identity-v1.json",
    "gate_record": "release/evidence/schema-fixtures/gate-record-v1.json",
    "schema_registry": "release/evidence/schema-fixtures/schema-registry-v1.json",
}
RUNNER_INPUT_PATHS = dict(evidence.FUTURE_RUNNER_INPUTS)
RUN_MANIFEST_INPUT_PATHS = {
    "run-manifest-schema": "release/evidence/schemas/run-manifest-v1.schema.json",
    "run-manifest-validator": "src/quarry_recon/run_manifest.py",
}
SCOPE_INPUT_PATHS = {
    **SCHEMA_PATHS,
    **MANIFEST_PATHS,
    **RUN_MANIFEST_INPUT_PATHS,
    **RUNNER_INPUT_PATHS,
    "release-contracts-tests": "tests/test_release_contracts.py",
    "release-contracts-validator": "src/quarry_recon/release_contracts.py",
    "resource-gate-report-validator": "src/quarry_recon/resource_contract.py",
    "schema-validation-registry": evidence.REGISTRY_PATH,
    "schema-validation-registry-schema": evidence.SCHEMA_PATHS["schema_registry"],
    "schema-validation-candidate-identity-schema": evidence.SCHEMA_PATHS["candidate_identity"],
    "schema-validation-gate-record-schema": evidence.SCHEMA_PATHS["gate_record"],
    "schema-validation-fixture-manifest": SCHEMA_VALIDATION_FIXTURE_MANIFEST_PATH,
    **{
        f"schema-validation-fixture-{name.replace('_', '-')}": path
        for name, path in SCHEMA_VALIDATION_FIXTURE_PATHS.items()
    },
}
PRODUCTION_TRUST_POLICY_PATH = "release/evidence/trust-policy-v1.json"

_DIGEST_RE = evidence._DIGEST_RE
_TOKEN_RE = evidence._TOKEN_RE
_GATE_ID_RE = evidence._GATE_ID_RE
_MEDIA_TYPE_RE = evidence._MEDIA_TYPE_RE
_DOCUMENT_BYTES = evidence.MAX_RECORD_BYTES
_BUILD_LOG_OUTPUT_BYTES = 65_536
_INSTALL_OUTPUT_BYTES = 65_536
_INSTALL_FILE_COUNT = 2_000
_INSTALL_FILE_BYTES = 64 * 1024 * 1024
_INSTALL_CASE_ROSTER = (
    "import", "packaged-data", "absolute-installed-cli", "checkout-isolation",
)
_CLEAN_BUILD_COMMAND = (
    "python", "-m", "build", "--sdist", "--wheel", "--outdir", "dist",
)
_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)
_ED25519_B_Y = (4 * pow(5, _ED25519_P - 2, _ED25519_P)) % _ED25519_P


def raw_sha256(data: bytes) -> str:
    """Return the raw-byte digest used by input and artifact bindings."""
    if type(data) is not bytes:
        raise evidence.EvidenceError("raw digest input must be exact bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _object(value: object, name: str, members: Iterable[str]) -> dict:
    expected = set(members)
    if type(value) is not dict:
        raise evidence.EvidenceError(f"{name} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise evidence.EvidenceError(f"{name} has invalid members (missing {missing}; unknown {unknown})")
    return value


def _array(value: object, name: str) -> list:
    if type(value) is not list:
        raise evidence.EvidenceError(f"{name} must be an array")
    return value


def _string(value: object, name: str, *, empty: bool = False) -> str:
    if type(value) is not str or (not empty and not value) or any(ord(char) < 0x20 for char in value):
        raise evidence.EvidenceError(f"{name} must be a control-free string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise evidence.EvidenceError(f"{name} must be valid Unicode") from exc
    return value


def _token(value: object, name: str) -> str:
    text = _string(value, name)
    if _TOKEN_RE.fullmatch(text) is None:
        raise evidence.EvidenceError(f"{name} must be a stable token")
    return text


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise evidence.EvidenceError(f"{name} must be a lowercase sha256: digest")
    return value


def _integer(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= evidence.MAX_JSON_INTEGER:
        raise evidence.EvidenceError(f"{name} must be an exact non-negative integer")
    return value


def _timestamp(value: object, name: str) -> datetime:
    return evidence._timestamp(value, name)


def _path(value: object, name: str) -> str:
    text = _string(value, name)
    if "\\" in text or PureWindowsPath(text).is_absolute():
        raise evidence.EvidenceError(f"{name} must be a normalized relative POSIX path")
    pure = PurePosixPath(text)
    if pure.is_absolute() or text != pure.as_posix() or any(part in {"", ".", ".."} for part in pure.parts):
        raise evidence.EvidenceError(f"{name} must be a normalized relative POSIX path")
    return text


def _absolute_posix_path(value: object, name: str) -> str:
    """Accept a lexical, canonical POSIX absolute path without touching disk."""
    text = _string(value, name)
    if "\\" in text or PureWindowsPath(text).is_absolute():
        raise evidence.EvidenceError(f"{name} must be a canonical absolute POSIX path")
    pure = PurePosixPath(text)
    if (not pure.is_absolute() or text != pure.as_posix() or len(pure.parts) < 2 or
            any(part in {"", ".", ".."} for part in pure.parts)):
        raise evidence.EvidenceError(f"{name} must be a canonical absolute POSIX path")
    return text


def _is_within_path(path: str, parent: str) -> bool:
    """Return lexical strict ancestry; validation deliberately never reads paths."""
    path_parts = PurePosixPath(path).parts
    parent_parts = PurePosixPath(parent).parts
    return len(path_parts) > len(parent_parts) and path_parts[:len(parent_parts)] == parent_parts


def _unique(records: Sequence[dict], key: str, name: str, *, ordered: bool = True) -> None:
    values = [record[key] for record in records]
    if len(values) != len(set(values)):
        raise evidence.EvidenceError(f"{name} contains duplicate {key} values")
    if ordered and values != sorted(values):
        raise evidence.EvidenceError(f"{name} must be sorted by {key}")


def _review(value: object, name: str) -> dict | None:
    if value is None:
        return None
    item = _object(value, name, {"approved_at", "review_id", "reviewer", "signature"})
    _timestamp(item["approved_at"], f"{name}.approved_at")
    _token(item["review_id"], f"{name}.review_id")
    _token(item["reviewer"], f"{name}.reviewer")
    if item["signature"] is not None:
        signature = _object(item["signature"], f"{name}.signature", {
            "algorithm", "key_id", "value",
        })
        if signature["algorithm"] != "ed25519":
            raise evidence.EvidenceError(f"{name}.signature algorithm is unsupported")
        _token(signature["key_id"], f"{name}.signature.key_id")
        _base64(signature["value"], f"{name}.signature.value", size=64)
    return item


def _canonical_reader(data: bytes, name: str) -> object:
    if type(data) is not bytes or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise evidence.EvidenceError(f"{name} must end in exactly one LF")
    document = evidence.load_json_bytes(data[:-1], maximum=_DOCUMENT_BYTES)
    if data != evidence.canonical_json_bytes(document) + b"\n":
        raise evidence.EvidenceError(f"{name} is not the exact canonical JSON-line byte representation")
    return document


def canonical_json_line(document: object) -> bytes:
    """Return the sole file representation for v1 contract/evidence JSON."""
    return evidence.canonical_json_bytes(document) + b"\n"


_CONFORMANCE_CASES = (
    ("positive-aggregate-verify", "positive", None),
    ("missing-record", "error", "missing-record"),
    ("duplicate-gate", "error", "duplicate-gate"),
    ("wrong-candidate", "error", "wrong-candidate"),
    ("malformed-schema", "error", "malformed-schema"),
    ("invalid-signature", "error", "invalid-signature"),
    ("expired-disposition", "error", "expired-disposition"),
    ("unexpected-skip", "error", "unexpected-skip"),
    ("conflicting-result", "error", "conflicting-result"),
)
_CONFORMANCE_TEST_PATH = "tests/test_release_contracts.py"
_CONFORMANCE_TEST_NODEID = (
    "tests/test_release_contracts.py::TestArtifactsAndAggregation::"
    "test_evidence_schema_manifest_and_report_reconcile_actual_public_cases"
)


def conformance_error_digest(code: str) -> str:
    """Address one stable public conformance failure code canonically."""
    _token(code, "conformance error code")
    return evidence.canonical_digest({"error_code": code})


def normalized_conformance_error_digest(exc: BaseException) -> str:
    """Normalize the stable public refusal families used by the golden vectors."""
    if not isinstance(exc, evidence.EvidenceError):
        raise evidence.EvidenceError("conformance outcome is not a release evidence refusal")
    message = str(exc)
    if message.startswith("aggregate record inventory mismatch"):
        code = "duplicate-gate" if "duplicate ['" in message else "missing-record"
    elif "does not match the exact candidate identity" in message:
        code = "wrong-candidate"
    elif message.startswith("unsupported gate schema"):
        code = "malformed-schema"
    elif message.startswith("ed25519 signature"):
        code = "invalid-signature"
    elif "scope rule expired" in message:
        code = "expired-disposition"
    elif "not_applicable gate needs" in message:
        code = "unexpected-skip"
    elif message == "release aggregate status conflicts with the selected disposition":
        code = "conflicting-result"
    else:
        raise evidence.EvidenceError("conformance refusal has no registered normalized error code")
    return conformance_error_digest(code)


def validate_aggregator_conformance_manifest(document: object) -> dict:
    """Validate the candidate-independent, fixed v1 conformance roster."""
    doc = _object(document, "aggregator conformance manifest", {
        "cases", "release", "schema_version",
    })
    _schema(doc, CONFORMANCE_MANIFEST_SCHEMA, "aggregator conformance manifest")
    cases = _array(doc["cases"], "aggregator conformance manifest.cases")
    expected = [
        {
            "id": case_id,
            "kind": kind,
            "error_code": error_code,
            "test_nodeid": _CONFORMANCE_TEST_NODEID,
            "test_path": _CONFORMANCE_TEST_PATH,
        }
        for case_id, kind, error_code in _CONFORMANCE_CASES
    ]
    if cases != expected:
        raise evidence.EvidenceError("aggregator conformance manifest has the wrong case roster or order")
    return doc


def read_aggregator_conformance_manifest(data: bytes) -> dict:
    return validate_aggregator_conformance_manifest(
        _canonical_reader(data, "aggregator conformance manifest")
    )


def _schema(document: dict, expected: str, name: str) -> None:
    if document["schema_version"] != expected:
        raise evidence.EvidenceError(f"unsupported {name} schema {document['schema_version']!r}")
    if document["release"] != RELEASE:
        raise evidence.EvidenceError(f"{name}.release must be exactly {RELEASE!r}")


def _approved(document: dict, name: str) -> None:
    if document["approval"] is None:
        raise evidence.EvidenceError(f"{name} is a draft and has no accepted review")


def _expected_obligations() -> list[dict]:
    records = []
    for gate_id, collector, lanes in OBLIGATION_CONTRACTS:
        selected = gate_id not in UNSELECTED_CORPUS_GATES
        operation = gate_id in {"E-AGGREGATE", "E-APPROVAL"}
        disposition = (
            "operation" if operation else
            "unselected" if not selected else
            "required_not_applicable" if gate_id in LIVE_GATES else
            "required_pass"
        )
        records.append({
            "collector_lane": collector,
            "disposition": disposition,
            "id": gate_id,
            "phase": gate_id[0],
            "record_producing": not operation,
            "required_evidence_lanes": list(lanes),
            "selected": selected,
        })
    return records


def build_release_scope(input_bodies: Mapping[str, bytes], *, approval: object = None) -> dict:
    """Build the sole v1 scope payload from the exact tracked input bytes."""
    if not isinstance(input_bodies, Mapping) or any(type(key) is not str for key in input_bodies):
        raise evidence.EvidenceError("scope input bodies must be a name-to-bytes mapping")
    if set(input_bodies) != set(SCOPE_INPUT_PATHS):
        raise evidence.EvidenceError("scope builder input bodies do not match the exact v1 input set")
    bindings = []
    for name, path in sorted(SCOPE_INPUT_PATHS.items()):
        body = input_bodies[name]
        if type(body) is not bytes:
            raise evidence.EvidenceError("scope builder input bodies must be exact bytes")
        bindings.append({"digest": raw_sha256(body), "name": name, "path": path})
    record_inputs = sorted(
        [record["name"] for record in bindings]
        + ["candidate-identity", "production-trust-policy", "release-scope"]
    )
    document = {
        "approval": approval,
        "input_bindings": bindings,
        "obligations": _expected_obligations(),
        "production_trust_policy": {
            "digest": None,
            "name": "production-trust-policy",
            "path": PRODUCTION_TRUST_POLICY_PATH,
            "required_before_nomination": True,
        },
        "record_inputs": record_inputs,
        "release": RELEASE,
        "schema_version": RELEASE_SCOPE_SCHEMA,
        "selected_record_slots": list(SELECTED_RECORD_SLOTS),
        "stages": [
            {
                "depends_on": [],
                "id": "preaggregate",
                "inputs": list(SELECTED_RECORD_SLOTS),
                "output": "verified-record-set",
            },
            {
                "depends_on": ["preaggregate"],
                "id": "aggregate",
                "inputs": ["verified-record-set"],
                "output": "E-AGGREGATE",
            },
            {
                "depends_on": ["aggregate"],
                "id": "approval",
                "inputs": ["E-AGGREGATE"],
                "output": "E-APPROVAL",
            },
        ],
    }
    return validate_release_scope(document)


def validate_release_scope(
    document: object, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    """Validate the exact v0.3.10 universe and synthetic-only selection."""
    doc = _object(document, "release scope", {
        "approval", "input_bindings", "obligations", "production_trust_policy",
        "record_inputs", "release", "schema_version", "selected_record_slots", "stages",
    })
    _schema(doc, RELEASE_SCOPE_SCHEMA, "release scope")
    _review(doc["approval"], "release scope.approval")

    bindings = _array(doc["input_bindings"], "release scope.input_bindings")
    for index, record in enumerate(bindings):
        item = _object(record, f"release scope.input_bindings[{index}]", {"digest", "name", "path"})
        _token(item["name"], f"release scope.input_bindings[{index}].name")
        _path(item["path"], f"release scope.input_bindings[{index}].path")
        _digest(item["digest"], f"release scope.input_bindings[{index}].digest")
    _unique(bindings, "name", "release scope.input_bindings")
    if {item["name"]: item["path"] for item in bindings} != SCOPE_INPUT_PATHS:
        raise evidence.EvidenceError("release scope input bindings are not the exact v1 input set")

    trust = _object(doc["production_trust_policy"], "release scope.production_trust_policy", {
        "digest", "name", "path", "required_before_nomination",
    })
    if trust != {
        "digest": None,
        "name": "production-trust-policy",
        "path": PRODUCTION_TRUST_POLICY_PATH,
        "required_before_nomination": True,
    }:
        raise evidence.EvidenceError("release scope must leave the production trust root explicitly pending")

    expected_record_inputs = [item["name"] for item in bindings] + [
        "candidate-identity", "production-trust-policy", "release-scope",
    ]
    expected_record_inputs.sort()
    if doc["record_inputs"] != expected_record_inputs:
        raise evidence.EvidenceError("release scope record_inputs must bind the exact frozen input set")

    expected_obligations = _expected_obligations()
    if doc["obligations"] != expected_obligations:
        raise evidence.EvidenceError("release scope obligations do not match the exact 64-row universe")
    if len(RECORD_UNIVERSE) != 62 or len(SELECTED_RECORD_SLOTS) != 56:
        raise evidence.EvidenceError("internal release obligation cardinality drift")
    if doc["selected_record_slots"] != list(SELECTED_RECORD_SLOTS):
        raise evidence.EvidenceError("release scope selected slots are not the exact synthetic-only 56")

    expected_stages = [
        {"depends_on": [], "id": "preaggregate", "inputs": list(SELECTED_RECORD_SLOTS),
         "output": "verified-record-set"},
        {"depends_on": ["preaggregate"], "id": "aggregate", "inputs": ["verified-record-set"],
         "output": "E-AGGREGATE"},
        {"depends_on": ["aggregate"], "id": "approval", "inputs": ["E-AGGREGATE"],
         "output": "E-APPROVAL"},
    ]
    if doc["stages"] != expected_stages:
        raise evidence.EvidenceError("release scope stages must be the acyclic preaggregate/aggregate/approval plan")
    _validate_stage_graph(doc["stages"])
    if require_ready:
        _approved(doc, "release scope")
        if trust_policy is None:
            raise evidence.EvidenceError(
                "production trust policy authority is unresolved before nomination"
            )
        verify_contract_review(
            doc, policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
        )
    return doc


def _validate_stage_graph(stages: object) -> None:
    records = _array(stages, "release scope.stages")
    ids = []
    outputs = set()
    completed = set()
    for index, record in enumerate(records):
        item = _object(record, f"release scope.stages[{index}]", {"depends_on", "id", "inputs", "output"})
        stage_id = _token(item["id"], f"release scope.stages[{index}].id")
        dependencies = _array(item["depends_on"], f"release scope.stages[{index}].depends_on")
        if any(type(member) is not str for member in dependencies) or len(set(dependencies)) != len(dependencies):
            raise evidence.EvidenceError("release scope stage dependencies must be unique strings")
        if not set(dependencies).issubset(completed):
            raise evidence.EvidenceError("release scope stage graph has a forward edge or cycle")
        output = _string(item["output"], f"release scope.stages[{index}].output")
        if output in outputs:
            raise evidence.EvidenceError("release scope stages have conflicting outputs")
        outputs.add(output)
        completed.add(stage_id)
        ids.append(stage_id)
    if len(ids) != len(set(ids)):
        raise evidence.EvidenceError("release scope stages contain duplicate ids")


def read_release_scope(
    data: bytes, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_release_scope(
        _canonical_reader(data, "release scope"),
        require_ready=require_ready,
        trust_policy=trust_policy,
        trusted_policy_digest=trusted_policy_digest,
    )


def validate_support_matrix(
    document: object, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    doc = _object(document, "support matrix", {
        "aggregators", "approval", "environments", "release", "schema_version",
        "template_sets", "tools",
    })
    _schema(doc, SUPPORT_MATRIX_SCHEMA, "support matrix")
    _review(doc["approval"], "support matrix.approval")
    environments = _array(doc["environments"], "support matrix.environments")
    environment_keys = []
    for index, record in enumerate(environments):
        item = _object(record, f"support matrix.environments[{index}]", {
            "architecture", "isolation_profile", "lane", "os", "python", "runner_image",
        })
        if item["lane"] not in LANE_ORDER or item["lane"] == "L0-authorized-live":
            raise evidence.EvidenceError("support matrix environment lane is unsupported")
        for field in ("architecture", "os", "python"):
            _token(item[field], f"support matrix environment {field}")
        for field in ("isolation_profile", "runner_image"):
            if item[field] is not None:
                _digest(item[field], f"support matrix environment {field}")
        environment_keys.append((
            LANE_ORDER.index(item["lane"]), item["os"], item["architecture"], item["python"],
        ))
    if not environments or environment_keys != sorted(environment_keys) or \
            len(environment_keys) != len(set(environment_keys)):
        raise evidence.EvidenceError("support matrix environments must be non-empty, sorted and unique")
    required_lanes = {
        lane for gate, _collector, lanes in OBLIGATION_CONTRACTS
        if gate in SELECTED_RECORD_SLOTS and gate not in LIVE_GATES for lane in lanes
    }
    if {row["lane"] for row in environments} != required_lanes:
        raise evidence.EvidenceError("support matrix does not cover the exact selected evidence lanes")

    aggregators = _array(doc["aggregators"], "support matrix.aggregators")
    aggregator_keys = []
    for index, record in enumerate(aggregators):
        item = _object(record, f"support matrix.aggregators[{index}]", {
            "architecture", "executable_digest", "implementation", "isolation_profile",
            "os", "python", "runner_image",
        })
        for field in ("architecture", "implementation", "os", "python"):
            _token(item[field], f"support matrix aggregator {field}")
        for field in ("executable_digest", "isolation_profile", "runner_image"):
            if item[field] is not None:
                _digest(item[field], f"support matrix aggregator {field}")
        aggregator_keys.append((
            item["os"], item["architecture"], item["implementation"], item["python"],
        ))
    if not aggregators or aggregator_keys != sorted(aggregator_keys) or \
            len(aggregator_keys) != len(set(aggregator_keys)):
        raise evidence.EvidenceError("support matrix aggregators must be non-empty, sorted and unique")

    for field in ("tools", "template_sets"):
        records = _array(doc[field], f"support matrix.{field}")
        for index, record in enumerate(records):
            item = _object(record, f"support matrix.{field}[{index}]", {"digest", "name", "version"})
            _token(item["name"], f"support matrix.{field}[{index}].name")
            _string(item["version"], f"support matrix.{field}[{index}].version")
            _digest(item["digest"], f"support matrix.{field}[{index}].digest")
        _unique(records, "name", f"support matrix.{field}")
    if require_ready:
        _approved(doc, "support matrix")
        if trust_policy is None:
            raise evidence.EvidenceError("support matrix has no external review authority")
        verify_contract_review(
            doc, policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
        )
        if (not doc["tools"] or not doc["template_sets"] or
                any(row["runner_image"] is None or row["isolation_profile"] is None
                    for row in environments) or
                any(row["runner_image"] is None or row["isolation_profile"] is None or
                    row["executable_digest"] is None for row in aggregators)):
            raise evidence.EvidenceError(
                "support matrix has unresolved runtime, tool or template-set identities"
            )
    return doc


def read_support_matrix(
    data: bytes, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_support_matrix(
        _canonical_reader(data, "support matrix"), require_ready=require_ready,
        trust_policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
    )


def validate_threshold_manifest(
    document: object, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    doc = _object(document, "threshold manifest", {
        "approval", "benchmarks", "release", "schema_version", "thresholds",
    })
    _schema(doc, THRESHOLD_MANIFEST_SCHEMA, "threshold manifest")
    _review(doc["approval"], "threshold manifest.approval")
    benchmarks = _array(doc["benchmarks"], "threshold manifest.benchmarks")
    if [row.get("gate_id") if type(row) is dict else None for row in benchmarks] != \
            list(PERFORMANCE_OPERATIONS):
        raise evidence.EvidenceError("benchmark manifest must cover every performance gate in order")
    for index, record in enumerate(benchmarks):
        item = _object(record, f"threshold manifest.benchmarks[{index}]", {
            "concurrency", "fixture_digest", "gate_id", "invalidation_policy", "operation",
            "repetitions", "resource_limits", "runner_class", "tool_digests",
            "trial_retention", "warmup_runs",
        })
        if item["operation"] != PERFORMANCE_OPERATIONS[item["gate_id"]]:
            raise evidence.EvidenceError("benchmark operation does not match its frozen gate contract")
        if item["invalidation_policy"] != "record-and-rerun-complete-trial-set" or \
                item["trial_retention"] != "all-raw-trials":
            raise evidence.EvidenceError("benchmark trial retention/invalidation policy is not canonical")
        if item["fixture_digest"] is not None:
            _digest(item["fixture_digest"], "benchmark fixture digest")
        if item["runner_class"] is not None:
            _token(item["runner_class"], "benchmark runner class")
        for field in ("concurrency", "repetitions", "warmup_runs"):
            if item[field] is not None:
                _integer(item[field], f"benchmark {field}")
        if item["repetitions"] is not None and item["repetitions"] > 1000:
            raise evidence.EvidenceError("benchmark repetitions exceed the canonical trial-id space")
        limits = _object(item["resource_limits"], "benchmark resource_limits", {
            "cpu_millicores", "disk_bytes", "memory_bytes",
        })
        for field, value in limits.items():
            if value is not None:
                _integer(value, f"benchmark resource_limits.{field}")
        tools = _array(item["tool_digests"], "benchmark tool_digests")
        for digest in tools:
            _digest(digest, "benchmark tool digest")
        if tools != sorted(set(tools)):
            raise evidence.EvidenceError("benchmark tool digests must be sorted and unique")

    thresholds = _array(doc["thresholds"], "threshold manifest.thresholds")
    observed_contracts = []
    for index, record in enumerate(thresholds):
        item = _object(record, f"threshold manifest.thresholds[{index}]", {
            "baseline_digest", "class", "gate_id", "limit", "metric", "operator",
            "statistic", "unit",
        })
        for field in ("metric", "unit"):
            _token(item[field], f"threshold manifest.thresholds[{index}].{field}")
        if item["class"] not in {"absolute", "regression"} or \
                item["operator"] not in {"at_least", "at_most"} or \
                item["statistic"] not in {"maximum", "median", "minimum", "p95"}:
            raise evidence.EvidenceError("threshold class, operator or statistic is unsupported")
        if item["limit"] is not None:
            _integer(item["limit"], f"threshold manifest.thresholds[{index}].limit")
        if item["baseline_digest"] is not None:
            _digest(item["baseline_digest"], "threshold baseline digest")
        if item["class"] == "absolute" and item["baseline_digest"] is not None:
            raise evidence.EvidenceError("absolute threshold must not name a regression baseline")
        observed_contracts.append((
            item["gate_id"], item["class"], item["metric"], item["operator"],
            item["statistic"], item["unit"],
        ))
    if observed_contracts != list(THRESHOLD_CONTRACTS):
        raise evidence.EvidenceError("threshold rows do not match the complete frozen metric contract")
    if require_ready:
        _approved(doc, "threshold manifest")
        if trust_policy is None:
            raise evidence.EvidenceError("threshold manifest has no external review authority")
        verify_contract_review(
            doc, policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
        )
        if any(record["limit"] is None for record in thresholds) or any(
            record["class"] == "regression" and record["baseline_digest"] is None
            for record in thresholds
        ):
            raise evidence.EvidenceError("threshold manifest has unresolved numeric/baseline limits")
        for benchmark in benchmarks:
            if (benchmark["fixture_digest"] is None or benchmark["runner_class"] is None or
                    not benchmark["tool_digests"] or benchmark["concurrency"] in {None, 0} or
                    benchmark["repetitions"] in {None, 0} or benchmark["warmup_runs"] is None or
                    any(value in {None, 0} for value in benchmark["resource_limits"].values())):
                raise evidence.EvidenceError("benchmark manifest has unresolved execution context")
    return doc


def read_threshold_manifest(
    data: bytes, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_threshold_manifest(
        _canonical_reader(data, "threshold manifest"), require_ready=require_ready,
        trust_policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
    )


def validate_corpus_manifest(
    document: object, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    doc = _object(document, "corpus manifest", {
        "approval", "release", "schema_version", "sources",
    })
    _schema(doc, CORPUS_MANIFEST_SCHEMA, "corpus manifest")
    _review(doc["approval"], "corpus manifest.approval")
    sources = _array(doc["sources"], "corpus manifest.sources")
    if [source.get("gate_id") if type(source) is dict else None for source in sources] != list(CORPUS_GATES):
        raise evidence.EvidenceError("corpus manifest must contain all seven corpus gates in canonical order")
    for index, source in enumerate(sources):
        item = _object(source, f"corpus manifest.sources[{index}]", {
            "attestation_digest", "fixture_digest", "gate_id", "kind", "selected",
        })
        expected_kind = "synthetic" if item["gate_id"] == "C-CORPUS-SYNTHETIC" else "private"
        if item["kind"] != expected_kind or type(item["selected"]) is not bool:
            raise evidence.EvidenceError("corpus source kind/selection is invalid")
        expected_selected = item["gate_id"] in SELECTED_CORPUS_GATES
        if item["selected"] is not expected_selected:
            raise evidence.EvidenceError("v0.3.10 public scope must select only the synthetic corpus")
        for field in ("attestation_digest", "fixture_digest"):
            if item[field] is not None:
                _digest(item[field], f"corpus manifest.sources[{index}].{field}")
        if expected_kind == "private" and (
            item["attestation_digest"] is not None or item["fixture_digest"] is not None
        ):
            raise evidence.EvidenceError("unselected private corpus identities must not enter public scope")
    if require_ready:
        _approved(doc, "corpus manifest")
        if trust_policy is None:
            raise evidence.EvidenceError("corpus manifest has no external review authority")
        verify_contract_review(
            doc, policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
        )
        synthetic = sources[-1]
        if synthetic["fixture_digest"] is None or synthetic["attestation_digest"] is None:
            raise evidence.EvidenceError(
                "selected synthetic corpus has no frozen fixture and attestation identities"
            )
    return doc


def read_corpus_manifest(
    data: bytes, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_corpus_manifest(
        _canonical_reader(data, "corpus manifest"), require_ready=require_ready,
        trust_policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
    )


def validate_no_live_rule(
    document: object, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    doc = _object(document, "no-live rule", {
        "approval", "expires_at", "gates", "live_required", "rationale", "release", "rule_id",
        "schema_version",
    })
    _schema(doc, NO_LIVE_RULE_SCHEMA, "no-live rule")
    if doc["rule_id"] != "v310-no-live":
        raise evidence.EvidenceError("no-live rule id is not canonical")
    if doc["live_required"] is not False or doc["gates"] != list(LIVE_GATES):
        raise evidence.EvidenceError("no-live rule must omit live execution for all four Phase D gates")
    _string(doc["rationale"], "no-live rule.rationale")
    expires = None
    if doc["expires_at"] is not None:
        expires = _timestamp(doc["expires_at"], "no-live rule.expires_at")
    approval = _review(doc["approval"], "no-live rule.approval")
    if approval is not None and expires is not None and \
            expires <= _timestamp(approval["approved_at"], "no-live rule.approval.approved_at"):
        raise evidence.EvidenceError("no-live rule expires before its approval can take effect")
    if require_ready:
        _approved(doc, "no-live rule")
        if trust_policy is None:
            raise evidence.EvidenceError("no-live rule has no external review authority")
        verify_contract_review(
            doc, policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
        )
    return doc


def read_no_live_rule(
    data: bytes, *, require_ready: bool = False, trust_policy: object | None = None,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_no_live_rule(
        _canonical_reader(data, "no-live rule"), require_ready=require_ready,
        trust_policy=trust_policy, trusted_policy_digest=trusted_policy_digest,
    )


def validate_artifact_index(document: object, *, identity: object) -> dict:
    """Validate the complete immutable artifact inventory for one candidate."""
    candidate = evidence.validate_candidate_identity(identity)
    doc = _object(document, "artifact index", {
        "artifacts", "candidate_identity_digest", "release", "schema_version",
    })
    _schema(doc, ARTIFACT_INDEX_SCHEMA, "artifact index")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(candidate):
        raise evidence.EvidenceError("artifact index does not bind the exact candidate identity")
    records = _array(doc["artifacts"], "artifact index.artifacts")
    keys = []
    paths = []
    for index, record in enumerate(records):
        item = _object(record, f"artifact index.artifacts[{index}]", {
            "digest", "gate_id", "media_type", "name", "path", "size",
        })
        gate_id = _string(item["gate_id"], f"artifact index.artifacts[{index}].gate_id")
        if _GATE_ID_RE.fullmatch(gate_id) is None or gate_id not in RECORD_UNIVERSE:
            raise evidence.EvidenceError("artifact index contains an unknown or noncanonical gate id")
        name = _token(item["name"], f"artifact index.artifacts[{index}].name")
        _path(item["path"], f"artifact index.artifacts[{index}].path")
        _digest(item["digest"], f"artifact index.artifacts[{index}].digest")
        _integer(item["size"], f"artifact index.artifacts[{index}].size")
        if type(item["media_type"]) is not str or _MEDIA_TYPE_RE.fullmatch(item["media_type"]) is None:
            raise evidence.EvidenceError("artifact index media type is invalid")
        keys.append((gate_id, name))
        paths.append(item["path"])
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise evidence.EvidenceError("artifact index must be sorted and unique by gate_id/name")
    if len(paths) != len(set(paths)):
        raise evidence.EvidenceError("artifact index contains a conflicting reused path")
    return doc


def read_artifact_index(data: bytes, *, identity: object) -> dict:
    return validate_artifact_index(_canonical_reader(data, "artifact index"), identity=identity)


class ArtifactResolver:
    """Descriptor-relative, no-follow resolver for one validated artifact index.

    One root descriptor is pinned for the resolver lifetime and every artifact
    is opened relative to it.  Paths are never authorized by a prior string
    resolution or stat.
    """

    def __init__(self, root: str | os.PathLike[str], index: object, *, identity: object):
        raw_root = os.fspath(root)
        if type(raw_root) is not str:
            raise evidence.EvidenceError("artifact root must be a native text path")
        root_path = Path(raw_root)
        if (not root_path.is_absolute() or raw_root != root_path.as_posix() or
                len(root_path.parts) < 2 or any(part in {".", ".."} for part in root_path.parts)):
            raise evidence.EvidenceError("artifact root must be a normalized absolute path")
        if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY") or
                os.open not in os.supports_dir_fd):
            raise evidence.EvidenceError("artifact resolver requires no-follow directory descriptors")
        self._root = root_path
        try:
            snapshot_body = canonical_json_line(index)
        except evidence.EvidenceError:
            raise
        except (RuntimeError, TypeError, ValueError) as exc:
            raise evidence.EvidenceError("cannot snapshot artifact index") from exc
        snapshot = _canonical_reader(snapshot_body, "artifact index snapshot")
        validated = validate_artifact_index(snapshot, identity=identity)
        if canonical_json_line(validated) != snapshot_body:
            raise evidence.EvidenceError("artifact index changed while it was being validated")
        frozen = _canonical_reader(snapshot_body, "artifact index snapshot")
        records = tuple(MappingProxyType(dict(record)) for record in frozen["artifacts"])
        self._records = MappingProxyType({
            (record["gate_id"], record["name"]): record
            for record in records
        })
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        descriptor = None
        try:
            descriptor = os.open("/", flags)
            for part in root_path.parts[1:]:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            self._root_fd: int | None = descriptor
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise evidence.EvidenceError(f"cannot securely open artifact root: {exc}") from exc

    def close(self) -> None:
        """Release the pinned root descriptor; repeated closes are harmless."""
        if self._root_fd is not None:
            descriptor = self._root_fd
            self._root_fd = None
            try:
                os.close(descriptor)
            except OSError as exc:
                raise evidence.EvidenceError(f"cannot close artifact root descriptor: {exc}") from exc

    def __enter__(self) -> ArtifactResolver:
        if self._root_fd is None:
            raise evidence.EvidenceError("artifact resolver is closed")
        return self

    def __exit__(self, exc_type: object, _exc: object, _traceback: object) -> None:
        try:
            self.close()
        except evidence.EvidenceError:
            if exc_type is None:
                raise

    def __del__(self) -> None:  # pragma: no cover - defensive descriptor cleanup
        try:
            self.close()
        except (AttributeError, evidence.EvidenceError):
            pass

    def keys(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._records)

    def _record(self, gate_id: str, name: str) -> Mapping[str, object]:
        try:
            return self._records[(gate_id, name)]
        except KeyError as exc:
            raise evidence.EvidenceError(f"unknown artifact {gate_id}/{name}") from exc

    def record(self, gate_id: str, name: str) -> dict:
        """Return a defensive copy of one immutable, validated index row."""
        return dict(self._record(gate_id, name))

    def _consume(self, gate_id: str, name: str, *, capture: bool) -> bytes | None:
        record = self._record(gate_id, name)
        if capture and record["size"] > _DOCUMENT_BYTES:
            raise evidence.EvidenceError("artifact is too large for a bounded in-memory read")
        if self._root_fd is None:
            raise evidence.EvidenceError("artifact resolver is closed")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        opened: list[int] = []
        parent_fds: list[int] = []
        try:
            descriptor = self._root_fd
            parts = PurePosixPath(record["path"]).parts
            for part in parts[:-1]:
                child = os.open(part, flags | nofollow, dir_fd=descriptor)
                opened.append(child)
                parent_fds.append(child)
                descriptor = child
            file_flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                          getattr(os, "O_NONBLOCK", 0) | nofollow)
            file_fd = os.open(parts[-1], file_flags, dir_fd=descriptor)
            opened.append(file_fd)
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise evidence.EvidenceError("artifact must be a single-link regular file")
            if before.st_size != record["size"]:
                raise evidence.EvidenceError("artifact size does not match its index")
            body = bytearray() if capture else None
            hasher = hashlib.sha256()
            consumed = 0
            while consumed < before.st_size:
                chunk = os.read(file_fd, min(1024 * 1024, before.st_size - consumed))
                if not chunk:
                    break
                hasher.update(chunk)
                consumed += len(chunk)
                if body is not None:
                    body.extend(chunk)
            if os.read(file_fd, 1):
                raise evidence.EvidenceError("artifact grew while it was being verified")
            after = os.fstat(file_fd)
            signature = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            )
            path_signature = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            )
            if signature(before) != signature(after):
                raise evidence.EvidenceError("artifact identity changed while it was being verified")
            check_descriptor = os.open("/", flags | nofollow)
            opened.append(check_descriptor)
            for part in self._root.parts[1:]:
                child = os.open(part, flags | nofollow, dir_fd=check_descriptor)
                opened.append(child)
                check_descriptor = child
            if path_signature(os.fstat(check_descriptor)) != \
                    path_signature(os.fstat(self._root_fd)):
                raise evidence.EvidenceError("artifact root path changed while it was being verified")
            for index, part in enumerate(parts[:-1]):
                child = os.open(part, flags | nofollow, dir_fd=check_descriptor)
                opened.append(child)
                check_descriptor = child
                if path_signature(os.fstat(child)) != path_signature(os.fstat(parent_fds[index])):
                    raise evidence.EvidenceError(
                        "artifact ancestor path changed while it was being verified"
                    )
            check_fd = os.open(parts[-1], file_flags, dir_fd=check_descriptor)
            opened.append(check_fd)
            if signature(os.fstat(check_fd)) != signature(after):
                raise evidence.EvidenceError("artifact path changed while it was being verified")
            observed_digest = "sha256:" + hasher.hexdigest()
            if consumed != record["size"] or observed_digest != record["digest"]:
                raise evidence.EvidenceError("artifact raw bytes do not match its index")
            return None if body is None else bytes(body)
        except OSError as exc:
            raise evidence.EvidenceError(f"cannot securely open artifact {gate_id}/{name}: {exc}") from exc
        finally:
            for fd in reversed(opened):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def read(self, gate_id: str, name: str) -> bytes:
        """Rehash and return one bounded artifact's exact bytes."""
        body = self._consume(gate_id, name, capture=True)
        if body is None:  # pragma: no cover - internal capture invariant
            raise evidence.EvidenceError("artifact resolver did not retain a requested body")
        return body

    def verify(self, gate_id: str, name: str) -> dict:
        """Stream-rehash one artifact without retaining its bytes in memory."""
        self._consume(gate_id, name, capture=False)
        return self.record(gate_id, name)

    def verify_all(self) -> dict[tuple[str, str], dict]:
        return {key: self.verify(*key) for key in self.keys()}


def _base64(value: object, name: str, *, size: int) -> bytes:
    text = _string(value, name)
    if not text.startswith("base64:"):
        raise evidence.EvidenceError(f"{name} must use the base64: encoding label")
    try:
        decoded = base64.b64decode(text[7:], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise evidence.EvidenceError(f"{name} is not canonical base64") from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != text[7:]:
        raise evidence.EvidenceError(f"{name} must contain exactly {size} canonical bytes")
    return decoded


def _bounded_base64(value: object, name: str, *, maximum: int) -> bytes:
    """Read canonical base64 retained output without treating it as text.

    Build tools may emit newlines and other printable control characters.  The
    gate record therefore retains their combined stdout/stderr as bounded raw
    bytes instead of asking a JSON string to normalize it.
    """
    text = _string(value, name)
    if not text.startswith("base64:"):
        raise evidence.EvidenceError(f"{name} must use the base64: encoding label")
    try:
        decoded = base64.b64decode(text[7:], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise evidence.EvidenceError(f"{name} is not canonical base64") from exc
    if not decoded:
        raise evidence.EvidenceError(f"{name} must retain non-empty combined output")
    if len(decoded) > maximum:
        raise evidence.EvidenceError(f"{name} exceeds its retained-output bound")
    if base64.b64encode(decoded).decode("ascii") != text[7:]:
        raise evidence.EvidenceError(f"{name} is not canonical base64")
    return decoded


def validate_trust_policy(document: object, *, at: datetime | None = None) -> dict:
    doc = _object(document, "trust policy", {
        "expires_at", "keys", "policy_id", "release", "schema_version", "thresholds", "valid_from",
    })
    _schema(doc, TRUST_POLICY_SCHEMA, "trust policy")
    _token(doc["policy_id"], "trust policy.policy_id")
    valid_from = _timestamp(doc["valid_from"], "trust policy.valid_from")
    expires_at = _timestamp(doc["expires_at"], "trust policy.expires_at")
    if expires_at <= valid_from:
        raise evidence.EvidenceError("trust policy expires before it becomes valid")
    keys = _array(doc["keys"], "trust policy.keys")
    if not keys:
        raise evidence.EvidenceError("trust policy must contain at least one key")
    public_keys = []
    for index, record in enumerate(keys):
        item = _object(record, f"trust policy.keys[{index}]", {
            "algorithm", "expires_at", "gate_ids", "key_id", "public_key", "revoked_at",
            "roles", "valid_from",
        })
        if item["algorithm"] != "ed25519":
            raise evidence.EvidenceError("trust policy supports only ed25519")
        _token(item["key_id"], f"trust policy.keys[{index}].key_id")
        public_keys.append(
            _base64(item["public_key"], f"trust policy.keys[{index}].public_key", size=32)
        )
        key_start = _timestamp(item["valid_from"], f"trust policy.keys[{index}].valid_from")
        key_end = _timestamp(item["expires_at"], f"trust policy.keys[{index}].expires_at")
        if key_start < valid_from or key_end > expires_at or key_end <= key_start:
            raise evidence.EvidenceError("trust key validity must be a non-empty policy subinterval")
        if item["revoked_at"] is not None:
            revoked = _timestamp(item["revoked_at"], f"trust policy.keys[{index}].revoked_at")
            if revoked < key_start:
                raise evidence.EvidenceError("trust key revocation predates key validity")
        roles = _array(item["roles"], f"trust policy.keys[{index}].roles")
        if roles != [role for role in ROLE_ORDER if role in set(roles)] or not roles:
            raise evidence.EvidenceError("trust key roles must be non-empty, unique and canonical")
        if len(roles) != 1:
            raise evidence.EvidenceError("gate and approval authority must use disjoint key material")
        gate_ids = _array(item["gate_ids"], f"trust policy.keys[{index}].gate_ids")
        if any(type(gate_id) is not str for gate_id in gate_ids):
            raise evidence.EvidenceError("trust key gate ids must be strings")
        expected_order = [gate_id for gate_id in SELECTED_RECORD_SLOTS if gate_id in set(gate_ids)]
        if gate_ids != expected_order or len(gate_ids) != len(set(gate_ids)):
            raise evidence.EvidenceError("trust key gate ids must be known, unique and canonical")
        if (roles == ["approval"] and gate_ids) or (roles == ["gate"] and not gate_ids):
            raise evidence.EvidenceError("trust key gate scope conflicts with its sole role")
    _unique(keys, "key_id", "trust policy.keys")
    if len(public_keys) != len(set(public_keys)):
        raise evidence.EvidenceError("trust policy contains duplicate public-key material")
    authorized_gates = {gate_id for key in keys for gate_id in key["gate_ids"]}
    if authorized_gates != set(SELECTED_RECORD_SLOTS):
        raise evidence.EvidenceError("trust policy does not authorize every selected gate")
    thresholds = _array(doc["thresholds"], "trust policy.thresholds")
    if [row.get("role") if type(row) is dict else None for row in thresholds] != list(ROLE_ORDER):
        raise evidence.EvidenceError("trust policy must declare canonical approval and gate thresholds")
    for index, row in enumerate(thresholds):
        item = _object(row, f"trust policy.thresholds[{index}]", {"minimum_signatures", "role"})
        count = _integer(item["minimum_signatures"], "trust policy threshold")
        if count != 1:
            raise evidence.EvidenceError("frozen v1 records carry exactly one required signature")
        if not any(item["role"] in key["roles"] for key in keys):
            raise evidence.EvidenceError("trust policy threshold has no eligible key")
    if at is not None:
        if at.tzinfo is None or at.utcoffset() is None:
            raise evidence.EvidenceError("trust-policy verification time must be timezone-aware")
        moment = at.astimezone(timezone.utc)
        if not valid_from <= moment < expires_at:
            raise evidence.EvidenceError("trust policy is not valid at the verification time")
    return doc


def read_trust_policy(data: bytes, *, at: datetime | None = None) -> dict:
    return validate_trust_policy(_canonical_reader(data, "trust policy"), at=at)


def _validate_trusted_policy(
    policy: object, *, trusted_policy_digest: str | None, at: datetime | None = None,
) -> dict:
    """Validate policy bytes against an explicit out-of-band trust root.

    No production authority is compiled into or committed with the candidate.
    Structural policy validation is intentionally insufficient at nomination,
    aggregation and approval boundaries.
    """
    policy_doc = validate_trust_policy(policy, at=at)
    if trusted_policy_digest is None:
        raise evidence.EvidenceError("external production trust policy authority is missing")
    _digest(trusted_policy_digest, "trusted policy digest")
    if evidence.canonical_digest(policy_doc) != trusted_policy_digest:
        raise evidence.EvidenceError("trust policy does not match the external production authority")
    return policy_doc


def validate_signature_envelope(document: object) -> dict:
    doc = _object(document, "signature envelope", {
        "algorithm", "candidate_identity_digest", "key_id", "payload_digest", "role",
        "schema_version", "signature", "trust_policy_digest",
    })
    if doc["schema_version"] != SIGNATURE_ENVELOPE_SCHEMA:
        raise evidence.EvidenceError("unsupported signature envelope schema")
    if doc["algorithm"] != "ed25519" or doc["role"] not in ROLE_ORDER:
        raise evidence.EvidenceError("signature envelope algorithm or role is unsupported")
    _token(doc["key_id"], "signature envelope.key_id")
    for field in ("candidate_identity_digest", "payload_digest", "trust_policy_digest"):
        _digest(doc[field], f"signature envelope.{field}")
    _base64(doc["signature"], "signature envelope.signature", size=64)
    return doc


def read_signature_envelope(data: bytes) -> dict:
    return validate_signature_envelope(_canonical_reader(data, "signature envelope"))


def signature_preimage(
    *, role: str, payload_digest: str, candidate_identity_digest: str, trust_policy_digest: str,
) -> bytes:
    if role not in ROLE_ORDER:
        raise evidence.EvidenceError("signature role is unsupported")
    for value, name in ((payload_digest, "payload"),
                        (candidate_identity_digest, "candidate"),
                        (trust_policy_digest, "trust policy")):
        _digest(value, f"signature {name} digest")
    context = {
        "candidate_identity_digest": candidate_identity_digest,
        "payload_digest": payload_digest,
        "role": role,
        "trust_policy_digest": trust_policy_digest,
    }
    return b"quarry.release-signature.v1\0" + evidence.canonical_json_bytes(context)


def _edwards_x(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P) % _ED25519_P
    x = pow(xx, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P:
        x = x * _ED25519_I % _ED25519_P
    if (x * x - xx) % _ED25519_P:
        raise evidence.EvidenceError("ed25519 point is not on the curve")
    if x == 0 and sign:
        raise evidence.EvidenceError("ed25519 point uses a noncanonical sign bit")
    if x & 1 != sign:
        x = _ED25519_P - x
    return x


def _point_decode(encoded: bytes, name: str) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise evidence.EvidenceError(f"{name} must be 32 bytes")
    integer = int.from_bytes(encoded, "little")
    sign = integer >> 255
    y = integer & ((1 << 255) - 1)
    if y >= _ED25519_P:
        raise evidence.EvidenceError(f"{name} is not a canonical ed25519 point")
    x = _edwards_x(y, sign)
    point = (x, y, 1, x * y % _ED25519_P)
    if _point_encode(point) != encoded:
        raise evidence.EvidenceError(f"{name} is not a canonical ed25519 point")
    if _point_equal(_scalar_mult(point, 8), (0, 1, 1, 0)):
        raise evidence.EvidenceError(f"{name} is a small-order ed25519 point")
    if not _point_equal(_scalar_mult(point, _ED25519_L), (0, 1, 1, 0)):
        raise evidence.EvidenceError(f"{name} is not in the prime-order ed25519 subgroup")
    return point


def _point_add(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_P
    b = (y1 + x1) * (y2 + x2) % _ED25519_P
    c = 2 * _ED25519_D * t1 * t2 % _ED25519_P
    d = 2 * z1 * z2 % _ED25519_P
    e = (b - a) % _ED25519_P
    f = (d - c) % _ED25519_P
    g = (d + c) % _ED25519_P
    h = (b + a) % _ED25519_P
    return e * f % _ED25519_P, g * h % _ED25519_P, f * g % _ED25519_P, e * h % _ED25519_P


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return ((left[0] * right[2] - right[0] * left[2]) % _ED25519_P == 0 and
            (left[1] * right[2] - right[1] * left[2]) % _ED25519_P == 0)


def _point_encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = point
    inverse = pow(z, _ED25519_P - 2, _ED25519_P)
    affine_x = x * inverse % _ED25519_P
    affine_y = y * inverse % _ED25519_P
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")


_ED25519_BASE = (
    _edwards_x(_ED25519_B_Y, 0), _ED25519_B_Y, 1,
    _edwards_x(_ED25519_B_Y, 0) * _ED25519_B_Y % _ED25519_P,
)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify one strict RFC 8032 Ed25519 signature or fail closed."""
    if type(public_key) is not bytes or type(message) is not bytes or type(signature) is not bytes:
        raise evidence.EvidenceError("ed25519 verifier inputs must be exact bytes")
    if len(public_key) != 32 or len(signature) != 64:
        raise evidence.EvidenceError("ed25519 public key/signature length is invalid")
    public = _point_decode(public_key, "ed25519 public key")
    encoded_r = signature[:32]
    r_point = _point_decode(encoded_r, "ed25519 signature R")
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ED25519_L:
        raise evidence.EvidenceError("ed25519 signature scalar is noncanonical")
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % _ED25519_L
    if not _point_equal(_scalar_mult(_ED25519_BASE, scalar),
                        _point_add(r_point, _scalar_mult(public, challenge))):
        raise evidence.EvidenceError("ed25519 signature verification failed")


def _policy_public_key(
    policy: dict, key_id: str, role: str, at: datetime, *, gate_id: str | None = None,
) -> bytes:
    matches = [key for key in policy["keys"] if key["key_id"] == key_id]
    if len(matches) != 1:
        raise evidence.EvidenceError("signature key is not present exactly once in the trust policy")
    key = matches[0]
    if role not in key["roles"]:
        raise evidence.EvidenceError("signature key is not authorized for this role")
    if role == "gate" and gate_id not in key["gate_ids"]:
        raise evidence.EvidenceError("signature key is not authorized for this gate")
    start = _timestamp(key["valid_from"], "trust key.valid_from")
    end = _timestamp(key["expires_at"], "trust key.expires_at")
    if not start <= at < end:
        raise evidence.EvidenceError("signature key is not valid at the verification time")
    if key["revoked_at"] is not None and at >= _timestamp(key["revoked_at"], "trust key.revoked_at"):
        raise evidence.EvidenceError("signature key was revoked at the verification time")
    return _base64(key["public_key"], "trust key.public_key", size=32)


def contract_review_payload_digest(document: object) -> str:
    """Digest a frozen contract manifest with only its review signature cleared."""
    if type(document) is not dict or type(document.get("approval")) is not dict:
        raise evidence.EvidenceError("contract review payload must contain review metadata")
    unsigned = dict(document)
    review = dict(document["approval"])
    if set(review) != {"approved_at", "review_id", "reviewer", "signature"}:
        raise evidence.EvidenceError("contract review metadata has invalid members")
    review["signature"] = None
    unsigned["approval"] = review
    return evidence.canonical_digest(unsigned)


def contract_review_preimage(*, payload_digest: str, trust_policy_digest: str) -> bytes:
    """Return the domain-separated preimage for a pre-nomination input review."""
    _digest(payload_digest, "contract review payload digest")
    _digest(trust_policy_digest, "contract review trust policy digest")
    context = {
        "payload_digest": payload_digest,
        "trust_policy_digest": trust_policy_digest,
    }
    return b"quarry.release-contract-review.v1\0" + evidence.canonical_json_bytes(context)


def verify_contract_review(
    document: object, *, policy: object, trusted_policy_digest: str | None,
) -> dict:
    """Verify one manifest's pre-nomination review with approval authority."""
    if type(document) is not dict:
        raise evidence.EvidenceError("reviewed contract must be an object")
    review = _review(document.get("approval"), "contract approval")
    if review is None or review["signature"] is None:
        raise evidence.EvidenceError("contract input is a draft without an authenticated review")
    at = _timestamp(review["approved_at"], "contract approval.approved_at")
    policy_doc = _validate_trusted_policy(
        policy, trusted_policy_digest=trusted_policy_digest, at=at,
    )
    signature = review["signature"]
    public = _policy_public_key(policy_doc, signature["key_id"], "approval", at)
    message = contract_review_preimage(
        payload_digest=contract_review_payload_digest(document),
        trust_policy_digest=evidence.canonical_digest(policy_doc),
    )
    verify_ed25519(public, message, _base64(signature["value"], "review signature", size=64))
    return document


def verify_signature_envelope(
    envelope: object, *, policy: object, payload_digest: str,
    candidate_identity_digest: str, role: str, at: datetime, gate_id: str | None = None,
) -> dict:
    policy_doc = validate_trust_policy(policy, at=at)
    signature = validate_signature_envelope(envelope)
    policy_digest = evidence.canonical_digest(policy_doc)
    expected = {
        "candidate_identity_digest": candidate_identity_digest,
        "payload_digest": payload_digest,
        "role": role,
        "trust_policy_digest": policy_digest,
    }
    for field, value in expected.items():
        if signature[field] != value:
            raise evidence.EvidenceError(f"signature envelope has the wrong {field}")
    public = _policy_public_key(
        policy_doc, signature["key_id"], role, at, gate_id=gate_id,
    )
    message = signature_preimage(role=role, payload_digest=payload_digest,
                                 candidate_identity_digest=candidate_identity_digest,
                                 trust_policy_digest=policy_digest)
    verify_ed25519(public, message, _base64(signature["signature"], "signature", size=64))
    return signature


def gate_payload_digest(gate: object, *, identity: object) -> str:
    doc = evidence.validate_gate_record(gate, identity=identity)
    unsigned = dict(doc)
    unsigned["signature"] = None
    return evidence.canonical_digest(unsigned)


def verify_gate_signature(gate: object, *, identity: object, policy: object) -> dict:
    doc = evidence.validate_gate_record(gate, identity=identity)
    signature = doc["signature"]
    if signature is None:
        raise evidence.EvidenceError("gate record is unsigned")
    if signature["algorithm"] != "ed25519":
        raise evidence.EvidenceError("gate record signature algorithm is unsupported")
    at = _timestamp(doc["finished_at"], "gate.finished_at")
    policy_doc = validate_trust_policy(policy, at=at)
    public = _policy_public_key(
        policy_doc, signature["key_id"], "gate", at, gate_id=doc["gate_id"],
    )
    message = signature_preimage(
        role="gate",
        payload_digest=gate_payload_digest(doc, identity=identity),
        candidate_identity_digest=evidence.canonical_digest(identity),
        trust_policy_digest=evidence.canonical_digest(policy_doc),
    )
    raw_signature = _base64(signature["value"], "gate.signature.value", size=64)
    verify_ed25519(public, message, raw_signature)
    return doc


def required_assertion_id(gate_id: str) -> str:
    """Return the frozen root assertion id for one record-producing obligation."""
    if gate_id not in RECORD_UNIVERSE:
        raise evidence.EvidenceError("required assertion requested for an unknown obligation")
    return gate_id.lower()


def required_artifact_contract(gate_id: str) -> tuple[tuple[str, str], ...]:
    """Return the exact supporting-artifact names/media types for a pass gate."""
    try:
        return REQUIRED_ARTIFACTS[gate_id]
    except KeyError as exc:
        raise evidence.EvidenceError(
            "required artifact contract requested for a non-passing obligation"
        ) from exc


def validate_evidence_report(document: object, *, identity: object, gate_id: str) -> dict:
    candidate = evidence.validate_candidate_identity(identity)
    doc = _object(document, "gate evidence report", {
        "benchmark", "candidate_identity_digest", "gate_id", "instances", "materials",
        "measurements", "release", "schema_version",
    })
    _schema(doc, EVIDENCE_REPORT_SCHEMA, "gate evidence report")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(candidate):
        raise evidence.EvidenceError("gate evidence report binds the wrong candidate")
    if doc["gate_id"] != gate_id or gate_id not in RECORD_UNIVERSE:
        raise evidence.EvidenceError("gate evidence report binds the wrong or unknown gate")
    benchmark = doc["benchmark"]
    if benchmark is not None:
        item = _object(benchmark, "gate evidence report benchmark", {
            "concurrency", "fixture_digest", "gate_id", "invalidation_policy", "operation",
            "repetitions", "resource_limits", "runner_class", "tool_digests",
            "trial_retention", "warmup_runs",
        })
        if item["gate_id"] != gate_id or gate_id not in PERFORMANCE_OPERATIONS:
            raise evidence.EvidenceError("gate evidence benchmark binds the wrong performance gate")
        if item["operation"] != PERFORMANCE_OPERATIONS[gate_id]:
            raise evidence.EvidenceError("gate evidence benchmark operation is not canonical")
        _digest(item["fixture_digest"], "gate evidence benchmark fixture digest")
        _token(item["runner_class"], "gate evidence benchmark runner class")
        if item["invalidation_policy"] != "record-and-rerun-complete-trial-set" or \
                item["trial_retention"] != "all-raw-trials":
            raise evidence.EvidenceError("gate evidence benchmark trial policy is not canonical")
        for field in ("concurrency", "repetitions", "warmup_runs"):
            _integer(item[field], f"gate evidence benchmark {field}")
        if item["concurrency"] == 0 or item["repetitions"] == 0:
            raise evidence.EvidenceError("gate evidence benchmark concurrency/repetitions must be positive")
        if item["repetitions"] > 1000:
            raise evidence.EvidenceError(
                "gate evidence benchmark repetitions exceed the canonical trial-id space"
            )
        limits = _object(item["resource_limits"], "gate evidence benchmark resources", {
            "cpu_millicores", "disk_bytes", "memory_bytes",
        })
        for field, value in limits.items():
            if _integer(value, f"gate evidence benchmark resources.{field}") == 0:
                raise evidence.EvidenceError("gate evidence benchmark resource limits must be positive")
        tools = _array(item["tool_digests"], "gate evidence benchmark tool digests")
        for digest in tools:
            _digest(digest, "gate evidence benchmark tool digest")
        if not tools or tools != sorted(set(tools)):
            raise evidence.EvidenceError("gate evidence benchmark tool digests are not canonical")
    instances = _array(doc["instances"], "gate evidence report.instances")
    if not instances:
        raise evidence.EvidenceError("gate evidence report must contain an executed instance")
    for index, record in enumerate(instances):
        item = _object(record, f"gate evidence report.instances[{index}]", {
            "artifacts", "assertions", "environment", "finished_at", "id", "lane",
            "selection", "started_at", "toolchain",
        })
        _token(item["id"], f"gate evidence report.instances[{index}].id")
        if item["lane"] not in LANE_ORDER:
            raise evidence.EvidenceError("gate evidence report instance lane is unsupported")
        environment = _object(item["environment"], "gate evidence report environment", {
            "architecture", "isolation_profile", "os", "python", "runner_image",
        })
        for field in ("architecture", "os", "python"):
            _string(environment[field], f"gate evidence report environment.{field}")
        _digest(environment["isolation_profile"], "gate evidence report isolation profile")
        _digest(environment["runner_image"], "gate evidence report runner image")
        if _timestamp(item["finished_at"], "gate evidence report finished_at") < \
                _timestamp(item["started_at"], "gate evidence report started_at"):
            raise evidence.EvidenceError("gate evidence report instance finishes before it starts")
        counts = _object(item["selection"], "gate evidence report selection", {
            "collected", "deselected", "failed", "passed", "selected", "skipped", "xfailed", "xpassed",
        })
        normalized = {key: _integer(value, f"gate evidence report selection.{key}")
                      for key, value in counts.items()}
        if normalized["collected"] != normalized["selected"] + normalized["deselected"]:
            raise evidence.EvidenceError("gate evidence report collection counts do not reconcile")
        if normalized["selected"] != sum(normalized[key] for key in
                                         ("passed", "failed", "skipped", "xfailed", "xpassed")):
            raise evidence.EvidenceError("gate evidence report terminal counts do not reconcile")
        assertions = _array(item["assertions"], "gate evidence report assertions")
        for assertion_index, assertion in enumerate(assertions):
            assertion_doc = _object(assertion, f"gate evidence report assertion[{assertion_index}]", {
                "id", "reason", "status",
            })
            _token(assertion_doc["id"], "gate evidence report assertion id")
            if assertion_doc["status"] not in evidence.GATE_STATUSES:
                raise evidence.EvidenceError("gate evidence report assertion status is invalid")
            if assertion_doc["reason"] is not None:
                _string(assertion_doc["reason"], "gate evidence report assertion reason")
        _unique(assertions, "id", "gate evidence report assertions")
        artifacts = _array(item["artifacts"], "gate evidence report instance artifacts")
        for artifact_index, artifact in enumerate(artifacts):
            artifact_doc = _object(artifact, f"gate evidence report artifact[{artifact_index}]", {
                "digest", "name",
            })
            _token(artifact_doc["name"], "gate evidence report artifact name")
            _digest(artifact_doc["digest"], "gate evidence report artifact digest")
        _unique(artifacts, "name", "gate evidence report instance artifacts")
        toolchain = _array(item["toolchain"], "gate evidence report instance toolchain")
        for tool_index, tool in enumerate(toolchain):
            tool_doc = _object(tool, f"gate evidence report toolchain[{tool_index}]", {
                "digest", "name", "path", "version",
            })
            _token(tool_doc["name"], "gate evidence report tool name")
            _digest(tool_doc["digest"], "gate evidence report tool digest")
            evidence._absolute_tool_path(tool_doc["path"], "gate evidence report tool path")
            _string(tool_doc["version"], "gate evidence report tool version")
        _unique(toolchain, "name", "gate evidence report instance toolchain")
    _unique(instances, "id", "gate evidence report.instances")

    materials = _array(doc["materials"], "gate evidence report.materials")
    material_keys = []
    for index, material in enumerate(materials):
        item = _object(material, f"gate evidence report.materials[{index}]", {
            "digest", "kind", "name",
        })
        if item["kind"] not in {"corpus_attestation", "corpus_fixture", "template_set"}:
            raise evidence.EvidenceError("gate evidence material kind is unsupported")
        _token(item["name"], "gate evidence material name")
        _digest(item["digest"], "gate evidence material digest")
        material_keys.append((item["kind"], item["name"]))
    if material_keys != sorted(material_keys) or len(material_keys) != len(set(material_keys)):
        raise evidence.EvidenceError("gate evidence materials must be sorted and unique")

    measurements = _array(doc["measurements"], "gate evidence report.measurements")
    measurement_keys = []
    for index, measurement in enumerate(measurements):
        item = _object(measurement, f"gate evidence report.measurements[{index}]", {
            "baseline_digest", "class", "invalidated_trials", "metric", "observed_trials",
            "statistic", "unit", "value",
        })
        _token(item["metric"], "gate evidence measurement metric")
        _token(item["unit"], "gate evidence measurement unit")
        if item["class"] not in {"absolute", "regression"} or \
                item["statistic"] not in {"maximum", "median", "minimum", "p95"}:
            raise evidence.EvidenceError("gate evidence measurement class/statistic is unsupported")
        if item["baseline_digest"] is not None:
            _digest(item["baseline_digest"], "gate evidence measurement baseline digest")
        if item["class"] == "absolute" and item["baseline_digest"] is not None:
            raise evidence.EvidenceError("absolute measurement must not name a regression baseline")
        observed = _integer(item["observed_trials"], "gate evidence measurement observed_trials")
        invalidated = _integer(
            item["invalidated_trials"], "gate evidence measurement invalidated_trials",
        )
        if observed == 0 or invalidated >= observed:
            raise evidence.EvidenceError("gate evidence measurement has no retained valid trial")
        if invalidated:
            raise evidence.EvidenceError(
                "passing benchmark must rerun a complete trial set after any invalidation"
            )
        _integer(item["value"], "gate evidence measurement value")
        measurement_keys.append((item["class"], item["metric"]))
    if len(measurement_keys) != len(set(measurement_keys)):
        raise evidence.EvidenceError("gate evidence measurements contain duplicate identities")
    return doc


def read_evidence_report(data: bytes, *, identity: object, gate_id: str) -> dict:
    return validate_evidence_report(
        _canonical_reader(data, "gate evidence report"), identity=identity, gate_id=gate_id,
    )


def _raw_input_map(scope: dict, *, policy: dict) -> dict[str, str]:
    result = {record["name"]: record["digest"] for record in scope["input_bindings"]}
    result["production-trust-policy"] = raw_sha256(canonical_json_line(policy))
    result["release-scope"] = raw_sha256(canonical_json_line(scope))
    return result


def expected_gate_inputs(scope: object, *, identity: object, policy: object) -> list[dict]:
    scope_doc = validate_release_scope(scope)
    identity_doc = evidence.validate_candidate_identity(identity)
    policy_doc = validate_trust_policy(policy)
    inputs = _raw_input_map(scope_doc, policy=policy_doc)
    inputs["candidate-identity"] = evidence.canonical_digest(identity_doc)
    if sorted(inputs) != scope_doc["record_inputs"]:
        raise evidence.EvidenceError("scope record input inventory is inconsistent")
    return [{"digest": inputs[name], "name": name} for name in sorted(inputs)]


def read_candidate_identity(data: bytes) -> dict:
    """Read the frozen candidate format in its one canonical JSON-line form."""
    return evidence.validate_candidate_identity(_canonical_reader(data, "candidate identity"))


def read_gate_record(data: bytes, *, identity: object) -> dict:
    """Read the frozen gate format in its one canonical JSON-line form."""
    return evidence.validate_gate_record(
        _canonical_reader(data, "gate record"), identity=identity,
    )


def validate_candidate_bindings(
    identity: object, *, scope: object, policy: object, trusted_policy_digest: str | None,
) -> dict:
    """Require a nomination identity to bind every additive scope/trust input."""
    identity_doc = evidence.validate_candidate_identity(identity)
    scope_doc = validate_release_scope(scope)
    policy_doc = _validate_trusted_policy(
        policy, trusted_policy_digest=trusted_policy_digest,
    )
    verify_contract_review(
        scope_doc, policy=policy_doc, trusted_policy_digest=trusted_policy_digest,
    )
    if identity_doc["release"] != RELEASE or identity_doc["package_version"] != RELEASE:
        raise evidence.EvidenceError("candidate package version is not nomination-eligible")
    expected = {record["name"]: (record["path"], record["digest"])
                for record in scope_doc["input_bindings"]}
    expected["production-trust-policy"] = (
        scope_doc["production_trust_policy"]["path"],
        raw_sha256(canonical_json_line(policy_doc)),
    )
    expected["release-scope"] = (
        "release/evidence/release-scope-v1.json",
        raw_sha256(canonical_json_line(scope_doc)),
    )
    declared = {record["name"]: (record["path"], record["digest"])
                for record in identity_doc["inputs"]}
    for name, binding in expected.items():
        if declared.get(name) != binding:
            raise evidence.EvidenceError(f"candidate omits or redirects scope input {name!r}")
    permitted = set(evidence.DEFAULT_IDENTITY_INPUTS) | set(expected)
    if set(declared) != permitted:
        raise evidence.EvidenceError("candidate identity contains undeclared release inputs")
    return identity_doc


def verify_scope_input_bodies(scope: object, bodies: Mapping[str, bytes]) -> None:
    scope_doc = validate_release_scope(scope)
    if not isinstance(bodies, Mapping) or any(type(key) is not str for key in bodies):
        raise evidence.EvidenceError("scope input bodies must be a name-to-bytes mapping")
    expected = {record["name"]: record for record in scope_doc["input_bindings"]}
    if set(bodies) != set(expected):
        raise evidence.EvidenceError("scope input bodies do not exactly match input bindings")
    for name, record in expected.items():
        body = bodies[name]
        if type(body) is not bytes or raw_sha256(body) != record["digest"]:
            raise evidence.EvidenceError(f"scope input raw bytes drifted: {name!r}")


def _verify_gate_artifacts(gate: dict, resolver: ArtifactResolver) -> dict[str, bytes]:
    signed = tuple(MappingProxyType(dict(artifact)) for artifact in gate["artifacts"])
    indexed = [resolver.record(gate["gate_id"], artifact["name"]) for artifact in signed]
    expected = [{"digest": row["digest"], "media_type": row["media_type"], "name": row["name"]}
                for row in indexed]
    if [dict(artifact) for artifact in signed] != expected:
        raise evidence.EvidenceError("gate artifacts do not exactly match the artifact index")
    verified: dict[str, bytes] = {}
    for artifact, row in zip(signed, indexed, strict=True):
        if row["name"] == "gate-evidence" and row["media_type"] != "application/json":
            raise evidence.EvidenceError("gate-evidence must use the canonical application/json media type")
        body = resolver.read(gate["gate_id"], row["name"])
        if (resolver.record(gate["gate_id"], row["name"]) != row or
                raw_sha256(body) != artifact["digest"]):
            raise evidence.EvidenceError("artifact metadata changed across signed verification")
        verified[row["name"]] = body
    return verified


def _artifact_document(body: bytes, gate_id: str, name: str) -> dict:
    value = _canonical_reader(body, f"supporting artifact {gate_id}/{name}")
    if type(value) is not dict:
        raise evidence.EvidenceError(f"supporting artifact {gate_id}/{name} must be an object")
    return value


def _validate_generic_supporting_artifact(
    body: bytes, *, gate_id: str, name: str, identity: dict,
) -> dict:
    doc = _object(
        _artifact_document(body, gate_id, name),
        f"supporting artifact {gate_id}/{name}",
        {
            "artifact_type", "assertion", "candidate_identity_digest", "gate_id", "name",
            "records", "release", "schema_version",
        },
    )
    if doc["schema_version"] != SUPPORTING_ARTIFACT_SCHEMA or doc["release"] != RELEASE:
        raise evidence.EvidenceError("supporting artifact schema or release is unsupported")
    if doc["artifact_type"] != "machine-report":
        raise evidence.EvidenceError("supporting artifact type is not the machine-report contract")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(identity) or \
            doc["gate_id"] != gate_id or doc["name"] != name:
        raise evidence.EvidenceError("supporting artifact is bound to the wrong candidate, gate or name")
    expected_assertion = {
        "id": f"{required_assertion_id(gate_id)}.{name}",
        "reason": None,
        "status": "pass",
    }
    if doc["assertion"] != expected_assertion:
        raise evidence.EvidenceError("supporting artifact does not pass its frozen evidence assertion")
    records = _array(doc["records"], f"supporting artifact {gate_id}/{name}.records")
    if not records:
        raise evidence.EvidenceError("supporting artifact contains no machine records")
    for index, record in enumerate(records):
        item = _object(record, f"supporting artifact record {index}", {
            "id", "result", "result_digest", "status",
        })
        _token(item["id"], "supporting artifact record id")
        _digest(item["result_digest"], "supporting artifact record result digest")
        if item["status"] != "pass":
            raise evidence.EvidenceError("supporting artifact contains a non-passing machine record")
        expected_result = {
            "outcome": "pass",
            "subject": f"{gate_id}/{name}",
        }
        if item["result"] != expected_result or \
                item["result_digest"] != evidence.canonical_digest(expected_result):
            raise evidence.EvidenceError("supporting artifact result digest is unresolved or substituted")
    _unique(records, "id", f"supporting artifact {gate_id}/{name}.records")
    return doc


_NETWORK_DENIAL_LANES = (
    "H0-hermetic", "C0-private-corpus", "P0-package-supply",
)
_NETWORK_DENIAL_ATTEMPTS = (
    "native-tool", "proxy", "resolver", "socket", "subprocess",
)

_NETWORK_BOUNDARY_DNS_NAMES = frozenset({
    "fixture.test", "redirect.fixture.test", "xn--bcher-kva.fixture.test",
    "rebind.fixture.test", "mixed.fixture.test", "protected.fixture.test",
})
_NETWORK_BOUNDARY_HTTP_CONTACTS = frozenset({
    ("fixture.test:8080", "/start"),
    ("redirect.fixture.test:8080", "/final"),
    ("xn--bcher-kva.fixture.test:8080", "/idna"),
    ("10.203.0.1:8080", "/cidr"),
    ("rebind.fixture.test:8080", "/rebind"),
})


def _network_boundary_environment(row: dict) -> dict:
    return {key: row[key] for key in (
        "architecture", "isolation_profile", "os", "python", "runner_image",
    )}


def _validate_network_boundary_summary(summary: object, *, proxy: bool) -> list[dict]:
    name = "network boundary proxy" if proxy else "network boundary broker"
    members = (
        {"active_sockets", "active_threads", "complete", "dropped_records", "fatal",
         "open_plans", "records", "request_id", "schema_version"}
        if proxy else
        {"active_operations", "complete", "dropped_records", "fatal", "listener_hup",
         "open_plans", "profile", "records", "request_id", "retained_connections",
         "schema_version"}
    )
    item = _object(summary, name, members)
    expected_schema = (
        "quarry.browser-proxy-summary.v1" if proxy
        else "quarry.network-broker-summary.v1"
    )
    if item["schema_version"] != expected_schema:
        raise evidence.EvidenceError(f"{name} schema is unsupported")
    request_id = _string(item["request_id"], f"{name}.request_id")
    if re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        raise evidence.EvidenceError(f"{name} request identity is invalid")
    dropped = _integer(item["dropped_records"], f"{name}.dropped_records")
    open_plans = _integer(item["open_plans"], f"{name}.open_plans")
    if (item["complete"] is not True or item["fatal"] is not None
            or dropped != 0 or open_plans != 0):
        raise evidence.EvidenceError(f"{name} did not settle completely")
    if proxy:
        active_sockets = _integer(item["active_sockets"], f"{name}.active_sockets")
        active_threads = _integer(item["active_threads"], f"{name}.active_threads")
        if active_sockets != 0 or active_threads != 0:
            raise evidence.EvidenceError("network boundary proxy retained active work")
        record_members = {
            "decision", "host", "method", "peer", "port", "reason", "sequence", "stage",
        }
    else:
        active_operations = _integer(
            item["active_operations"], f"{name}.active_operations",
        )
        retained_connections = _integer(
            item["retained_connections"], f"{name}.retained_connections",
        )
        if (item["profile"] != "standard" or item["listener_hup"] is not True
                or active_operations != 0 or retained_connections != 0):
            raise evidence.EvidenceError("network boundary broker retained authority or work")
        record_members = {
            "decision", "peer", "port", "protocol", "reason", "result", "sequence",
            "socket_type", "stage", "syscall", "tid",
        }
    records = _array(item["records"], f"{name}.records")
    maximum = 8192 if proxy else 1024
    if not records or len(records) > maximum:
        raise evidence.EvidenceError(f"{name} record count is outside its bound")
    sequences = []
    for index, record in enumerate(records):
        observed = _object(record, f"{name}.records[{index}]", record_members)
        sequence = _integer(observed["sequence"], f"{name}.records[{index}].sequence")
        sequences.append(sequence)
        if observed["decision"] not in {"allow", "deny"}:
            raise evidence.EvidenceError(f"{name} record decision is invalid")
        _string(observed["stage"], f"{name}.records[{index}].stage")
        _string(observed["reason"], f"{name}.records[{index}].reason")
        for field in (("method",) if proxy else ("syscall",)):
            _string(observed[field], f"{name}.records[{index}].{field}")
        for field in ("host", "peer") if proxy else ("peer", "result"):
            if observed[field] is not None:
                _string(observed[field], f"{name}.records[{index}].{field}")
        if observed["port"] is not None:
            if not 0 <= _integer(observed["port"], f"{name}.records[{index}].port") <= 65535:
                raise evidence.EvidenceError(f"{name} record port is invalid")
        if not proxy:
            for field in ("protocol", "socket_type", "tid"):
                _integer(observed[field], f"{name}.records[{index}].{field}")
            if observed["tid"] < 1:
                raise evidence.EvidenceError("network boundary broker record TID is invalid")
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise evidence.EvidenceError(f"{name} records are not in unique sequence order")
    return records


def _validate_network_boundary_diagnostic(value: object) -> None:
    diagnostic = _object(value, "network boundary diagnostic", {
        "acceptance_errors", "broker", "dns_records", "http_records", "proxy",
        "proxy_effects", "reaped", "refused", "schema_version", "tracee_results",
    })
    if diagnostic["schema_version"] != "quarry.network-boundary-h1.v1":
        raise evidence.EvidenceError("network boundary diagnostic schema is unsupported")
    if diagnostic["acceptance_errors"] != []:
        raise evidence.EvidenceError("network boundary diagnostic contains acceptance errors")
    if diagnostic["reaped"] != []:
        raise evidence.EvidenceError("network boundary diagnostic retained adopted descendants")
    expected_tracee = {
        "approved": 0,
        "direct_ip": errno.EPERM,
        "scanner_self": errno.EPERM,
        "metadata": errno.EPERM,
        "control_plane": errno.EPERM,
        "sendto_allowed": 1,
        "sendto_metadata": errno.EPERM,
        "sendmsg_allowed": 1,
        "sendmsg_control": errno.EPERM,
    }
    tracee = _object(
        diagnostic["tracee_results"], "network boundary tracee results",
        set(expected_tracee),
    )
    for field in expected_tracee:
        _integer(tracee[field], f"network boundary tracee results.{field}")
    if tracee != expected_tracee:
        raise evidence.EvidenceError("network boundary tracee effects do not match the fixed matrix")
    expected_refused = {
        "unicode_idna": True, "scope": True, "direct_ip": True,
        "mixed": True, "protected": True, "rebind": True,
    }
    refused = _object(
        diagnostic["refused"], "network boundary proxy refusal matrix",
        set(expected_refused),
    )
    if any(refused[field] is not True for field in expected_refused):
        raise evidence.EvidenceError("network boundary proxy refusal matrix is incomplete")
    expected_effects = {
        "start_status": 302,
        "start_location": "http://redirect.fixture.test:8080/final",
        "redirect_status": 200,
        "idna_status": 404,
        "cidr_status": 404,
        "rebind_first_status": 404,
    }
    effects = _object(
        diagnostic["proxy_effects"], "network boundary proxy effects",
        set(expected_effects),
    )
    for field in (
        "start_status", "redirect_status", "idna_status", "cidr_status",
        "rebind_first_status",
    ):
        _integer(effects[field], f"network boundary proxy effects.{field}")
    _string(effects["start_location"], "network boundary proxy effects.start_location")
    if effects != expected_effects:
        raise evidence.EvidenceError("network boundary proxy effects do not match the fixed matrix")

    broker = _validate_network_boundary_summary(diagnostic["broker"], proxy=False)
    proxy = _validate_network_boundary_summary(diagnostic["proxy"], proxy=True)
    if diagnostic["broker"]["request_id"] != diagnostic["proxy"]["request_id"]:
        raise evidence.EvidenceError("network boundary mediator summaries name different invocations")
    direct = {
        (record["peer"], record["decision"])
        for record in broker if record["syscall"] == "connect"
    }
    if not {
        ("10.203.0.1", "allow"), ("8.8.4.4", "deny"),
        ("10.203.0.2", "deny"), ("169.254.169.254", "deny"),
        ("10.203.0.99", "deny"),
    } <= direct:
        raise evidence.EvidenceError("network boundary direct-peer decisions are incomplete")
    datagrams = {
        (record["syscall"], record["peer"], record["decision"],
         record["stage"], record["result"])
        for record in broker if record["syscall"] in {"sendto", "sendmsg"}
    }
    if not {
        ("sendto", "10.203.0.1", "allow", "settled", "1"),
        ("sendto", "169.254.169.254", "deny", "settled", None),
        ("sendmsg", "10.203.0.1", "allow", "settled", "1"),
        ("sendmsg", "10.203.0.99", "deny", "settled", None),
    } <= datagrams:
        raise evidence.EvidenceError("network boundary datagram decisions are incomplete")
    proxy_decisions = {
        (record["host"], record["decision"]) for record in proxy
    }
    if not {
        ("bücher.fixture.test", "deny"), ("oos.fixture.test", "deny"),
        ("8.8.4.4", "deny"), ("mixed.fixture.test", "deny"),
        ("protected.fixture.test", "deny"), ("rebind.fixture.test", "deny"),
    } <= proxy_decisions:
        raise evidence.EvidenceError("network boundary proxy decisions are incomplete")

    dns_records = _array(diagnostic["dns_records"], "network boundary DNS records")
    if not dns_records or len(dns_records) > 128:
        raise evidence.EvidenceError("network boundary DNS record count is outside its bound")
    names = set()
    rebind_counts = []
    for index, record in enumerate(dns_records):
        item = _object(record, f"network boundary DNS record {index}", {"count", "dns", "kind"})
        name = _string(item["dns"], f"network boundary DNS record {index}.dns")
        kind = _integer(item["kind"], f"network boundary DNS record {index}.kind")
        count = _integer(item["count"], f"network boundary DNS record {index}.count")
        if kind not in {1, 28} or count < 1:
            raise evidence.EvidenceError("network boundary DNS record is outside the fixed query matrix")
        names.add(name)
        if name == "rebind.fixture.test":
            rebind_counts.append(count)
    if names != _NETWORK_BOUNDARY_DNS_NAMES or not rebind_counts or max(rebind_counts) < 2:
        raise evidence.EvidenceError("network boundary DNS effects are incomplete")

    http_records = _array(diagnostic["http_records"], "network boundary HTTP records")
    if not http_records or len(http_records) > 64:
        raise evidence.EvidenceError("network boundary HTTP record count is outside its bound")
    contacts = set()
    for index, record in enumerate(http_records):
        item = _object(record, f"network boundary HTTP record {index}", {"host", "path"})
        contacts.add((
            _string(item["host"], f"network boundary HTTP record {index}.host"),
            _string(item["path"], f"network boundary HTTP record {index}.path"),
        ))
    if contacts != _NETWORK_BOUNDARY_HTTP_CONTACTS:
        raise evidence.EvidenceError("network boundary HTTP contact set is not exact")


def _validate_network_boundary_trace(body: bytes, *, identity: dict, support: dict) -> dict:
    """Validate the candidate-bound H1 namespace and mediator witness."""
    doc = _object(
        _artifact_document(body, "C-NETWORK-BOUNDARY", "network-boundary-trace"),
        "network boundary trace",
        {"candidate_identity_digest", "gate_id", "instances", "release", "schema_version"},
    )
    if doc["schema_version"] != NETWORK_BOUNDARY_TRACE_SCHEMA or doc["release"] != RELEASE:
        raise evidence.EvidenceError("network boundary trace schema or release is unsupported")
    if doc["gate_id"] != "C-NETWORK-BOUNDARY":
        raise evidence.EvidenceError("network boundary trace is bound to the wrong gate")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("network boundary trace is bound to the wrong candidate")

    supported = [
        row for row in support["environments"] if row["lane"] == "H1-tool-integration"
    ]
    if not supported or len(supported) > 32:
        raise evidence.EvidenceError("support matrix has no bounded H1 environment set")
    for index, row in enumerate(supported):
        for field in ("architecture", "os", "python"):
            _token(row[field], f"support matrix H1 environment {index}.{field}")
        for field in ("isolation_profile", "runner_image"):
            _digest(row[field], f"support matrix H1 environment {index}.{field}")
    expected = sorted(supported, key=lambda row: (row["runner_image"], row["python"]))
    expected_keys = [(row["runner_image"], row["python"]) for row in expected]
    if len(expected_keys) != len(set(expected_keys)):
        raise evidence.EvidenceError("support matrix has ambiguous H1 identities")

    instances = _array(doc["instances"], "network boundary trace.instances")
    if not 1 <= len(instances) <= 32:
        raise evidence.EvidenceError("network boundary trace instance count is outside its bound")
    observed_keys = []
    observed_environments = []
    for index, record in enumerate(instances):
        item = _object(record, f"network boundary trace.instances[{index}]", {
            "diagnostic", "environment", "identity",
        })
        identity_record = _object(item["identity"], f"network boundary identity {index}", {
            "lane", "python", "runner_image",
        })
        if identity_record["lane"] != "H1-tool-integration":
            raise evidence.EvidenceError("network boundary trace has a non-H1 identity")
        _token(identity_record["python"], f"network boundary identity {index}.python")
        _digest(identity_record["runner_image"], f"network boundary identity {index}.runner_image")
        observed_keys.append((identity_record["runner_image"], identity_record["python"]))
        environment = _object(item["environment"], f"network boundary environment {index}", {
            "architecture", "isolation_profile", "os", "python", "runner_image",
        })
        for field in ("architecture", "os", "python"):
            _token(environment[field], f"network boundary environment {index}.{field}")
        for field in ("isolation_profile", "runner_image"):
            _digest(environment[field], f"network boundary environment {index}.{field}")
        if (environment["python"], environment["runner_image"]) != \
                (identity_record["python"], identity_record["runner_image"]):
            raise evidence.EvidenceError("network boundary identity disagrees with its environment")
        observed_environments.append(environment)
        _validate_network_boundary_diagnostic(item["diagnostic"])
    if observed_keys != expected_keys or observed_environments != [
            _network_boundary_environment(row) for row in expected
    ]:
        raise evidence.EvidenceError("network boundary trace does not cover exact supported H1 images")
    return doc


def _validate_network_denial_report(body: bytes, *, identity: dict, support: dict) -> dict:
    """Validate the one complete, image-bound C-NET-DENY denial matrix."""
    doc = _object(
        _artifact_document(body, "C-NET-DENY", "network-denial-report"),
        "network denial report",
        {"candidate_identity_digest", "gate_id", "instances", "release", "schema_version"},
    )
    if doc["schema_version"] != NETWORK_DENIAL_REPORT_SCHEMA or doc["release"] != RELEASE:
        raise evidence.EvidenceError("network denial report schema or release is unsupported")
    if doc["gate_id"] != "C-NET-DENY":
        raise evidence.EvidenceError("network denial report is bound to the wrong gate")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("network denial report is bound to the wrong candidate")
    instances = _array(doc["instances"], "network denial report.instances")
    if not 3 <= len(instances) <= 256:
        raise evidence.EvidenceError("network denial report instance count is outside its bound")

    supported_instances = [
        row for row in support["environments"] if row["lane"] in _NETWORK_DENIAL_LANES
    ]
    if {row["lane"] for row in supported_instances} != set(_NETWORK_DENIAL_LANES):
        raise evidence.EvidenceError("support matrix omits a required network denial lane")
    for index, row in enumerate(supported_instances):
        for field in ("architecture", "os", "python"):
            _token(row[field], f"support matrix network denial environment {index}.{field}")
        for field in ("isolation_profile", "runner_image"):
            _digest(row[field], f"support matrix network denial environment {index}.{field}")
    expected = sorted(
        supported_instances,
        key=lambda row: (LANE_ORDER.index(row["lane"]), row["runner_image"], row["python"]),
    )
    expected_identities = [
        (row["lane"], row["runner_image"], row["python"]) for row in expected
    ]
    expected_environments = [{
        "architecture": row["architecture"],
        "isolation_profile": row["isolation_profile"],
        "os": row["os"],
        "python": row["python"],
        "runner_image": row["runner_image"],
    } for row in expected]
    if len(expected_identities) != len(set(expected_identities)):
        raise evidence.EvidenceError("support matrix has ambiguous network denial identities")

    observed_identities = []
    observed_environments = []
    for index, record in enumerate(instances):
        item = _object(record, f"network denial report.instances[{index}]", {
            "attempts", "environment", "identity",
        })
        identity_record = _object(item["identity"], f"network denial identity {index}", {
            "lane", "python", "runner_image",
        })
        if identity_record["lane"] not in _NETWORK_DENIAL_LANES:
            raise evidence.EvidenceError("network denial report has an unsupported lane")
        _token(identity_record["python"], f"network denial identity {index}.python")
        _digest(identity_record["runner_image"], f"network denial identity {index}.runner_image")
        identity_key = (
            identity_record["lane"], identity_record["runner_image"], identity_record["python"],
        )
        observed_identities.append(identity_key)

        environment = _object(item["environment"], f"network denial environment {index}", {
            "architecture", "isolation_profile", "os", "python", "runner_image",
        })
        for field in ("architecture", "os", "python"):
            _token(environment[field], f"network denial environment {index}.{field}")
        for field in ("isolation_profile", "runner_image"):
            _digest(environment[field], f"network denial environment {index}.{field}")
        if (environment["python"] != identity_record["python"]
                or environment["runner_image"] != identity_record["runner_image"]):
            raise evidence.EvidenceError("network denial identity disagrees with its environment")
        observed_environments.append(environment)

        attempts = _array(item["attempts"], f"network denial attempts {index}")
        if len(attempts) != len(_NETWORK_DENIAL_ATTEMPTS):
            raise evidence.EvidenceError("network denial instance must contain exactly five attempts")
        for attempt_index, (attempt, expected_kind) in enumerate(
                zip(attempts, _NETWORK_DENIAL_ATTEMPTS, strict=True)):
            attempt_record = _object(
                attempt, f"network denial attempt {index}/{attempt_index}",
                {"denial", "elapsed_milliseconds", "kind", "outcome"},
            )
            if attempt_record["kind"] != expected_kind:
                raise evidence.EvidenceError("network denial attempts are not in canonical complete order")
            if attempt_record["outcome"] != "denied":
                raise evidence.EvidenceError("network denial attempt was not denied")
            _integer(attempt_record["elapsed_milliseconds"],
                     f"network denial attempt {index}/{attempt_index}.elapsed_milliseconds")
            if attempt_record["elapsed_milliseconds"] > 60_000:
                raise evidence.EvidenceError("network denial attempt duration exceeds its bound")
            denial = _object(attempt_record["denial"],
                             f"network denial attempt {index}/{attempt_index}.denial",
                             {"code", "detail"})
            _token(denial["code"], f"network denial attempt {index}/{attempt_index}.denial.code")
            detail = _string(denial["detail"],
                             f"network denial attempt {index}/{attempt_index}.denial.detail")
            if len(detail) > 512:
                raise evidence.EvidenceError("network denial attempt detail exceeds its bound")

    ordering = [
        (LANE_ORDER.index(lane), runner_image, python)
        for lane, runner_image, python in observed_identities
    ]
    if ordering != sorted(ordering) or len(observed_identities) != len(set(observed_identities)):
        raise evidence.EvidenceError("network denial instances must have sorted unique identities")
    if observed_identities != [
            (row["lane"], row["runner_image"], row["python"]) for row in expected
    ] or observed_environments != expected_environments:
        raise evidence.EvidenceError("network denial report does not cover the exact supported runner images")
    return doc


def _archive_member_name(value: str, name: str) -> PurePosixPath:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise evidence.EvidenceError(f"{name} member name is not valid Unicode") from exc
    pure = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (not value or any(ord(character) < 32 or ord(character) == 127 for character in value) or
            "\\" in value or ":" in value or windows.drive or windows.is_absolute() or
            pure.is_absolute() or value != pure.as_posix() or
            any(part in {"", ".", ".."} for part in pure.parts)):
        raise evidence.EvidenceError(f"{name} contains an unsafe or noncanonical member name")
    return pure


def _reject_archive_collisions(entries: Sequence[tuple[PurePosixPath, bool]], name: str) -> None:
    files = {path for path, is_directory in entries if not is_directory}
    directories = {path for path, is_directory in entries if is_directory}
    if files & directories:
        raise evidence.EvidenceError(f"{name} contains a file/directory name collision")
    for path, _is_directory in entries:
        if any(PurePosixPath(*path.parts[:index]) in files for index in range(1, len(path.parts))):
            raise evidence.EvidenceError(f"{name} contains a file used as a parent directory")


def _metadata_value(body: bytes, field: str, name: str) -> str:
    try:
        lines = body.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise evidence.EvidenceError(f"{name} metadata is not UTF-8") from exc
    prefix = field + ":"
    values = [line[len(prefix):].strip() for line in lines if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise evidence.EvidenceError(f"{name} metadata has no unique {field} field")
    return values[0]


def _metadata_values(body: bytes, field: str, name: str) -> list[str]:
    try:
        lines = body.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise evidence.EvidenceError(f"{name} metadata is not UTF-8") from exc
    prefix = field + ":"
    values = [line[len(prefix):].strip() for line in lines if line.startswith(prefix)]
    if any(not value for value in values):
        raise evidence.EvidenceError(f"{name} metadata contains an empty {field} field")
    return values


def _wheel_metadata(body: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(body), "r") as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise evidence.EvidenceError("wheel has no unique METADATA member")
            return archive.read(names[0])
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise evidence.EvidenceError(f"wheel metadata cannot be read: {exc}") from exc


def _validate_wheel(body: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(body), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if not infos or len(names) != len(set(names)):
                raise evidence.EvidenceError("wheel is empty or contains duplicate members")
            entries = []
            for info in infos:
                member_path = _archive_member_name(info.filename.rstrip("/"), "wheel")
                entries.append((member_path, info.is_dir()))
                if info.flag_bits & 1:
                    raise evidence.EvidenceError("wheel contains an encrypted member")
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise evidence.EvidenceError("wheel contains a link or special member")
            _reject_archive_collisions(entries, "wheel")
            if sum(info.file_size for info in infos) > _DOCUMENT_BYTES * 32:
                raise evidence.EvidenceError("wheel expands beyond the bounded verification budget")
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            entry_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
            license_names = [name for name in names if ".dist-info/licenses/" in name]
            if not all(len(group) == 1 for group in (
                metadata_names, wheel_names, record_names, entry_names, license_names,
            )):
                raise evidence.EvidenceError("wheel omits unique metadata, record, entry point or license data")
            metadata = archive.read(metadata_names[0])
            if (_metadata_value(metadata, "Name", "wheel") != "quarry-recon" or
                    _metadata_value(metadata, "Version", "wheel") != RELEASE):
                raise evidence.EvidenceError("wheel metadata does not identify the nominated package")
            if not any(name.startswith("quarry_recon/") and name.endswith(".py") for name in names):
                raise evidence.EvidenceError("wheel contains no importable quarry_recon package code")
            if not any(name.startswith("quarry_recon/data/") and not name.endswith("/")
                       for name in names):
                raise evidence.EvidenceError("wheel omits required packaged data")
            if not any(name.endswith(".schema.json") for name in names):
                raise evidence.EvidenceError("wheel omits required release schemas")
            entry_points = archive.read(entry_names[0]).decode("utf-8", "strict")
            if "[console_scripts]" not in entry_points or \
                    "quarry=quarry_recon.cli:cli" not in entry_points.replace(" ", ""):
                raise evidence.EvidenceError("wheel omits the quarry console entry point")
            if not archive.read(wheel_names[0]) or not archive.read(license_names[0]):
                raise evidence.EvidenceError("wheel metadata or license data is empty")
            try:
                record_rows = list(csv.reader(io.StringIO(
                    archive.read(record_names[0]).decode("utf-8", "strict")
                )))
            except (UnicodeDecodeError, csv.Error) as exc:
                raise evidence.EvidenceError("wheel RECORD is not canonical CSV") from exc
            if any(len(row) != 3 for row in record_rows):
                raise evidence.EvidenceError("wheel RECORD has a malformed row")
            by_record_name = {row[0]: row[1:] for row in record_rows}
            if len(by_record_name) != len(record_rows) or set(by_record_name) != set(names):
                raise evidence.EvidenceError("wheel RECORD does not inventory every member exactly once")
            for name in names:
                digest_field, size_field = by_record_name[name]
                if name == record_names[0]:
                    if digest_field or size_field:
                        raise evidence.EvidenceError("wheel RECORD self-row must omit hash and size")
                    continue
                member_body = archive.read(name)
                encoded = base64.urlsafe_b64encode(hashlib.sha256(member_body).digest()) \
                    .rstrip(b"=").decode("ascii")
                if digest_field != "sha256=" + encoded or size_field != str(len(member_body)):
                    raise evidence.EvidenceError("wheel RECORD hash or size does not match a member")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise evidence.EvidenceError(f"wheel is not a readable ZIP archive: {exc}") from exc


def _validate_sdist(body: bytes) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name.rstrip("/") for member in members]
            if not members or len(names) != len(set(names)):
                raise evidence.EvidenceError("sdist is empty or contains duplicate members")
            paths = [_archive_member_name(name, "sdist") for name in names]
            _reject_archive_collisions(
                list(zip(paths, (member.isdir() for member in members))), "sdist",
            )
            roots = {path.parts[0] for path in paths}
            expected_root = f"quarry_recon-{RELEASE}"
            if roots != {expected_root}:
                raise evidence.EvidenceError("sdist does not have the nominated package root")
            if any(not (member.isfile() or member.isdir()) for member in members):
                raise evidence.EvidenceError("sdist contains a link or special member")
            if sum(member.size for member in members if member.isfile()) > _DOCUMENT_BYTES * 32:
                raise evidence.EvidenceError("sdist expands beyond the bounded verification budget")
            required = {
                f"{expected_root}/LICENSE",
                f"{expected_root}/NOTICE",
                f"{expected_root}/PKG-INFO",
                f"{expected_root}/pyproject.toml",
            }
            if not required.issubset(set(names)):
                raise evidence.EvidenceError("sdist omits package metadata, build input or license data")
            metadata_file = archive.extractfile(f"{expected_root}/PKG-INFO")
            if metadata_file is None:
                raise evidence.EvidenceError("sdist PKG-INFO is not a regular file")
            metadata = metadata_file.read(_DOCUMENT_BYTES + 1)
            if len(metadata) > _DOCUMENT_BYTES:
                raise evidence.EvidenceError("sdist PKG-INFO exceeds its verification bound")
            if (_metadata_value(metadata, "Name", "sdist") != "quarry-recon" or
                    _metadata_value(metadata, "Version", "sdist") != RELEASE):
                raise evidence.EvidenceError("sdist metadata does not identify the nominated package")
            if not any(name.startswith(f"{expected_root}/src/quarry_recon/") and
                       name.endswith(".py") for name in names):
                raise evidence.EvidenceError("sdist contains no quarry_recon package source")
            if not any(name.startswith(f"{expected_root}/src/quarry_recon/data/")
                       for name in names):
                raise evidence.EvidenceError("sdist omits required package data")
            if not any(name.endswith(".schema.json") for name in names):
                raise evidence.EvidenceError("sdist omits required release schemas")
            for name in required:
                selected = archive.extractfile(name)
                if selected is None or not selected.read(1):
                    raise evidence.EvidenceError("sdist contains an empty required metadata file")
    except (OSError, tarfile.TarError) as exc:
        raise evidence.EvidenceError(f"sdist is not a readable gzip tar archive: {exc}") from exc


def _validate_package_artifacts(bodies: Mapping[str, bytes], *, identity: dict) -> None:
    _validate_sdist(bodies["sdist"])
    _validate_wheel(bodies["wheel"])
    doc = _object(
        _artifact_document(bodies["package-inventory"], "C-PACKAGE-BUILD", "package-inventory"),
        "package inventory",
        {
            "artifact_type", "candidate_identity_digest", "gate_id", "package", "release",
            "schema_version", "subjects",
        },
    )
    if doc["artifact_type"] != "package-inventory" or \
            doc["schema_version"] != PACKAGE_INVENTORY_SCHEMA or doc["release"] != RELEASE or \
            doc["gate_id"] != "C-PACKAGE-BUILD" or \
            doc["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("package inventory is bound to the wrong contract")
    if doc["package"] != {"name": "quarry-recon", "version": RELEASE}:
        raise evidence.EvidenceError("package inventory identifies the wrong package")
    expected = [{
        "digest": raw_sha256(bodies[name]),
        "media_type": media_type,
        "name": name,
        "size": len(bodies[name]),
    } for name, media_type in (("sdist", "application/gzip"), ("wheel", "application/zip"))]
    if doc["subjects"] != expected:
        raise evidence.EvidenceError("package inventory does not reconcile the sdist and wheel bytes")

    build_log = _object(
        _artifact_document(bodies["build-log"], "C-PACKAGE-BUILD", "build-log"),
        "clean build log",
        {
            "artifact_type", "candidate_identity_digest", "clean_tree", "command",
            "combined_output", "exit_code", "gate_id", "package", "release",
            "schema_version", "subjects",
        },
    )
    if build_log["artifact_type"] != "clean-build-log" or \
            build_log["schema_version"] != GATE_ARTIFACT_SCHEMA or \
            build_log["release"] != RELEASE or \
            build_log["gate_id"] != "C-PACKAGE-BUILD" or \
            build_log["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("clean build log is bound to the wrong contract")
    if build_log["package"] != {"name": "quarry-recon", "version": RELEASE}:
        raise evidence.EvidenceError("clean build log identifies the wrong package")
    if build_log["command"] != list(_CLEAN_BUILD_COMMAND):
        raise evidence.EvidenceError("clean build log does not carry the exact clean build command")
    if build_log["clean_tree"] is not True:
        raise evidence.EvidenceError("clean build log does not attest a clean working tree")
    if type(build_log["exit_code"]) is not int or build_log["exit_code"] != 0:
        raise evidence.EvidenceError("clean build log does not record a zero exit")
    _bounded_base64(
        build_log["combined_output"], "clean build log.combined_output",
        maximum=_BUILD_LOG_OUTPUT_BYTES,
    )
    if build_log["subjects"] != expected:
        raise evidence.EvidenceError("clean build log does not reconcile the sdist and wheel bytes")


def _package_install_owner(
    report: dict, *, artifact_name: str, digest: str, gate: dict,
) -> dict:
    """Resolve one install artifact to its sole signed P0 collector fact."""
    owners = [
        instance for instance in report["instances"]
        if {"digest": digest, "name": artifact_name} in instance["artifacts"]
    ]
    if len(owners) != 1:
        raise evidence.EvidenceError(
            "package install artifact is not referenced by one exact signed gate evidence instance"
        )
    owner = owners[0]
    if owner["lane"] != "P0-package-supply" or owner["environment"] != gate["environment"]:
        raise evidence.EvidenceError(
            "package install artifact is attributed to the wrong signed P0 environment"
        )
    return owner


def _package_install_interval(
    doc: dict, *, owner: dict, gate: dict, name: str,
) -> None:
    started = _timestamp(doc["started_at"], f"{name}.started_at")
    finished = _timestamp(doc["finished_at"], f"{name}.finished_at")
    if not (
        _timestamp(gate["started_at"], "package install gate.started_at")
        <= started <= finished
        <= _timestamp(gate["finished_at"], "package install gate.finished_at")
    ):
        raise evidence.EvidenceError("package install artifact lies outside its signed gate interval")
    if not (
        _timestamp(owner["started_at"], "package install owner.started_at")
        <= started <= finished
        <= _timestamp(owner["finished_at"], "package install owner.finished_at")
    ):
        raise evidence.EvidenceError(
            "package install artifact lies outside its signed evidence instance interval"
        )


def _package_install_common(
    doc: dict, *, identity: dict, owner: dict, name: str,
) -> tuple[str, str, str]:
    if (doc["candidate_identity_digest"] != evidence.canonical_digest(identity) or
            doc["gate_id"] != "C-PACKAGE-INSTALL" or doc["release"] != RELEASE or
            doc["package"] != {"name": "quarry-recon", "version": RELEASE}):
        raise evidence.EvidenceError(f"{name} is bound to the wrong candidate, gate, release or package")
    if doc["evidence_instance_id"] != owner["id"] or doc["environment"] != owner["environment"]:
        raise evidence.EvidenceError(
            f"{name} does not bind its exact signed P0 evidence instance/environment"
        )
    checkout = _absolute_posix_path(doc["checkout_root"], f"{name}.checkout_root")
    prefix = _absolute_posix_path(doc["install_prefix"], f"{name}.install_prefix")
    cwd = _absolute_posix_path(doc["invocation_cwd"], f"{name}.invocation_cwd")
    if (_is_within_path(prefix, checkout) or _is_within_path(checkout, prefix) or
            _is_within_path(cwd, checkout) or _is_within_path(cwd, prefix) or
            cwd == checkout or cwd == prefix or checkout == prefix):
        raise evidence.EvidenceError(
            f"{name} does not use a disposable install prefix and invocation cwd outside checkout/prefix"
        )
    return checkout, prefix, cwd


def _validate_package_install_artifacts(
    gate: dict, bodies: Mapping[str, bytes], *, identity: dict, report: dict,
    resolver: ArtifactResolver,
) -> None:
    """Reconcile retained P0 install facts without probing the collector filesystem.

    Install paths are treated solely as signed collector facts.  Aggregation uses
    lexical path checks and the pinned artifact resolver; it never follows or
    stats a collector path.  The external trusted P0 collector and signing step
    remain required before a real release can be nominated.
    """
    wheel_record = resolver.record("C-PACKAGE-BUILD", "wheel")
    wheel = resolver.read("C-PACKAGE-BUILD", "wheel")
    if wheel_record["digest"] != raw_sha256(wheel) or wheel_record["size"] != len(wheel):
        raise evidence.EvidenceError("retained C-PACKAGE-BUILD wheel bytes do not match their index")

    inventory_body = bodies["install-inventory"]
    inventory_digest = raw_sha256(inventory_body)
    inventory = _object(
        _artifact_document(inventory_body, "C-PACKAGE-INSTALL", "install-inventory"),
        "package install inventory",
        {
            "artifact_type", "candidate_identity_digest", "checkout_root", "environment",
            "evidence_instance_id", "files", "gate_id", "install_prefix", "invocation_cwd",
            "package", "release", "schema_version", "source_wheel", "started_at",
            "finished_at",
        },
    )
    if (inventory["artifact_type"] != "package-install-inventory" or
            inventory["schema_version"] != PACKAGE_INSTALL_INVENTORY_SCHEMA):
        raise evidence.EvidenceError("package install inventory uses the wrong dedicated schema variant")
    inventory_owner = _package_install_owner(
        report, artifact_name="install-inventory", digest=inventory_digest, gate=gate,
    )
    checkout, prefix, cwd = _package_install_common(
        inventory, identity=identity, owner=inventory_owner, name="package install inventory",
    )
    _package_install_interval(
        inventory, owner=inventory_owner, gate=gate, name="package install inventory",
    )
    wheel_subject = _object(inventory["source_wheel"], "package install inventory.source_wheel", {
        "digest", "size",
    })
    if wheel_subject != {"digest": wheel_record["digest"], "size": wheel_record["size"]}:
        raise evidence.EvidenceError(
            "package install inventory source wheel does not match retained C-PACKAGE-BUILD wheel bytes"
        )
    files = _array(inventory["files"], "package install inventory.files")
    if not 1 <= len(files) <= _INSTALL_FILE_COUNT:
        raise evidence.EvidenceError("package install inventory file count exceeds its bounded contract")
    file_by_path: dict[str, dict] = {}
    total_size = 0
    for index, file in enumerate(files):
        item = _object(file, f"package install inventory.files[{index}]", {"digest", "path", "size"})
        path = _absolute_posix_path(item["path"], f"package install inventory.files[{index}].path")
        _digest(item["digest"], f"package install inventory.files[{index}].digest")
        size = _integer(item["size"], f"package install inventory.files[{index}].size")
        if not _is_within_path(path, prefix):
            raise evidence.EvidenceError("package install inventory file is outside the install prefix")
        file_by_path[path] = {"digest": item["digest"], "size": size}
        total_size += size
    if [file["path"] for file in files] != sorted(file_by_path) or len(file_by_path) != len(files):
        raise evidence.EvidenceError("package install inventory files must be sorted and unique by absolute path")
    if total_size > _INSTALL_FILE_BYTES:
        raise evidence.EvidenceError("package install inventory retained bytes exceed the bounded contract")
    record_suffix = f"/quarry_recon-{RELEASE}.dist-info/RECORD"
    record_paths = [path for path in file_by_path if path.endswith(record_suffix)]
    if len(record_paths) != 1:
        raise evidence.EvidenceError("package install inventory must retain one exact installed package RECORD")
    record_path = record_paths[0]
    site_root = record_path[:-len(record_suffix)]
    if not _is_within_path(site_root, prefix):
        raise evidence.EvidenceError("package install inventory site-packages root is outside the install prefix")
    _validate_wheel(wheel)
    try:
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            source_files = {}
            for info in archive.infolist():
                if info.is_dir():
                    raise evidence.EvidenceError("source wheel contains a directory member")
                member = _path(info.filename, "source wheel member")
                if member in source_files:
                    raise evidence.EvidenceError("source wheel contains duplicate file members")
                if member == record_suffix[1:]:
                    continue
                body = archive.read(info)
                source_files[member] = {"digest": raw_sha256(body), "size": len(body)}
    except (OSError, zipfile.BadZipFile) as exc:
        raise evidence.EvidenceError(f"source wheel cannot be reopened for install reconciliation: {exc}") from exc
    expected_files = {
        f"{site_root}/{member}": fact for member, fact in source_files.items()
    }
    allowed_generated = {
        record_path,
        f"{prefix}/bin/quarry",
        f"{site_root}/quarry_recon-{RELEASE}.dist-info/INSTALLER",
        f"{site_root}/quarry_recon-{RELEASE}.dist-info/REQUESTED",
        f"{site_root}/quarry_recon-{RELEASE}.dist-info/direct_url.json",
    }
    if set(file_by_path) != set(expected_files) | allowed_generated:
        raise evidence.EvidenceError(
            "package install inventory file set does not reconcile retained wheel and exact pip outputs"
        )
    for path, fact in expected_files.items():
        if file_by_path[path] != fact:
            raise evidence.EvidenceError(
                "package install inventory source-wheel file does not match retained wheel bytes"
            )
    smoke_body = bodies["smoke-results"]
    smoke = _object(
        _artifact_document(smoke_body, "C-PACKAGE-INSTALL", "smoke-results"),
        "package install smoke results",
        {
            "artifact_type", "candidate_identity_digest", "cases", "checkout_root", "environment",
            "evidence_instance_id", "finished_at", "gate_id", "install_inventory_digest",
            "install_prefix", "invocation_cwd", "package", "release", "schema_version",
            "source_wheel", "started_at",
        },
    )
    if (smoke["artifact_type"] != "package-install-smoke-results" or
            smoke["schema_version"] != PACKAGE_INSTALL_SMOKE_SCHEMA):
        raise evidence.EvidenceError("package install smoke results use the wrong dedicated schema variant")
    smoke_owner = _package_install_owner(
        report, artifact_name="smoke-results", digest=raw_sha256(smoke_body), gate=gate,
    )
    smoke_checkout, smoke_prefix, smoke_cwd = _package_install_common(
        smoke, identity=identity, owner=smoke_owner, name="package install smoke results",
    )
    _package_install_interval(
        smoke, owner=smoke_owner, gate=gate, name="package install smoke results",
    )
    if (smoke_owner["id"] != inventory_owner["id"] or
            (smoke_checkout, smoke_prefix, smoke_cwd) != (checkout, prefix, cwd) or
            smoke["source_wheel"] != wheel_subject or
            smoke["install_inventory_digest"] != inventory_digest):
        raise evidence.EvidenceError(
            "package install smoke results do not bind the exact inventory, wheel and P0 execution context"
        )
    cases = _array(smoke["cases"], "package install smoke results.cases")
    if [case.get("id") if type(case) is dict else None for case in cases] != list(_INSTALL_CASE_ROSTER):
        raise evidence.EvidenceError("package install smoke cases do not use the exact ordered roster")
    for index, case in enumerate(cases):
        item = _object(case, f"package install smoke results.cases[{index}]", {
            "details", "exit_code", "id", "output_bytes", "output_digest",
        })
        if item["exit_code"] != 0 or type(item["exit_code"]) is not int:
            raise evidence.EvidenceError("package install smoke case does not record a zero exit")
        _digest(item["output_digest"], "package install smoke case output digest")
        if _integer(item["output_bytes"], "package install smoke case output bytes") > _INSTALL_OUTPUT_BYTES:
            raise evidence.EvidenceError("package install smoke case output exceeds the bounded contract")
        expected_detail_members = (
            {"checkout_on_sys_path", "path", "version"}
            if item["id"] == "checkout-isolation" else {"path", "version"}
        )
        details = _object(
            item["details"], "package install smoke case details", expected_detail_members,
        )
        path = _absolute_posix_path(details["path"], "package install smoke case detail path")
        expected_path = {
            "import": f"{site_root}/quarry_recon/__init__.py",
            "packaged-data": f"{site_root}/quarry_recon/data/target.template.yaml",
            "absolute-installed-cli": f"{prefix}/bin/quarry",
            "checkout-isolation": f"{site_root}/quarry_recon/__init__.py",
        }[item["id"]]
        if path != expected_path:
            raise evidence.EvidenceError(
                "package install smoke case does not bind its exact installed module, resource or CLI path"
            )
        if not _is_within_path(path, prefix):
            raise evidence.EvidenceError("package install smoke module/resource/CLI path is outside the install prefix")
        if path not in file_by_path:
            raise evidence.EvidenceError(
                "package install smoke module/resource/CLI path is absent from the retained installed-file inventory"
            )
        if details["version"] != RELEASE:
            raise evidence.EvidenceError("package install smoke case identifies the wrong package version")
        if item["id"] == "checkout-isolation" and details["checkout_on_sys_path"] is not False:
            raise evidence.EvidenceError(
                "package install checkout-isolation case does not prove checkout absence from sys.path"
            )


def _statistic(values: Sequence[int], kind: str) -> int:
    ordered = sorted(values)
    if not ordered:
        raise evidence.EvidenceError("benchmark statistic has no raw trial values")
    if kind == "minimum":
        return ordered[0]
    if kind == "maximum":
        return ordered[-1]
    if kind == "median":
        return ordered[(len(ordered) - 1) // 2]
    if kind == "p95":
        return ordered[(95 * len(ordered) + 99) // 100 - 1]
    raise evidence.EvidenceError("benchmark statistic is unsupported")


def _validate_benchmark_artifacts(
    gate: dict, bodies: Mapping[str, bytes], *, identity: dict, report: dict,
    thresholds: dict,
) -> None:
    gate_id = gate["gate_id"]
    benchmark = report["benchmark"]
    if benchmark is None:
        raise evidence.EvidenceError("performance evidence has no benchmark context")
    benchmark_digest = evidence.canonical_digest(benchmark)
    expected_thresholds = [row for row in thresholds["thresholds"] if row["gate_id"] == gate_id]

    baseline = _object(
        _artifact_document(bodies["benchmark-baseline"], gate_id, "benchmark-baseline"),
        "benchmark baseline",
        {"artifact_type", "gate_id", "metrics", "release", "schema_version"},
    )
    if baseline["artifact_type"] != "benchmark-baseline" or \
            baseline["schema_version"] != BENCHMARK_BASELINE_SCHEMA or \
            baseline["release"] != RELEASE or baseline["gate_id"] != gate_id:
        raise evidence.EvidenceError("benchmark baseline is bound to the wrong gate")
    regression_rows = [row for row in expected_thresholds if row["class"] == "regression"]
    expected_baseline_digest = raw_sha256(bodies["benchmark-baseline"])
    if not regression_rows or any(
        row["baseline_digest"] != expected_baseline_digest for row in regression_rows
    ):
        raise evidence.EvidenceError("regression threshold baseline is absent or does not rehash")
    baseline_metrics = _array(baseline["metrics"], "benchmark baseline.metrics")
    expected_baseline_keys = [(row["metric"], row["unit"]) for row in regression_rows]
    observed_baseline_keys = []
    baseline_values: dict[str, int] = {}
    for index, metric in enumerate(baseline_metrics):
        item = _object(metric, f"benchmark baseline.metrics[{index}]", {
            "metric", "unit", "value",
        })
        _token(item["metric"], "benchmark baseline metric")
        _token(item["unit"], "benchmark baseline unit")
        value = _integer(item["value"], "benchmark baseline value")
        if value == 0:
            raise evidence.EvidenceError("regression benchmark baseline must be nonzero")
        observed_baseline_keys.append((item["metric"], item["unit"]))
        baseline_values[item["metric"]] = value
    if observed_baseline_keys != expected_baseline_keys:
        raise evidence.EvidenceError("benchmark baseline does not cover the exact regression metrics")

    trials = _object(
        _artifact_document(bodies["raw-trials"], gate_id, "raw-trials"),
        "benchmark raw trials",
        {
            "artifact_type", "benchmark_digest", "candidate_identity_digest", "gate_id",
            "release", "resource_limits_observed", "schema_version", "trials",
            "warmup_runs",
        },
    )
    if trials["artifact_type"] != "benchmark-trials" or \
            trials["schema_version"] != BENCHMARK_TRIALS_SCHEMA or \
            trials["release"] != RELEASE or \
            trials["gate_id"] != gate_id or trials["benchmark_digest"] != benchmark_digest or \
            trials["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("raw benchmark trials are bound to the wrong execution contract")
    if trials["warmup_runs"] != benchmark["warmup_runs"]:
        raise evidence.EvidenceError("raw benchmark trials omit the accepted warmup protocol")
    observed_resources = _object(
        trials["resource_limits_observed"], "benchmark observed resources",
        {"cpu_millicores", "disk_bytes", "memory_bytes"},
    )
    for field, accepted in benchmark["resource_limits"].items():
        observed = _integer(observed_resources[field], f"benchmark observed {field}")
        if observed > accepted:
            raise evidence.EvidenceError("benchmark execution exceeded an accepted resource limit")
    trial_rows = _array(trials["trials"], "benchmark raw trials.trials")
    if len(trial_rows) != benchmark["repetitions"]:
        raise evidence.EvidenceError("raw benchmark trial count does not match the accepted manifest")
    expected_metric_keys = [(row["class"], row["metric"], row["unit"])
                            for row in expected_thresholds]
    values_by_key = {key: [] for key in expected_metric_keys}
    for trial_index, trial in enumerate(trial_rows):
        item = _object(trial, f"benchmark raw trials.trials[{trial_index}]", {
            "id", "metrics",
        })
        if item["id"] != f"trial-{trial_index:03d}":
            raise evidence.EvidenceError("raw benchmark trials are missing or reordered")
        metrics = _array(item["metrics"], "benchmark raw trial metrics")
        observed_keys = []
        for metric_index, metric in enumerate(metrics):
            value = _object(metric, f"benchmark raw trial metric {metric_index}", {
                "baseline_value", "class", "current_value", "metric", "unit", "value",
            })
            key = (value["class"], value["metric"], value["unit"])
            observed_keys.append(key)
            current = _integer(value["current_value"], "benchmark current value")
            observed = _integer(value["value"], "benchmark observed value")
            if value["class"] == "absolute":
                if value["baseline_value"] is not None or observed != current:
                    raise evidence.EvidenceError("absolute trial metric is not its observed raw value")
            elif value["class"] == "regression":
                baseline_value = _integer(value["baseline_value"], "benchmark trial baseline")
                if baseline_values.get(value["metric"]) != baseline_value:
                    raise evidence.EvidenceError("raw trial does not bind the resolved regression baseline")
                numerator = (current - baseline_value) * 10_000
                derived = max(0, numerator // baseline_value)
                if observed != derived:
                    raise evidence.EvidenceError("regression trial value is not derived in basis points")
            else:
                raise evidence.EvidenceError("raw benchmark trial has an unsupported threshold class")
            if key in values_by_key:
                values_by_key[key].append(observed)
        if observed_keys != expected_metric_keys:
            raise evidence.EvidenceError("raw trial does not contain the exact benchmark metrics")

    invalidations = _object(
        _artifact_document(
            bodies["trial-invalidations"], gate_id, "trial-invalidations",
        ),
        "benchmark trial invalidations",
        {
            "artifact_type", "benchmark_digest", "candidate_identity_digest", "gate_id",
            "invalidations", "raw_trials_digest", "release", "schema_version",
        },
    )
    expected_invalidation_header = {
        "artifact_type": "benchmark-invalidations",
        "benchmark_digest": benchmark_digest,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": gate_id,
        "raw_trials_digest": raw_sha256(bodies["raw-trials"]),
        "release": RELEASE,
        "schema_version": BENCHMARK_INVALIDATIONS_SCHEMA,
    }
    if any(invalidations[field] != value for field, value in expected_invalidation_header.items()):
        raise evidence.EvidenceError(
            "passing benchmark has missing or unrelated retained trials"
        )
    invalidation_rows = _array(invalidations["invalidations"], "benchmark invalidations")
    for index, invalidation in enumerate(invalidation_rows):
        item = _object(invalidation, f"benchmark invalidations[{index}]", {
            "id", "reason", "superseded_trials", "superseded_trials_digest",
        })
        _token(item["id"], "benchmark invalidation id")
        _string(item["reason"], "benchmark invalidation reason")
        _digest(item["superseded_trials_digest"], "superseded trial-set digest")
        if item["superseded_trials_digest"] == invalidations["raw_trials_digest"]:
            raise evidence.EvidenceError("current complete trial set cannot be marked invalidated")
        superseded = _object(
            item["superseded_trials"], "retained superseded benchmark trials",
            {
                "artifact_type", "benchmark_digest", "candidate_identity_digest", "gate_id",
                "release", "resource_limits_observed", "schema_version", "trials",
                "warmup_runs",
            },
        )
        if (superseded["artifact_type"] != "benchmark-trials" or
                superseded["benchmark_digest"] != benchmark_digest or
                superseded["candidate_identity_digest"] != evidence.canonical_digest(identity) or
                superseded["gate_id"] != gate_id or superseded["release"] != RELEASE or
                superseded["schema_version"] != BENCHMARK_TRIALS_SCHEMA or
                item["superseded_trials_digest"] != raw_sha256(canonical_json_line(superseded))):
            raise evidence.EvidenceError("invalidated raw trial set is not retained and rehashed")
        _integer(superseded["warmup_runs"], "retained superseded warmup count")
        superseded_resources = _object(
            superseded["resource_limits_observed"], "retained superseded resources",
            {"cpu_millicores", "disk_bytes", "memory_bytes"},
        )
        for field, value in superseded_resources.items():
            _integer(value, f"retained superseded resource {field}")
        superseded_rows = _array(superseded["trials"], "retained superseded trials")
        if not superseded_rows or len(superseded_rows) > 1000:
            raise evidence.EvidenceError(
                "invalidated raw trial set has a noncanonical retained trial count"
            )
        for trial_index, trial in enumerate(superseded_rows):
            trial_doc = _object(trial, f"retained superseded trial {trial_index}", {
                "id", "metrics",
            })
            if trial_doc["id"] != f"trial-{trial_index:03d}":
                raise evidence.EvidenceError("retained superseded trials are missing or reordered")
            metrics = _array(trial_doc["metrics"], "retained superseded trial metrics")
            if not metrics:
                raise evidence.EvidenceError("retained superseded trial contains no metrics")
            for metric_index, metric in enumerate(metrics):
                metric_doc = _object(
                    metric, f"retained superseded trial metric {metric_index}",
                    {
                        "baseline_value", "class", "current_value", "metric", "unit",
                        "value",
                    },
                )
                if metric_doc["class"] not in {"absolute", "regression"}:
                    raise evidence.EvidenceError("retained superseded metric class is unsupported")
                _token(metric_doc["metric"], "retained superseded metric")
                _token(metric_doc["unit"], "retained superseded metric unit")
                _integer(metric_doc["current_value"], "retained superseded current value")
                _integer(metric_doc["value"], "retained superseded observed value")
                if metric_doc["baseline_value"] is not None:
                    _integer(metric_doc["baseline_value"], "retained superseded baseline value")
    _unique(invalidation_rows, "id", "benchmark invalidations")

    recomputed = []
    for threshold in expected_thresholds:
        key = (threshold["class"], threshold["metric"], threshold["unit"])
        recomputed.append({
            "baseline_digest": threshold["baseline_digest"],
            "class": threshold["class"],
            "invalidated_trials": 0,
            "metric": threshold["metric"],
            "observed_trials": benchmark["repetitions"],
            "statistic": threshold["statistic"],
            "unit": threshold["unit"],
            "value": _statistic(values_by_key[key], threshold["statistic"]),
        })
    if report["measurements"] != recomputed:
        raise evidence.EvidenceError("benchmark summary does not recompute from its raw trials")

    benchmark_report = _object(
        _artifact_document(bodies["benchmark-report"], gate_id, "benchmark-report"),
        "benchmark report",
        {
            "artifact_type", "baseline_digest", "benchmark_digest",
            "candidate_identity_digest", "gate_id", "measurements", "raw_trials_digest",
            "release", "schema_version", "trial_invalidations_digest",
        },
    )
    expected_report = {
        "artifact_type": "benchmark-report",
        "baseline_digest": expected_baseline_digest,
        "benchmark_digest": benchmark_digest,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": gate_id,
        "measurements": recomputed,
        "raw_trials_digest": raw_sha256(bodies["raw-trials"]),
        "release": RELEASE,
        "schema_version": BENCHMARK_REPORT_SCHEMA,
        "trial_invalidations_digest": raw_sha256(bodies["trial-invalidations"]),
    }
    if benchmark_report != expected_report:
        raise evidence.EvidenceError("benchmark report does not reconcile its retained trial artifacts")


def _validate_sbom(
    body: bytes, *, identity: dict, support: dict, package_wheel_body: bytes,
) -> None:
    doc = _object(
        _artifact_document(body, "C-SBOM", "sbom"),
        "SBOM",
        {
            "artifact_type", "candidate_identity_digest", "components",
            "dependency_graph_digest", "gate_id", "package", "release", "schema_version",
        },
    )
    if doc["artifact_type"] != "sbom" or \
            doc["schema_version"] != GATE_ARTIFACT_SCHEMA or doc["release"] != RELEASE or \
            doc["gate_id"] != "C-SBOM" or \
            doc["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("SBOM is bound to the wrong candidate or contract")
    if doc["package"] != {"name": "quarry-recon", "version": RELEASE}:
        raise evidence.EvidenceError("SBOM identifies the wrong nominated package")
    _digest(doc["dependency_graph_digest"], "SBOM dependency graph digest")
    requirements = _metadata_values(
        _wheel_metadata(package_wheel_body), "Requires-Dist", "wheel",
    )
    if not requirements:
        raise evidence.EvidenceError("candidate wheel metadata has no dependency set")
    declared_dependencies = {}
    for requirement in requirements:
        match = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", requirement)
        if match is None:
            raise evidence.EvidenceError("candidate package dependency is not canonical")
        normalized = match.group(0).lower().replace("_", "-").replace(".", "-")
        if normalized in declared_dependencies:
            raise evidence.EvidenceError("candidate package dependencies contain a duplicate name")
        declared_dependencies[normalized] = requirement
    components = _array(doc["components"], "SBOM.components")
    observed: list[tuple[str, str]] = []
    for index, component in enumerate(components):
        item = _object(component, f"SBOM.components[{index}]", {
            "content_digest", "declared_requirement", "license", "name", "relationship",
            "version",
        })
        _token(item["name"], "SBOM component name")
        _string(item["version"], "SBOM component version")
        _string(item["license"], "SBOM component license")
        _digest(item["content_digest"], "SBOM component content digest")
        if item["relationship"] not in {"dependency", "project", "template", "tool"}:
            raise evidence.EvidenceError("SBOM component relationship is unsupported")
        if item["declared_requirement"] is not None:
            _string(item["declared_requirement"], "SBOM declared requirement")
        observed.append((item["relationship"], item["name"]))
    if not components or observed != sorted(observed) or len(observed) != len(set(observed)):
        raise evidence.EvidenceError("SBOM components must be non-empty, sorted and unique")
    required = {
        ("project", "quarry-recon", RELEASE, identity["source_tree_digest"]),
        *(("tool", row["name"], row["version"], row["digest"]) for row in support["tools"]),
        *(("template", row["name"], row["version"], row["digest"])
          for row in support["template_sets"]),
    }
    actual = {
        (row["relationship"], row["name"], row["version"], row["content_digest"])
        for row in components
    }
    if not required.issubset(actual):
        raise evidence.EvidenceError("SBOM omits the project or accepted bundled tool/template inventory")
    direct = {
        row["name"].lower().replace("_", "-").replace(".", "-"): row["declared_requirement"]
        for row in components if row["relationship"] == "dependency" and
        row["declared_requirement"] is not None
    }
    if direct != declared_dependencies:
        raise evidence.EvidenceError("SBOM does not reconcile every declared direct dependency")


def _package_subjects(resolver: ArtifactResolver) -> list[dict]:
    return [{
        "digest": resolver.record("C-PACKAGE-BUILD", name)["digest"],
        "name": name,
    } for name in ("sdist", "wheel")]


def _validate_provenance_artifacts(
    bodies: Mapping[str, bytes], *, gate: dict, identity: dict, resolver: ArtifactResolver,
    policy: dict,
) -> None:
    provenance = _object(
        _artifact_document(bodies["provenance"], "C-PROVENANCE", "provenance"),
        "provenance",
        {
            "artifact_type", "builder", "candidate_identity_digest", "gate_id", "materials",
            "release", "schema_version", "subjects",
        },
    )
    expected_materials = [{
        "digest": evidence.canonical_digest(identity),
        "name": "candidate-identity",
    }] + [{"digest": row["digest"], "name": row["name"]} for row in identity["inputs"]]
    expected_materials.sort(key=lambda row: row["name"])
    expected_builder = {
        "environment": gate["environment"],
        "toolchain": gate["toolchain"],
    }
    if provenance != {
        "artifact_type": "provenance",
        "builder": expected_builder,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-PROVENANCE",
        "materials": expected_materials,
        "release": RELEASE,
        "schema_version": GATE_ARTIFACT_SCHEMA,
        "subjects": _package_subjects(resolver),
    }:
        raise evidence.EvidenceError("provenance does not bind the candidate, builder, inputs and packages")
    envelope = _artifact_document(
        bodies["signature-verification"], "C-PROVENANCE", "signature-verification",
    )
    verify_signature_envelope(
        envelope,
        policy=policy,
        payload_digest=raw_sha256(bodies["provenance"]),
        candidate_identity_digest=evidence.canonical_digest(identity),
        role="gate",
        at=_timestamp(gate["finished_at"], "gate.finished_at"),
        gate_id="C-PROVENANCE",
    )


def _publication_subjects(scope: dict, resolver: ArtifactResolver) -> list[dict]:
    subjects = []
    for gate_id, name, media_type in (
        ("C-PACKAGE-BUILD", "sdist", "application/gzip"),
        ("C-PACKAGE-BUILD", "wheel", "application/zip"),
        ("C-SBOM", "sbom", "application/json"),
        ("C-PROVENANCE", "provenance", "application/json"),
    ):
        record = resolver.record(gate_id, name)
        subjects.append({
            "digest": record["digest"],
            "media_type": media_type,
            "name": f"{gate_id}/{name}",
        })
    for binding in scope["input_bindings"]:
        if binding["name"].endswith("-schema"):
            subjects.append({
                "digest": binding["digest"],
                "media_type": "application/schema+json",
                "name": binding["name"],
            })
    return sorted(subjects, key=lambda row: row["name"])


def _validate_publication_subjects(
    body: bytes, *, identity: dict, scope: dict, resolver: ArtifactResolver,
) -> None:
    doc = _object(
        _artifact_document(body, "E-ARTIFACTS", "publication-subjects"),
        "publication subjects",
        {
            "artifact_type", "candidate_identity_digest", "gate_id", "release",
            "schema_version", "subjects",
        },
    )
    expected = {
        "artifact_type": "publication-subjects",
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "E-ARTIFACTS",
        "release": RELEASE,
        "schema_version": PUBLICATION_SUBJECTS_SCHEMA,
        "subjects": _publication_subjects(scope, resolver),
    }
    if doc != expected:
        raise evidence.EvidenceError(
            "publication subjects do not reconcile package, SBOM, provenance and schemas"
        )


def _semantic_package_build(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_package_artifacts(bodies, identity=context["identity"])


def _semantic_package_install(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_package_install_artifacts(
        gate,
        bodies,
        identity=context["identity"],
        report=context["report"],
        resolver=context["resolver"],
    )


def _semantic_benchmark(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_benchmark_artifacts(
        gate,
        bodies,
        identity=context["identity"],
        report=context["report"],
        thresholds=context["thresholds"],
    )


def _resource_threshold_policy(thresholds: dict, gate_id: str) -> dict[str, dict]:
    """Resolve the resource parser policy from the reviewed threshold manifest.

    The resource report carries a copy of these values for audit readability,
    but that copy is never authority.  Aggregation has already strict-validated
    and signature-checked ``thresholds`` before an obligation verifier runs.
    """
    required = resource_contract._GATE_METRICS.get(gate_id)
    if required is None:
        raise evidence.EvidenceError("resource threshold policy requested for an unsupported gate")
    rows = [row for row in thresholds["thresholds"] if row["gate_id"] == gate_id]
    if [row["metric"] for row in rows] != list(required):
        raise evidence.EvidenceError(
            "reviewed threshold manifest does not exactly cover the resource gate metrics"
        )
    policy = {}
    for row in rows:
        metric = row["metric"]
        if row["limit"] is None:
            raise evidence.EvidenceError("resource gate has an unresolved reviewed threshold")
        expected_class = "regression" if metric.endswith("_delta") else "absolute"
        if row["class"] != expected_class:
            raise evidence.EvidenceError("resource threshold changes its frozen threshold class")
        policy[metric] = {
            "operator": row["operator"],
            "statistic": row["statistic"],
            "unit": row["unit"],
            "limit": row["limit"],
            "baseline_digest": row["baseline_digest"],
        }
    return policy


def _resource_trace_digests(
    gate_id: str, bodies: Mapping[str, bytes], resolver: ArtifactResolver,
) -> list[str]:
    """Return the exact signed/indexed artifacts every resource trial must cite."""
    names = [
        name for name, _media_type in required_artifact_contract(gate_id)
        if name != "resource-gate-report"
    ]
    digests = []
    for name in names:
        if name not in bodies:
            raise evidence.EvidenceError(
                f"resource report has no retained supporting body for {gate_id}/{name}"
            )
        record = resolver.record(gate_id, name)
        observed = raw_sha256(bodies[name])
        if record["digest"] != observed:
            raise evidence.EvidenceError(
                f"resource report trace body does not match indexed {gate_id}/{name}"
            )
        digests.append(observed)
    if len(digests) != len(set(digests)):
        raise evidence.EvidenceError(
            "resource trial artifacts do not have unique signed content identities"
        )
    return sorted(digests)


def _reconcile_resource_measurements(
    resource_report: dict, *, report: dict, thresholds: dict,
) -> None:
    gate_id = resource_report["gate_id"]
    threshold_rows = [
        row for row in thresholds["thresholds"] if row["gate_id"] == gate_id
    ]
    resource_rows = resource_report["measurements"]
    summary_rows = report["measurements"]
    expected_metrics = [row["metric"] for row in threshold_rows]
    if ([row["metric"] for row in resource_rows] != expected_metrics or
            [row["metric"] for row in summary_rows] != expected_metrics):
        raise evidence.EvidenceError(
            "resource measurements do not preserve reviewed threshold order and coverage"
        )
    for threshold, resource_row, summary in zip(
        threshold_rows, resource_rows, summary_rows, strict=True,
    ):
        if resource_row["value"] != summary["value"]:
            raise evidence.EvidenceError(
                "resource measurement does not reconcile the gate evidence/raw trials"
            )
        expected_summary = {
            "baseline_digest": threshold["baseline_digest"],
            "class": threshold["class"],
            "metric": threshold["metric"],
            "statistic": threshold["statistic"],
            "unit": threshold["unit"],
        }
        observed_summary = {
            key: summary[key] for key in expected_summary
        }
        if observed_summary != expected_summary:
            raise evidence.EvidenceError(
                "resource measurement is bound to a different reviewed threshold"
            )


def _validate_resource_gate_report(
    gate: dict, bodies: Mapping[str, bytes], *, identity: dict, report: dict,
    resolver: ArtifactResolver, thresholds: dict,
) -> None:
    gate_id = gate["gate_id"]
    if gate_id not in RESOURCE_SEMANTIC_GATES:
        raise evidence.EvidenceError("resource semantic adapter does not close this gate")
    body = bodies.get("resource-gate-report")
    if body is None:
        raise evidence.EvidenceError("resource gate has no resource-gate-report artifact")
    resource_digest = raw_sha256(body)
    owning_instances = [
        instance for instance in report["instances"]
        if {"digest": resource_digest, "name": "resource-gate-report"}
        in instance["artifacts"]
    ]
    if len(owning_instances) != 1:
        raise evidence.EvidenceError(
            "resource gate report is not attributed to one exact evidence instance"
        )
    owner = owning_instances[0]
    accepted_policy = _resource_threshold_policy(thresholds, gate_id)
    threshold_digest = raw_sha256(canonical_json_line(thresholds))
    benchmark = report["benchmark"]
    benchmark_digest = (
        evidence.canonical_digest(benchmark) if gate_id.startswith("C-PERF-")
        else None
    )
    try:
        parsed = resource_contract.read_gate_report(
            body,
            gate_id=gate_id,
            candidate_identity_digest=evidence.canonical_digest(identity),
            evidence_instance_id=owner["id"],
            threshold_manifest_digest=threshold_digest,
            benchmark_manifest_digest=benchmark_digest,
            accepted_thresholds=accepted_policy,
        )
    except resource_contract.ResourceContractError as exc:
        raise evidence.EvidenceError(f"resource gate report is not accepted: {exc}") from exc

    if parsed["evidence_instance_id"] != owner["id"]:
        raise evidence.EvidenceError(
            "resource gate report does not bind its exact signed evidence instance"
        )
    if owner["environment"] != gate["environment"]:
        raise evidence.EvidenceError(
            "resource gate report is attributed to different signed hardware/runtime identity"
        )
    if not (
        _timestamp(owner["started_at"], "resource owner.started_at")
        <= _timestamp(parsed["started_at"], "resource report.started_at")
        <= _timestamp(parsed["finished_at"], "resource report.finished_at")
        <= _timestamp(owner["finished_at"], "resource owner.finished_at")
    ):
        raise evidence.EvidenceError(
            "resource gate report lies outside its signed evidence instance"
        )

    expected_trace_digests = _resource_trace_digests(gate_id, bodies, resolver)
    for trial in parsed["trials"]:
        if trial["artifact_digests"] != expected_trace_digests:
            raise evidence.EvidenceError(
                "resource trial does not reconcile every signed indexed supporting artifact"
            )
    _reconcile_resource_measurements(parsed, report=report, thresholds=thresholds)


def _semantic_resource_fault(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_generic_supporting_artifact(
        bodies["fault-matrix"], gate_id=gate["gate_id"], name="fault-matrix",
        identity=context["identity"],
    )
    _validate_resource_gate_report(
        gate,
        bodies,
        identity=context["identity"],
        report=context["report"],
        resolver=context["resolver"],
        thresholds=context["thresholds"],
    )


def _semantic_resource_benchmark(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    # Baseline identity, retained raw repetitions, invalidations and summary
    # arithmetic remain the canonical performance authority.  The resource
    # report is an additional obligation-specific matrix, never a substitute.
    _semantic_benchmark(gate, bodies, **context)
    _validate_resource_gate_report(
        gate,
        bodies,
        identity=context["identity"],
        report=context["report"],
        resolver=context["resolver"],
        thresholds=context["thresholds"],
    )


def _semantic_network_denial(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_network_denial_report(
        bodies["network-denial-report"],
        identity=context["identity"], support=context["support"],
    )


def _semantic_v310_05(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Promote the frozen V310-05 artifact family without widening its contract."""
    gate_id = gate["gate_id"]
    candidate_digest = evidence.canonical_digest(context["identity"])
    v310_bodies = {
        kind: bodies[kind]
        for kind, _media_type in required_artifact_contract(gate_id)
    }
    try:
        reports = release_v310_05.verify_gate_artifacts(
            gate_id, v310_bodies, candidate_identity_digest=candidate_digest,
        )
    except release_v310_05.V31005EvidenceError as exc:
        raise evidence.EvidenceError(f"V310-05 evidence is not accepted: {exc}") from exc

    report = context["report"]
    gate_started = _timestamp(gate["started_at"], "V310-05 gate.started_at")
    gate_finished = _timestamp(gate["finished_at"], "V310-05 gate.finished_at")
    for kind, parsed in reports.items():
        digest = raw_sha256(bodies[kind])
        owners = [
            instance for instance in report["instances"]
            if {"digest": digest, "name": kind} in instance["artifacts"]
        ]
        if len(owners) != 1:
            raise evidence.EvidenceError(
                "V310-05 report is not referenced by one exact signed gate evidence instance"
            )
        if not (
            gate_started
            <= _timestamp(parsed["started_at"], "V310-05 report.started_at")
            <= _timestamp(parsed["finished_at"], "V310-05 report.finished_at")
            <= gate_finished
        ):
            raise evidence.EvidenceError("V310-05 report lies outside its signed gate interval")
        if not (
            _timestamp(owners[0]["started_at"], "V310-05 owner.started_at")
            <= _timestamp(parsed["started_at"], "V310-05 report.started_at")
            <= _timestamp(parsed["finished_at"], "V310-05 report.finished_at")
            <= _timestamp(owners[0]["finished_at"], "V310-05 owner.finished_at")
        ):
            raise evidence.EvidenceError(
                "V310-05 report lies outside its signed evidence instance interval"
            )


def _semantic_network_boundary(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_network_boundary_trace(
        bodies["network-boundary-trace"],
        identity=context["identity"], support=context["support"],
    )


def _semantic_sbom(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    resolver = context["resolver"]
    _validate_sbom(
        bodies["sbom"],
        identity=context["identity"],
        support=context["support"],
        package_wheel_body=resolver.read("C-PACKAGE-BUILD", "wheel"),
    )


def _semantic_provenance(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_provenance_artifacts(
        bodies,
        gate=gate,
        identity=context["identity"],
        resolver=context["resolver"],
        policy=context["policy"],
    )


def _semantic_publication_subjects(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_publication_subjects(
        bodies["publication-subjects"],
        identity=context["identity"],
        scope=context["scope"],
        resolver=context["resolver"],
    )


# These provisional parsers exercise the artifact-family substrate, but none is
# sufficient to close its whole normative obligation yet (for example transitive
# dependency closure belongs to later owners).
PROVISIONAL_SEMANTIC_VERIFIERS = MappingProxyType({
    "C-SBOM": _semantic_sbom,
    "C-PROVENANCE": _semantic_provenance,
    **{gate_id: _semantic_benchmark for gate_id in PERFORMANCE_OPERATIONS},
    "E-ARTIFACTS": _semantic_publication_subjects,
})


def _semantic_identity(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    expected = context["identity"]
    body = bodies["identity-verification"]
    observed = read_candidate_identity(body)
    if observed != expected or body != canonical_json_line(expected):
        raise evidence.EvidenceError(
            "identity-verification artifact is not the exact candidate identity"
        )


def _semantic_thresholds(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    expected = context["thresholds"]
    body = bodies["threshold-reconciliation"]
    observed = read_threshold_manifest(
        body,
        require_ready=True,
        trust_policy=context["policy"],
        trusted_policy_digest=context["trusted_policy_digest"],
    )
    if observed != expected or body != canonical_json_line(expected):
        raise evidence.EvidenceError(
            "threshold-reconciliation artifact is not the exact threshold manifest"
        )


def _semantic_support(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    expected = context["support"]
    body = bodies["support-reconciliation"]
    observed = read_support_matrix(
        body,
        require_ready=True,
        trust_policy=context["policy"],
        trusted_policy_digest=context["trusted_policy_digest"],
    )
    if observed != expected or body != canonical_json_line(expected):
        raise evidence.EvidenceError(
            "support-reconciliation artifact is not the exact support matrix"
        )


def _read_synthetic_corpus_disclosure_attestation(body: bytes) -> dict:
    """Read the candidate-independent public synthetic-corpus attestation."""
    doc = _object(
        _artifact_document(body, "A-CORPUS", "corpus-disclosure-report"),
        "synthetic corpus disclosure attestation",
        {
            "artifact_type", "checks", "corpus_gate_id", "derivation_tree_digests",
            "fixture_digest", "fixture_schema_digest", "release", "schema_version",
            "synthetic_value_inventory_digest",
        },
    )
    if (doc["artifact_type"] != "synthetic-corpus-disclosure-attestation" or
            doc["schema_version"] != GATE_ARTIFACT_SCHEMA or doc["release"] != RELEASE):
        raise evidence.EvidenceError("synthetic corpus disclosure attestation has unsupported identity")
    if doc["corpus_gate_id"] != "C-CORPUS-SYNTHETIC":
        raise evidence.EvidenceError("synthetic corpus disclosure attestation names the wrong corpus gate")
    _digest(doc["fixture_digest"], "synthetic corpus fixture digest")
    _digest(doc["fixture_schema_digest"], "synthetic corpus fixture schema digest")
    _digest(
        doc["synthetic_value_inventory_digest"],
        "synthetic corpus value inventory digest",
    )
    derivations = _array(
        doc["derivation_tree_digests"], "synthetic corpus derivation tree digests",
    )
    if len(derivations) != 2:
        raise evidence.EvidenceError("synthetic corpus attestation requires two isolated derivations")
    for digest in derivations:
        _digest(digest, "synthetic corpus derivation tree digest")
    if derivations != [doc["fixture_digest"], doc["fixture_digest"]]:
        raise evidence.EvidenceError(
            "synthetic corpus derivations do not both match the frozen fixture identity"
        )
    checks = _object(doc["checks"], "synthetic corpus disclosure checks", {
        "deterministic_derivation", "disclosure_review", "schema_validation",
    })
    if checks != {
        "deterministic_derivation": "pass",
        "disclosure_review": "pass",
        "schema_validation": "pass",
    }:
        raise evidence.EvidenceError("synthetic corpus disclosure checks are not all passing")
    return doc


def _semantic_corpus(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Bind the public synthetic disclosure attestation without private claims."""
    if gate["gate_id"] != "A-CORPUS":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("corpus semantic verifier received the wrong gate")
    corpus = context["corpus"]
    if not isinstance(corpus, dict):  # pragma: no cover - aggregate invariant
        raise evidence.EvidenceError("corpus verifier requires the accepted corpus manifest")
    selected = [row for row in corpus["sources"] if row["selected"]]
    if (len(selected) != 1 or selected[0]["gate_id"] != "C-CORPUS-SYNTHETIC" or
            selected[0]["kind"] != "synthetic" or
            selected[0]["fixture_digest"] is None or
            selected[0]["attestation_digest"] is None):
        raise evidence.EvidenceError("A-CORPUS has no unique selected synthetic corpus")
    attestation_body = bodies["corpus-disclosure-report"]
    if raw_sha256(attestation_body) != selected[0]["attestation_digest"]:
        raise evidence.EvidenceError(
            "synthetic corpus disclosure attestation does not match the frozen manifest digest"
        )
    attestation = _read_synthetic_corpus_disclosure_attestation(attestation_body)
    if attestation["fixture_digest"] != selected[0]["fixture_digest"]:
        raise evidence.EvidenceError(
            "synthetic corpus disclosure attestation names a different fixture identity"
        )


def _semantic_taxonomy(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Reconcile the one A-TAXONOMY artifact with its signed H0 collection."""
    if gate["gate_id"] != "A-TAXONOMY":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("taxonomy semantic verifier received the wrong gate")
    taxonomy = evidence.read_pytest_taxonomy(bodies["classification-manifest"])
    inputs = context["input_bodies"]
    if not isinstance(inputs, Mapping):  # pragma: no cover - aggregate invariant
        raise evidence.EvidenceError("taxonomy verifier requires verified scope input bodies")
    try:
        taxonomy_schema = evidence.load_json_bytes(inputs["pytest-taxonomy-schema"])
        job_map_schema = evidence.load_json_bytes(inputs["verification-job-map-schema"])
        workflow_body = inputs["verification-workflow-ci"]
        job_map_body = inputs["verification-job-map"]
    except KeyError as exc:  # pragma: no cover - frozen scope inventory invariant
        raise evidence.EvidenceError("taxonomy verifier is missing a frozen taxonomy input") from exc
    evidence._validate_registered_schema(
        taxonomy_schema,
        name="pytest-taxonomy",
        record_version=evidence.PYTEST_TAXONOMY_SCHEMA,
    )
    evidence._validate_registered_schema(
        job_map_schema,
        name="verification-job-map",
        record_version=evidence.VERIFICATION_JOB_MAP_SCHEMA,
    )
    evidence.read_verification_job_map(
        job_map_body,
        workflow_bodies={".github/workflows/ci.yml": workflow_body},
    )

    instances = context["report"]["instances"]
    if len(instances) != 1 or instances[0]["lane"] != "H0-hermetic":
        raise evidence.EvidenceError(
            "A-TAXONOMY requires exactly one H0 classification evidence instance"
        )
    instance = instances[0]
    if instance["environment"] != gate["environment"]:
        raise evidence.EvidenceError(
            "taxonomy evidence instance does not match the signed H0 environment"
        )
    selection = taxonomy["selection"]
    if selection["mark_expression"] != "offline" or selection["keyword_expression"] != "":
        raise evidence.EvidenceError(
            "A-TAXONOMY must collect the exact offline marker with no keyword filter"
        )
    selected_by_lane = {
        record["lane"]: record["selected"] for record in selection["selected_by_lane"]
    }
    if selection["selected"] == 0 or selected_by_lane["H0-hermetic"] != selection["selected"] or \
            any(count for lane, count in selected_by_lane.items() if lane != "H0-hermetic"):
        raise evidence.EvidenceError(
            "A-TAXONOMY selection must contain only a positive H0 collection"
        )
    expected_counts = {
        "collected": selection["collected"],
        "deselected": selection["deselected"],
        "failed": 0,
        "passed": selection["selected"],
        "selected": selection["selected"],
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    if instance["selection"] != expected_counts or gate["selection"] != expected_counts:
        raise evidence.EvidenceError(
            "taxonomy collected/selected/deselected counts do not match signed evidence"
        )
    pytest_tools = [tool for tool in gate["toolchain"] if tool["name"] == "pytest"]
    if len(pytest_tools) != 1 or taxonomy["collector"]["version"] != pytest_tools[0]["version"]:
        raise evidence.EvidenceError(
            "taxonomy collector does not match the attested pytest toolchain"
        )
    if taxonomy["collector"]["python_version"] != instance["environment"]["python"]:
        raise evidence.EvidenceError(
            "taxonomy collector Python does not match the signed H0 environment"
        )


_H0_ISOLATION_ATTEMPTS = (
    "native-tool", "proxy", "resolver", "socket", "subprocess",
)


def _h0_environment(row: dict) -> dict:
    return {key: row[key] for key in (
        "architecture", "isolation_profile", "os", "python", "runner_image",
    )}


def _h0_artifact(
    body: bytes, *, name: str, artifact_type: str, identity: dict, members: set[str],
) -> dict:
    doc = _object(
        _artifact_document(body, "B-HERMETIC-ALL", name),
        f"B-HERMETIC-ALL {name}",
        {
            "artifact_type", "candidate_identity_digest", "gate_id", "name",
            "release", "schema_version", *members,
        },
    )
    expected_identity = {
        "artifact_type": artifact_type,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-HERMETIC-ALL",
        "name": name,
        "release": RELEASE,
        "schema_version": GATE_ARTIFACT_SCHEMA,
    }
    if any(doc[key] != value for key, value in expected_identity.items()):
        raise evidence.EvidenceError(
            f"B-HERMETIC-ALL {name} is bound to the wrong candidate, gate, release or name"
        )
    return doc


def _semantic_h0_hermetic_all(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Recompute the complete H0 roster, shard outcomes and isolation witnesses.

    This verifier intentionally does not make the current development H0 runner
    an isolation producer.  B-HERMETIC-ALL remains open until a candidate-qualified
    runner supplies the bound isolation-self-test artifact validated below.
    """
    if gate["gate_id"] != "B-HERMETIC-ALL":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("H0 hermetic verifier received the wrong gate")
    identity = context["identity"]
    support = context["support"]
    report = context["report"]
    if not isinstance(identity, dict) or not isinstance(support, dict) or not isinstance(report, dict):
        raise evidence.EvidenceError("H0 hermetic verifier requires accepted release context")
    expected_environments = [
        _h0_environment(row) for row in support["environments"]
        if row["lane"] == "H0-hermetic"
    ]
    if not expected_environments:
        raise evidence.EvidenceError("B-HERMETIC-ALL has no supported H0 environments")

    collection_body = bodies["collection-manifest"]
    taxonomy = evidence.read_pytest_taxonomy(collection_body)
    pytest_tools = [tool for tool in gate["toolchain"] if tool["name"] == "pytest"]
    if len(pytest_tools) != 1:
        raise evidence.EvidenceError("B-HERMETIC-ALL requires one exact pytest tool identity")
    selection = taxonomy["selection"]
    selected_by_lane = {
        row["lane"]: row["selected"] for row in selection["selected_by_lane"]
    }
    full_nodes = taxonomy["lanes"][0]["nodes"]
    if (selection["mark_expression"] != "offline" or
            selection["keyword_expression"] != "" or not full_nodes or
            selection["selected"] != len(full_nodes) or
            selected_by_lane["H0-hermetic"] != len(full_nodes) or
            any(value for lane, value in selected_by_lane.items()
                if lane != "H0-hermetic")):
        raise evidence.EvidenceError(
            "H0 collection taxonomy must select the positive complete offline roster"
        )
    collector = taxonomy["collector"]
    if (collector["python_version"] != gate["environment"]["python"] or
            collector["version"] != pytest_tools[0]["version"]):
        raise evidence.EvidenceError(
            "H0 collection taxonomy collector does not match the signed environment/toolchain"
        )

    inputs = context["input_bodies"]
    if not isinstance(inputs, Mapping):
        raise evidence.EvidenceError("H0 hermetic verifier requires frozen runner topology inputs")
    try:
        job_map = evidence.read_verification_job_map(
            inputs["verification-job-map"],
            workflow_bodies={".github/workflows/ci.yml": inputs["verification-workflow-ci"]},
        )
    except KeyError as exc:  # pragma: no cover - frozen scope invariant
        raise evidence.EvidenceError("H0 hermetic verifier is missing its runner topology") from exc
    offline_jobs = [row for row in job_map["jobs"] if row["lane"] == "H0-hermetic"]
    if (len(offline_jobs) != 1 or offline_jobs[0]["selection"] != {
        "keyword_expression": "", "mark_expression": "offline",
    }):
        raise evidence.EvidenceError("H0 runner topology must have one exact offline job")
    topology = []
    topology_ids = {}
    for instance in offline_jobs[0]["instances"]:
        matrix = {row["name"]: row["value"] for row in instance["matrix"]}
        if set(matrix) != {"python-version", "shard"}:
            raise evidence.EvidenceError("H0 runner topology has unexpected matrix dimensions")
        if not matrix["shard"].isdigit():
            raise evidence.EvidenceError("H0 runner topology has a non-numeric shard")
        topology.append((matrix["python-version"], matrix["shard"]))
        topology_ids[(matrix["python-version"], int(matrix["shard"]))] = instance["id"]
    expected_topology = [
        (python, str(shard)) for python in ("3.10", "3.12") for shard in range(6)
    ]
    if topology != expected_topology:
        raise evidence.EvidenceError("H0 runner topology is not the frozen 2x6 offline matrix")
    if [environment["python"].rsplit(".", 1)[0] for environment in expected_environments] != \
            ["3.10", "3.12"]:
        raise evidence.EvidenceError("H0 support environments do not match the frozen runner matrix")

    test_report = _h0_artifact(
        bodies["test-report"], name="test-report", artifact_type="h0-test-report",
        identity=identity, members={"collection_manifest_digest", "runs"},
    )
    if test_report["collection_manifest_digest"] != raw_sha256(collection_body):
        raise evidence.EvidenceError("H0 test report binds a different collection manifest")
    run_rows = _array(test_report["runs"], "H0 test report.runs")
    observed_run_environments = []
    logical_counts_by_environment: dict[tuple[str, ...], dict] = {}
    report_instance_by_environment = {
        tuple(instance["environment"][field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        )): instance["id"]
        for instance in report["instances"]
    }
    for run_index, record in enumerate(run_rows):
        run = _object(record, f"H0 test report.runs[{run_index}]", {
            "environment", "evidence_instance_id", "fragments",
        })
        environment = _object(
            run["environment"], f"H0 test report.runs[{run_index}].environment",
            {"architecture", "isolation_profile", "os", "python", "runner_image"},
        )
        key = tuple(environment[field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        ))
        if run["evidence_instance_id"] != report_instance_by_environment.get(key):
            raise evidence.EvidenceError(
                "H0 test run does not bind its exact signed gate-evidence instance"
            )
        fragments = _array(run["fragments"], f"H0 test report.runs[{run_index}].fragments")
        if not fragments:
            raise evidence.EvidenceError("H0 test report has no shard fragments")
        parsed_fragments = []
        for fragment_index, fragment_record in enumerate(fragments):
            embedded = _object(
                fragment_record,
                f"H0 test report.runs[{run_index}].fragments[{fragment_index}]",
                {"digest", "job_instance_id", "report"},
            )
            fragment_body = evidence.canonical_json_bytes(embedded["report"])
            fragment = evidence.read_h0_shard_outcome_report(fragment_body)
            if embedded["digest"] != raw_sha256(fragment_body):
                raise evidence.EvidenceError("H0 shard digest does not match its embedded document")
            python_minor = environment["python"].rsplit(".", 1)[0]
            if embedded["job_instance_id"] != topology_ids.get(
                (python_minor, fragment["shard_index"])
            ):
                raise evidence.EvidenceError(
                    "H0 shard does not bind its exact verification job instance"
                )
            parsed_fragments.append(fragment)
        shard_count = 6
        if (len(parsed_fragments) != shard_count or
                [row["shard_index"] for row in parsed_fragments] != list(range(shard_count)) or
                any(row["shard_count"] != shard_count for row in parsed_fragments)):
            raise evidence.EvidenceError("H0 test report must contain every shard index exactly once")
        full_roster = {
            "count": len(full_nodes), "digest": evidence.h0_roster_digest(full_nodes),
        }
        for shard_index, fragment in enumerate(parsed_fragments):
            selected_nodes = [
                nodeid for nodeid in full_nodes
                if evidence.h0_shard_index(nodeid, shard_count) == shard_index
            ]
            selected_roster = {
                "count": len(selected_nodes),
                "digest": evidence.h0_roster_digest(selected_nodes),
            }
            fragment_collector = fragment["collector"]
            if (fragment_collector["name"] != collector["name"] or
                    fragment_collector["python_implementation"] != collector["python_implementation"] or
                    fragment_collector["python_version"] != environment["python"] or
                    fragment_collector["version"] != collector["version"] or
                    fragment["full_h0_roster"] != full_roster or
                    fragment["selected_roster"] != selected_roster or
                    fragment["passed_roster"] != selected_roster):
                raise evidence.EvidenceError(
                    "H0 shard collector or full/selected/pass roster does not reconcile"
                )
            outcomes = fragment["outcomes"]
            if (fragment["collection_failures"] != 0 or fragment["session_exit_code"] != 0 or
                    outcomes["passed"] != len(selected_nodes) or
                    any(outcomes[name] for name in ("failed", "skipped", "xfailed", "xpassed"))):
                raise evidence.EvidenceError("H0 shard contains collection, execution or non-pass outcomes")
        logical_counts_by_environment[key] = {
            "collected": selection["collected"],
            "deselected": selection["deselected"],
            "failed": 0,
            "passed": len(full_nodes),
            "selected": len(full_nodes),
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        }
        observed_run_environments.append(environment)
    if observed_run_environments != expected_environments:
        raise evidence.EvidenceError(
            "H0 test report does not cover the exact supported H0 environments"
        )

    isolation = _h0_artifact(
        bodies["isolation-self-test"], name="isolation-self-test",
        artifact_type="h0-isolation-self-test", identity=identity, members={"instances"},
    )
    isolation_rows = _array(isolation["instances"], "H0 isolation self-test.instances")
    observed_isolation_environments = []
    for index, record in enumerate(isolation_rows):
        item = _object(record, f"H0 isolation self-test.instances[{index}]", {
            "attempts", "environment", "evidence_instance_id", "isolation_profile",
        })
        environment = _object(
            item["environment"], f"H0 isolation self-test.instances[{index}].environment",
            {"architecture", "isolation_profile", "os", "python", "runner_image"},
        )
        if item["isolation_profile"] != environment["isolation_profile"]:
            raise evidence.EvidenceError("H0 isolation self-test profile does not match its environment")
        isolation_key = tuple(environment[field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        ))
        if item["evidence_instance_id"] != report_instance_by_environment.get(isolation_key):
            raise evidence.EvidenceError(
                "H0 isolation self-test does not bind its exact signed gate-evidence instance"
            )
        attempts = _array(item["attempts"], f"H0 isolation self-test.instances[{index}].attempts")
        if [attempt.get("kind") if type(attempt) is dict else None for attempt in attempts] != \
                list(_H0_ISOLATION_ATTEMPTS):
            raise evidence.EvidenceError("H0 isolation self-test attempt roster or order is not exact")
        for attempt_index, attempt in enumerate(attempts):
            observed = _object(
                attempt, f"H0 isolation self-test.instances[{index}].attempts[{attempt_index}]",
                {"denial", "kind", "outcome"},
            )
            denial = _object(observed["denial"], "H0 isolation self-test denial", {
                "code", "detail",
            })
            _token(denial["code"], "H0 isolation self-test denial.code")
            detail = _string(denial["detail"], "H0 isolation self-test denial.detail")
            if len(detail) > 512:
                raise evidence.EvidenceError("H0 isolation self-test denial.detail exceeds 512 characters")
            if observed["outcome"] != "denied":
                raise evidence.EvidenceError("H0 isolation self-test contains a non-denied attempt")
        observed_isolation_environments.append(environment)
    if observed_isolation_environments != expected_environments:
        raise evidence.EvidenceError(
            "H0 isolation self-test does not cover the exact supported H0 environments"
        )

    report_instances = report["instances"]
    if ([instance["environment"] for instance in report_instances] != expected_environments or
            any(instance["lane"] != "H0-hermetic" for instance in report_instances)):
        raise evidence.EvidenceError(
            "B-HERMETIC-ALL gate evidence does not have one exact instance per H0 environment"
        )
    for instance in report_instances:
        key = tuple(instance["environment"][field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        ))
        if instance["selection"] != logical_counts_by_environment.get(key):
            raise evidence.EvidenceError(
                "B-HERMETIC-ALL gate evidence counts do not match logical H0 collection counts"
            )


def _semantic_evidence_schema(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Reconcile the fixed public aggregator vectors without aggregating again."""
    if gate["gate_id"] != "A-EVIDENCE-SCHEMA":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("evidence-schema verifier received the wrong gate")
    inputs = context["input_bodies"]
    if not isinstance(inputs, Mapping):  # pragma: no cover - aggregate invariant
        raise evidence.EvidenceError("evidence-schema verifier requires frozen scope inputs")
    try:
        manifest_body = inputs["aggregator-conformance-manifest"]
    except KeyError as exc:  # pragma: no cover - frozen scope inventory invariant
        raise evidence.EvidenceError("evidence-schema verifier is missing its golden manifest") from exc
    manifest = read_aggregator_conformance_manifest(manifest_body)
    scope = context["scope"]
    if not isinstance(scope, dict):  # pragma: no cover - aggregate invariant
        raise evidence.EvidenceError("evidence-schema verifier requires the accepted release scope")
    binding = next(
        (row for row in scope["input_bindings"]
         if row["name"] == "aggregator-conformance-manifest"),
        None,
    )
    if binding is None or raw_sha256(manifest_body) != binding["digest"]:
        raise evidence.EvidenceError("aggregator conformance manifest does not match its frozen scope binding")

    doc = _object(
        _artifact_document(bodies["conformance-report"], "A-EVIDENCE-SCHEMA", "conformance-report"),
        "aggregator conformance report",
        {
            "artifact_type", "candidate_identity_digest", "cases", "gate_evidence_counts",
            "gate_id", "manifest_digest", "release", "schema_version", "test_nodeid",
            "test_source_digest",
        },
    )
    if (doc["artifact_type"] != "aggregator-conformance-report" or
            doc["schema_version"] != GATE_ARTIFACT_SCHEMA or doc["release"] != RELEASE or
            doc["gate_id"] != "A-EVIDENCE-SCHEMA"):
        raise evidence.EvidenceError("aggregator conformance report has unsupported identity")
    identity = context["identity"]
    if not isinstance(identity, dict):  # pragma: no cover - aggregate invariant
        raise evidence.EvidenceError("evidence-schema verifier requires the candidate identity")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("aggregator conformance report is bound to the wrong candidate")
    if doc["manifest_digest"] != raw_sha256(manifest_body):
        raise evidence.EvidenceError("aggregator conformance report names the wrong golden manifest")
    test_binding = next(
        (row for row in scope["input_bindings"] if row["name"] == "release-contracts-tests"),
        None,
    )
    if (test_binding is None or test_binding["path"] != _CONFORMANCE_TEST_PATH or
            doc["test_source_digest"] != test_binding["digest"] or
            doc["test_nodeid"] != _CONFORMANCE_TEST_NODEID):
        raise evidence.EvidenceError("aggregator conformance report does not bind the exact conformance test source/node")
    cases = _array(doc["cases"], "aggregator conformance report.cases")
    expected_cases = manifest["cases"]
    if len(cases) != len(expected_cases):
        raise evidence.EvidenceError("aggregator conformance report does not contain the exact case roster")
    for observed, expected in zip(cases, expected_cases, strict=True):
        item = _object(observed, "aggregator conformance report.case", {
            "aggregate_digests", "error_digest", "id", "status",
        })
        if (item["id"] != expected["id"] or item["status"] != "pass" or
                expected["test_path"] != _CONFORMANCE_TEST_PATH or
                expected["test_nodeid"] != doc["test_nodeid"]):
            raise evidence.EvidenceError("aggregator conformance report case roster or order disagrees with the manifest")
        digests = _array(item["aggregate_digests"], "aggregator conformance report aggregate digests")
        if expected["kind"] == "positive":
            if len(digests) != 2:
                raise evidence.EvidenceError("positive conformance case requires two aggregate digests")
            if any(_digest(value, "conformance aggregate digest") != value for value in digests) or \
                    digests[0] != digests[1] or item["error_digest"] is not None:
                raise evidence.EvidenceError("positive conformance case has unequal or invalid aggregate digests")
        elif (digests or item["error_digest"] !=
              conformance_error_digest(expected["error_code"])):
            raise evidence.EvidenceError("negative conformance case has the wrong normalized error digest")

    counts = _object(doc["gate_evidence_counts"], "aggregator conformance report gate evidence counts", {
        "gate_evidence_artifacts", "gate_records",
    })
    expected_counts = {
        "gate_records": len(SELECTED_RECORD_SLOTS),
        "gate_evidence_artifacts": len(SELECTED_RECORD_SLOTS) - len(LIVE_GATES),
    }
    if counts != expected_counts:
        raise evidence.EvidenceError("aggregator conformance report gate evidence counts are not exact")
    resolver = context["resolver"]
    if not isinstance(resolver, ArtifactResolver):  # pragma: no cover - aggregate invariant
        raise evidence.EvidenceError("evidence-schema verifier requires the artifact resolver")
    observed_gate_evidence = sum(name == "gate-evidence" for _gate, name in resolver.keys())
    if observed_gate_evidence != counts["gate_evidence_artifacts"]:
        raise evidence.EvidenceError("aggregator conformance report gate evidence count does not reconcile")


def _read_schema_validation_fixture_manifest(data: bytes) -> dict:
    doc = _object(_canonical_reader(data, "schema validation fixture manifest"),
                  "schema validation fixture manifest", {"fixtures", "release", "schema_version"})
    if doc["schema_version"] != "quarry.schema-validation-fixtures.v1" or doc["release"] != RELEASE:
        raise evidence.EvidenceError("schema validation fixture manifest has unsupported identity")
    fixtures = _array(doc["fixtures"], "schema validation fixture manifest.fixtures")
    normalized = []
    for index, record in enumerate(fixtures):
        item = _object(record, f"schema validation fixture manifest.fixtures[{index}]",
                       {"name", "path"})
        normalized.append({
            "name": _token(item["name"], f"schema validation fixture manifest.fixtures[{index}].name"),
            "path": _path(item["path"], f"schema validation fixture manifest.fixtures[{index}].path"),
        })
    _unique(normalized, "name", "schema validation fixture manifest.fixtures")
    expected = [
        {"name": name, "path": SCHEMA_VALIDATION_FIXTURE_PATHS[name]}
        for name in sorted(SCHEMA_VALIDATION_FIXTURE_PATHS)
    ]
    if normalized != expected:
        raise evidence.EvidenceError("schema validation fixture manifest has the wrong fixture inventory")
    return doc


def _schema_fixture_reader(name: str, document: object, *, identity: dict) -> dict:
    if name == "candidate_identity":
        return evidence.validate_candidate_identity(document)
    if name == "gate_record":
        return evidence.validate_gate_record(document, identity=identity)
    if name == "schema_registry":
        return evidence._validate_schema_registry(document)
    raise evidence.EvidenceError("schema validation fixture names an unregistered reader")


def _semantic_schema_validation(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Recompute every registered schema fixture outcome from frozen source bytes."""
    if gate["gate_id"] != "B-SCHEMA":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("schema validation verifier received the wrong gate")
    identity = context["identity"]
    report = context["report"]
    scope = context["scope"]
    inputs = context["input_bodies"]
    if not isinstance(identity, dict) or not isinstance(report, dict) or not isinstance(scope, dict) or not isinstance(inputs, Mapping):
        raise evidence.EvidenceError("schema validation verifier requires accepted release context")
    doc = _object(_artifact_document(bodies["schema-validation-report"], "B-SCHEMA", "schema-validation-report"),
                  "schema validation report", {
                      "artifact_type", "candidate_identity_digest", "evidence_finished_at",
                      "evidence_instance_id", "evidence_started_at", "environment",
                      "fixture_manifest_digest", "gate_id", "legacy_migration", "outcomes", "registry_digest",
                      "release", "schema_version",
                  })
    if (doc["artifact_type"] != "schema-validation-report" or
            doc["schema_version"] != GATE_ARTIFACT_SCHEMA or doc["release"] != RELEASE or
            doc["gate_id"] != "B-SCHEMA"):
        raise evidence.EvidenceError("schema validation report has unsupported identity")
    if doc["candidate_identity_digest"] != evidence.canonical_digest(identity):
        raise evidence.EvidenceError("schema validation report is bound to the wrong candidate")
    if doc["legacy_migration"] != {
        "disposition": "no-supported-legacy-fixtures", "supported_legacy_migrations": [],
    }:
        raise evidence.EvidenceError("schema validation report has an unsupported legacy-fixture disposition")
    signed_artifact = next(
        (artifact for artifact in gate["artifacts"] if artifact["name"] == "schema-validation-report"),
        None,
    )
    if signed_artifact is None or signed_artifact["digest"] != raw_sha256(bodies["schema-validation-report"]):
        raise evidence.EvidenceError("schema validation report is not the exact signed gate artifact")
    evidence_started = _timestamp(doc["evidence_started_at"], "schema validation report.evidence_started_at")
    evidence_finished = _timestamp(doc["evidence_finished_at"], "schema validation report.evidence_finished_at")
    if not _timestamp(gate["started_at"], "B-SCHEMA gate.started_at") <= evidence_started <= evidence_finished <= _timestamp(gate["finished_at"], "B-SCHEMA gate.finished_at"):
        raise evidence.EvidenceError("schema validation report lies outside its signed gate interval")
    instances = report["instances"]
    if len(instances) != 1:
        raise evidence.EvidenceError("B-SCHEMA must bind exactly one signed H0 gate-evidence instance")
    instance = instances[0]
    if (doc["evidence_instance_id"] != instance["id"] or doc["environment"] != instance["environment"] or
            doc["evidence_started_at"] != instance["started_at"] or
            doc["evidence_finished_at"] != instance["finished_at"]):
        raise evidence.EvidenceError("schema validation report does not bind its exact signed H0 gate-evidence instance/environment/time")

    bindings = {row["name"]: row for row in scope["input_bindings"]}
    required_inputs = {
        "schema-validation-registry", "schema-validation-fixture-manifest",
        "schema-validation-candidate-identity-schema", "schema-validation-gate-record-schema",
        "schema-validation-registry-schema",
        *{f"schema-validation-fixture-{name.replace('_', '-')}" for name in SCHEMA_VALIDATION_FIXTURE_PATHS},
    }
    if not required_inputs.issubset(bindings) or not required_inputs.issubset(inputs):
        raise evidence.EvidenceError("schema validation verifier is missing a frozen registry or fixture input")
    for name in required_inputs:
        if raw_sha256(inputs[name]) != bindings[name]["digest"]:
            raise evidence.EvidenceError("schema validation source bytes drift from their frozen scope binding")
    registry_body = inputs["schema-validation-registry"]
    fixture_manifest_body = inputs["schema-validation-fixture-manifest"]
    if (doc["registry_digest"] != raw_sha256(registry_body) or
            doc["fixture_manifest_digest"] != raw_sha256(fixture_manifest_body)):
        raise evidence.EvidenceError("schema validation report names the wrong frozen registry or fixture manifest")
    registry = evidence._validate_schema_registry(evidence.load_json_bytes(registry_body))
    fixtures = _read_schema_validation_fixture_manifest(fixture_manifest_body)["fixtures"]
    fixture_by_name = {row["name"]: row for row in fixtures}
    outcomes = _array(doc["outcomes"], "schema validation report.outcomes")
    if len(outcomes) != len(registry["schemas"]):
        raise evidence.EvidenceError("schema validation report does not contain the exact registered schema roster")
    if [
        (row.get("name"), row.get("record_version")) if type(row) is dict else (None, None)
        for row in outcomes
    ] != [(row["name"], row["record_version"]) for row in registry["schemas"]]:
        raise evidence.EvidenceError("schema validation report does not contain the exact registered schema roster")
    fixture_identity: dict | None = None
    for index, (registered, observed) in enumerate(zip(registry["schemas"], outcomes, strict=True)):
        item = _object(observed, f"schema validation report.outcomes[{index}]", {
            "accept", "fixture_digest", "malformed", "name", "record_version", "round_trip",
            "schema_digest", "unknown_member", "unknown_version",
        })
        fixture = fixture_by_name.get(registered["name"])
        if fixture is None:
            raise evidence.EvidenceError("schema validation fixture manifest omits a registered schema")
        schema_input = {
            "candidate_identity": "schema-validation-candidate-identity-schema",
            "gate_record": "schema-validation-gate-record-schema",
            "schema_registry": "schema-validation-registry-schema",
        }.get(registered["name"])
        if schema_input is None:  # pragma: no cover - registry reader invariant
            raise evidence.EvidenceError("schema validation report names an unsupported registered schema")
        fixture_input = f"schema-validation-fixture-{registered['name'].replace('_', '-')}"
        schema_body = inputs[schema_input]
        fixture_body = inputs[fixture_input]
        expected = {
            "name": registered["name"], "record_version": registered["record_version"],
            "schema_digest": raw_sha256(schema_body), "fixture_digest": raw_sha256(fixture_body),
            "accept": "pass", "round_trip": "pass", "unknown_version": "reject",
            "unknown_member": "reject", "malformed": "reject",
        }
        if item != expected:
            raise evidence.EvidenceError("schema validation report outcome does not match frozen schema/fixture facts")
        evidence._validate_registered_schema(
            evidence.load_json_bytes(schema_body), name=registered["name"],
            record_version=registered["record_version"],
        )
        fixture_document = _canonical_reader(fixture_body, f"schema validation fixture {registered['name']}")
        reader_identity = fixture_identity if registered["name"] == "gate_record" else identity
        if reader_identity is None:
            raise evidence.EvidenceError("schema validation gate fixture precedes its candidate fixture")
        accepted = _schema_fixture_reader(registered["name"], fixture_document, identity=reader_identity)
        if registered["name"] == "candidate_identity":
            fixture_identity = accepted
        if evidence.canonical_json_bytes(accepted) != fixture_body[:-1]:
            raise evidence.EvidenceError("schema validation fixture does not round-trip exactly")
        unknown = dict(fixture_document)
        unknown["schema_version"] = "quarry.unknown.v1"
        malformed = dict(fixture_document)
        malformed.pop("schema_version", None)
        unknown_member = dict(fixture_document)
        unknown_member["unexpected_member"] = None
        for variant, label in (
            (unknown, "unknown-version"), (unknown_member, "unknown-member"),
            (malformed, "malformed"),
        ):
            try:
                _schema_fixture_reader(registered["name"], variant, identity=reader_identity)
            except evidence.EvidenceError:
                continue
            raise evidence.EvidenceError(f"schema validation {label} fixture was accepted")


# Only obligation-owned parsers whose complete supporting graph is recomputed
# are promoted.  In particular C-PERF-PHASE-FAIRNESS stays fail-closed until a
# typed per-obligation roster can be reconciled with C-POLICY-TRACE.
SEMANTIC_VERIFIERS = MappingProxyType({
    "A-IDENTITY": _semantic_identity,
    "A-EVIDENCE-SCHEMA": _semantic_evidence_schema,
    "A-TAXONOMY": _semantic_taxonomy,
    "A-CORPUS": _semantic_corpus,
    "A-THRESHOLDS": _semantic_thresholds,
    "A-SUPPORT": _semantic_support,
    "B-HERMETIC-ALL": _semantic_h0_hermetic_all,
    "B-SCHEMA": _semantic_schema_validation,
    "C-PACKAGE-BUILD": _semantic_package_build,
    "C-NETWORK-BOUNDARY": _semantic_network_boundary,
    "C-NET-DENY": _semantic_network_denial,
    "C-PACKAGE-INSTALL": _semantic_package_install,
    "C-FAULT-DISK": _semantic_resource_fault,
    "C-FAULT-RESOLVER": _semantic_resource_fault,
    "C-PERF-INGEST": _semantic_resource_benchmark,
    "C-PERF-DISK": _semantic_resource_benchmark,
    "C-PERF-RESOLVER": _semantic_resource_benchmark,
    **{gate_id: _semantic_v310_05 for gate_id in V310_05_SEMANTIC_GATES},
})


def _validate_supporting_artifacts(
    gate: dict, bodies: Mapping[str, bytes], *, identity: dict, report: dict,
    resolver: ArtifactResolver, scope: dict, support: dict, thresholds: dict, corpus: dict,
    policy: dict, trusted_policy_digest: str, input_bodies: Mapping[str, bytes],
) -> None:
    gate_id = gate["gate_id"]
    verifier = SEMANTIC_VERIFIERS.get(gate_id)
    if verifier is None:
        raise evidence.EvidenceError(
            f"gate {gate_id} has no registered obligation-specific semantic verifier"
        )
    verifier(
        gate,
        bodies,
        identity=identity,
        report=report,
        resolver=resolver,
        scope=scope,
        support=support,
        thresholds=thresholds,
        corpus=corpus,
        policy=policy,
        trusted_policy_digest=trusted_policy_digest,
        input_bodies=input_bodies,
    )


def _verify_pass_report(
    gate: dict, body: bytes, *, identity: dict, required_lanes: Sequence[str],
    support: dict, thresholds: dict, corpus: dict,
) -> dict:
    report = read_evidence_report(body, identity=identity, gate_id=gate["gate_id"])
    observed_lanes = []
    observed_environments = []
    reported_artifacts = []
    reported_tools: dict[str, dict] = {}
    totals = {key: 0 for key in gate["selection"]}
    gate_started = _timestamp(gate["started_at"], "gate.started_at")
    gate_finished = _timestamp(gate["finished_at"], "gate.finished_at")
    expected_assertion = [{
        "id": required_assertion_id(gate["gate_id"]),
        "reason": None,
        "status": "pass",
    }]
    for instance in report["instances"]:
        observed_lanes.append(instance["lane"])
        environment = instance["environment"]
        observed_environments.append((
            instance["lane"], environment["os"], environment["architecture"],
            environment["python"], environment["runner_image"],
            environment["isolation_profile"],
        ))
        instance_started = _timestamp(instance["started_at"], "gate evidence instance.started_at")
        instance_finished = _timestamp(instance["finished_at"], "gate evidence instance.finished_at")
        if not gate_started <= instance_started <= instance_finished <= gate_finished:
            raise evidence.EvidenceError("gate evidence instance lies outside its signed gate interval")
        for key, value in instance["selection"].items():
            totals[key] += value
        if any(instance["selection"][key] for key in ("failed", "skipped", "xfailed", "xpassed")):
            raise evidence.EvidenceError("passing gate report contains a non-pass runner outcome")
        if instance["assertions"] != expected_assertion:
            raise evidence.EvidenceError(
                "every gate evidence instance must pass the frozen obligation assertion"
            )
        if instance["selection"]["selected"] == 0:
            raise evidence.EvidenceError("gate evidence instance is a zero-selection vacuous pass")
        if instance["toolchain"] != gate["toolchain"]:
            raise evidence.EvidenceError(
                "every gate evidence instance must bind the complete signed toolchain"
            )
        reported_artifacts.extend(
            (artifact["name"], artifact["digest"]) for artifact in instance["artifacts"]
        )
        for tool in instance["toolchain"]:
            previous = reported_tools.setdefault(tool["name"], tool)
            if previous != tool:
                raise evidence.EvidenceError("gate evidence tool identity conflicts across instances")
    canonical_lanes = [lane for lane in LANE_ORDER if lane in set(observed_lanes)]
    if tuple(canonical_lanes) != tuple(required_lanes):
        raise evidence.EvidenceError("gate report does not cover the exact required evidence lanes")

    supported_environments = {
        (
            environment["lane"], environment["os"], environment["architecture"],
            environment["python"], environment["runner_image"],
            environment["isolation_profile"],
        )
        for environment in support["environments"]
    }
    if not set(observed_environments).issubset(supported_environments):
        raise evidence.EvidenceError("gate evidence uses an environment outside the support matrix")
    if not any(instance["environment"] == gate["environment"] for instance in report["instances"]):
        raise evidence.EvidenceError("signed gate environment is absent from its evidence instances")
    if gate["gate_id"] == "B-HERMETIC-ALL" and (
        set(observed_environments) != {
            environment for environment in supported_environments
            if environment[0] == "H0-hermetic"
        } or len(observed_environments) != sum(
            environment[0] == "H0-hermetic" for environment in supported_environments
        )
    ):
        raise evidence.EvidenceError("B-HERMETIC-ALL does not cover the complete support matrix")
    if gate["gate_id"] == "C-PYTHON-MATRIX":
        expected = {
            environment for environment in supported_environments
            if environment[0] in required_lanes
        }
        if set(observed_environments) != expected or len(observed_lanes) != len(expected):
            raise evidence.EvidenceError("C-PYTHON-MATRIX does not cover every lane/environment pair")

    top_tools = {tool["name"]: tool for tool in gate["toolchain"]}
    if reported_tools != top_tools:
        raise evidence.EvidenceError("gate evidence toolchain does not reconcile with the signed gate")
    if not reported_tools:
        raise evidence.EvidenceError("passing gate has no attested execution toolchain")
    supported_tools = {
        tool["name"]: {key: tool[key] for key in ("digest", "name", "version")}
        for tool in support["tools"]
    }
    observed_tools = {
        name: {key: tool[key] for key in ("digest", "name", "version")}
        for name, tool in reported_tools.items()
    }
    if any(supported_tools.get(name) != tool for name, tool in observed_tools.items()):
        raise evidence.EvidenceError("gate evidence uses a tool outside the support matrix")
    if gate["gate_id"] == "C-TOOLS":
        if observed_tools != supported_tools:
            raise evidence.EvidenceError("C-TOOLS does not cover the exact supported tool identities")

    if gate["assertions"] != expected_assertion:
        raise evidence.EvidenceError("gate assertion does not match the frozen obligation assertion")
    if len(reported_artifacts) != len(set(reported_artifacts)):
        raise evidence.EvidenceError("gate report references an artifact more than once")
    expected_artifacts = sorted(
        (artifact["name"], artifact["digest"])
        for artifact in gate["artifacts"] if artifact["name"] != "gate-evidence"
    )
    observed_contract = tuple(
        (artifact["name"], artifact["media_type"])
        for artifact in gate["artifacts"] if artifact["name"] != "gate-evidence"
    )
    if observed_contract != required_artifact_contract(gate["gate_id"]):
        raise evidence.EvidenceError(
            "gate artifacts do not match the frozen obligation evidence contract"
        )
    if sorted(reported_artifacts) != expected_artifacts:
        raise evidence.EvidenceError("gate report does not reconcile its supporting artifacts")
    if totals != gate["selection"]:
        raise evidence.EvidenceError("gate selection does not reconcile with its evidence report instances")

    expected_materials = []
    if gate["gate_id"] == "C-TOOLS":
        expected_materials.extend(
            {"digest": row["digest"], "kind": "template_set", "name": row["name"]}
            for row in support["template_sets"]
        )
    if gate["gate_id"] in {"A-CORPUS", "C-CORPUS-SYNTHETIC"}:
        selected = [row for row in corpus["sources"] if row["selected"]]
        if (len(selected) != 1 or selected[0]["fixture_digest"] is None or
                selected[0]["attestation_digest"] is None):
            raise evidence.EvidenceError(
                "selected synthetic corpus has no unique fixture and attestation identities"
            )
        expected_materials.extend((
            {
                "digest": selected[0]["attestation_digest"],
                "kind": "corpus_attestation",
                "name": selected[0]["gate_id"],
            },
            {
                "digest": selected[0]["fixture_digest"],
                "kind": "corpus_fixture",
                "name": selected[0]["gate_id"],
            },
        ))
    expected_materials.sort(key=lambda row: (row["kind"], row["name"]))
    if report["materials"] != expected_materials:
        raise evidence.EvidenceError("gate evidence materials do not match the selected support/corpus inputs")

    expected_benchmarks = [row for row in thresholds["benchmarks"]
                           if row["gate_id"] == gate["gate_id"]]
    if len(expected_benchmarks) > 1:
        raise evidence.EvidenceError("threshold manifest contains conflicting benchmark contexts")
    expected_benchmark = expected_benchmarks[0] if expected_benchmarks else None
    if report["benchmark"] != expected_benchmark:
        raise evidence.EvidenceError("gate evidence does not bind its exact benchmark execution context")
    expected_trials = 1
    if expected_benchmark is not None:
        selected = [row for row in corpus["sources"] if row["selected"]]
        if len(selected) != 1 or expected_benchmark["fixture_digest"] != selected[0]["fixture_digest"]:
            raise evidence.EvidenceError("benchmark uses a fixture outside the selected corpus")
        supported_tool_digests = {row["digest"] for row in support["tools"]}
        if not set(expected_benchmark["tool_digests"]).issubset(supported_tool_digests):
            raise evidence.EvidenceError("benchmark uses a tool outside the support matrix")
        if sorted(tool["digest"] for tool in reported_tools.values()) != \
                expected_benchmark["tool_digests"]:
            raise evidence.EvidenceError("benchmark tool identities do not reconcile with gate evidence")
        expected_trials = expected_benchmark["repetitions"]

    expected_thresholds = [row for row in thresholds["thresholds"]
                           if row["gate_id"] == gate["gate_id"]]
    expected_measurements = [{
        "baseline_digest": row["baseline_digest"],
        "class": row["class"],
        "metric": row["metric"],
        "statistic": row["statistic"],
        "unit": row["unit"],
    }
                             for row in expected_thresholds]
    observed_measurements = [{
        "baseline_digest": row["baseline_digest"],
        "class": row["class"],
        "metric": row["metric"],
        "statistic": row["statistic"],
        "unit": row["unit"],
    }
                             for row in report["measurements"]]
    if observed_measurements != expected_measurements:
        raise evidence.EvidenceError("gate evidence does not report the exact threshold metrics")
    for threshold, measurement in zip(expected_thresholds, report["measurements"]):
        if measurement["observed_trials"] != expected_trials:
            raise evidence.EvidenceError("gate evidence omits benchmark trial results")
        limit = threshold["limit"]
        if limit is None:
            raise evidence.EvidenceError("gate evidence cannot apply an unresolved threshold")
        passed = (measurement["value"] <= limit if threshold["operator"] == "at_most"
                  else measurement["value"] >= limit)
        if not passed:
            raise evidence.EvidenceError("gate evidence violates an accepted numeric threshold")
    return report


def _verify_no_live_gate(gate: dict, rule: dict, *, aggregate_time: datetime) -> None:
    if gate["status"] != "not_applicable" or gate["lane"] != "H0-hermetic":
        raise evidence.EvidenceError("Phase D must be an H0 not_applicable record under the no-live rule")
    if (any(gate["selection"].values()) or gate["assertions"] or gate["artifacts"] or
            gate["toolchain"]):
        raise evidence.EvidenceError(
            "Phase D no-live records must report zero execution, tools and artifacts"
        )
    approval = rule["approval"]
    if approval is None:
        raise evidence.EvidenceError("Phase D no-live rule is not approved")
    expected_rule = {
        "approved_at": approval["approved_at"],
        "digest": evidence.canonical_digest(rule),
        "expires_at": rule["expires_at"],
        "id": rule["rule_id"],
    }
    if gate["not_applicable_rule"] != expected_rule:
        raise evidence.EvidenceError("Phase D record does not bind the exact approved no-live rule")
    if rule["expires_at"] is not None and \
            _timestamp(rule["expires_at"], "no-live rule.expires_at") <= aggregate_time:
        raise evidence.EvidenceError("no-live rule expired before aggregation")


def _validate_aggregator_identity(value: object) -> dict:
    item = _object(value, "aggregator identity", {
        "architecture", "executable_digest", "implementation", "isolation_profile",
        "os", "python", "runner_image",
    })
    for field in ("architecture", "implementation", "os", "python"):
        _string(item[field], f"aggregator identity.{field}")
    for field in ("executable_digest", "isolation_profile", "runner_image"):
        _digest(item[field], f"aggregator identity.{field}")
    return item


def aggregate_records(
    *, scope: object, identity: object, records: Sequence[object], artifact_index: object,
    artifact_root: str | os.PathLike[str], trust_policy: object, support_matrix: object,
    threshold_manifest: object, corpus_manifest: object, no_live_rule: object,
    input_bodies: Mapping[str, bytes], generated_at: str, aggregator_identity: object,
    trusted_policy_digest: str | None = None,
) -> dict:
    """Verify the complete scope-selected graph and emit a deterministic aggregate payload.

    The returned payload has no self digest and no detached approval.  Callers
    content-address its canonical bytes, then obtain a later approval signature.
    """
    scope_doc = validate_release_scope(scope)
    policy = _validate_trusted_policy(
        trust_policy,
        trusted_policy_digest=trusted_policy_digest,
        at=_timestamp(generated_at, "aggregate.generated_at"),
    )
    scope_doc = validate_release_scope(
        scope_doc, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    identity_doc = validate_candidate_bindings(
        identity, scope=scope_doc, policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    verify_scope_input_bodies(scope_doc, input_bodies)
    support = validate_support_matrix(
        support_matrix, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    thresholds = validate_threshold_manifest(
        threshold_manifest, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    corpus = validate_corpus_manifest(
        corpus_manifest, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    no_live = validate_no_live_rule(
        no_live_rule, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    aggregator = _validate_aggregator_identity(aggregator_identity)
    if aggregator not in support["aggregators"]:
        raise evidence.EvidenceError("aggregator identity is outside the accepted support matrix")
    manifest_by_name = {
        "support-matrix": support,
        "threshold-benchmark": thresholds,
        "corpus-selection": corpus,
        "no-live-rule": no_live,
    }
    for name, document in manifest_by_name.items():
        if raw_sha256(canonical_json_line(document)) != \
                {row["name"]: row["digest"] for row in scope_doc["input_bindings"]}[name]:
            raise evidence.EvidenceError(f"scope binds different {name} bytes")

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise evidence.EvidenceError("aggregate records must be an ordered sequence")
    validated = [evidence.validate_gate_record(record, identity=identity_doc) for record in records]
    ids = [record["gate_id"] for record in validated]
    if ids != list(SELECTED_RECORD_SLOTS):
        missing = sorted(set(SELECTED_RECORD_SLOTS) - set(ids))
        extra = sorted(set(ids) - set(SELECTED_RECORD_SLOTS))
        duplicates = sorted({gate for gate in ids if ids.count(gate) > 1})
        raise evidence.EvidenceError(
            f"aggregate record inventory mismatch (missing {missing}; extra {extra}; duplicate {duplicates})"
        )
    expected_inputs = expected_gate_inputs(scope_doc, identity=identity_doc, policy=policy)
    contract_by_gate = {gate: (collector, lanes) for gate, collector, lanes in OBLIGATION_CONTRACTS}
    summaries = []
    aggregate_time = _timestamp(generated_at, "aggregate.generated_at")
    earliest_gate = min(_timestamp(gate["started_at"], "gate.started_at") for gate in validated)
    phase_intervals = {
        phase: (
            min(_timestamp(gate["started_at"], "gate.started_at")
                for gate in validated if gate["gate_id"].startswith(phase + "-")),
            max(_timestamp(gate["finished_at"], "gate.finished_at")
                for gate in validated if gate["gate_id"].startswith(phase + "-")),
        )
        for phase in ("A", "B", "C", "D", "E")
    }
    for previous, following in zip(("A", "B", "C", "D"), ("B", "C", "D", "E")):
        if phase_intervals[previous][1] > phase_intervals[following][0]:
            raise evidence.EvidenceError(
                f"release gate lifecycle overlaps {previous} and {following} phases"
            )
    for name, document in (
        ("release scope", scope_doc),
        ("support matrix", support),
        ("threshold manifest", thresholds),
        ("corpus manifest", corpus),
        ("no-live rule", no_live),
    ):
        approval = document["approval"]
        if approval is None or _timestamp(approval["approved_at"], f"{name}.approval.approved_at") >= \
                earliest_gate:
            raise evidence.EvidenceError(f"{name} was not approved before its consuming gates")
    with ArtifactResolver(artifact_root, artifact_index, identity=identity_doc) as resolver:
        indexed_keys = set(resolver.keys())
        referenced_keys: set[tuple[str, str]] = set()
        for gate in validated:
            collector, required_lanes = contract_by_gate[gate["gate_id"]]
            if gate["required"] is not True or gate["lane"] != collector:
                raise evidence.EvidenceError("gate required/collector lane does not match release scope")
            if gate["inputs"] != expected_inputs:
                raise evidence.EvidenceError("gate inputs do not exactly bind the release scope")
            if _timestamp(gate["finished_at"], "gate.finished_at") > aggregate_time:
                raise evidence.EvidenceError("aggregate predates a selected gate record")
            verify_gate_signature(gate, identity=identity_doc, policy=policy)
            artifact_bodies = _verify_gate_artifacts(gate, resolver)
            referenced_keys.update((gate["gate_id"], name) for name in artifact_bodies)
            if gate["gate_id"] in LIVE_GATES:
                _verify_no_live_gate(gate, no_live, aggregate_time=aggregate_time)
            else:
                if gate["status"] != "pass" or gate["not_applicable_rule"] is not None:
                    raise evidence.EvidenceError("selected non-live obligation is not a passing record")
                if "gate-evidence" not in artifact_bodies:
                    raise evidence.EvidenceError("passing gate has no canonical gate-evidence artifact")
                report_body = artifact_bodies["gate-evidence"]
                if report_body is None:  # pragma: no cover - internal artifact routing invariant
                    raise evidence.EvidenceError("gate-evidence body was not retained for validation")
                report = _verify_pass_report(
                    gate,
                    report_body,
                    identity=identity_doc,
                    required_lanes=required_lanes,
                    support=support,
                    thresholds=thresholds,
                    corpus=corpus,
                )
                _validate_supporting_artifacts(
                    gate,
                    artifact_bodies,
                    identity=identity_doc,
                    report=report,
                    resolver=resolver,
                    scope=scope_doc,
                    support=support,
                    thresholds=thresholds,
                    corpus=corpus,
                    policy=policy,
                    trusted_policy_digest=trusted_policy_digest,
                    input_bodies=input_bodies,
                )
            summaries.append({
                "artifacts": gate["artifacts"],
                "gate_id": gate["gate_id"],
                "reason": gate["reason"],
                "record_digest": evidence.canonical_digest(gate),
                "status": gate["status"],
            })
        if referenced_keys != indexed_keys:
            raise evidence.EvidenceError("artifact index contains missing or unreferenced artifacts")
    aggregate = {
        "aggregator": aggregator,
        "candidate": evidence.candidate_summary(identity_doc),
        "decision": "pass",
        "generated_at": generated_at,
        "records": summaries,
        "release": RELEASE,
        "schema_version": AGGREGATE_SCHEMA,
        "scope_digest": evidence.canonical_digest(scope_doc),
        "trust_policy_digest": evidence.canonical_digest(policy),
    }
    return validate_aggregate(
        aggregate, identity=identity_doc, scope=scope_doc, policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )


def validate_aggregate(
    aggregate: object, *, identity: object, scope: object, policy: object,
    trusted_policy_digest: str | None = None,
) -> dict:
    scope_doc = validate_release_scope(scope)
    policy_doc = _validate_trusted_policy(
        policy, trusted_policy_digest=trusted_policy_digest,
    )
    scope_doc = validate_release_scope(
        scope_doc, require_ready=True, trust_policy=policy_doc,
        trusted_policy_digest=trusted_policy_digest,
    )
    identity_doc = validate_candidate_bindings(
        identity, scope=scope_doc, policy=policy_doc,
        trusted_policy_digest=trusted_policy_digest,
    )
    doc = _object(aggregate, "release aggregate", {
        "aggregator", "candidate", "decision", "generated_at", "records", "release",
        "schema_version", "scope_digest", "trust_policy_digest",
    })
    _schema(doc, AGGREGATE_SCHEMA, "release aggregate")
    _validate_aggregator_identity(doc["aggregator"])
    if doc["candidate"] != evidence.candidate_summary(identity_doc):
        raise evidence.EvidenceError("release aggregate binds the wrong candidate")
    if doc["decision"] != "pass":
        raise evidence.EvidenceError("accepted aggregate decision must be pass")
    generated = _timestamp(doc["generated_at"], "release aggregate.generated_at")
    validate_trust_policy(policy_doc, at=generated)
    if doc["scope_digest"] != evidence.canonical_digest(scope_doc):
        raise evidence.EvidenceError("release aggregate binds the wrong scope")
    if doc["trust_policy_digest"] != evidence.canonical_digest(policy_doc):
        raise evidence.EvidenceError("release aggregate binds the wrong trust policy")
    records = _array(doc["records"], "release aggregate.records")
    if [row.get("gate_id") if type(row) is dict else None for row in records] != list(SELECTED_RECORD_SLOTS):
        raise evidence.EvidenceError("release aggregate record summaries are incomplete or reordered")
    for index, record in enumerate(records):
        item = _object(record, f"release aggregate.records[{index}]", {
            "artifacts", "gate_id", "reason", "record_digest", "status",
        })
        _digest(item["record_digest"], "release aggregate record digest")
        expected_status = "not_applicable" if item["gate_id"] in LIVE_GATES else "pass"
        if item["status"] != expected_status:
            raise evidence.EvidenceError("release aggregate status conflicts with the selected disposition")
        if item["gate_id"] in LIVE_GATES:
            _string(item["reason"], "release aggregate not-applicable reason")
        elif item["reason"] is not None:
            raise evidence.EvidenceError("passing aggregate record must not carry a reason")
        artifacts = _array(item["artifacts"], "release aggregate record artifacts")
        for artifact in artifacts:
            artifact_doc = _object(artifact, "release aggregate record artifact", {
                "digest", "media_type", "name",
            })
            _digest(artifact_doc["digest"], "release aggregate artifact digest")
            _token(artifact_doc["name"], "release aggregate artifact name")
            if type(artifact_doc["media_type"]) is not str or \
                    _MEDIA_TYPE_RE.fullmatch(artifact_doc["media_type"]) is None:
                raise evidence.EvidenceError("release aggregate artifact media type is invalid")
        _unique(artifacts, "name", "release aggregate record artifacts")
        names = {artifact["name"] for artifact in artifacts}
        if item["gate_id"] in LIVE_GATES and names:
            raise evidence.EvidenceError("no-live aggregate records must not contain execution artifacts")
        if item["gate_id"] not in LIVE_GATES and "gate-evidence" not in names:
            raise evidence.EvidenceError("passing aggregate record has no gate-evidence artifact")
    return doc


def read_aggregate(
    data: bytes, *, identity: object, scope: object, policy: object,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_aggregate(_canonical_reader(data, "release aggregate"),
                              identity=identity, scope=scope, policy=policy,
                              trusted_policy_digest=trusted_policy_digest)


def verify_aggregate(
    aggregate: object, *, identity: object, scope: object, policy: object,
    trusted_policy_digest: str | None, records: Sequence[object], artifact_index: object,
    artifact_root: str | os.PathLike[str], support_matrix: object,
    threshold_manifest: object, corpus_manifest: object, no_live_rule: object,
    input_bodies: Mapping[str, bytes],
) -> dict:
    """Reopen the complete evidence graph and reproduce an aggregate exactly.

    :func:`validate_aggregate` is the structural reader for an already verified
    payload.  This verifier is the promotion boundary: record signatures and
    all indexed artifact bytes are rechecked before the supplied payload can be
    treated as the deterministic aggregate for that graph.
    """
    document = validate_aggregate(
        aggregate,
        identity=identity,
        scope=scope,
        policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    reproduced = aggregate_records(
        scope=scope,
        identity=identity,
        records=records,
        artifact_index=artifact_index,
        artifact_root=artifact_root,
        trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
        support_matrix=support_matrix,
        threshold_manifest=threshold_manifest,
        corpus_manifest=corpus_manifest,
        no_live_rule=no_live_rule,
        input_bodies=input_bodies,
        generated_at=document["generated_at"],
        aggregator_identity=document["aggregator"],
    )
    if document != reproduced:
        raise evidence.EvidenceError(
            "release aggregate does not reproduce from the verified record/artifact graph"
        )
    return document


def read_verified_aggregate(
    data: bytes, *, identity: object, scope: object, policy: object,
    trusted_policy_digest: str | None, records: Sequence[object], artifact_index: object,
    artifact_root: str | os.PathLike[str], support_matrix: object,
    threshold_manifest: object, corpus_manifest: object, no_live_rule: object,
    input_bodies: Mapping[str, bytes],
) -> dict:
    return verify_aggregate(
        _canonical_reader(data, "release aggregate"),
        identity=identity,
        scope=scope,
        policy=policy,
        trusted_policy_digest=trusted_policy_digest,
        records=records,
        artifact_index=artifact_index,
        artifact_root=artifact_root,
        support_matrix=support_matrix,
        threshold_manifest=threshold_manifest,
        corpus_manifest=corpus_manifest,
        no_live_rule=no_live_rule,
        input_bodies=input_bodies,
    )


def approval_payload_digest(approval: object) -> str:
    """Digest the detached approval statement, excluding only its signature."""
    if type(approval) is not dict:
        raise evidence.EvidenceError("detached approval must be an object")
    statement = dict(approval)
    if set(statement) != {
        "aggregate_digest", "approved_at", "candidate_identity_digest", "decision", "release",
        "schema_version", "scope_digest", "signature", "trust_policy_digest",
    }:
        raise evidence.EvidenceError("detached approval has invalid statement members")
    del statement["signature"]
    return evidence.canonical_digest(statement)


def validate_detached_approval(
    approval: object, *, identity: object, scope: object, policy: object, aggregate: object,
    trusted_policy_digest: str | None = None,
) -> dict:
    identity_doc = evidence.validate_candidate_identity(identity)
    scope_doc = validate_release_scope(scope)
    policy_doc = _validate_trusted_policy(
        policy, trusted_policy_digest=trusted_policy_digest,
    )
    aggregate_doc = validate_aggregate(
        aggregate, identity=identity_doc, scope=scope_doc, policy=policy_doc,
        trusted_policy_digest=trusted_policy_digest,
    )
    doc = _object(approval, "detached approval", {
        "aggregate_digest", "approved_at", "candidate_identity_digest", "decision", "release",
        "schema_version", "scope_digest", "signature", "trust_policy_digest",
    })
    _schema(doc, APPROVAL_SCHEMA, "detached approval")
    if doc["decision"] != "approve":
        raise evidence.EvidenceError("detached approval decision must be approve")
    expected = {
        "aggregate_digest": evidence.canonical_digest(aggregate_doc),
        "candidate_identity_digest": evidence.canonical_digest(identity_doc),
        "scope_digest": evidence.canonical_digest(scope_doc),
        "trust_policy_digest": evidence.canonical_digest(policy_doc),
    }
    for field, value in expected.items():
        if doc[field] != value:
            raise evidence.EvidenceError(f"detached approval binds the wrong {field}")
    approved_at = _timestamp(doc["approved_at"], "detached approval.approved_at")
    if approved_at <= _timestamp(aggregate_doc["generated_at"], "aggregate.generated_at"):
        raise evidence.EvidenceError("detached approval must follow aggregate generation")
    statement_digest = approval_payload_digest(doc)
    signature = verify_signature_envelope(
        doc["signature"], policy=policy_doc, payload_digest=statement_digest,
        candidate_identity_digest=expected["candidate_identity_digest"], role="approval", at=approved_at,
    )
    if signature["trust_policy_digest"] != doc["trust_policy_digest"]:
        raise evidence.EvidenceError("detached approval signature binds a conflicting trust policy")
    return doc


def verify_detached_approval(
    approval: object, *, identity: object, scope: object, policy: object, aggregate: object,
    trusted_policy_digest: str | None, records: Sequence[object], artifact_index: object,
    artifact_root: str | os.PathLike[str], support_matrix: object,
    threshold_manifest: object, corpus_manifest: object, no_live_rule: object,
    input_bodies: Mapping[str, bytes],
) -> dict:
    """Verify approval only after reproducing the full immutable aggregate graph."""
    aggregate_doc = verify_aggregate(
        aggregate,
        identity=identity,
        scope=scope,
        policy=policy,
        trusted_policy_digest=trusted_policy_digest,
        records=records,
        artifact_index=artifact_index,
        artifact_root=artifact_root,
        support_matrix=support_matrix,
        threshold_manifest=threshold_manifest,
        corpus_manifest=corpus_manifest,
        no_live_rule=no_live_rule,
        input_bodies=input_bodies,
    )
    document = validate_detached_approval(
        approval,
        identity=identity,
        scope=scope,
        policy=policy,
        aggregate=aggregate_doc,
        trusted_policy_digest=trusted_policy_digest,
    )
    rule = validate_no_live_rule(
        no_live_rule, require_ready=True, trust_policy=policy,
        trusted_policy_digest=trusted_policy_digest,
    )
    if rule["expires_at"] is not None and _timestamp(
        rule["expires_at"], "no-live rule.expires_at"
    ) <= _timestamp(document["approved_at"], "detached approval.approved_at"):
        raise evidence.EvidenceError("no-live rule expired before detached approval")
    return document


def read_detached_approval(
    data: bytes, *, identity: object, scope: object, policy: object, aggregate: object,
    trusted_policy_digest: str | None = None,
) -> dict:
    return validate_detached_approval(
        _canonical_reader(data, "detached approval"), identity=identity, scope=scope,
        policy=policy, aggregate=aggregate, trusted_policy_digest=trusted_policy_digest,
    )


def read_verified_detached_approval(
    data: bytes, *, identity: object, scope: object, policy: object, aggregate: object,
    trusted_policy_digest: str | None, records: Sequence[object], artifact_index: object,
    artifact_root: str | os.PathLike[str], support_matrix: object,
    threshold_manifest: object, corpus_manifest: object, no_live_rule: object,
    input_bodies: Mapping[str, bytes],
) -> dict:
    return verify_detached_approval(
        _canonical_reader(data, "detached approval"),
        identity=identity,
        scope=scope,
        policy=policy,
        aggregate=aggregate,
        trusted_policy_digest=trusted_policy_digest,
        records=records,
        artifact_index=artifact_index,
        artifact_root=artifact_root,
        support_matrix=support_matrix,
        threshold_manifest=threshold_manifest,
        corpus_manifest=corpus_manifest,
        no_live_rule=no_live_rule,
        input_bodies=input_bodies,
    )
