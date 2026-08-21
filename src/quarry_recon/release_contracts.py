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

from . import path_identity_evidence
from . import release_evidence as evidence
from . import report_truth
from . import release_v310_05
from . import resource_contract
from . import run_manifest
from . import source_registry_evidence


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
MANIFEST_EVIDENCE_CASES_SCHEMA = "quarry.manifest-evidence-cases.v1"
QUALITY_POLICY_SCHEMA = "quarry.quality-policy.v1"
COVERAGE_POLICY_SCHEMA = "quarry.coverage-policy.v1"
COVERAGE_SHARD_SCHEMA = "quarry.coverage-shard.v1"
STATIC_SECURITY_POLICY_SCHEMA = "quarry.static-security-policy.v1"
STATIC_SECURITY_FRAGMENT_SCHEMA = "quarry.static-security-scan-fragment.v1"
SECURITY_FINDINGS_SCHEMA = "quarry.security-findings.v1"
VULNERABILITY_FINDINGS_SCHEMA = "quarry.vulnerability-findings.v1"
DETERMINISM_FIXTURE_SCHEMA = "quarry.determinism-fixture.v1"
DETERMINISM_FRAGMENT_SCHEMA = "quarry.determinism-tree-diff-fragment.v1"
ARTIFACT_TREE_DIFF_SCHEMA = "quarry.artifact-tree-diff.v1"
PYTHON_MATRIX_REPORT_SCHEMA = "quarry.python-matrix-report.v1"
SOURCE_REGISTRY_RECONCILIATION_SCHEMA = source_registry_evidence.SCHEMA_VERSION
PATH_IDENTITY_PROPERTY_CORPUS_SCHEMA = path_identity_evidence.PROPERTY_CORPUS_SCHEMA_VERSION
PATH_IDENTITY_CONTAINMENT_DECISIONS_SCHEMA = \
    path_identity_evidence.CONTAINMENT_DECISIONS_SCHEMA_VERSION

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
    ("B-COVERAGE", "absolute", "repository_line_coverage", "at_least", "minimum", "basis_points"),
    ("B-COVERAGE", "regression", "repository_line_coverage_loss", "at_most", "maximum", "basis_points"),
    ("B-COVERAGE", "absolute", "repository_branch_coverage", "at_least", "minimum", "basis_points"),
    ("B-COVERAGE", "regression", "repository_branch_coverage_loss", "at_most", "maximum", "basis_points"),
    ("B-COVERAGE", "absolute", "critical_module_line_coverage", "at_least", "minimum", "basis_points"),
    ("B-COVERAGE", "regression", "critical_module_line_coverage_loss", "at_most", "maximum", "basis_points"),
    ("B-COVERAGE", "absolute", "critical_module_branch_coverage", "at_least", "minimum", "basis_points"),
    ("B-COVERAGE", "regression", "critical_module_branch_coverage_loss", "at_most", "maximum", "basis_points"),
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
    "B-COVERAGE": (
        ("coverage-report", "application/json"),
        *( (f"coverage-shard-{index}", "application/json") for index in range(6) ),
    ),
    "B-STATIC-SECURITY": (
        ("security-findings", "application/json"),
        ("security-scan-fragment", "application/json"),
    ),
    "B-DETERMINISM": (
        ("artifact-tree-diff", "application/json"),
        ("artifact-tree-diff-fragment", "application/json"),
    ),
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
    "C-SBOM": (
        ("sbom", "application/json"),
        ("sbom-observation-3.10", "application/json"),
        ("sbom-observation-3.11", "application/json"),
        ("sbom-observation-3.12", "application/json"),
    ),
    "C-VULNERABILITY": (
        ("vulnerability-findings", "application/json"),
        ("vulnerability-observation-3.10", "application/json"),
        ("vulnerability-observation-3.11", "application/json"),
        ("vulnerability-observation-3.12", "application/json"),
    ),
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
    "manifest-evidence-cases-schema": "release/evidence/schemas/manifest-evidence-cases-v1.schema.json",
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
    "quality-policy-schema": "release/evidence/schemas/quality-policy-v1.schema.json",
    "coverage-policy-schema": "release/evidence/schemas/coverage-policy-v1.schema.json",
    "coverage-shard-schema": "release/evidence/schemas/coverage-shard-v1.schema.json",
    "static-security-policy-schema": "release/evidence/schemas/static-security-policy-v1.schema.json",
    "static-security-fragment-schema": "release/evidence/schemas/static-security-scan-fragment-v1.schema.json",
    "security-findings-schema": "release/evidence/schemas/security-findings-v1.schema.json",
    "vulnerability-findings-schema": "release/evidence/schemas/vulnerability-findings-v1.schema.json",
    "vulnerability-observation-schema": "release/evidence/schemas/vulnerability-observation-v1.schema.json",
    "determinism-fixture-schema": "release/evidence/schemas/determinism-fixture-v1.schema.json",
    "determinism-fragment-schema": "release/evidence/schemas/determinism-tree-diff-fragment-v1.schema.json",
    "artifact-tree-diff-schema": "release/evidence/schemas/artifact-tree-diff-v1.schema.json",
    "python-matrix-report-schema": "release/evidence/schemas/python-matrix-report-v1.schema.json",
    "source-registry-reconciliation-schema": "release/evidence/schemas/source-registry-reconciliation-v1.schema.json",
    "path-identity-corpus-schema":
        "release/evidence/schemas/path-identity-property-corpus-v1.schema.json",
    "path-identity-decisions-schema":
        "release/evidence/schemas/path-identity-containment-decisions-v1.schema.json",
}
SCHEMA_VERSIONS = {
    "aggregate-schema": AGGREGATE_SCHEMA,
    "artifact-index-schema": ARTIFACT_INDEX_SCHEMA,
    "corpus-selection-schema": CORPUS_MANIFEST_SCHEMA,
    "detached-approval-schema": APPROVAL_SCHEMA,
    "gate-artifact-schema": GATE_ARTIFACT_SCHEMA,
    "manifest-evidence-cases-schema": MANIFEST_EVIDENCE_CASES_SCHEMA,
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
    "quality-policy-schema": QUALITY_POLICY_SCHEMA,
    "coverage-policy-schema": COVERAGE_POLICY_SCHEMA,
    "coverage-shard-schema": COVERAGE_SHARD_SCHEMA,
    "static-security-policy-schema": STATIC_SECURITY_POLICY_SCHEMA,
    "static-security-fragment-schema": STATIC_SECURITY_FRAGMENT_SCHEMA,
    "security-findings-schema": SECURITY_FINDINGS_SCHEMA,
    "vulnerability-findings-schema": VULNERABILITY_FINDINGS_SCHEMA,
    "vulnerability-observation-schema": "quarry.vulnerability-observation.v1",
    "determinism-fixture-schema": DETERMINISM_FIXTURE_SCHEMA,
    "determinism-fragment-schema": DETERMINISM_FRAGMENT_SCHEMA,
    "artifact-tree-diff-schema": ARTIFACT_TREE_DIFF_SCHEMA,
    "python-matrix-report-schema": PYTHON_MATRIX_REPORT_SCHEMA,
    "source-registry-reconciliation-schema": SOURCE_REGISTRY_RECONCILIATION_SCHEMA,
    "path-identity-corpus-schema": PATH_IDENTITY_PROPERTY_CORPUS_SCHEMA,
    "path-identity-decisions-schema": PATH_IDENTITY_CONTAINMENT_DECISIONS_SCHEMA,
}
MANIFEST_PATHS = {
    "aggregator-conformance-manifest": "release/evidence/aggregator-conformance-v1.json",
    "corpus-selection": "release/evidence/corpus-selection-v1.json",
    "no-live-rule": "release/evidence/no-live-rule-v1.json",
    "support-matrix": "release/evidence/support-matrix-v1.json",
    "threshold-benchmark": "release/evidence/threshold-benchmark-v1.json",
    "manifest-evidence-cases": "release/evidence/manifest-evidence-cases-v1.json",
    "quality-policy": "release/evidence/quality-policy-v1.json",
    "coverage-policy": "release/evidence/coverage-policy-v1.json",
    "static-security-policy": "release/evidence/static-security-policy-v1.json",
    "determinism-fixture": "release/evidence/determinism-fixture-v1.json",
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
    "manifest-revision-runtime": "src/quarry_recon/revision.py",
    "manifest-campaign-runtime": "src/quarry_recon/campaign.py",
    "manifest-settle-runtime": "src/quarry_recon/settle.py",
    "manifest-store-runtime": "src/quarry_recon/store.py",
    "manifest-state-runtime": "src/quarry_recon/state.py",
    "manifest-run-contract-tests": "tests/test_run_manifest_contract.py",
    "manifest-revision-tests": "tests/test_v310_revision_transaction.py",
    "manifest-campaign-tests": "tests/test_v310_campaign_truth.py",
}
SCOPE_INPUT_PATHS = {
    **SCHEMA_PATHS,
    **MANIFEST_PATHS,
    **RUN_MANIFEST_INPUT_PATHS,
    **RUNNER_INPUT_PATHS,
    "release-contracts-tests": "tests/test_release_contracts.py",
    "quality-contract-tests": "tests/test_quality_contract.py",
    "coverage-contract-tests": "tests/test_coverage_contract.py",
    "coverage-config": ".coveragerc",
    "coverage-shard-producer": "scripts/emit_coverage_shard.py",
    "static-security-producer": "scripts/emit_static_security.py",
    "determinism-producer": "scripts/emit_determinism.py",
    "security-exceptions": "release/evidence/security-exceptions-v1.json",
    "security-exception-checker": "scripts/check_security_exceptions.py",
    "secret-baseline": ".secrets.baseline",
    "static-security-config-tests": "tests/test_config.py",
    "static-security-path-tests": "tests/test_phase1_privfs_core.py",
    "static-security-archive-tests": "tests/test_release_h0.py",
    "determinism-contract-tests": "tests/test_determinism_contract.py",
    "determinism-release-evidence": "src/quarry_recon/release_evidence.py",
    "determinism-run-manifest": "src/quarry_recon/run_manifest.py",
    "determinism-report-truth": "src/quarry_recon/report_truth.py",
    "sbom-observation-producer": "scripts/emit_sbom_observation.py",
    "sbom-observation-tests": "tests/test_emit_sbom_observation.py",
    "vulnerability-requirements-producer": "scripts/emit_vulnerability_requirements.py",
    "vulnerability-contract-tests": "tests/test_vulnerability_contract.py",
    "release-v310-10-tests": "tests/test_release_v310_10.py",
    "package-metadata": "pyproject.toml",
    "docs-parity-tests": "tests/test_docs_parity.py",
    "docs-policy-readme": "README.md",
    "docs-policy-oob": "docs/oob.md",
    "docs-policy-target-reference": "docs/target-reference.md",
    "docs-policy-configuration": "docs/configuration.md",
    "docs-policy-secrets": "docs/secrets.md",
    "docs-policy-external-integrations": "docs/external-integrations.md",
    "docs-policy-outputs-coverage": "docs/outputs-and-coverage.md",
    "docs-policy-release-gates": "docs/releases/RELEASE-GATES.md",
    "docs-policy-tools-index": "docs/tools.md",
    "docs-policy-tools-index-generator": "scripts/gen_tool_index.py",
    "docs-policy-target-template": "src/quarry_recon/data/target.template.yaml",
    "docs-policy-config-template": "src/quarry_recon/data/config.template.yaml",
    "docs-policy-tools-registry": "src/quarry_recon/data/tools.yaml",
    "docs-policy-sources-registry": "src/quarry_recon/data/sources.yaml",
    "docs-policy-sources-module": "src/quarry_recon/sources.py",
    "docs-policy-ownership-policy": "src/quarry_recon/policy.py",
    "docs-policy-transport-doors": "src/quarry_recon/network_policy.py",
    "docs-policy-target-profile": "src/quarry_recon/config.py",
    "docs-policy-nuclei-runtime": "src/quarry_recon/nuclei_policy.py",
    "docs-policy-private-reach-runtime": "src/quarry_recon/netguard.py",
    "source-registry-reconciliation-producer": "scripts/emit_source_registry_reconciliation.py",
    "source-registry-reconciliation-runtime": "src/quarry_recon/source_registry_evidence.py",
    "source-registry-reconciliation-h1-tests": "tests/test_source_registry_h1_contract.py",
    "source-registry-reconciliation-tests": "tests/test_source_registry_contract.py",
    **path_identity_evidence.INPUT_PATHS,
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

_DOCS_POLICY_TEST_PATH = "tests/test_docs_parity.py"
_DOCS_POLICY_TEST_ROSTER = (
    "tests/test_docs_parity.py::test_every_config_key_is_documented",
    "tests/test_docs_parity.py::test_every_target_field_and_mode_is_documented",
    "tests/test_docs_parity.py::test_every_secret_block_is_documented",
    "tests/test_docs_parity.py::test_all_relative_doc_links_resolve",
    "tests/test_docs_parity.py::test_every_command_is_documented_somewhere",
    "tests/test_docs_parity.py::test_every_entity_is_documented",
    "tests/test_docs_parity.py::test_every_coverage_kind_is_documented_with_its_class",
    "tests/test_docs_parity.py::test_all_fenced_yaml_examples_parse",
    "tests/test_docs_parity.py::test_readme_states_the_current_source_count",
    "tests/test_docs_parity.py::test_source_registry_has_exact_ownership_and_transport_references",
    "tests/test_docs_parity.py::test_nuclei_policy_label_is_exact_in_registry_and_generated_docs",
    "tests/test_docs_parity.py::test_private_reach_default_and_protected_exclusions_are_documented",
    "tests/test_docs_parity.py::test_oob_public_self_hosted_and_off_transport_are_documented",
)
_DOCS_POLICY_MATERIALS = (
    "docs-policy-readme",
    "docs-policy-oob",
    "docs-policy-target-reference",
    "docs-policy-configuration",
    "docs-policy-secrets",
    "docs-policy-external-integrations",
    "docs-policy-outputs-coverage",
    "docs-policy-release-gates",
    "docs-policy-tools-index",
    "docs-policy-tools-index-generator",
    "docs-policy-target-template",
    "docs-policy-config-template",
    "docs-policy-tools-registry",
    "docs-policy-sources-registry",
    "docs-policy-sources-module",
    "docs-policy-ownership-policy",
    "docs-policy-transport-doors",
    "docs-policy-target-profile",
    "docs-policy-nuclei-runtime",
    "docs-policy-private-reach-runtime",
)

QUALITY_POLICY_PATH = "release/evidence/quality-policy-v1.json"
COVERAGE_POLICY_PATH = "release/evidence/coverage-policy-v1.json"
STATIC_SECURITY_POLICY_PATH = "release/evidence/static-security-policy-v1.json"
_STATIC_SECURITY_JOB_ID = ".github/workflows/ci.yml#jobs.offline[python-version=3.12,shard=0]"
_STATIC_SECURITY_CHECK_IDS = (
    "bandit", "detect-secrets", "unsafe-api-inventory", "h0-properties",
    "dependency-manifest",
)
_STATIC_SECURITY_BINDINGS = (
    "static-security-policy", "static-security-policy-schema",
    "static-security-fragment-schema", "security-findings-schema",
    "security-exceptions", "security-exception-checker",
    "static-security-producer", "secret-baseline",
    "static-security-config-tests", "static-security-path-tests",
    "static-security-archive-tests", "package-metadata",
)
_DETERMINISM_JOB_ID = _STATIC_SECURITY_JOB_ID
_DETERMINISM_BINDINGS = (
    "determinism-fixture", "determinism-fixture-schema",
    "determinism-fragment-schema", "artifact-tree-diff-schema",
    "determinism-producer", "determinism-release-evidence",
    "determinism-run-manifest", "determinism-report-truth",
)
_SOURCE_REGISTRY_BINDINGS = (
    "docs-policy-sources-registry", "docs-policy-sources-module",
    "docs-policy-ownership-policy", "docs-policy-transport-doors",
    "source-registry-reconciliation-schema", "source-registry-reconciliation-producer",
    "source-registry-reconciliation-runtime", "source-registry-reconciliation-tests",
    "source-registry-reconciliation-h1-tests",
)
_COVERAGE_CONFIG_PATH = ".coveragerc"
_COVERAGE_CONFIG_BYTES = b"[run]\nbranch = True\nparallel = False\nrelative_files = True\nsource = src/quarry_recon\n"
_COVERAGE_SOURCE_ROOT = "src/quarry_recon"
_COVERAGE_CRITICAL_MODULES = (
    "src/quarry_recon/runner.py", "src/quarry_recon/runner_supervisor.py",
    "src/quarry_recon/runner_worker.py", "src/quarry_recon/runner_repository.py",
    "src/quarry_recon/runner_protocol.py", "src/quarry_recon/store.py",
    "src/quarry_recon/repository_identity.py", "src/quarry_recon/privfs.py",
    "src/quarry_recon/revision.py", "src/quarry_recon/run_manifest.py",
    "src/quarry_recon/campaign.py", "src/quarry_recon/settle.py",
    "src/quarry_recon/release_contracts.py", "src/quarry_recon/release_evidence.py",
)
_COVERAGE_H0_JOB_IDS = tuple(
    ".github/workflows/ci.yml#jobs.offline[python-version=3.12,shard="
    f"{shard}]" for shard in range(6)
)
_QUALITY_CHECK_IDS = ("formatting", "lint", "type", "docs", "dead-code", "complexity")
_QUALITY_SOURCE_ROSTER = ("src", "tests", "scripts")
_QUALITY_MYPY_SOURCES = (
    "src/quarry_recon/report_truth.py",
    "src/quarry_recon/release_v310_05.py",
    "src/quarry_recon/release_v310_08.py",
    "src/quarry_recon/repository_identity.py",
)


def _quality_policy_contract() -> tuple[dict[str, object], ...]:
    """Return the exact, ordered B-QUALITY non-regression checks."""
    ruff_config = {"path": "pyproject.toml"}
    return (
        {"id": "formatting", "argv": ["ruff", "format", "--check", "--output-format", "json", *_QUALITY_SOURCE_ROSTER], "tool": "ruff", "version": "0.16.3", "sources": list(_QUALITY_SOURCE_ROSTER), "config": ruff_config, "expected_exit_code": 1, "budget": 266},
        {"id": "lint", "argv": ["ruff", "check", *_QUALITY_SOURCE_ROSTER, "--select", "E4,E7,E9,F", "--output-format", "json"], "tool": "ruff", "version": "0.16.3", "sources": list(_QUALITY_SOURCE_ROSTER), "config": ruff_config, "expected_exit_code": 1, "budget": 832},
        {"id": "type", "argv": ["mypy", "--no-incremental", "--follow-imports=skip", *_QUALITY_MYPY_SOURCES], "tool": "mypy", "version": "2.3.1", "sources": list(_QUALITY_MYPY_SOURCES), "config": ruff_config, "expected_exit_code": 0, "budget": 0},
        {"id": "docs", "argv": ["pytest", *_DOCS_POLICY_TEST_ROSTER], "tool": "pytest", "version": "9.1.1", "sources": ["tests/test_docs_parity.py"], "config": {"path": "tests/test_docs_parity.py"}, "expected_exit_code": 0, "budget": 0},
        {"id": "dead-code", "argv": ["ruff", "check", *_QUALITY_SOURCE_ROSTER, "--select", "F401,F841,F811,B018", "--output-format", "json"], "tool": "ruff", "version": "0.16.3", "sources": list(_QUALITY_SOURCE_ROSTER), "config": ruff_config, "expected_exit_code": 1, "budget": 126},
        {"id": "complexity", "argv": ["ruff", "check", *_QUALITY_SOURCE_ROSTER, "--select", "C90", "--config", "lint.mccabe.max-complexity=50", "--output-format", "json"], "tool": "ruff", "version": "0.16.3", "sources": list(_QUALITY_SOURCE_ROSTER), "config": ruff_config, "expected_exit_code": 1, "budget": 12},
    )


def validate_quality_policy(document: object) -> dict:
    """Validate the policy that freezes B-QUALITY's command and budget roster."""
    doc = _object(document, "quality policy", {"checks", "release", "schema_version"})
    _schema(doc, QUALITY_POLICY_SCHEMA, "quality policy")
    checks = _array(doc["checks"], "quality policy.checks")
    if len(checks) != len(_QUALITY_CHECK_IDS):
        raise evidence.EvidenceError("quality policy must contain exactly six checks")
    expected = _quality_policy_contract()
    for index, (check, contract) in enumerate(zip(checks, expected, strict=True)):
        item = _object(check, f"quality policy.checks[{index}]", {
            "argv", "budget", "config", "expected_exit_code", "id", "sources", "tool", "version",
        })
        config = _object(item["config"], f"quality policy.checks[{index}].config", {"digest", "path"})
        _digest(config["digest"], "quality policy config digest")
        _path(config["path"], "quality policy config path")
        if {key: item[key] for key in ("id", "argv", "tool", "version", "sources", "expected_exit_code", "budget")} != {
            key: contract[key] for key in ("id", "argv", "tool", "version", "sources", "expected_exit_code", "budget")
        } or config["path"] != contract["config"]["path"]:
            raise evidence.EvidenceError("quality policy check command, tool, source roster or budget is not frozen")
        _integer(item["budget"], "quality policy budget")
        if type(item["expected_exit_code"]) is not int or not 0 <= item["expected_exit_code"] <= 255:
            raise evidence.EvidenceError("quality policy expected exit code is invalid")
    return doc


def read_quality_policy(data: bytes) -> dict:
    return validate_quality_policy(_canonical_reader(data, "quality policy"))


def validate_coverage_policy(document: object) -> dict:
    """Validate the deliberately small, exact B-COVERAGE collection policy."""
    doc = _object(document, "coverage policy", {
        "config", "critical_modules", "h0_job_ids", "python", "release",
        "schema_version", "source_roster", "tool", "version",
    })
    _schema(doc, COVERAGE_POLICY_SCHEMA, "coverage policy")
    if (doc["tool"], doc["version"], doc["python"]) != ("coverage", "7.15.4", "3.12"):
        raise evidence.EvidenceError("coverage policy tool identity is not frozen")
    config = _object(doc["config"], "coverage policy.config", {"digest", "path"})
    if config["path"] != _COVERAGE_CONFIG_PATH:
        raise evidence.EvidenceError("coverage policy config path is not frozen")
    _digest(config["digest"], "coverage policy config digest")
    roster = _array(doc["source_roster"], "coverage policy source roster")
    if (not roster or roster != sorted(roster) or len(roster) != len(set(roster)) or
            any(not isinstance(path, str) or not path.startswith(_COVERAGE_SOURCE_ROOT + "/") or not path.endswith(".py")
                for path in roster)):
        raise evidence.EvidenceError("coverage policy source roster must be sorted, unique Python modules")
    critical = _array(doc["critical_modules"], "coverage policy critical modules")
    if critical != list(_COVERAGE_CRITICAL_MODULES) or not set(critical).issubset(roster):
        raise evidence.EvidenceError("coverage policy critical-module roster is not frozen")
    if _array(doc["h0_job_ids"], "coverage policy H0 job ids") != list(_COVERAGE_H0_JOB_IDS):
        raise evidence.EvidenceError("coverage policy H0 job topology is not frozen")
    return doc


def read_coverage_policy(data: bytes) -> dict:
    return validate_coverage_policy(_canonical_reader(data, "coverage policy"))


def read_coverage_shard(data: bytes) -> dict:
    """Read one candidate-independent, canonical Coverage.py shard fragment."""
    doc = _object(_canonical_reader(data, "coverage shard"), "coverage shard", {
        "config_digest", "coverage_policy_digest", "coverage_version", "files",
        "h0_fragment_digest", "job_instance_id", "raw_coverage_data_digest",
        "schema_version", "source_roster",
    })
    _schema(doc, COVERAGE_SHARD_SCHEMA, "coverage shard")
    if doc["schema_version"] != COVERAGE_SHARD_SCHEMA or doc["coverage_version"] != "7.15.4":
        raise evidence.EvidenceError("coverage shard schema or coverage version is unsupported")
    _digest(doc["config_digest"], "coverage shard config digest")
    _digest(doc["coverage_policy_digest"], "coverage shard policy digest")
    _digest(doc["h0_fragment_digest"], "coverage shard H0 fragment digest")
    _digest(doc["raw_coverage_data_digest"], "coverage shard raw data digest")
    _string(doc["job_instance_id"], "coverage shard job instance id")
    roster = _array(doc["source_roster"], "coverage shard source roster")
    if not roster or roster != sorted(roster) or len(roster) != len(set(roster)):
        raise evidence.EvidenceError("coverage shard source roster must be sorted and unique")
    for path in roster:
        if not isinstance(path, str) or not path.startswith(_COVERAGE_SOURCE_ROOT + "/") or not path.endswith(".py"):
            raise evidence.EvidenceError("coverage shard source roster has an invalid path")
    files = _array(doc["files"], "coverage shard files")
    if len(files) != len(roster):
        raise evidence.EvidenceError("coverage shard files do not cover the frozen roster")
    for index, row in enumerate(files):
        item = _object(row, f"coverage shard files[{index}]", {
            "executed_branches", "executed_lines", "path", "possible_branches", "statements",
        })
        if item["path"] != roster[index]:
            raise evidence.EvidenceError("coverage shard files are not in frozen roster order")
        statements = _array(item["statements"], "coverage shard statements")
        executed_lines = _array(item["executed_lines"], "coverage shard executed lines")
        for values, label in ((statements, "statements"), (executed_lines, "executed lines")):
            if any(_integer(value, f"coverage shard {label}") == 0 for value in values) or values != sorted(set(values)):
                raise evidence.EvidenceError(f"coverage shard {label} must be sorted unique positive lines")
        if not set(executed_lines).issubset(statements):
            raise evidence.EvidenceError("coverage shard executed lines exceed statements")
        arcs = []
        for values, label in ((item["possible_branches"], "possible branches"), (item["executed_branches"], "executed branches")):
            parsed = []
            for arc in _array(values, f"coverage shard {label}"):
                if type(arc) is not list or len(arc) != 2 or any(type(value) is not int or abs(value) > evidence.MAX_JSON_INTEGER for value in arc):
                    raise evidence.EvidenceError(f"coverage shard {label} has an invalid arc")
                parsed.append(tuple(arc))
            if parsed != sorted(set(parsed)):
                raise evidence.EvidenceError(f"coverage shard {label} must be sorted and unique")
            arcs.append(parsed)
        if not set(arcs[1]).issubset(arcs[0]):
            raise evidence.EvidenceError("coverage shard executed branches exceed possible branches")
    if len(data) > 1024 * 1024:
        raise evidence.EvidenceError("coverage shard exceeds the one MiB artifact bound")
    return doc


def read_static_security_policy(data: bytes) -> dict:
    """Read the exact source, scan and H0 property roster for B-STATIC-SECURITY."""
    doc = _object(_canonical_reader(data, "static security policy"), "static security policy", {
        "ast_inventory", "bandit", "dependency_manifest", "detect_secrets",
        "h0_property_tests", "release", "schema_version", "unsafe_apis",
    })
    if doc["schema_version"] != STATIC_SECURITY_POLICY_SCHEMA or doc["release"] != RELEASE:
        raise evidence.EvidenceError("static security policy has unsupported identity")
    bandit = _object(doc["bandit"], "static security Bandit policy", {
        "confidence", "exceptions", "severity", "source_roster", "tool", "version",
    })
    if bandit != {**bandit, "tool": "bandit", "version": "1.9.4", "severity": "HIGH", "confidence": "HIGH", "source_roster": ["src"]}:
        raise evidence.EvidenceError("static security Bandit policy is not frozen to HIGH/HIGH src")
    for name, row, path in (("exceptions", bandit["exceptions"], "release/evidence/security-exceptions-v1.json"),
                            ("baseline", _object(doc["detect_secrets"], "static security secret policy", {"baseline", "mode", "tool", "version"})["baseline"], ".secrets.baseline"),
                            ("dependency", doc["dependency_manifest"], "pyproject.toml")):
        item = _object(row, f"static security {name} binding", {"digest", "path"})
        _digest(item["digest"], f"static security {name} digest")
        if item["path"] != path:
            raise evidence.EvidenceError("static security binding path is not frozen")
    secrets = _object(doc["detect_secrets"], "static security secret policy", {"baseline", "mode", "tool", "version"})
    if {key: secrets[key] for key in ("mode", "tool", "version")} != {"mode": "tracked-files", "tool": "detect-secrets", "version": "1.5.0"}:
        raise evidence.EvidenceError("static security secret policy is not frozen to tracked detect-secrets")
    if doc["unsafe_apis"] != ["subprocess.Popen", "subprocess.run", "yaml.load"]:
        raise evidence.EvidenceError("static security unsafe API categories are not frozen")
    inventory = _object(doc["ast_inventory"], "static security AST inventory", {"entries", "source_roster"})
    if inventory["source_roster"] != ["src/quarry_recon"] or not inventory["entries"]:
        raise evidence.EvidenceError("static security AST inventory source roster is not frozen")
    entries = _array(inventory["entries"], "static security AST entries")
    if entries != sorted(entries, key=lambda row: (row["path"], row["line"], row["api"])):
        raise evidence.EvidenceError("static security AST inventory is not canonically ordered")
    properties = _object(doc["h0_property_tests"], "static security H0 properties", {"nodes", "sources"})
    if properties["sources"] != ["tests/test_config.py", "tests/test_phase1_privfs_core.py", "tests/test_release_h0.py"] or len(properties["nodes"]) != 3:
        raise evidence.EvidenceError("static security H0 property roster is not frozen")
    return doc


def read_static_security_fragment(data: bytes) -> dict:
    """Read one canonical, candidate-independent shard-0 security scan."""
    doc = _object(_canonical_reader(data, "static security scan fragment"),
                  "static security scan fragment", {
        "artifact_type", "ast_inventory", "dependency_manifest",
        "detect_secrets_baseline_digest", "findings", "h0_fragment_digest",
        "h0_property_tests", "job_instance_id", "policy_digest", "release",
        "scan_tools", "schema_version", "suppressions", "unsuppressed_findings",
    })
    if (doc["artifact_type"] != "security-scan-fragment" or
            doc["schema_version"] != STATIC_SECURITY_FRAGMENT_SCHEMA or
            doc["release"] != RELEASE or doc["job_instance_id"] != _STATIC_SECURITY_JOB_ID):
        raise evidence.EvidenceError("static security scan fragment has unsupported identity")
    for field in ("detect_secrets_baseline_digest", "h0_fragment_digest", "policy_digest"):
        _digest(doc[field], f"static security scan {field}")
    dependency = _object(doc["dependency_manifest"], "static security dependency manifest", {
        "digest", "name", "path",
    })
    _digest(dependency["digest"], "static security dependency digest")
    if dependency["name"] != "package-metadata" or dependency["path"] != "pyproject.toml":
        raise evidence.EvidenceError("static security dependency binding is not frozen")
    if doc["scan_tools"] != [
        {"name": "bandit", "version": "1.9.4"},
        {"name": "detect-secrets", "version": "1.5.0"},
    ]:
        raise evidence.EvidenceError("static security scan tool roster is not frozen")
    properties = _object(doc["h0_property_tests"], "static security scan H0 properties", {
        "nodes", "sources",
    })
    for field in ("nodes", "sources"):
        values = _array(properties[field], f"static security scan H0 {field}")
        if len(values) != 3 or len(set(values)) != 3 or any(type(value) is not str or not value for value in values):
            raise evidence.EvidenceError("static security scan H0 property roster is invalid")

    def findings(field: str, *, source: str) -> list:
        rows = _array(doc[field], f"static security scan {field}")
        parsed = []
        for index, row in enumerate(rows):
            item = _object(row, f"static security scan {field}[{index}]", {
                "api", "id", "line", "path", "source",
            })
            _string(item["api"], f"static security scan {field} api")
            _token(item["id"], f"static security scan {field} id")
            if _integer(item["line"], f"static security scan {field} line") == 0:
                raise evidence.EvidenceError("static security scan line must be positive")
            _string(item["path"], f"static security scan {field} path")
            if item["source"] != source:
                raise evidence.EvidenceError("static security scan finding source is invalid")
            parsed.append(item)
        if parsed != sorted(parsed, key=lambda row: (row["path"], row["line"], row["api"]) if source == "ast" else (row["id"],)):
            raise evidence.EvidenceError(f"static security scan {field} is not canonically ordered")
        if len({row["id"] for row in parsed}) != len(parsed):
            raise evidence.EvidenceError(f"static security scan {field} IDs are not unique")
        return parsed

    ast_inventory = findings("ast_inventory", source="ast")
    if not ast_inventory:
        raise evidence.EvidenceError("static security scan AST inventory is empty")
    finding_rows = findings("findings", source="bandit")
    suppressions = _array(doc["suppressions"], "static security scan suppressions")
    for index, row in enumerate(suppressions):
        item = _object(row, f"static security scan suppression[{index}]", {
            "expires_before", "finding_id", "id", "owner", "rationale",
        })
        for field in ("expires_before", "finding_id", "id", "owner", "rationale"):
            _string(item[field], f"static security scan suppression {field}")
    if suppressions != sorted(suppressions, key=lambda row: row["id"]) or \
            len({row["id"] for row in suppressions}) != len(suppressions):
        raise evidence.EvidenceError("static security scan suppressions are not canonical and unique")
    if _integer(doc["unsuppressed_findings"], "static security unsuppressed findings") != len(finding_rows):
        raise evidence.EvidenceError("static security unsuppressed finding count does not reconcile")
    return doc


def _static_security_checks(fragment: Mapping[str, object]) -> list[dict]:
    """Digest the five independently reviewed B-STATIC-SECURITY outcomes."""
    facts = (
        ("bandit", {
            "findings": fragment["findings"],
            "suppressions": fragment["suppressions"],
            "tool": fragment["scan_tools"][0],
        }),
        ("detect-secrets", {
            "baseline_digest": fragment["detect_secrets_baseline_digest"],
            "tool": fragment["scan_tools"][1],
        }),
        ("unsafe-api-inventory", {"entries": fragment["ast_inventory"]}),
        ("h0-properties", fragment["h0_property_tests"]),
        ("dependency-manifest", fragment["dependency_manifest"]),
    )
    return [{"id": name, "result_digest": evidence.canonical_digest(fact), "status": "pass"}
            for name, fact in facts]


def read_determinism_fixture(data: bytes) -> dict:
    """Read the small, source-controlled artifact fixture for B-DETERMINISM."""
    doc = _object(_canonical_reader(data, "determinism fixture"), "determinism fixture", {
        "artifacts", "release", "schema_version",
    })
    _schema(doc, DETERMINISM_FIXTURE_SCHEMA, "determinism fixture")
    if doc["schema_version"] != DETERMINISM_FIXTURE_SCHEMA or doc["release"] != RELEASE:
        raise evidence.EvidenceError("determinism fixture has unsupported identity")
    rows = _array(doc["artifacts"], "determinism fixture artifacts")
    if len(rows) != 3:
        raise evidence.EvidenceError("determinism fixture must have exactly three artifacts")
    expected_builders = ("release-evidence", "run-manifest", "report-truth")
    paths = []
    for index, row in enumerate(rows):
        item = _object(row, f"determinism fixture artifacts[{index}]", {
            "builder", "document", "path",
        })
        if item["builder"] != expected_builders[index] or type(item["document"]) is not dict:
            raise evidence.EvidenceError("determinism fixture builder roster is not frozen")
        path = _string(item["path"], "determinism fixture path")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", path) is None:
            raise evidence.EvidenceError("determinism fixture path is invalid")
        paths.append(path)
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise evidence.EvidenceError("determinism fixture paths are not canonical")
    return doc


def _determinism_expected_tree(fixture: Mapping[str, object], run_id: str) -> dict:
    """Rebuild every retained deterministic byte from the frozen fixture."""
    builders = {
        "release-evidence": lambda value: evidence.canonical_json_bytes(value) + b"\n",
        "run-manifest": run_manifest.canonical_json_bytes,
        "report-truth": report_truth.canonical_json_bytes,
    }
    files = []
    for row in fixture["artifacts"]:
        item = _object(row, "determinism fixture artifact", {"builder", "document", "path"})
        builder = builders[item["builder"]]
        try:
            body = builder(item["document"])
        except (TypeError, ValueError, run_manifest.ManifestError, report_truth.ReportTruthError) as exc:
            raise evidence.EvidenceError("determinism fixture cannot be rebuilt") from exc
        files.append({"bytes": len(body), "digest": raw_sha256(body), "path": item["path"]})
    return {"files": files, "id": run_id, "tree_digest": evidence.canonical_digest(files)}


def _read_determinism_run(value: object, label: str) -> dict:
    run = _object(value, label, {"files", "id", "tree_digest"})
    _token(run["id"], f"{label} id")
    _digest(run["tree_digest"], f"{label} tree digest")
    files = _array(run["files"], f"{label} files")
    if len(files) != 3:
        raise evidence.EvidenceError("determinism tree must retain exactly three files")
    parsed = []
    for index, row in enumerate(files):
        item = _object(row, f"{label} files[{index}]", {"bytes", "digest", "path"})
        size = _integer(item["bytes"], f"{label} file bytes")
        if size < 0:
            raise evidence.EvidenceError("determinism file size is negative")
        _digest(item["digest"], f"{label} file digest")
        path = _string(item["path"], f"{label} file path")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", path) is None:
            raise evidence.EvidenceError("determinism file path is invalid")
        parsed.append(item)
    if parsed != sorted(parsed, key=lambda row: row["path"]) or len({row["path"] for row in parsed}) != len(parsed):
        raise evidence.EvidenceError("determinism tree files are not canonically ordered")
    if run["tree_digest"] != evidence.canonical_digest(parsed):
        raise evidence.EvidenceError("determinism tree digest does not recompute from retained file facts")
    return run


def read_determinism_fragment(data: bytes) -> dict:
    """Read a canonical raw paired-tree diff emitted in the exact shard-0 job."""
    doc = _object(_canonical_reader(data, "determinism tree diff fragment"),
                  "determinism tree diff fragment", {
        "artifact_differences", "artifact_type", "differences", "fixture_digest",
        "fixture_manifest_digest", "h0_fragment_digest", "job_instance_id", "release", "runs", "schema_version",
    })
    _schema(doc, DETERMINISM_FRAGMENT_SCHEMA, "determinism tree diff fragment")
    if ({key: doc[key] for key in ("artifact_type", "job_instance_id", "release", "schema_version")} != {
            "artifact_type": "artifact-tree-diff-fragment", "job_instance_id": _DETERMINISM_JOB_ID,
            "release": RELEASE, "schema_version": DETERMINISM_FRAGMENT_SCHEMA}):
        raise evidence.EvidenceError("determinism fragment has unsupported identity")
    for field in ("fixture_digest", "fixture_manifest_digest", "h0_fragment_digest"):
        _digest(doc[field], f"determinism fragment {field}")
    runs = [_read_determinism_run(row, f"determinism run {index}")
            for index, row in enumerate(_array(doc["runs"], "determinism runs"))]
    if [row["id"] for row in runs] != ["run-1", "run-2"] or len(runs) != 2:
        raise evidence.EvidenceError("determinism fragment must contain exactly two isolated runs")
    left, right = ({row["path"]: row for row in run["files"]} for run in runs)
    expected = [
        {"left": left.get(path), "path": path, "right": right.get(path)}
        for path in sorted(set(left) | set(right)) if left.get(path) != right.get(path)
    ]
    differences = _array(doc["differences"], "determinism differences")
    if differences != expected or _integer(doc["artifact_differences"], "artifact differences") != len(expected):
        raise evidence.EvidenceError("determinism differences do not recompute from both retained trees")
    return doc

_MANIFEST_TEST_SOURCES = (
    "manifest-run-contract-tests",
    "manifest-revision-tests",
    "manifest-campaign-tests",
)
# This is the owner subset for B-MANIFEST's semantic authority.  Candidate
# identity still binds the full source closure; projections and durability have
# different gate owners and are intentionally not duplicated here.
_MANIFEST_MATERIALS = (
    "run-manifest-schema",
    "run-manifest-validator",
    "manifest-revision-runtime",
    "manifest-campaign-runtime",
    "manifest-settle-runtime",
    "manifest-store-runtime",
    "manifest-state-runtime",
)
_MANIFEST_TEST_ROSTER = (
    "tests/test_run_manifest_contract.py::test_writer_emits_one_canonical_reconciled_v1_manifest",
    "tests/test_run_manifest_contract.py::test_noncanonical_and_duplicate_member_encodings_are_not_commitments",
    "tests/test_run_manifest_contract.py::test_lifecycle_identity_is_verified_by_authoritative_consumers",
    "tests/test_v310_revision_transaction.py::test_disjoint_revisions_republish_the_full_effective_overlay",
    "tests/test_v310_revision_transaction.py::test_revision_binds_pointer_entities_segments_raw_and_views",
    "tests/test_v310_campaign_truth.py::test_a_later_silent_child_cannot_launder_an_earlier_gap",
    "tests/test_v310_campaign_truth.py::test_gap_history_and_resolution_survive_reload",
    "tests/test_run_manifest_contract.py::test_summary_projections_are_recomputed_from_authenticated_logs",
    "tests/test_run_manifest_contract.py::test_malformed_remainder_is_explicitly_gapped_not_clean",
    "tests/test_run_manifest_contract.py::test_event_sink_degradation_cannot_be_bound_to_a_clean_summary",
    "tests/test_run_manifest_contract.py::test_envelope_degradation_cannot_be_bound_to_a_clean_summary",
    "tests/test_v310_campaign_truth.py::test_only_matching_positive_coverage_resolves_the_historical_gap",
    "tests/test_v310_campaign_truth.py::test_mismatched_or_incomplete_coverage_cannot_resolve_a_gap[wrong-source]",
    "tests/test_v310_campaign_truth.py::test_mismatched_or_incomplete_coverage_cannot_resolve_a_gap[wrong-measure]",
    "tests/test_v310_campaign_truth.py::test_mismatched_or_incomplete_coverage_cannot_resolve_a_gap[incomplete-coverage]",
    "tests/test_v310_campaign_truth.py::test_matching_obligation_evidence_can_resolve_an_unmeasured_remainder_gap",
    "tests/test_v310_campaign_truth.py::test_terminal_breakdown_must_equal_the_final_obligation_totals",
    "tests/test_v310_campaign_truth.py::test_a_manifested_child_cannot_erase_the_mandatory_obligation_roster",
)
_MANIFEST_CORRUPTION_CASES = (
    ("run-manifest-corruption", (
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[extra-keys]",
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[schema-version]",
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[entity-counts]",
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[tools-failed]",
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[verdict]",
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[generation]",
        "tests/test_run_manifest_contract.py::test_semantic_manifest_corruption_refuses_every_consumer[base-files]",
        "tests/test_run_manifest_contract.py::test_lifecycle_sidecar_has_one_strict_semantic_contract[extra-key]",
        "tests/test_run_manifest_contract.py::test_lifecycle_sidecar_has_one_strict_semantic_contract[bad-updated]",
        "tests/test_run_manifest_contract.py::test_lifecycle_sidecar_has_one_strict_semantic_contract[bad-detail]",
        "tests/test_run_manifest_contract.py::test_lifecycle_sidecar_has_one_strict_semantic_contract[bad-stage]",
        "tests/test_run_manifest_contract.py::test_lifecycle_sidecar_has_one_strict_semantic_contract[invalid-state]",
    )),
    ("revision-overlay-pointer-corruption", (
        "tests/test_v310_revision_transaction.py::test_evidence_corruption_matrix_fails_closed[pointer]",
        "tests/test_v310_revision_transaction.py::test_evidence_corruption_matrix_fails_closed[entity]",
        "tests/test_v310_revision_transaction.py::test_evidence_corruption_matrix_fails_closed[segment]",
        "tests/test_v310_revision_transaction.py::test_evidence_corruption_matrix_fails_closed[raw]",
    )),
    ("campaign-terminal-history-corruption", (
        "tests/test_v310_campaign_truth.py::test_contradictory_terminal_documents_are_unusable[success]",
        "tests/test_v310_campaign_truth.py::test_contradictory_terminal_documents_are_unusable[clean]",
        "tests/test_v310_campaign_truth.py::test_contradictory_terminal_documents_are_unusable[terminal]",
        "tests/test_v310_campaign_truth.py::test_contradictory_terminal_documents_are_unusable[non-terminal]",
        "tests/test_v310_campaign_truth.py::test_contradictory_terminal_documents_are_unusable[open-gaps]",
        "tests/test_v310_campaign_truth.py::test_a_forged_resolution_without_matching_evidence_is_unusable",
    )),
)
_MANIFEST_CORRUPTION_CODE_ROSTER = (
    (
        "manifest.extra_keys", "manifest.schema_version", "manifest.entity_counts",
        "manifest.tools_failed", "manifest.verdict", "manifest.generation", "manifest.base_files",
        "lifecycle.extra_key", "lifecycle.bad_updated", "lifecycle.bad_detail",
        "lifecycle.bad_stage", "lifecycle.invalid_state",
    ),
    ("revision.pointer", "revision.entity", "revision.segment", "revision.raw"),
    (
        "campaign.terminal_success", "campaign.terminal_clean", "campaign.terminal_cause",
        "campaign.terminal_nonterminal", "campaign.open_gaps", "campaign.forged_resolution",
    ),
)
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
    if (pure.is_absolute() or not pure.parts or text != pure.as_posix() or
            any(part in {"", ".", ".."} for part in pure.parts)):
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


def _manifest_result_digest(spec: Mapping[str, object], observed: Mapping[str, object]) -> str:
    """Digest one frozen manifest case result without running any test code."""
    return evidence.canonical_digest({
        "case_id": spec["case_id"], "nodeid": spec["nodeid"], "observed": observed,
    })


def _manifest_observed_result(spec: Mapping[str, object]) -> dict:
    """Build the canonical recorded result required by a frozen case spec."""
    observed = {
        "code": spec["expected_code"], "error_class": spec["error_class"],
        "outcome": spec["expected_outcome"],
    }
    return {
        "case_id": spec["case_id"], "nodeid": spec["nodeid"], "observed": observed,
        "result_digest": _manifest_result_digest(spec, observed), "test_status": "pass",
    }


def _read_manifest_evidence_cases(data: bytes) -> dict:
    """Read the frozen, candidate-independent B-MANIFEST result specification."""
    doc = _object(_canonical_reader(data, "manifest evidence cases"), "manifest evidence cases", {
        "corruption_cases", "invariants", "release", "schema_version",
    })
    if doc["release"] != RELEASE or doc["schema_version"] != MANIFEST_EVIDENCE_CASES_SCHEMA:
        raise evidence.EvidenceError("manifest evidence cases has the wrong release or schema")

    def read_spec(
        value: object, name: str, expected_outcome: str, error_class: str | None,
        code_prefix: str | None,
    ) -> dict:
        spec = _object(value, name, {
            "case_id", "error_class", "expected_code", "expected_outcome", "nodeid", "selector",
        })
        _token(spec["case_id"], f"{name}.case_id")
        _string(spec["nodeid"], f"{name}.nodeid")
        _token(spec["selector"], f"{name}.selector")
        if spec["expected_outcome"] != expected_outcome:
            raise evidence.EvidenceError(f"{name}.expected_outcome is not {expected_outcome}")
        expected_code = spec["case_id"] if code_prefix is None else code_prefix
        if spec["expected_code"] != expected_code:
            raise evidence.EvidenceError(f"{name}.expected_code is not the exact normalized code")
        if spec["error_class"] != error_class:
            raise evidence.EvidenceError(f"{name}.error_class is not the exact closed class")
        return spec

    invariants = _array(doc["invariants"], "manifest evidence cases.invariants")
    if len(invariants) != len(_MANIFEST_TEST_ROSTER):
        raise evidence.EvidenceError("manifest evidence invariant roster has the wrong cardinality")
    expected_nodes = list(_MANIFEST_TEST_ROSTER)
    parsed_invariants = [read_spec(spec, f"manifest invariant {index}", "pass", None, None)
                         for index, spec in enumerate(invariants)]
    if [spec["nodeid"] for spec in parsed_invariants] != expected_nodes:
        raise evidence.EvidenceError("manifest evidence invariant node roster or order is not exact")

    cases = _array(doc["corruption_cases"], "manifest evidence cases.corruption_cases")
    if len(cases) != len(_MANIFEST_CORRUPTION_CASES):
        raise evidence.EvidenceError("manifest evidence corruption case roster has the wrong cardinality")
    parsed_cases = []
    group_expectations = (
        ("refused", "ManifestError"),
        ("unusable", "RevisionUnusable"),
        ("unusable", "CampaignUnusable"),
    )
    for index, (value, (expected_id, expected_members)) in enumerate(zip(cases, _MANIFEST_CORRUPTION_CASES)):
        case = _object(value, f"manifest corruption case {index}", {"id", "members"})
        if case["id"] != expected_id:
            raise evidence.EvidenceError("manifest evidence corruption case roster or order is not exact")
        members = _array(case["members"], f"manifest corruption case {index}.members")
        if len(members) != len(expected_members):
            raise evidence.EvidenceError("manifest evidence corruption member roster has the wrong cardinality")
        outcome, error_class = group_expectations[index]
        expected_codes = _MANIFEST_CORRUPTION_CODE_ROSTER[index]
        parsed_members = [read_spec(
            spec, f"manifest corruption case {index} member {member_index}", outcome,
            error_class, expected_codes[member_index],
        )
                          for member_index, spec in enumerate(members)]
        if [spec["nodeid"] for spec in parsed_members] != list(expected_members):
            raise evidence.EvidenceError("manifest evidence corruption member roster or order is not exact")
        parsed_cases.append({"id": expected_id, "members": parsed_members})
    all_specs = parsed_invariants + [member for case in parsed_cases for member in case["members"]]
    if len({spec["case_id"] for spec in all_specs}) != len(all_specs):
        raise evidence.EvidenceError("manifest evidence case ids must be unique")
    return {"invariants": parsed_invariants, "corruption_cases": parsed_cases}


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
    if expected == COVERAGE_SHARD_SCHEMA:
        return
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
            item = _object(
                record,
                f"support matrix.{field}[{index}]",
                {"digest", "license", "name", "version"},
            )
            _token(item["name"], f"support matrix.{field}[{index}].name")
            _string(item["license"], f"support matrix.{field}[{index}].license")
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


_PYTHON_MATRIX_LANES = ("H0-hermetic", "P0-package-supply")
_PYTHON_MATRIX_SELECTION_FIELDS = (
    "collected", "deselected", "failed", "passed", "selected", "skipped", "xfailed", "xpassed",
)


def _matrix_environment(value: object, name: str) -> dict:
    environment = _object(value, name, {
        "architecture", "isolation_profile", "os", "python", "runner_image",
    })
    for field in ("architecture", "os", "python"):
        _string(environment[field], f"{name}.{field}")
    for field in ("isolation_profile", "runner_image"):
        _digest(environment[field], f"{name}.{field}")
    return environment


def validate_python_matrix_report(document: object, *, identity: object) -> dict:
    """Read the candidate-bound C-PYTHON-MATRIX report before cross-gate reconciliation."""
    identity_doc = evidence.validate_candidate_identity(identity)
    doc = _object(document, "python matrix report", {
        "artifact_type", "candidate_identity_digest", "gate_id", "package_metadata_digest",
        "release", "rows", "schema_version", "support_matrix_digest",
    })
    _schema(doc, PYTHON_MATRIX_REPORT_SCHEMA, "python matrix report")
    if (doc["artifact_type"] != "python-matrix-report" or doc["gate_id"] != "C-PYTHON-MATRIX" or
            doc["candidate_identity_digest"] != evidence.canonical_digest(identity_doc)):
        raise evidence.EvidenceError("python matrix report is bound to the wrong candidate or gate")
    for field in ("package_metadata_digest", "support_matrix_digest"):
        _digest(doc[field], f"python matrix report.{field}")
    rows = _array(doc["rows"], "python matrix report.rows")
    if len(rows) != 6:
        raise evidence.EvidenceError("python matrix report has the wrong frozen support-row cardinality")
    parsed = []
    for index, record in enumerate(rows):
        row = _object(record, f"python matrix report.rows[{index}]", {
            "candidate_identity_digest", "environment", "h0", "lane", "p0",
            "package_metadata_digest", "support_matrix_digest",
        })
        if row["lane"] not in _PYTHON_MATRIX_LANES:
            raise evidence.EvidenceError("python matrix report has an unsupported lane")
        _matrix_environment(
            row["environment"], f"python matrix report.rows[{index}].environment",
        )
        if (row["candidate_identity_digest"] != doc["candidate_identity_digest"] or
                row["support_matrix_digest"] != doc["support_matrix_digest"] or
                row["package_metadata_digest"] != doc["package_metadata_digest"]):
            raise evidence.EvidenceError("python matrix row redirects a report-level candidate or scope binding")
        if row["lane"] == "H0-hermetic":
            if row["p0"] is not None:
                raise evidence.EvidenceError("H0 python matrix row contains P0 evidence")
            h0 = _object(row["h0"], f"python matrix report.rows[{index}].h0", {
                "evidence_instance_id", "fragment_count", "full_h0_roster", "selection",
                "test_report_digest",
            })
            _token(h0["evidence_instance_id"], "python matrix H0 evidence instance")
            if _integer(h0["fragment_count"], "python matrix H0 fragment count") != 6:
                raise evidence.EvidenceError("python matrix H0 fragment count must be exactly six")
            roster = _object(h0["full_h0_roster"], "python matrix H0 full roster", {"count", "digest"})
            if _integer(roster["count"], "python matrix H0 roster count") == 0:
                raise evidence.EvidenceError("python matrix H0 roster is empty")
            _digest(roster["digest"], "python matrix H0 roster digest")
            selection = _object(h0["selection"], "python matrix H0 selection", _PYTHON_MATRIX_SELECTION_FIELDS)
            for field in _PYTHON_MATRIX_SELECTION_FIELDS:
                _integer(selection[field], f"python matrix H0 selection.{field}")
            _digest(h0["test_report_digest"], "python matrix H0 test report digest")
        else:
            if row["h0"] is not None:
                raise evidence.EvidenceError("P0 python matrix row contains H0 evidence")
            p0 = _object(row["p0"], f"python matrix report.rows[{index}].p0", {
                "build_artifacts", "build_evidence_instance_id", "install_artifacts",
                "install_evidence_instance_id",
            })
            for field in ("build_evidence_instance_id", "install_evidence_instance_id"):
                _token(p0[field], f"python matrix P0 {field}")
            for field, expected_names in (
                ("build_artifacts", ("build-log", "package-inventory", "sdist", "wheel")),
                ("install_artifacts", ("install-inventory", "smoke-results")),
            ):
                artifacts = _array(p0[field], f"python matrix P0 {field}")
                observed = []
                for artifact_index, artifact in enumerate(artifacts):
                    item = _object(artifact, f"python matrix P0 {field}[{artifact_index}]", {"digest", "name"})
                    _digest(item["digest"], f"python matrix P0 {field} digest")
                    observed.append(item["name"])
                if tuple(observed) != expected_names:
                    raise evidence.EvidenceError("python matrix P0 source artifact roster is not exact and sorted")
        parsed.append(row)
    def sort_key(row: dict) -> tuple:
        return (
            LANE_ORDER.index(row["lane"]), row["environment"]["os"],
            row["environment"]["architecture"], row["environment"]["python"],
            row["environment"]["runner_image"], row["environment"]["isolation_profile"],
        )
    if parsed != sorted(parsed, key=sort_key) or len({
        (row["lane"], *(row["environment"][field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        ))) for row in parsed
    }) != len(parsed):
        raise evidence.EvidenceError("python matrix rows are not sorted one-to-one support environments")
    return doc


def read_python_matrix_report(data: bytes, *, identity: object) -> dict:
    return validate_python_matrix_report(
        _canonical_reader(data, "python matrix report"), identity=identity,
    )


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
            license_names = [name for name in names if name.endswith(".dist-info/licenses/LICENSE")]
            notice_names = [name for name in names if name.endswith(".dist-info/licenses/NOTICE")]
            if not all(len(group) == 1 for group in (
                metadata_names, wheel_names, record_names, entry_names, license_names, notice_names,
            )):
                raise evidence.EvidenceError(
                    "wheel omits unique metadata, record, entry point, license or notice data"
                )
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
            seen_members = set()
            dist_info_member = record_suffix[1:].rsplit("/", 1)[0]
            data_root = dist_info_member.removesuffix(".dist-info") + ".data"
            for info in archive.infolist():
                if info.is_dir():
                    raise evidence.EvidenceError("source wheel contains a directory member")
                member = _path(info.filename, "source wheel member")
                if member in seen_members:
                    raise evidence.EvidenceError("source wheel contains duplicate file members")
                seen_members.add(member)
                if member == record_suffix[1:]:
                    continue
                body = archive.read(info)
                member_parts = PurePosixPath(member).parts
                if member_parts[0].endswith(".data"):
                    if (member_parts[0] != data_root or len(member_parts) < 3 or
                            member_parts[1] != "data"):
                        raise evidence.EvidenceError(
                            "source wheel contains an unsupported or ambiguous .data scheme"
                        )
                    installed_path = "/".join((prefix, *member_parts[2:]))
                    if not _is_within_path(installed_path, prefix):
                        raise evidence.EvidenceError(
                            "source wheel .data member resolves outside the install prefix"
                        )
                else:
                    installed_path = f"{site_root}/{member}"
                if installed_path in source_files:
                    raise evidence.EvidenceError(
                        "source wheel members collide after PEP 427 installation mapping"
                    )
                source_files[installed_path] = {
                    "digest": raw_sha256(body), "size": len(body),
                }
    except (OSError, zipfile.BadZipFile) as exc:
        raise evidence.EvidenceError(f"source wheel cannot be reopened for install reconciliation: {exc}") from exc
    expected_files = source_files
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


_SBOM_OBSERVATION_NAMES = (
    "sbom-observation-3.10", "sbom-observation-3.11", "sbom-observation-3.12",
)
_SBOM_MAX_COMPONENTS = 128
_SBOM_MAX_FILES = 4_000
_SBOM_MAX_REQUIREMENTS = 256
_VULNERABILITY_OBSERVATION_NAMES = tuple(
    f"vulnerability-observation-{minor}" for minor in ("3.10", "3.11", "3.12")
)
_VULNERABILITY_MAX_FINDINGS = 4_096


def _vulnerability_observation(body: bytes, name: str, *, expected_python: str, sbom: dict) -> tuple[bytes, int, str, str, object, object]:
    """Read one canonical wrapper retaining every byte from one pip-audit run."""
    doc = _object(_artifact_document(body, "C-VULNERABILITY", name), "vulnerability observation", {
        "artifact_type", "exit_status", "finished_at", "requirements", "scanner", "schema_version", "started_at", "stderr", "stdout", "subject",
    })
    if doc["artifact_type"] != "vulnerability-observation" or doc["schema_version"] != "quarry.vulnerability-observation.v1":
        raise evidence.EvidenceError("vulnerability observation has an unsupported schema")
    scanner = _object(doc["scanner"], "vulnerability scanner", {"argv", "name", "version"})
    if scanner["name"] != "pip-audit" or scanner["version"] != "2.10.1":
        raise evidence.EvidenceError("vulnerability observation has an unsupported scanner identity")
    argv = _array(scanner["argv"], "vulnerability scanner argv")
    if (not all(type(value) is str for value in argv) or len(argv) != 10 or
            argv[:6] != ["pip-audit", "--strict", "--no-deps", "--disable-pip", "-r", "/dev/stdin"] or
            argv[6:] != ["--format", "cyclonedx-json", "--progress-spinner", "off"]):
        raise evidence.EvidenceError("vulnerability observation scanner argv is not the retained strict resolved-SBOM invocation")
    subject = _object(doc["subject"], "vulnerability scan subject", {"kind", "requirements_digest", "sbom_observation"})
    requirements = _string(doc["requirements"], "vulnerability observation.requirements")
    if not requirements.startswith("base64:"):
        raise evidence.EvidenceError("vulnerability observation requirements are not base64")
    try:
        requirements_body = base64.b64decode(requirements[7:], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise evidence.EvidenceError("vulnerability observation requirements are malformed") from exc
    if "base64:" + base64.b64encode(requirements_body).decode("ascii") != requirements:
        raise evidence.EvidenceError("vulnerability observation requirements are not canonical base64")
    expected_pins = [f"{row['name']}=={row['version']}" for row in sbom["components"] if row["name"] != "quarry-recon"]
    expected_pins.sort()
    expected_requirements = ("\n".join(expected_pins) + "\n").encode()
    if subject != {"kind": "resolved-sbom-closure", "requirements_digest": raw_sha256(expected_requirements), "sbom_observation": f"sbom-observation-{expected_python}"} or requirements_body != expected_requirements:
        raise evidence.EvidenceError("vulnerability observation does not bind the exact non-root C-SBOM dependency closure")
    if type(doc["exit_status"]) is not int or doc["exit_status"] not in {0, 1}:
        raise evidence.EvidenceError("vulnerability scanner exit status is not the exact pip-audit 0/1 contract")
    decoded = {}
    for field, bound in (("stdout", 512 * 1024), ("stderr", 64 * 1024)):
        value = _string(doc[field], f"vulnerability observation.{field}")
        if not value.startswith("base64:"):
            raise evidence.EvidenceError("vulnerability observation raw stream is not base64")
        try:
            raw = base64.b64decode(value[7:], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise evidence.EvidenceError("vulnerability observation raw stream is malformed") from exc
        if "base64:" + base64.b64encode(raw).decode("ascii") != value:
            raise evidence.EvidenceError("vulnerability observation raw stream is not canonical base64")
        if len(raw) > bound:
            raise evidence.EvidenceError("vulnerability observation raw stream exceeds its bound")
        decoded[field] = raw
    started_at = _timestamp(doc["started_at"], "vulnerability observation.started_at")
    finished_at = _timestamp(doc["finished_at"], "vulnerability observation.finished_at")
    if finished_at < started_at:
        raise evidence.EvidenceError("vulnerability observation finished before it started")
    return decoded["stdout"], doc["exit_status"], doc["started_at"], doc["finished_at"], started_at, finished_at


def _vulnerability_raw(body: bytes, name: str) -> tuple[set[tuple[str, str]], list[dict]]:
    """Extract the bounded, source-owned advisory facts from pip-audit CycloneDX."""
    doc = evidence.load_json_bytes(body, maximum=8 * 1024 * 1024)
    if type(doc) is not dict:
        raise evidence.EvidenceError("vulnerability raw scan must be an object")
    if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") != "1.4":
        raise evidence.EvidenceError("vulnerability raw scan is not a CycloneDX 1.4 document")
    components = _array(doc.get("components"), "vulnerability raw components")
    if not components or len(components) > _SBOM_MAX_COMPONENTS:
        raise evidence.EvidenceError("vulnerability raw component roster is empty or exceeds the bound")
    references: dict[str, tuple[str, str]] = {}
    component_facts: set[tuple[str, str]] = set()
    for index, value in enumerate(components):
        if type(value) is not dict:
            raise evidence.EvidenceError("vulnerability raw component is not an object")
        component = _object(value, f"vulnerability raw components[{index}]", {
            *value.keys(),
        })
        normalized = _sbom_name(component.get("name"), f"vulnerability raw components[{index}].name")
        version = _string(component.get("version"), f"vulnerability raw components[{index}].version")
        fact = (normalized, version)
        if fact in component_facts:
            raise evidence.EvidenceError("vulnerability raw components are not unique")
        component_facts.add(fact)
        reference = component.get("bom-ref")
        if type(reference) is str:
            _string(reference, f"vulnerability raw components[{index}].bom-ref")
            if reference in references:
                raise evidence.EvidenceError("vulnerability raw component references are not unique")
            references[reference] = fact
    vulnerabilities = doc.get("vulnerabilities", [])
    vulnerabilities = _array(vulnerabilities, "vulnerability raw advisories")
    if len(vulnerabilities) > _VULNERABILITY_MAX_FINDINGS:
        raise evidence.EvidenceError("vulnerability raw advisory roster exceeds the bound")
    findings = []
    for index, value in enumerate(vulnerabilities):
        if type(value) is not dict:
            raise evidence.EvidenceError("vulnerability raw advisory is not an object")
        advisory = _object(value, f"vulnerability raw advisories[{index}]", {*value.keys()})
        advisory_id = _token(advisory.get("id"), f"vulnerability raw advisories[{index}].id")
        affects = _array(advisory.get("affects"), f"vulnerability raw advisories[{index}].affects")
        if not affects:
            raise evidence.EvidenceError("vulnerability raw advisory omits its affected component")
        for affected_index, affected in enumerate(affects):
            if type(affected) is not dict:
                raise evidence.EvidenceError("vulnerability raw affected component is not an object")
            row = _object(affected, f"vulnerability raw advisories[{index}].affects[{affected_index}]", {*affected.keys()})
            reference = _string(row.get("ref"), "vulnerability raw affected component reference")
            component = references.get(reference)
            if component is None:
                raise evidence.EvidenceError("vulnerability raw advisory references an unknown component")
            findings.append({"advisory_id": advisory_id, "component": {
                "name": component[0], "version": component[1],
            }})
    findings.sort(key=lambda row: (row["advisory_id"], row["component"]["name"], row["component"]["version"]))
    if len({(row["advisory_id"], row["component"]["name"], row["component"]["version"])
            for row in findings}) != len(findings):
        raise evidence.EvidenceError("vulnerability raw advisory facts are duplicated")
    return component_facts, findings


def _validate_vulnerability_findings(
    body: bytes, *, identity: dict, report: dict, resolver: ArtifactResolver,
    support: dict, thresholds: dict, bodies: Mapping[str, bytes], policy: dict,
) -> None:
    """Fail closed unless raw advisories, SBOM environments, and authority all reconcile."""
    doc = _object(_artifact_document(body, "C-VULNERABILITY", "vulnerability-findings"),
                  "vulnerability findings", {
        "artifact_type", "candidate_identity_digest", "dispositions", "findings", "gate_id",
        "provider", "raw_scans", "release", "schema_version", "unaccepted_findings",
    })
    if {key: doc[key] for key in ("artifact_type", "candidate_identity_digest", "gate_id", "release", "schema_version")} != {
        "artifact_type": "vulnerability-findings", "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-VULNERABILITY", "release": RELEASE, "schema_version": VULNERABILITY_FINDINGS_SCHEMA,
    }:
        raise evidence.EvidenceError("vulnerability findings have the wrong candidate, gate or release")
    provider = _object(doc["provider"], "vulnerability provider", {
        "database_snapshot", "dependency_scans", "external_results", "freshness", "name", "trusted_attestation",
    })
    if provider["name"] != "release-vulnerability-authority":
        raise evidence.EvidenceError("vulnerability findings name an unsupported provider")
    # A raw pip-audit document does not prove database provenance or currency.  These
    # fields intentionally remain mandatory and independently attested before a pass.
    if any(provider[field] is None for field in ("database_snapshot", "freshness", "trusted_attestation")):
        raise evidence.EvidenceError("vulnerability provider database snapshot, freshness or trusted attestation is absent")
    snapshot = _object(provider["database_snapshot"], "vulnerability database snapshot", {"digest", "id", "source"})
    _digest(snapshot["digest"], "vulnerability database snapshot.digest")
    _token(snapshot["id"], "vulnerability database snapshot.id")
    _string(snapshot["source"], "vulnerability database snapshot.source")
    freshness = _object(provider["freshness"], "vulnerability database freshness", {"expires_at", "observed_at"})
    observed_at = _timestamp(freshness["observed_at"], "vulnerability database freshness.observed_at")
    expires_at = _timestamp(freshness["expires_at"], "vulnerability database freshness.expires_at")
    interval_start = min(_timestamp(row["started_at"], "vulnerability evidence started_at") for row in report["instances"])
    interval_end = max(_timestamp(row["finished_at"], "vulnerability evidence finished_at") for row in report["instances"])
    if expires_at <= observed_at:
        raise evidence.EvidenceError("vulnerability provider database freshness is stale")
    final_sbom = _artifact_document(resolver.read("C-SBOM", "sbom"), "C-SBOM", "sbom")
    expected_subjects = [{"digest": row["content_digest"], "name": row["name"], "relationship": row["relationship"], "version": row["version"]}
                         for row in final_sbom["components"] if row["relationship"] in {"tool", "template"}]
    expected_environments = [row for row in support["environments"] if row["lane"] == "P0-package-supply"]
    expected_environments.sort(key=lambda row: row["python"])
    if any(next((tool for tool in row["toolchain"] if tool["name"] == "pip-audit"), None) is None or
           next(tool for tool in row["toolchain"] if tool["name"] == "pip-audit")["version"] != "2.10.1"
           for row in report["instances"]):
        raise evidence.EvidenceError("vulnerability findings do not bind the exact pip-audit tool identity/version")
    scans = _array(doc["raw_scans"], "vulnerability raw scans")
    if len(scans) != 3:
        raise evidence.EvidenceError("vulnerability raw scans do not cover the frozen P0 topology")
    sbom = final_sbom
    sbom_by_python = {row["environment"]["python"]: row["name"] for row in sbom["observations"]}
    raw_findings = []
    expected_scans = []
    for environment, raw_name in zip(expected_environments, _VULNERABILITY_OBSERVATION_NAMES, strict=True):
        sbom_name = sbom_by_python.get(environment["python"])
        if sbom_name is None:
            raise evidence.EvidenceError("vulnerability scan lacks a matching C-SBOM environment")
        observation = _artifact_document(resolver.read("C-SBOM", sbom_name), "C-SBOM", sbom_name)
        raw, exit_status, scan_started_text, scan_finished_text, scan_started_at, scan_finished_at = _vulnerability_observation(
            bodies[raw_name], raw_name, expected_python=environment["python"].rsplit(".", 1)[0], sbom=observation,
        )
        components, findings = _vulnerability_raw(raw, raw_name)
        if (exit_status == 0) != (not findings):
            raise evidence.EvidenceError("vulnerability scanner exit status does not reconcile with raw advisories")
        sbom_components = {(_sbom_name(row["name"], "C-SBOM component"), row["version"])
                           for row in _array(observation["components"], "C-SBOM observation components")
                           if row["name"] != "quarry-recon"}
        if components != sbom_components:
            raise evidence.EvidenceError("vulnerability raw components do not reconcile with the matching C-SBOM environment")
        instance = next((row for row in report["instances"] if row["environment"] == {key: environment[key] for key in ("architecture", "isolation_profile", "os", "python", "runner_image")}), None)
        if instance is None:
            raise evidence.EvidenceError("vulnerability raw scan lacks an exact signed P0 evidence instance")
        instance_started_at = _timestamp(instance["started_at"], "vulnerability P0 instance.started_at")
        instance_finished_at = _timestamp(instance["finished_at"], "vulnerability P0 instance.finished_at")
        if scan_started_at < instance_started_at or scan_finished_at > instance_finished_at:
            raise evidence.EvidenceError("vulnerability raw scan lies outside its exact signed P0 instance interval")
        expected_scans.append({
            "cyclonedx_digest": raw_sha256(raw), "environment": instance["environment"],
            "evidence_instance_id": instance["id"], "name": raw_name,
            "exit_status": exit_status, "finished_at": scan_finished_text,
            "observation_digest": raw_sha256(bodies[raw_name]), "sbom_observation_digest": raw_sha256(resolver.read("C-SBOM", sbom_name)),
            "sbom_observation_name": sbom_name, "started_at": scan_started_text,
        })
        raw_findings.extend({**finding, "environment": instance["environment"], "raw_scan": raw_name}
                            for finding in findings)
    if scans != expected_scans:
        raise evidence.EvidenceError("vulnerability raw scan roster does not bind exact retained bytes and P0 instances")
    if provider["dependency_scans"] != expected_scans:
        raise evidence.EvidenceError("vulnerability provider attestation does not bind the exact retained dependency scans")
    if observed_at < interval_start or \
            observed_at > min(_timestamp(row["started_at"], "vulnerability scan.started_at") for row in expected_scans) or \
            expires_at < interval_end or \
            expires_at < max(_timestamp(row["finished_at"], "vulnerability scan.finished_at") for row in expected_scans):
        raise evidence.EvidenceError("vulnerability provider database freshness does not cover every dependency scan")
    external_subjects = ([{"digest": digest, "kind": "runner_image"} for digest in sorted({row["environment"]["runner_image"] for row in report["instances"]})] +
                         [{"digest": row["digest"], "kind": row["relationship"], "name": row["name"], "version": row["version"]}
                          for row in expected_subjects])
    external = _array(provider["external_results"], "vulnerability external results")
    if len(external) != len(external_subjects):
        raise evidence.EvidenceError("vulnerability external results do not cover the exact runner-image/tool/template roster")
    external_unaccepted = 0
    for index, value in enumerate(external):
        row = _object(value, f"vulnerability external results[{index}]", {"advisories", "subject"})
        if row["subject"] != external_subjects[index]:
            raise evidence.EvidenceError("vulnerability external result has an invented or missing subject")
        advisories = _array(row["advisories"], "vulnerability external advisories")
        if len(advisories) > _VULNERABILITY_MAX_FINDINGS:
            raise evidence.EvidenceError("vulnerability external advisory roster exceeds the bound")
        previous = None
        for advisory in advisories:
            item = _object(advisory, "vulnerability external advisory", {"exception", "id", "state"})
            advisory_id = _token(item["id"], "vulnerability external advisory.id")
            if previous is not None and advisory_id <= previous:
                raise evidence.EvidenceError("vulnerability external advisories are not sorted and unique")
            previous = advisory_id
            if item["state"] == "unaccepted":
                if item["exception"] is not None:
                    raise evidence.EvidenceError("unaccepted external advisory has an exception")
                external_unaccepted += 1
            elif item["state"] == "accepted_exception":
                exception = _object(item["exception"], "vulnerability external exception", {"approval", "expires_at", "owner", "rationale"})
                _string(exception["owner"], "vulnerability external exception.owner")
                _string(exception["rationale"], "vulnerability external exception.rationale")
                if len(exception["rationale"]) < 20 or _timestamp(exception["expires_at"], "vulnerability external exception.expires_at") <= interval_end or type(exception["approval"]) is not dict:
                    raise evidence.EvidenceError("vulnerability external exception is not approved, rationalized and unexpired")
                verify_signature_envelope(exception["approval"], policy=policy, role="approval", gate_id="C-VULNERABILITY",
                    payload_digest=raw_sha256(canonical_json_line({"expires_at": exception["expires_at"], "id": advisory_id, "owner": exception["owner"], "rationale": exception["rationale"], "subject": row["subject"]})),
                    candidate_identity_digest=evidence.canonical_digest(identity), at=interval_end)
            else:
                raise evidence.EvidenceError("vulnerability external advisory state is unsupported")
    attestation = _object(provider["trusted_attestation"], "vulnerability database attestation", {"issuer", "signature"})
    _string(attestation["issuer"], "vulnerability database attestation.issuer")
    if type(attestation["signature"]) is not dict:
        raise evidence.EvidenceError("vulnerability provider database attestation is untrusted")
    verify_signature_envelope(
        attestation["signature"], policy=policy, role="approval", gate_id="C-VULNERABILITY",
        payload_digest=raw_sha256(canonical_json_line({"database_snapshot": snapshot, "dependency_scans": expected_scans,
            "external_results": external, "freshness": freshness, "issuer": attestation["issuer"], "provider": provider["name"]})),
        candidate_identity_digest=evidence.canonical_digest(identity), at=interval_end,
    )
    if len(raw_findings) > _VULNERABILITY_MAX_FINDINGS:
        raise evidence.EvidenceError("vulnerability finding roster exceeds the bound")
    raw_findings.sort(key=lambda row: (row["advisory_id"], row["component"]["name"], row["component"]["version"], row["environment"]["python"]))
    if doc["findings"] != raw_findings:
        raise evidence.EvidenceError("vulnerability findings dropped or invented raw advisory facts")
    dispositions = _array(doc["dispositions"], "vulnerability dispositions")
    if len(dispositions) != len(raw_findings):
        raise evidence.EvidenceError("vulnerability dispositions do not cover the exact finding roster")
    expected_keys = [(row["advisory_id"], row["component"], row["environment"], row["raw_scan"]) for row in raw_findings]
    unaccepted = 0
    for index, disposition in enumerate(dispositions):
        row = _object(disposition, f"vulnerability dispositions[{index}]", {
            "advisory_id", "component", "environment", "exception", "raw_scan", "state",
        })
        key = (row["advisory_id"], row["component"], row["environment"], row["raw_scan"])
        if key != expected_keys[index]:
            raise evidence.EvidenceError("vulnerability dispositions are not the exact sorted finding roster")
        if row["state"] == "unaccepted":
            if row["exception"] is not None:
                raise evidence.EvidenceError("unaccepted vulnerability disposition has an exception")
            unaccepted += 1
        elif row["state"] == "accepted_exception":
            exception = _object(row["exception"], "vulnerability exception", {"approval", "expires_at", "owner", "rationale"})
            _string(exception["owner"], "vulnerability exception.owner")
            _string(exception["rationale"], "vulnerability exception.rationale")
            if len(exception["rationale"]) < 20:
                raise evidence.EvidenceError("vulnerability exception rationale is too short")
            if _timestamp(exception["expires_at"], "vulnerability exception.expires_at") <= interval_end:
                raise evidence.EvidenceError("vulnerability exception is expired")
            if type(exception["approval"]) is not dict:
                raise evidence.EvidenceError("vulnerability exception approval is absent")
            verify_signature_envelope(
                exception["approval"], policy=policy,
                payload_digest=raw_sha256(canonical_json_line({"advisory_id": row["advisory_id"], "component": row["component"], "environment": row["environment"], "expires_at": exception["expires_at"], "owner": exception["owner"], "rationale": exception["rationale"]})),
                candidate_identity_digest=evidence.canonical_digest(identity), role="approval",
                at=interval_end, gate_id="C-VULNERABILITY",
            )
        else:
            raise evidence.EvidenceError("vulnerability disposition state is unsupported")
    unaccepted += external_unaccepted
    if doc["unaccepted_findings"] != unaccepted:
        raise evidence.EvidenceError("vulnerability unaccepted finding count does not recompute")
    thresholds = [row for row in thresholds["thresholds"] if row["gate_id"] == "C-VULNERABILITY"]
    expected_threshold = ("C-VULNERABILITY", "absolute", "unaccepted_findings", "at_most", "maximum", "count")
    if [tuple(row[key] for key in ("gate_id", "class", "metric", "operator", "statistic", "unit")) for row in thresholds] != [expected_threshold]:
        raise evidence.EvidenceError("vulnerability threshold metric contract is not frozen")
    threshold = thresholds[0]
    expected_measurement = [{
        "baseline_digest": threshold["baseline_digest"], "class": "absolute", "invalidated_trials": 0,
        "metric": "unaccepted_findings", "observed_trials": 1, "statistic": "maximum",
        "unit": "count", "value": unaccepted,
    }]
    if report["measurements"] != expected_measurement:
        raise evidence.EvidenceError("vulnerability gate-evidence measurement does not recompute from findings")


def _sbom_name(value: object, name: str) -> str:
    text = _token(value, name)
    return re.sub(r"[-_.]+", "-", text).lower()


def _sbom_environment(value: object, name: str, *, raw: bool = False) -> dict:
    environment = _object(value, name, {
        "architecture", "isolation_profile", "os", "python", "runner_image",
    })
    for field in ("architecture", "os", "python"):
        _string(environment[field], f"{name}.{field}")
    for field in ("isolation_profile", "runner_image"):
        if environment[field] is not None:
            _digest(environment[field], f"{name}.{field}")
    if raw and (environment["isolation_profile"] is not None or environment["runner_image"] is not None):
        raise evidence.EvidenceError("C-SBOM raw observation must not invent signed runner identity fields")
    return environment


def _sbom_component(value: object, name: str, marker_environment: Mapping[str, str]) -> dict:
    component = _object(value, name, {
        "active_dependencies", "content_digest", "files", "license", "name", "raw_requirements",
        "version",
    })
    normalized = _sbom_name(component["name"], f"{name}.name")
    if component["name"] != normalized:
        raise evidence.EvidenceError("C-SBOM component names must be canonical")
    _string(component["version"], f"{name}.version")
    _string(component["license"], f"{name}.license")
    files = _array(component["files"], f"{name}.files")
    if not files or len(files) > _SBOM_MAX_FILES:
        raise evidence.EvidenceError("C-SBOM component files are empty or exceed the bound")
    parsed_files = []
    for index, value in enumerate(files):
        row = _object(value, f"{name}.files[{index}]", {"digest", "path", "size"})
        _digest(row["digest"], f"{name}.files[{index}].digest")
        _path(row["path"], f"{name}.files[{index}].path")
        _integer(row["size"], f"{name}.files[{index}].size")
        parsed_files.append(row)
    if [row["path"] for row in parsed_files] != sorted(row["path"] for row in parsed_files) or \
            len({row["path"] for row in parsed_files}) != len(parsed_files):
        raise evidence.EvidenceError("C-SBOM component files are not sorted and unique")
    if component["content_digest"] != raw_sha256(canonical_json_line(parsed_files)):
        raise evidence.EvidenceError("C-SBOM component content digest does not recompute from files")
    requirements = _array(component["raw_requirements"], f"{name}.raw_requirements")
    if len(requirements) > _SBOM_MAX_REQUIREMENTS:
        raise evidence.EvidenceError("C-SBOM component requirements exceed the bound")
    parsed_requirements = []
    for index, value in enumerate(requirements):
        row = _object(value, f"{name}.raw_requirements[{index}]", {"active", "name", "raw"})
        _string(row["raw"], f"{name}.raw_requirements[{index}].raw")
        dependency = _sbom_name(row["name"], f"{name}.raw_requirements[{index}].name")
        if row["name"] != dependency or type(row["active"]) is not bool:
            raise evidence.EvidenceError("C-SBOM raw requirement status is invalid")
        parsed_requirements.append(row)
    if [row["raw"] for row in parsed_requirements] != sorted(row["raw"] for row in parsed_requirements) or \
            len({row["raw"] for row in parsed_requirements}) != len(parsed_requirements):
        raise evidence.EvidenceError("C-SBOM raw requirement rows are not sorted and unique")
    dependencies = _array(component["active_dependencies"], f"{name}.active_dependencies")
    parsed_dependencies = [_sbom_name(value, f"{name}.active_dependencies") for value in dependencies]
    if dependencies != parsed_dependencies or parsed_dependencies != sorted(parsed_dependencies) or \
            len(set(parsed_dependencies)) != len(parsed_dependencies):
        raise evidence.EvidenceError("C-SBOM active dependency edges are not canonical")
    if parsed_dependencies != [row["name"] for row in parsed_requirements if row["active"]]:
        raise evidence.EvidenceError("C-SBOM active dependency edges do not match raw requirements")
    return component


def _validate_sbom_observation(
    body: bytes, *, name: str, expected_environment: dict, package_wheel: Mapping[str, object],
    producer_digest: str,
) -> dict:
    doc = _object(_artifact_document(body, "C-SBOM", name), "C-SBOM observation", {
        "artifact_type", "components", "dependency_graph_digest", "environment", "interpreter",
        "marker_environment", "marker_evaluator", "package", "producer", "schema_version",
        "source_wheel",
    })
    if doc["artifact_type"] != "sbom-observation" or doc["schema_version"] != GATE_ARTIFACT_SCHEMA:
        raise evidence.EvidenceError("C-SBOM observation has the wrong schema variant")
    observed_environment = _sbom_environment(doc["environment"], "C-SBOM observation.environment", raw=True)
    if any(observed_environment[field] != expected_environment[field] for field in ("architecture", "os", "python")):
        raise evidence.EvidenceError("C-SBOM observation identifies the wrong accepted P0 environment")
    interpreter = _object(doc["interpreter"], "C-SBOM observation.interpreter", {
        "base_prefix", "executable", "implementation", "prefix", "version",
    })
    for field in interpreter:
        _string(interpreter[field], f"C-SBOM observation.interpreter.{field}")
    if interpreter["implementation"] != "cpython" or not interpreter["version"].startswith(expected_environment["python"]):
        raise evidence.EvidenceError("C-SBOM observation interpreter does not match its environment")
    evaluator = _object(doc["marker_evaluator"], "C-SBOM observation.marker_evaluator", {
        "implementation", "version",
    })
    if evaluator["implementation"] != "pip._vendor.packaging":
        raise evidence.EvidenceError("C-SBOM observation used an unsupported marker evaluator")
    _string(evaluator["version"], "C-SBOM observation.marker_evaluator.version")
    if doc["producer"] != {
        "digest": producer_digest,
        "name": "sbom-observation-producer",
    }:
        raise evidence.EvidenceError("C-SBOM observation used an unbound producer")
    marker_environment = doc["marker_environment"]
    if type(marker_environment) is not dict or not marker_environment or len(marker_environment) > 32:
        raise evidence.EvidenceError("C-SBOM observation marker environment is invalid")
    for key, value in marker_environment.items():
        _token(key, "C-SBOM observation marker environment key")
        _string(value, "C-SBOM observation marker environment value", empty=True)
    if marker_environment.get("extra") != "" or marker_environment.get("python_full_version") != expected_environment["python"] or \
            marker_environment.get("python_version") != ".".join(expected_environment["python"].split(".")[:2]):
        raise evidence.EvidenceError("C-SBOM observation marker environment does not bind its interpreter")
    wheel = _object(doc["source_wheel"], "C-SBOM observation.source_wheel", {"digest", "size"})
    _digest(wheel["digest"], "C-SBOM observation.source_wheel.digest")
    _integer(wheel["size"], "C-SBOM observation.source_wheel.size")
    if wheel != dict(package_wheel):
        raise evidence.EvidenceError("C-SBOM observation is bound to the wrong nominated wheel")
    components = _array(doc["components"], "C-SBOM observation.components")
    if not components or len(components) > _SBOM_MAX_COMPONENTS:
        raise evidence.EvidenceError("C-SBOM observation component closure exceeds bounds")
    parsed = [_sbom_component(component, f"C-SBOM observation.components[{index}]", marker_environment)
              for index, component in enumerate(components)]
    names = [component["name"] for component in parsed]
    if names != sorted(names) or len(names) != len(set(names)):
        raise evidence.EvidenceError("C-SBOM observation components are not sorted and unique")
    if doc["package"] != {"name": "quarry-recon", "version": RELEASE} or "quarry-recon" not in names:
        raise evidence.EvidenceError("C-SBOM observation does not identify the nominated installed package")
    if sum(row["size"] for component in parsed for row in component["files"]) > 256 * 1024 * 1024:
        raise evidence.EvidenceError("C-SBOM observation claimed files exceed the global bound")
    by_name = {component["name"]: component for component in parsed}
    if any(dependency not in by_name for component in parsed for dependency in component["active_dependencies"]):
        raise evidence.EvidenceError("C-SBOM observation omits an active reachable dependency")
    reachable = {"quarry-recon"}
    pending = ["quarry-recon"]
    while pending:
        current = pending.pop()
        for dependency in by_name[current]["active_dependencies"]:
            if dependency not in reachable:
                reachable.add(dependency)
                pending.append(dependency)
    if reachable != set(by_name):
        raise evidence.EvidenceError("C-SBOM observation contains a non-reachable component")
    graph = [{"dependencies": component["active_dependencies"], "name": component["name"],
              "version": component["version"]} for component in parsed]
    if doc["dependency_graph_digest"] != raw_sha256(canonical_json_line(graph)):
        raise evidence.EvidenceError("C-SBOM observation dependency graph digest does not recompute")
    return doc


def _validate_sbom(
    body: bytes, *, identity: dict, support: dict, package_wheel_body: bytes,
    package_wheel: Mapping[str, object], producer_digest: str, report: dict,
    bodies: Mapping[str, bytes],
) -> None:
    doc = _object(_artifact_document(body, "C-SBOM", "sbom"), "SBOM", {
        "artifact_type", "candidate_identity_digest", "components", "dependency_graph_digest", "gate_id",
        "observations", "package", "release", "sbom_digest", "schema_version",
    })
    if (doc["artifact_type"] != "sbom" or doc["schema_version"] != GATE_ARTIFACT_SCHEMA or
            doc["release"] != RELEASE or doc["gate_id"] != "C-SBOM" or
            doc["candidate_identity_digest"] != evidence.canonical_digest(identity) or
            doc["package"] != {"name": "quarry-recon", "version": RELEASE}):
        raise evidence.EvidenceError("SBOM is bound to the wrong candidate or contract")
    observations = _array(doc["observations"], "SBOM.observations")
    expected_environments = [{key: row[key] for key in (
        "architecture", "isolation_profile", "os", "python", "runner_image",
    )} for row in support["environments"] if row["lane"] == "P0-package-supply"]
    expected_environments.sort(key=lambda row: row["python"])
    if len(observations) != len(_SBOM_OBSERVATION_NAMES) or len(expected_environments) != 3:
        raise evidence.EvidenceError("C-SBOM has the wrong frozen P0 observation topology")
    parsed_observations = []
    for index, value in enumerate(observations):
        row = _object(value, f"SBOM.observations[{index}]", {"digest", "environment", "evidence_instance_id", "name"})
        _digest(row["digest"], f"SBOM.observations[{index}].digest")
        _token(row["evidence_instance_id"], f"SBOM.observations[{index}].evidence_instance_id")
        _sbom_environment(row["environment"], f"SBOM.observations[{index}].environment")
        parsed_observations.append(row)
    if [(row["environment"]["python"], row["name"]) for row in parsed_observations] != [
            (environment["python"], name) for environment, name in zip(expected_environments, _SBOM_OBSERVATION_NAMES, strict=True)]:
        raise evidence.EvidenceError("SBOM observations are not the exact sorted Python 3.10/3.11/3.12 roster")
    if [row["environment"] for row in parsed_observations] != expected_environments:
        raise evidence.EvidenceError("SBOM observations do not cover the exact accepted P0 environments")
    raw_requirements = _metadata_values(_wheel_metadata(package_wheel_body), "Requires-Dist", "wheel")
    if not raw_requirements:
        raise evidence.EvidenceError("candidate wheel metadata has no dependency set")
    observed_documents = []
    for observation in parsed_observations:
        name = observation["name"]
        raw = bodies[name]
        if raw_sha256(raw) != observation["digest"]:
            raise evidence.EvidenceError("SBOM observation digest does not match retained raw bytes")
        owners = [instance for instance in report["instances"] if instance["lane"] == "P0-package-supply" and
                  instance["id"] == observation["evidence_instance_id"] and
                  instance["environment"] == observation["environment"] and
                  {"digest": observation["digest"], "name": name} in instance["artifacts"]]
        if len(owners) != 1:
            raise evidence.EvidenceError("SBOM raw observation does not bind one exact signed P0 evidence instance/environment")
        observed = _validate_sbom_observation(
            raw,
            name=name,
            expected_environment=observation["environment"],
            package_wheel=package_wheel,
            producer_digest=producer_digest,
        )
        root = next(component for component in observed["components"] if component["name"] == "quarry-recon")
        if [row["raw"] for row in root["raw_requirements"]] != sorted(raw_requirements):
            raise evidence.EvidenceError("C-SBOM direct roots do not exactly match nominated wheel metadata")
        observed_documents.append((observation, observed))
    components = _array(doc["components"], "SBOM.components")
    direct_by_name: dict[str, list[str]] = {}
    for requirement in raw_requirements:
        match = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", requirement)
        if match is None:
            raise evidence.EvidenceError("candidate wheel dependency name is unsupported")
        normalized = _sbom_name(match.group(0), "candidate wheel dependency name")
        direct_by_name.setdefault(normalized, []).append(requirement)
    installed_by_name: dict[tuple[str, str, str], list[tuple[dict, dict]]] = {}
    for observation, observed in observed_documents:
        for component in observed["components"]:
            installed_by_name.setdefault(
                (component["name"], component["version"], component["license"]), [],
            ).append((observation, component))
    expected_components = []
    for (name, version, license_value), rows in installed_by_name.items():
        environments = [{
            "active_dependencies": component["active_dependencies"],
            "content_digest": component["content_digest"], "environment": observation["environment"],
            "raw_requirements": component["raw_requirements"],
        } for observation, component in rows]
        environments.sort(key=lambda row: row["environment"]["python"])
        expected_components.append({
            "content_digest": raw_sha256(canonical_json_line(environments)),
            "declared_requirement": direct_by_name[name][0] if len(direct_by_name.get(name, ())) == 1 else None,
            "environments": environments,
            "license": license_value,
            "name": name,
            "relationship": "project" if name == "quarry-recon" else "dependency",
            "version": version,
        })
    expected_components.extend({
        "content_digest": row["digest"], "declared_requirement": None, "environments": [],
        "license": row["license"], "name": row["name"], "relationship": relationship,
        "version": row["version"],
    } for relationship, rows in (("template", support["template_sets"]), ("tool", support["tools"])) for row in rows)
    expected_components.sort(key=lambda row: (row["relationship"], row["name"], row["version"], row["license"] or ""))
    if len(components) != len(expected_components):
        raise evidence.EvidenceError("SBOM final rows do not exactly reconcile support inventory and license assertions")
    for actual, expected in zip(components, expected_components, strict=True):
        if actual != expected:
            raise evidence.EvidenceError("SBOM final rows do not exactly reconcile support inventory and license assertions")
    graph = [{"digest": row["digest"], "environment": row["environment"]} for row in parsed_observations]
    if doc["dependency_graph_digest"] != raw_sha256(canonical_json_line(graph)):
        raise evidence.EvidenceError("SBOM dependency graph digest does not recompute from observations")
    payload = {key: doc[key] for key in doc if key != "sbom_digest"}
    if doc["sbom_digest"] != raw_sha256(canonical_json_line(payload)):
        raise evidence.EvidenceError("SBOM top-level digest does not recompute")


_PROVENANCE_MATERIAL_ARTIFACTS = (
    ("C-PACKAGE-BUILD", "gate-evidence"),
    ("C-PACKAGE-INSTALL", "gate-evidence"),
    ("C-SBOM", "sbom"),
    ("C-VULNERABILITY", "vulnerability-findings"),
)


def _provenance_subjects(resolver: ArtifactResolver) -> list[dict]:
    """The two releasable package subjects (the established SLSA boundary)."""
    return [{
        "digest": resolver.record("C-PACKAGE-BUILD", name)["digest"],
        "name": name,
    } for name in ("sdist", "wheel")]


def _provenance_materials(identity: dict, resolver: ArtifactResolver) -> list[dict]:
    materials = [{
        "digest": evidence.canonical_digest(identity),
        "name": "candidate-identity",
    }] + [{"digest": row["digest"], "name": row["name"]} for row in identity["inputs"]] + [{
        "digest": resolver.record(gate_id, name)["digest"],
        "name": f"{gate_id}/{name}",
    } for gate_id, name in _PROVENANCE_MATERIAL_ARTIFACTS]
    materials.sort(key=lambda row: row["name"])
    return materials


def _provenance_owner(report: dict, bodies: Mapping[str, bytes], *, gate: dict) -> dict:
    """Return the one trusted P0 execution that produced this signed assertion."""
    expected = {
        ("provenance", raw_sha256(bodies["provenance"])),
        ("signature-verification", raw_sha256(bodies["signature-verification"])),
    }
    owners = [
        instance for instance in report["instances"]
        if expected.issubset({(artifact["name"], artifact["digest"]) for artifact in instance["artifacts"]})
    ]
    if len(owners) != 1:
        raise evidence.EvidenceError(
            "provenance artifacts are not referenced by one exact signed P0 evidence instance"
        )
    owner = owners[0]
    if (owner["lane"] != "P0-package-supply" or owner["environment"] != gate["environment"] or
            owner["toolchain"] != gate["toolchain"]):
        raise evidence.EvidenceError(
            "provenance execution identity does not match its signed P0 environment/toolchain"
        )
    return owner


def _provenance_builder_owner(resolver: ArtifactResolver, *, identity: dict) -> dict:
    """Resolve the trusted P0 build execution from its complete signed output set."""
    report = read_evidence_report(
        resolver.read("C-PACKAGE-BUILD", "gate-evidence"),
        identity=identity, gate_id="C-PACKAGE-BUILD",
    )
    expected = {
        (name, resolver.record("C-PACKAGE-BUILD", name)["digest"])
        for name in ("build-log", "package-inventory", "sdist", "wheel")
    }
    owners = [
        instance for instance in report["instances"]
        if expected.issubset({(artifact["name"], artifact["digest"]) for artifact in instance["artifacts"]})
    ]
    if len(owners) != 1 or owners[0]["lane"] != "P0-package-supply":
        raise evidence.EvidenceError(
            "package build artifacts are not referenced by one exact signed P0 builder evidence instance"
        )
    return owners[0]


def _validate_provenance_artifacts(
    bodies: Mapping[str, bytes], *, gate: dict, identity: dict, resolver: ArtifactResolver,
    report: dict, policy: dict,
) -> None:
    provenance = _object(
        _artifact_document(bodies["provenance"], "C-PROVENANCE", "provenance"),
        "provenance",
        {
            "artifact_type", "builder", "candidate_identity_digest", "gate_id", "materials",
            "release", "schema_version", "subjects",
        },
    )
    owner = _provenance_owner(report, bodies, gate=gate)
    builder_owner = _provenance_builder_owner(resolver, identity=identity)
    # A provenance collector may seal a builder's output only from the same
    # accepted execution context.  Referencing its instance id alone would let
    # a differently tooled P0 execution make that substitution.
    if (owner["environment"] != builder_owner["environment"] or
            owner["toolchain"] != builder_owner["toolchain"]):
        raise evidence.EvidenceError(
            "provenance execution context does not match the exact signed P0 package builder"
        )
    expected_materials = _provenance_materials(identity, resolver)
    expected_builder = {
        "environment": builder_owner["environment"],
        "evidence_instance_id": builder_owner["id"],
        "toolchain": builder_owner["toolchain"],
    }
    if provenance != {
        "artifact_type": "provenance",
        "builder": expected_builder,
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-PROVENANCE",
        "materials": expected_materials,
        "release": RELEASE,
        "schema_version": GATE_ARTIFACT_SCHEMA,
        "subjects": _provenance_subjects(resolver),
    }:
        raise evidence.EvidenceError(
            "provenance does not bind the candidate, trusted execution identity, inputs and release evidence graph"
        )
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
        package_wheel={key: resolver.record("C-PACKAGE-BUILD", "wheel")[key] for key in ("digest", "size")},
        producer_digest=raw_sha256(
            context["input_bodies"]["sbom-observation-producer"]
        ),
        report=context["report"],
        bodies=bodies,
    )


def _semantic_vulnerability(
    _gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_vulnerability_findings(
        bodies["vulnerability-findings"],
        identity=context["identity"], report=context["report"], resolver=context["resolver"],
        support=context["support"], thresholds=context["thresholds"], bodies=bodies, policy=context["policy"],
    )


def _semantic_provenance(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    _validate_provenance_artifacts(
        bodies,
        gate=gate,
        identity=context["identity"],
        resolver=context["resolver"],
        report=context["report"],
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


def _semantic_docs_policy(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Bind the fixed docs-policy tests to one signed H0 result and their truth bytes."""
    if gate["gate_id"] != "B-DOCS-POLICY":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("docs-policy verifier received the wrong gate")
    identity = context["identity"]
    report = context["report"]
    scope = context["scope"]
    inputs = context["input_bodies"]
    if not isinstance(identity, dict) or not isinstance(report, dict) or not isinstance(scope, dict) or not isinstance(inputs, Mapping):
        raise evidence.EvidenceError("docs-policy verifier requires accepted release context")
    signed = next((item for item in gate["artifacts"] if item["name"] == "parity-report"), None)
    if (signed is None or signed["media_type"] != "application/json" or
            signed["digest"] != raw_sha256(bodies["parity-report"])):
        raise evidence.EvidenceError("docs-policy report does not match its exact signed artifact digest")
    doc = _object(
        _artifact_document(bodies["parity-report"], "B-DOCS-POLICY", "parity-report"),
        "docs-policy parity report", {
            "artifact_type", "candidate_identity_digest", "docs_policy_materials", "environment",
            "evidence_finished_at", "evidence_instance_id", "evidence_started_at", "gate_id",
            "name", "release", "schema_version", "selection", "test_results", "test_source_digest",
        },
    )
    if {key: doc[key] for key in ("artifact_type", "candidate_identity_digest", "gate_id", "name", "release", "schema_version")} != {
        "artifact_type": "docs-policy-parity-report",
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-DOCS-POLICY",
        "name": "docs-policy-parity",
        "release": RELEASE,
        "schema_version": GATE_ARTIFACT_SCHEMA,
    }:
        raise evidence.EvidenceError("docs-policy report has the wrong candidate, gate, release or name")
    instances = report["instances"]
    if len(instances) != 1:
        raise evidence.EvidenceError("docs-policy report requires one exact signed H0 evidence instance")
    instance = instances[0]
    if (instance["lane"] != "H0-hermetic" or doc["evidence_instance_id"] != instance["id"] or
            doc["environment"] != instance["environment"] or
            doc["evidence_started_at"] != instance["started_at"] or
            doc["evidence_finished_at"] != instance["finished_at"]):
        raise evidence.EvidenceError("docs-policy report does not bind its exact signed H0 instance")
    bindings = {item["name"]: item for item in scope["input_bindings"]}
    test_binding = bindings.get("docs-parity-tests")
    if (test_binding is None or test_binding["path"] != _DOCS_POLICY_TEST_PATH or
            inputs.get("docs-parity-tests") is None or
            raw_sha256(inputs["docs-parity-tests"]) != test_binding["digest"] or
            doc["test_source_digest"] != test_binding["digest"]):
        raise evidence.EvidenceError("docs-policy report does not bind the frozen parity test source")
    expected_materials = []
    for name in _DOCS_POLICY_MATERIALS:
        binding = bindings.get(name)
        if binding is None or inputs.get(name) is None or raw_sha256(inputs[name]) != binding["digest"]:
            raise evidence.EvidenceError("docs-policy material is absent or drifted from the frozen scope")
        expected_materials.append({"digest": binding["digest"], "name": name, "path": binding["path"]})
    if doc["docs_policy_materials"] != expected_materials:
        raise evidence.EvidenceError("docs-policy report does not bind the exact frozen material roster")
    results = _array(doc["test_results"], "docs-policy parity report.test_results")
    expected_results = [{"nodeid": nodeid, "status": "pass"} for nodeid in _DOCS_POLICY_TEST_ROSTER]
    if results != expected_results:
        raise evidence.EvidenceError("docs-policy report test roster or order is not exact and passing")
    expected_selection = {
        "collected": len(expected_results), "deselected": 0, "failed": 0,
        "passed": len(expected_results), "selected": len(expected_results), "skipped": 0,
        "xfailed": 0, "xpassed": 0,
    }
    if doc["selection"] != expected_selection or instance["selection"] != expected_selection or gate["selection"] != expected_selection:
        raise evidence.EvidenceError("docs-policy report and signed gate counts do not reconcile")


def _semantic_quality(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Recompute the frozen six-check B-QUALITY non-regression report."""
    if gate["gate_id"] != "B-QUALITY":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("quality verifier received the wrong gate")
    identity = context["identity"]
    report = context["report"]
    scope = context["scope"]
    thresholds = context["thresholds"]
    inputs = context["input_bodies"]
    if not all(isinstance(value, dict) for value in (identity, report, scope, thresholds)) or not isinstance(inputs, Mapping):
        raise evidence.EvidenceError("quality verifier requires accepted release context")
    signed = next((item for item in gate["artifacts"] if item["name"] == "quality-report"), None)
    if (signed is None or signed["media_type"] != "application/json" or
            signed["digest"] != raw_sha256(bodies["quality-report"])):
        raise evidence.EvidenceError("quality report does not match its exact signed artifact digest")
    doc = _object(
        _artifact_document(bodies["quality-report"], "B-QUALITY", "quality-report"),
        "quality report", {
            "artifact_type", "bindings", "candidate_identity_digest", "environment",
            "evidence_finished_at", "evidence_instance_id", "evidence_started_at", "gate_id",
            "name", "observations", "quality_policy_digest", "quality_violations", "release",
            "schema_version", "selection", "threshold_manifest_digest", "toolchain",
        },
    )
    expected_identity = {
        "artifact_type": "quality-report",
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-QUALITY", "name": "quality-report", "release": RELEASE,
        "schema_version": GATE_ARTIFACT_SCHEMA,
    }
    if any(doc[key] != value for key, value in expected_identity.items()):
        raise evidence.EvidenceError("quality report has the wrong candidate, gate, release or name")
    instances = report["instances"]
    if len(instances) != 1 or instances[0]["lane"] != "H0-hermetic":
        raise evidence.EvidenceError("quality report requires one exact signed H0 evidence instance")
    instance = instances[0]
    if (doc["evidence_instance_id"] != instance["id"] or
            doc["environment"] != instance["environment"] or
            doc["evidence_started_at"] != instance["started_at"] or
            doc["evidence_finished_at"] != instance["finished_at"]):
        raise evidence.EvidenceError("quality report does not bind its exact signed H0 instance")
    if doc["toolchain"] != instance["toolchain"]:
        raise evidence.EvidenceError("quality report does not bind the signed toolchain identity")

    bindings = {item["name"]: item for item in scope["input_bindings"]}
    binding_names = (
        "docs-parity-tests", "package-metadata", "quality-policy",
        "verification-job-map", "verification-workflow-ci",
    )
    expected_bindings = []
    for name in binding_names:
        binding = bindings.get(name)
        body = inputs.get(name)
        if binding is None or type(body) is not bytes or raw_sha256(body) != binding["digest"]:
            raise evidence.EvidenceError("quality report input is absent or drifted from the frozen scope")
        expected_bindings.append({"digest": binding["digest"], "name": name, "path": binding["path"]})
    if doc["bindings"] != expected_bindings:
        raise evidence.EvidenceError("quality report does not bind the exact policy/package/workflow/job-map/docs-test roster")
    policy_body = inputs["quality-policy"]
    policy = read_quality_policy(policy_body)
    if doc["quality_policy_digest"] != raw_sha256(policy_body):
        raise evidence.EvidenceError("quality report does not bind the exact frozen quality policy")
    threshold_rows = [row for row in thresholds["thresholds"] if row["gate_id"] == "B-QUALITY"]
    expected_threshold = {
        "baseline_digest": None, "class": "absolute", "gate_id": "B-QUALITY", "limit": 0,
        "metric": "quality_violations", "operator": "at_most", "statistic": "maximum", "unit": "count",
    }
    if threshold_rows != [expected_threshold] or doc["threshold_manifest_digest"] != raw_sha256(canonical_json_line(thresholds)):
        raise evidence.EvidenceError("quality report does not bind the accepted zero-violation threshold policy")

    observations = _array(doc["observations"], "quality report.observations")
    if len(observations) != 6:
        raise evidence.EvidenceError("quality report must retain exactly six observations")
    toolchain = {item["name"]: item for item in instance["toolchain"]}
    breaches = 0
    for index, (observation, check) in enumerate(zip(observations, policy["checks"], strict=True)):
        item = _object(observation, f"quality report.observations[{index}]", {
            "argv", "breached", "budget", "config", "expected_exit_code", "exit_code", "id",
            "observed_count", "output", "output_kind", "result_digest", "sources", "tool",
            "version",
        })
        config = _object(item["config"], "quality report observation config", {"digest", "name", "path"})
        expected_config = {
            "digest": check["config"]["digest"], "name": "quality-config", "path": check["config"]["path"],
        }
        if config != expected_config or {key: item[key] for key in (
                "argv", "budget", "expected_exit_code", "id", "sources", "tool", "version"
        )} != {key: check[key] for key in ("argv", "budget", "expected_exit_code", "id", "sources", "tool", "version")}:
            raise evidence.EvidenceError("quality observation check, command, tool, config, source roster or budget is not frozen")
        config_body = inputs.get("package-metadata" if config["path"] == "pyproject.toml" else "docs-parity-tests")
        if type(config_body) is not bytes or raw_sha256(config_body) != config["digest"]:
            raise evidence.EvidenceError("quality observation config does not match its frozen source bytes")
        if type(item["exit_code"]) is not int or not 0 <= item["exit_code"] <= 255:
            raise evidence.EvidenceError("quality observation exit code is invalid")
        output = _bounded_base64(item["output"], "quality observation canonical findings", maximum=_BUILD_LOG_OUTPUT_BYTES)
        if item["result_digest"] != raw_sha256(output):
            raise evidence.EvidenceError("quality observation result digest does not match retained canonical findings")
        observed = _integer(item["observed_count"], "quality observation observed count")
        if item["output_kind"] != "canonical-findings":
            raise evidence.EvidenceError("quality observation output representation is not the frozen evidence form")
        try:
            machine_output = evidence.load_json_bytes(output, maximum=_BUILD_LOG_OUTPUT_BYTES)
        except evidence.EvidenceError as exc:
            raise evidence.EvidenceError("quality observation canonical findings are not parseable JSON") from exc
        if type(machine_output) is not list:
            raise evidence.EvidenceError("quality observation canonical findings are not an array")
        if output != evidence.canonical_json_bytes(machine_output):
            raise evidence.EvidenceError("quality observation canonical findings are not canonical bytes")
        if check["id"] in {"type", "docs"}:
            if machine_output:
                raise evidence.EvidenceError("zero-result quality observation retains unexpected findings")
        else:
            normalized = []
            for finding in machine_output:
                if type(finding) is not list or len(finding) != 4:
                    raise evidence.EvidenceError("quality finding must be a normalized path/code/row/column tuple")
                path, code, row, column = finding
                _path(path, "quality finding path")
                _token(code, "quality finding code")
                if (_integer(row, "quality finding row") == 0 or
                        _integer(column, "quality finding column") == 0):
                    raise evidence.EvidenceError("quality finding row and column must be positive")
                if not any(path == root or path.startswith(root + "/") for root in check["sources"]):
                    raise evidence.EvidenceError("quality finding lies outside the frozen source roster")
                normalized.append((path, code, row, column))
            if normalized != sorted(normalized) or len(normalized) != len(set(normalized)):
                raise evidence.EvidenceError("quality normalized findings must be sorted and unique")
        actual_count = len(machine_output)
        expected_exit = 0 if actual_count == 0 else check["expected_exit_code"]
        if item["exit_code"] != expected_exit:
            raise evidence.EvidenceError("quality observation exit code does not match its retained finding count")
        if observed != actual_count:
            raise evidence.EvidenceError("quality observation count does not match retained machine output")
        breached = observed > check["budget"]
        if type(item["breached"]) is not bool or item["breached"] != breached:
            raise evidence.EvidenceError("quality observation breach outcome does not match its budget")
        if breached:
            breaches += 1
        signed_tool = toolchain.get(check["tool"])
        if signed_tool is None or signed_tool["version"] != check["version"]:
            raise evidence.EvidenceError("quality observation tool identity is absent from the signed toolchain")
    if doc["quality_violations"] != breaches or breaches != 0:
        raise evidence.EvidenceError("quality report breach count must satisfy the accepted zero threshold")
    expected_selection = {
        "collected": 6, "deselected": 0, "failed": 0, "passed": 6, "selected": 6,
        "skipped": 0, "xfailed": 0, "xpassed": 0,
    }
    if doc["selection"] != expected_selection or instance["selection"] != expected_selection or gate["selection"] != expected_selection:
        raise evidence.EvidenceError("quality signed selection must contain exactly the six passing checks")


def _coverage_basis_points(counts: dict) -> int:
    total = _integer(counts["total"], "coverage total")
    covered = _integer(counts["covered"], "coverage covered")
    if covered > total:
        raise evidence.EvidenceError("coverage covered count exceeds its total")
    return 10000 if total == 0 else covered * 10000 // total


def _coverage_file_rows(value: object, roster: list[str], name: str) -> dict[str, dict]:
    rows = _array(value, name)
    parsed: dict[str, dict] = {}
    for index, row in enumerate(rows):
        item = _object(row, f"{name}[{index}]", {"branches", "lines", "path"})
        _path(item["path"], f"{name}[{index}].path")
        for kind in ("lines", "branches"):
            counts = _object(item[kind], f"{name}[{index}].{kind}", {"covered", "total"})
            _coverage_basis_points(counts)
        if item["path"] in parsed:
            raise evidence.EvidenceError("coverage report has a duplicate source file")
        parsed[item["path"]] = item
    if list(parsed) != roster:
        raise evidence.EvidenceError("coverage report source roster is omitted, reordered or drifted")
    return parsed


def _semantic_coverage(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Recompute B-COVERAGE from compact per-file line/branch totals."""
    identity, report, scope, thresholds = (
        context["identity"], context["report"], context["scope"], context["thresholds"]
    )
    inputs, resolver = context["input_bodies"], context["resolver"]
    if (not all(isinstance(value, dict) for value in (identity, report, scope, thresholds)) or
            not isinstance(inputs, Mapping) or not isinstance(resolver, ArtifactResolver)):
        raise evidence.EvidenceError("coverage verifier requires accepted release context")
    signed = next((item for item in gate["artifacts"] if item["name"] == "coverage-report"), None)
    if (signed is None or signed["media_type"] != "application/json" or
            signed["digest"] != raw_sha256(bodies["coverage-report"])):
        raise evidence.EvidenceError("coverage report does not match its exact signed artifact digest")
    doc = _object(_artifact_document(bodies["coverage-report"], "B-COVERAGE", "coverage-report"),
        "coverage report", {
            "artifact_type", "bindings", "candidate_identity_digest", "coverage_baseline",
            "coverage_data", "coverage_files", "coverage_policy_digest", "critical_modules",
            "environment", "evidence_finished_at", "evidence_instance_id", "evidence_started_at",
            "gate_id", "measurements", "name", "release", "schema_version", "source_tree_digest",
            "threshold_manifest_digest", "toolchain",
        })
    expected_identity = {
        "artifact_type": "coverage-report", "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-COVERAGE", "name": "coverage-report", "release": RELEASE,
        "schema_version": GATE_ARTIFACT_SCHEMA, "source_tree_digest": identity["source_tree_digest"],
    }
    if any(doc[key] != value for key, value in expected_identity.items()):
        raise evidence.EvidenceError("coverage report has the wrong candidate, source tree, gate or release")
    instances = report["instances"]
    if len(instances) != 1 or instances[0]["lane"] != "H0-hermetic" or instances[0]["environment"]["python"].rsplit(".", 1)[0] != "3.12":
        raise evidence.EvidenceError("coverage report requires one exact Python 3.12 signed H0 instance")
    instance = instances[0]
    if any(doc[field] != instance[key] for field, key in (
        ("evidence_instance_id", "id"), ("environment", "environment"),
        ("evidence_started_at", "started_at"), ("evidence_finished_at", "finished_at"),
    )) or doc["toolchain"] != instance["toolchain"]:
        raise evidence.EvidenceError("coverage report does not bind its signed H0 instance/toolchain")
    tools = {row["name"]: row for row in instance["toolchain"]}
    if len(instance["toolchain"]) != 2 or set(tools) != {"coverage", "pytest"} or \
            tools["coverage"]["version"] != "7.15.4":
        raise evidence.EvidenceError("coverage report toolchain must be exactly coverage and pytest")
    bindings = {row["name"]: row for row in scope["input_bindings"]}
    binding_names = (
        "coverage-config", "coverage-policy", "coverage-shard-producer",
        "coverage-shard-schema", "verification-job-map", "verification-workflow-ci",
    )
    expected_bindings = []
    for name in binding_names:
        row, body = bindings.get(name), inputs.get(name)
        if row is None or type(body) is not bytes or raw_sha256(body) != row["digest"]:
            raise evidence.EvidenceError("coverage report input is absent or drifted from scope")
        expected_bindings.append({"digest": row["digest"], "name": name, "path": row["path"]})
    if doc["bindings"] != expected_bindings:
        raise evidence.EvidenceError("coverage report bindings are not the frozen policy/config/topology set")
    policy_body = inputs["coverage-policy"]
    policy = read_coverage_policy(policy_body)
    if (doc["coverage_policy_digest"] != raw_sha256(policy_body) or
            inputs["coverage-config"] != _COVERAGE_CONFIG_BYTES or
            policy["config"]["digest"] != raw_sha256(inputs["coverage-config"])):
        raise evidence.EvidenceError("coverage report does not bind frozen policy/config bytes")
    job_map = evidence.read_verification_job_map(inputs["verification-job-map"], workflow_bodies={
        ".github/workflows/ci.yml": inputs["verification-workflow-ci"],
    })
    mapped_ids = [row["id"] for job in job_map["jobs"] if job["lane"] == "H0-hermetic"
                  for row in job["instances"] if {item["name"]: item["value"] for item in row["matrix"]}.get("python-version") == "3.12"]
    if mapped_ids != policy["h0_job_ids"]:
        raise evidence.EvidenceError("coverage policy H0 jobs do not match verification topology")
    baseline = _object(doc["coverage_baseline"], "coverage baseline", {"files"})
    before = _coverage_file_rows(baseline["files"], policy["source_roster"], "coverage baseline.files")
    baseline_digest = raw_sha256(canonical_json_line(baseline))
    rows = [row for row in thresholds["thresholds"] if row["gate_id"] == "B-COVERAGE"]
    contracts = [row for row in QUALITY_THRESHOLD_CONTRACTS if row[0] == "B-COVERAGE"]
    if [tuple(row[key] for key in ("gate_id", "class", "metric", "operator", "statistic", "unit")) for row in rows] != contracts:
        raise evidence.EvidenceError("coverage threshold rows do not match the frozen metric contract")
    regression = [row for row in rows if row["class"] == "regression"]
    if any(row["baseline_digest"] not in {None, baseline_digest} for row in regression) or \
            len({row["baseline_digest"] for row in regression}) > 1:
        raise evidence.EvidenceError("coverage regression thresholds do not share the embedded baseline digest")
    if doc["threshold_manifest_digest"] != raw_sha256(canonical_json_line(thresholds)):
        raise evidence.EvidenceError("coverage report does not bind its exact threshold manifest")
    h0_body = resolver.read("B-HERMETIC-ALL", "test-report")
    h0 = _artifact_document(h0_body, "B-HERMETIC-ALL", "test-report")
    taxonomy_body = resolver.read("A-TAXONOMY", "classification-manifest")
    taxonomy = evidence.read_pytest_taxonomy(taxonomy_body)
    if h0["collection_manifest_digest"] != raw_sha256(taxonomy_body):
        raise evidence.EvidenceError("coverage H0 report does not bind the exact taxonomy collection")
    expected_selection = {
        "collected": taxonomy["selection"]["collected"],
        "deselected": taxonomy["selection"]["deselected"],
        "failed": 0, "passed": taxonomy["selection"]["selected"],
        "selected": taxonomy["selection"]["selected"], "skipped": 0,
        "xfailed": 0, "xpassed": 0,
    }
    if instance["selection"] != expected_selection or gate["selection"] != expected_selection:
        raise evidence.EvidenceError("coverage signed selection does not match the bound H0 taxonomy")
    h0_runs = [run for run in _array(h0["runs"], "H0 coverage test runs")
               if run["environment"]["python"].rsplit(".", 1)[0] == "3.12"]
    if len(h0_runs) != 1 or h0_runs[0]["evidence_instance_id"] != instance["id"] or \
            h0_runs[0]["environment"] != instance["environment"]:
        raise evidence.EvidenceError("coverage report does not bind the exact Python 3.12 H0 execution")
    expected_fragments = {}
    for fragment in h0_runs[0]["fragments"]:
        expected_fragments[fragment["job_instance_id"]] = fragment["digest"]
        if fragment["report"]["collector"]["version"] != tools["pytest"]["version"]:
            raise evidence.EvidenceError("coverage report pytest identity does not match its H0 fragments")
    data = _array(doc["coverage_data"], "coverage report data")
    if [row.get("job_instance_id") if type(row) is dict else None for row in data] != policy["h0_job_ids"]:
        raise evidence.EvidenceError("coverage data does not contain exactly the six frozen H0 jobs")
    for row in data:
        item = _object(row, "coverage data entry", {"digest", "h0_fragment_digest", "job_instance_id"})
        _digest(item["digest"], "coverage raw data digest")
        if item["h0_fragment_digest"] != expected_fragments.get(item["job_instance_id"]):
            raise evidence.EvidenceError("coverage data does not bind its exact H0 shard fragment")
    if len({row["digest"] for row in data}) != len(data):
        raise evidence.EvidenceError("coverage data digests must be unique across the six H0 shards")
    shard_universe = None
    executed_lines = {path: set() for path in policy["source_roster"]}
    executed_branches = {path: set() for path in policy["source_roster"]}
    for index, job_id in enumerate(policy["h0_job_ids"]):
        name = f"coverage-shard-{index}"
        if name not in bodies:
            raise evidence.EvidenceError("coverage report is missing a signed shard fragment")
        shard_body = resolver.read("B-COVERAGE", name)
        signed_shard = next((item for item in gate["artifacts"] if item["name"] == name), None)
        if (shard_body != bodies[name] or signed_shard is None or
                signed_shard["media_type"] != "application/json" or
                signed_shard["digest"] != raw_sha256(shard_body)):
            raise evidence.EvidenceError("coverage shard does not match its signed indexed artifact")
        shard = read_coverage_shard(shard_body)
        expected_data = data[index]
        if (shard["job_instance_id"] != job_id or shard["config_digest"] != raw_sha256(inputs["coverage-config"]) or
                shard["coverage_policy_digest"] != raw_sha256(policy_body) or
                shard["h0_fragment_digest"] != expected_fragments[job_id] or
                shard["raw_coverage_data_digest"] != expected_data["digest"] or
                shard["source_roster"] != policy["source_roster"]):
            raise evidence.EvidenceError("coverage shard does not bind the frozen job, H0 fragment, config, policy or raw data")
        universe = [(row["path"], row["statements"], row["possible_branches"]) for row in shard["files"]]
        if shard_universe is None:
            shard_universe = universe
        elif universe != shard_universe:
            raise evidence.EvidenceError("coverage shards do not share one statement/branch universe")
        for file_row in shard["files"]:
            executed_lines[file_row["path"]].update(file_row["executed_lines"])
            executed_branches[file_row["path"]].update(map(tuple, file_row["executed_branches"]))
    if shard_universe is None:  # pragma: no cover - fixed six-shard policy
        raise evidence.EvidenceError("coverage report has no shard universe")
    current_rows = [{
        "path": path,
        "lines": {"covered": len(executed_lines[path]), "total": len(statements)},
        "branches": {"covered": len(executed_branches[path]), "total": len(branches)},
    } for path, statements, branches in shard_universe]
    current = _coverage_file_rows(current_rows, policy["source_roster"], "coverage shard union")
    if doc["coverage_files"] != current_rows:
        raise evidence.EvidenceError("coverage report totals do not recompute from signed shard fragments")
    repo_line_counts = {"covered": sum(row["lines"]["covered"] for row in current.values()), "total": sum(row["lines"]["total"] for row in current.values())}
    repo_branch_counts = {"covered": sum(row["branches"]["covered"] for row in current.values()), "total": sum(row["branches"]["total"] for row in current.values())}
    base_repo_line_counts = {"covered": sum(row["lines"]["covered"] for row in before.values()), "total": sum(row["lines"]["total"] for row in before.values())}
    base_repo_branch_counts = {"covered": sum(row["branches"]["covered"] for row in before.values()), "total": sum(row["branches"]["total"] for row in before.values())}
    if any(counts["total"] == 0 for counts in (repo_line_counts, repo_branch_counts, base_repo_line_counts, base_repo_branch_counts)):
        raise evidence.EvidenceError("coverage repository line and branch totals must be positive")
    repo_line = _coverage_basis_points(repo_line_counts)
    repo_branch = _coverage_basis_points(repo_branch_counts)
    base_repo_line = _coverage_basis_points(base_repo_line_counts)
    base_repo_branch = _coverage_basis_points(base_repo_branch_counts)
    critical = _array(doc["critical_modules"], "coverage critical modules")
    expected_critical = []
    for path in policy["critical_modules"]:
        line, branch = _coverage_basis_points(current[path]["lines"]), _coverage_basis_points(current[path]["branches"])
        expected_critical.append({"path": path, "line_coverage": line, "branch_coverage": branch})
    if critical != expected_critical:
        raise evidence.EvidenceError("coverage critical module values do not recompute from current files")
    critical_line_losses = [max(0, _coverage_basis_points(before[path]["lines"]) - _coverage_basis_points(current[path]["lines"])) for path in policy["critical_modules"]]
    critical_branch_losses = [max(0, _coverage_basis_points(before[path]["branches"]) - _coverage_basis_points(current[path]["branches"])) for path in policy["critical_modules"]]
    values = {
        "repository_line_coverage": repo_line,
        "repository_line_coverage_loss": max(0, base_repo_line - repo_line),
        "repository_branch_coverage": repo_branch,
        "repository_branch_coverage_loss": max(0, base_repo_branch - repo_branch),
        "critical_module_line_coverage": min(row["line_coverage"] for row in expected_critical),
        "critical_module_line_coverage_loss": max(critical_line_losses),
        "critical_module_branch_coverage": min(row["branch_coverage"] for row in expected_critical),
        "critical_module_branch_coverage_loss": max(critical_branch_losses),
    }
    expected_measurements = []
    for row in rows:
        value = values[row["metric"]]
        breached = row["limit"] is not None and ((row["operator"] == "at_least" and value < row["limit"]) or (row["operator"] == "at_most" and value > row["limit"]))
        expected_measurements.append({"metric": row["metric"], "value": value, "breached": breached})
    if doc["measurements"] != expected_measurements:
        raise evidence.EvidenceError("coverage measurements, threshold arithmetic or breach outcomes do not reconcile")
    if any(row["breached"] for row in expected_measurements):
        raise evidence.EvidenceError("coverage report contains a threshold breach")
    expected_gate_measurements = [{
        "baseline_digest": threshold["baseline_digest"], "class": threshold["class"],
        "invalidated_trials": 0, "metric": threshold["metric"], "observed_trials": 1,
        "statistic": threshold["statistic"], "unit": threshold["unit"],
        "value": values[threshold["metric"]],
    } for threshold in rows]
    if report["measurements"] != expected_gate_measurements:
        raise evidence.EvidenceError("coverage gate-evidence measurements do not match the recomputed report")


def _semantic_static_security(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Reconcile one candidate-bound security report with its shard-0 raw scan."""
    identity, report, scope, thresholds, resolver, inputs = (
        context["identity"], context["report"], context["scope"], context["thresholds"],
        context["resolver"], context["input_bodies"],
    )
    if (not all(isinstance(value, dict) for value in (identity, report, scope, thresholds)) or
            not isinstance(resolver, ArtifactResolver) or not isinstance(inputs, Mapping)):
        raise evidence.EvidenceError("static security verifier requires accepted release context")
    signed = {item["name"]: item for item in gate["artifacts"]}
    for name in ("security-findings", "security-scan-fragment"):
        if name not in bodies or signed.get(name, {}).get("digest") != raw_sha256(bodies[name]):
            raise evidence.EvidenceError("static security artifact does not match its exact signed digest")
    policy_body = inputs.get("static-security-policy")
    if type(policy_body) is not bytes:
        raise evidence.EvidenceError("static security policy source is absent")
    policy = read_static_security_policy(policy_body)
    exceptions_body = inputs.get("security-exceptions")
    if type(exceptions_body) is not bytes or raw_sha256(exceptions_body) != policy["bandit"]["exceptions"]["digest"]:
        raise evidence.EvidenceError("static security exceptions are absent or drifted")
    exceptions = _object(
        evidence.load_json_bytes(exceptions_body, maximum=_DOCUMENT_BYTES),
        "security exceptions", {"exceptions", "policy", "schema_version"},
    )
    if exceptions["schema_version"] != "quarry.security-exceptions.v1":
        raise evidence.EvidenceError("static security exception schema is unsupported")
    doc = _object(_artifact_document(bodies["security-findings"], "B-STATIC-SECURITY", "security-findings"), "security findings", {
        "artifact_type", "ast_inventory", "bindings", "candidate_identity_digest", "dependency_manifest",
        "detect_secrets_baseline_digest", "environment", "evidence_finished_at", "evidence_instance_id",
        "evidence_started_at", "findings", "gate_id", "h0_fragment_digest", "h0_property_tests", "checks", "selection",
        "job_instance_id", "name", "policy_digest", "release", "scan_fragment_digest", "schema_version",
        "suppressions", "toolchain", "unsuppressed_findings",
    })
    if {key: doc[key] for key in ("artifact_type", "candidate_identity_digest", "gate_id", "name", "release", "schema_version")} != {
        "artifact_type": "security-findings", "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-STATIC-SECURITY", "name": "security-findings", "release": RELEASE,
        "schema_version": SECURITY_FINDINGS_SCHEMA,
    }:
        raise evidence.EvidenceError("security findings have the wrong candidate, gate or release")
    instances = report["instances"]
    if len(instances) != 1 or instances[0]["lane"] != "H0-hermetic" or instances[0]["environment"]["python"].rsplit(".", 1)[0] != "3.12":
        raise evidence.EvidenceError("security findings require one exact Python 3.12 H0 instance")
    instance = instances[0]
    if any(doc[field] != instance[key] for field, key in (("evidence_instance_id", "id"), ("environment", "environment"), ("evidence_started_at", "started_at"), ("evidence_finished_at", "finished_at"))) or doc["toolchain"] != instance["toolchain"]:
        raise evidence.EvidenceError("security findings do not bind the exact signed H0 instance/toolchain")
    expected_selection = {"collected": 5, "deselected": 0, "failed": 0, "passed": 5, "selected": 5, "skipped": 0, "xfailed": 0, "xpassed": 0}
    if doc["selection"] != expected_selection or instance["selection"] != expected_selection or gate["selection"] != expected_selection:
        raise evidence.EvidenceError("security findings checks and signed selection do not reconcile")
    checks = _array(doc["checks"], "security findings checks")
    if [row.get("id") if type(row) is dict else None for row in checks] != list(_STATIC_SECURITY_CHECK_IDS) or any(_object(row, "security check", {"id", "result_digest", "status"})["status"] != "pass" for row in checks):
        raise evidence.EvidenceError("security findings check roster is not the exact five-check outcome set")
    tool_names = {row["name"]: row for row in instance["toolchain"]}
    if set(tool_names) != {"bandit", "detect-secrets", "pytest"} or tool_names["bandit"]["version"] != "1.9.4" or tool_names["detect-secrets"]["version"] != "1.5.0":
        raise evidence.EvidenceError("security findings toolchain is not the frozen scan/test roster")
    by_name = {row["name"]: row for row in scope["input_bindings"]}
    expected_bindings = []
    for name in _STATIC_SECURITY_BINDINGS:
        row, body = by_name.get(name), inputs.get(name)
        if row is None or type(body) is not bytes or raw_sha256(body) != row["digest"]:
            raise evidence.EvidenceError("static security source input is absent or drifted")
        expected_bindings.append({"digest": row["digest"], "name": name, "path": row["path"]})
    if doc["bindings"] != expected_bindings or doc["policy_digest"] != raw_sha256(policy_body):
        raise evidence.EvidenceError("security findings do not bind the exact frozen source/config policy")
    if doc["dependency_manifest"] != expected_bindings[-1] or doc["detect_secrets_baseline_digest"] != policy["detect_secrets"]["baseline"]["digest"]:
        raise evidence.EvidenceError("security findings dependency or secrets baseline binding is not exact")
    fragment = read_static_security_fragment(bodies["security-scan-fragment"])
    if (doc["scan_fragment_digest"] != raw_sha256(bodies["security-scan-fragment"]) or
            fragment["artifact_type"] != "security-scan-fragment"):
        raise evidence.EvidenceError("security findings do not bind the canonical raw scan fragment")
    for field in ("ast_inventory", "dependency_manifest", "detect_secrets_baseline_digest", "findings", "h0_fragment_digest", "h0_property_tests", "job_instance_id", "policy_digest", "release", "suppressions", "unsuppressed_findings"):
        if doc[field] != fragment[field]:
            raise evidence.EvidenceError("security findings do not reproduce the exact raw scan facts")
    if (fragment["scan_tools"] != [{"name": "bandit", "version": "1.9.4"}, {"name": "detect-secrets", "version": "1.5.0"}] or
            doc["dependency_manifest"] != {"digest": policy["dependency_manifest"]["digest"], "name": "package-metadata", "path": "pyproject.toml"} or
            doc["h0_property_tests"] != policy["h0_property_tests"]):
        raise evidence.EvidenceError("security findings do not bind the frozen dependency/property policy")
    if checks != _static_security_checks(fragment):
        raise evidence.EvidenceError("security findings check digests do not recompute from retained facts")
    h0 = _artifact_document(resolver.read("B-HERMETIC-ALL", "test-report"), "B-HERMETIC-ALL", "test-report")
    run = next((row for row in h0["runs"] if row["environment"]["python"].rsplit(".", 1)[0] == "3.12"), None)
    if (doc["job_instance_id"] != _STATIC_SECURITY_JOB_ID or run is None or run["evidence_instance_id"] != instance["id"] or
            next((row["digest"] for row in run["fragments"] if row["job_instance_id"] == _STATIC_SECURITY_JOB_ID), None) != doc["h0_fragment_digest"]):
        raise evidence.EvidenceError("security findings do not bind the exact shard-0 H0 fragment")
    taxonomy = evidence.read_pytest_taxonomy(resolver.read("A-TAXONOMY", "classification-manifest"))
    h0_nodes = set(next(row["nodes"] for row in taxonomy["lanes"] if row["lane"] == "H0-hermetic"))
    if not set(policy["h0_property_tests"]["nodes"]).issubset(h0_nodes):
        raise evidence.EvidenceError("security property node roster is absent from the signed H0 taxonomy")
    expected_ast = [{**row, "source": "ast"} for row in policy["ast_inventory"]["entries"]]
    if doc["ast_inventory"] != expected_ast or doc["findings"] != sorted(doc["findings"], key=lambda row: row["id"]) or doc["unsuppressed_findings"] != len(doc["findings"]):
        raise evidence.EvidenceError("security findings do not canonically recompute AST/unsuppressed facts")
    release_tuple = tuple(int(value) for value in policy["release"].split("."))
    expected_suppressions = []
    for row in exceptions["exceptions"]:
        expiry = tuple(int(value) for value in row["expires_before"].split("."))
        if release_tuple >= expiry:
            raise evidence.EvidenceError("security suppression is expired for the candidate release")
        key = (row["path"], row["line"], row["test_id"])
        stable = hashlib.sha256("\0".join(map(str, key)).encode()).hexdigest()[:20]
        expected_suppressions.append({"expires_before": row["expires_before"], "finding_id": "bandit-" + stable, "id": "security-suppression-" + stable, "owner": row["owner"], "rationale": row["rationale"]})
    if doc["suppressions"] != sorted(expected_suppressions, key=lambda row: row["id"]):
        raise evidence.EvidenceError("security suppressions do not exactly reconcile reviewed IDs, owner, rationale and expiry")
    rows = [row for row in thresholds["thresholds"] if row["gate_id"] == "B-STATIC-SECURITY"]
    expected_threshold = ("B-STATIC-SECURITY", "absolute", "unsuppressed_findings", "at_most", "maximum", "count")
    if [tuple(row[key] for key in ("gate_id", "class", "metric", "operator", "statistic", "unit")) for row in rows] != [expected_threshold]:
        raise evidence.EvidenceError("static security threshold metric contract is not frozen")
    threshold = rows[0]
    breached = threshold["limit"] is not None and doc["unsuppressed_findings"] > threshold["limit"]
    if breached:
        raise evidence.EvidenceError("security findings contain an accepted-threshold breach")
    expected_measurements = [{
        "baseline_digest": threshold["baseline_digest"], "class": threshold["class"],
        "invalidated_trials": 0, "metric": "unsuppressed_findings", "observed_trials": 1,
        "statistic": "maximum", "unit": "count", "value": doc["unsuppressed_findings"],
    }]
    if report["measurements"] != expected_measurements:
        raise evidence.EvidenceError("static security gate-evidence measurements do not match recomputed findings")


def _semantic_determinism(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Reconcile the candidate-bound diff with its retained two-run shard fragment."""
    identity, report, scope, resolver, inputs, thresholds = (
        context["identity"], context["report"], context["scope"], context["resolver"],
        context["input_bodies"], context["thresholds"],
    )
    if (not all(isinstance(value, dict) for value in (identity, report, scope, thresholds)) or
            not isinstance(resolver, ArtifactResolver) or not isinstance(inputs, Mapping)):
        raise evidence.EvidenceError("determinism verifier requires accepted release context")
    signed = {item["name"]: item for item in gate["artifacts"]}
    body = bodies.get("artifact-tree-diff")
    if type(body) is not bytes or signed.get("artifact-tree-diff", {}).get("digest") != raw_sha256(body):
        raise evidence.EvidenceError("artifact tree diff does not match its exact signed digest")
    doc = _object(_artifact_document(body, "B-DETERMINISM", "artifact-tree-diff"),
                  "artifact tree diff", {
        "artifact_differences", "artifact_type", "bindings", "candidate_identity_digest",
        "differences", "environment", "evidence_finished_at", "evidence_instance_id",
        "evidence_started_at", "fixture_digest", "fixture_manifest_digest", "gate_id", "h0_fragment_digest",
        "job_instance_id", "name", "raw_fragment_digest", "release", "runs",
        "schema_version", "toolchain",
    })
    _schema(doc, ARTIFACT_TREE_DIFF_SCHEMA, "artifact tree diff")
    if {key: doc[key] for key in ("artifact_type", "candidate_identity_digest", "gate_id", "name", "release", "schema_version")} != {
        "artifact_type": "artifact-tree-diff", "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-DETERMINISM", "name": "artifact-tree-diff", "release": RELEASE,
        "schema_version": ARTIFACT_TREE_DIFF_SCHEMA,
    }:
        raise evidence.EvidenceError("artifact tree diff has the wrong candidate, gate or release")
    _integer(doc["artifact_differences"], "artifact tree diff difference count")
    wrapper_runs = [
        _read_determinism_run(row, f"artifact tree diff run {index}")
        for index, row in enumerate(_array(doc["runs"], "artifact tree diff runs"))
    ]
    if [row["id"] for row in wrapper_runs] != ["run-1", "run-2"] or len(wrapper_runs) != 2:
        raise evidence.EvidenceError("artifact tree diff must contain exactly two isolated runs")
    instances = report["instances"]
    if len(instances) != 1 or instances[0]["lane"] != "H0-hermetic" or instances[0]["environment"]["python"].rsplit(".", 1)[0] != "3.12":
        raise evidence.EvidenceError("artifact tree diff requires one exact Python 3.12 H0 instance")
    instance = instances[0]
    if (any(doc[field] != instance[key] for field, key in (
                ("evidence_instance_id", "id"), ("environment", "environment"),
                ("evidence_started_at", "started_at"), ("evidence_finished_at", "finished_at"))) or
            doc["toolchain"] != instance["toolchain"]):
        raise evidence.EvidenceError("artifact tree diff does not bind its exact signed H0 instance/toolchain")
    expected_bindings = []
    by_name = {row["name"]: row for row in scope["input_bindings"]}
    for name in _DETERMINISM_BINDINGS:
        row, input_body = by_name.get(name), inputs.get(name)
        if row is None or type(input_body) is not bytes or raw_sha256(input_body) != row["digest"]:
            raise evidence.EvidenceError("determinism source binding is absent or drifted")
        expected_bindings.append({"digest": row["digest"], "name": name, "path": row["path"]})
    if doc["bindings"] != expected_bindings:
        raise evidence.EvidenceError("artifact tree diff does not bind the exact fixture/source manifests")
    fixture_body = inputs.get("determinism-fixture")
    if type(fixture_body) is not bytes:
        raise evidence.EvidenceError("determinism fixture source is absent")
    fixture = read_determinism_fixture(fixture_body)
    fragment_body = resolver.read("B-DETERMINISM", "artifact-tree-diff-fragment")
    fragment = read_determinism_fragment(fragment_body)
    if doc["raw_fragment_digest"] != raw_sha256(fragment_body):
        raise evidence.EvidenceError("artifact tree diff does not bind its retained raw fragment")
    for field in ("artifact_differences", "differences", "fixture_digest", "fixture_manifest_digest", "h0_fragment_digest", "job_instance_id", "release", "runs"):
        if doc[field] != fragment[field]:
            raise evidence.EvidenceError("artifact tree diff does not reproduce the exact raw paired-tree facts")
    if (doc["fixture_manifest_digest"] != raw_sha256(fixture_body) or
            len(fixture["artifacts"]) != len(fragment["runs"][0]["files"])):
        raise evidence.EvidenceError("artifact tree diff fixture binding does not reconcile")
    expected_runs = [
        _determinism_expected_tree(fixture, "run-1"),
        _determinism_expected_tree(fixture, "run-2"),
    ]
    if fragment["runs"] != expected_runs:
        raise evidence.EvidenceError("determinism trees do not recompute from the frozen fixture bytes")
    if doc["fixture_digest"] != expected_runs[0]["tree_digest"]:
        raise evidence.EvidenceError("determinism fixture digest is not the derived fixture-tree identity")
    h0 = _artifact_document(resolver.read("B-HERMETIC-ALL", "test-report"), "B-HERMETIC-ALL", "test-report")
    run = next((row for row in h0["runs"] if row["environment"]["python"].rsplit(".", 1)[0] == "3.12"), None)
    if (doc["job_instance_id"] != _DETERMINISM_JOB_ID or run is None or
            run["evidence_instance_id"] != instance["id"] or
            next((row["digest"] for row in run["fragments"] if row["job_instance_id"] == _DETERMINISM_JOB_ID), None) != doc["h0_fragment_digest"]):
        raise evidence.EvidenceError("artifact tree diff does not bind the exact shard-0 H0 fragment")
    rows = [row for row in thresholds["thresholds"] if row["gate_id"] == "B-DETERMINISM"]
    expected_threshold = ("B-DETERMINISM", "absolute", "artifact_differences", "at_most", "maximum", "count")
    if [tuple(row[key] for key in ("gate_id", "class", "metric", "operator", "statistic", "unit")) for row in rows] != [expected_threshold]:
        raise evidence.EvidenceError("determinism threshold metric contract is not frozen")
    threshold = rows[0]
    if threshold["limit"] != 0 or doc["artifact_differences"] > threshold["limit"]:
        raise evidence.EvidenceError("artifact tree diff contains a definitionally required threshold breach")
    expected_measurements = [{
        "baseline_digest": threshold["baseline_digest"], "class": threshold["class"],
        "invalidated_trials": 0, "metric": "artifact_differences", "observed_trials": 1,
        "statistic": "maximum", "unit": "count", "value": doc["artifact_differences"],
    }]
    if report["measurements"] != expected_measurements:
        raise evidence.EvidenceError("determinism gate-evidence measurements do not match recomputed diff")


def _semantic_source_registry(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Reconcile the bounded registry artifact without treating it as acceptance."""
    identity, report, scope, inputs = (
        context["identity"], context["report"], context["scope"], context["input_bodies"],
    )
    if (not isinstance(identity, dict) or not isinstance(report, dict) or
            not isinstance(scope, dict) or not isinstance(inputs, Mapping)):
        raise evidence.EvidenceError("source registry verifier requires accepted release context")
    body = bodies.get("registry-reconciliation")
    signed = {item["name"]: item for item in gate["artifacts"]}
    if (type(body) is not bytes or
            signed.get("registry-reconciliation", {}).get("digest") != raw_sha256(body)):
        raise evidence.EvidenceError("source registry reconciliation does not match its signed artifact")
    bound_inputs = {}
    scope_bindings = {row["name"]: row for row in scope["input_bindings"]}
    for name in _SOURCE_REGISTRY_BINDINGS:
        row, input_body = scope_bindings.get(name), inputs.get(name)
        if row is None or type(input_body) is not bytes or raw_sha256(input_body) != row["digest"]:
            raise evidence.EvidenceError("source registry reconciliation source input is absent or drifted")
        bound_inputs[name] = input_body
    try:
        artifact = source_registry_evidence.read(
            body, candidate_identity_digest=evidence.canonical_digest(identity), input_bodies=bound_inputs,
        )
    except source_registry_evidence.SourceRegistryEvidenceError as exc:
        raise evidence.EvidenceError(str(exc)) from exc
    expected_bindings = [
        {"digest": scope_bindings[name]["digest"], "name": name,
         "path": scope_bindings[name]["path"]}
        for name in sorted(_SOURCE_REGISTRY_BINDINGS)
    ]
    if artifact["input_bindings"] != expected_bindings:
        raise evidence.EvidenceError("source registry artifact does not bind the exact release scope inputs")
    lanes = [instance["lane"] for instance in report["instances"]]
    if lanes != ["H0-hermetic", "H1-tool-integration"]:
        raise evidence.EvidenceError("source registry evidence requires one nonzero H0 and one nonzero H1 instance")
    exact_selection = {"collected": 1, "deselected": 0, "failed": 0, "passed": 1, "selected": 1,
                       "skipped": 0, "xfailed": 0, "xpassed": 0}
    if (gate["selection"] != {key: value * 2 for key, value in exact_selection.items()} or
            any(instance["selection"] != exact_selection for instance in report["instances"])):
        raise evidence.EvidenceError("source registry evidence requires the exact two-case H0/H1 selection")
    receipts = [artifact["h0_static_emitter"]["receipt"], artifact["h1_synthetic_admission"]["receipt"]]
    for receipt, instance in zip(receipts, report["instances"], strict=True):
        if (receipt["lane"] != instance["lane"] or
                receipt["evidence_instance_id"] != instance["id"] or
                receipt["selection"] != instance["selection"] or receipt["result"] != "pass"):
            raise evidence.EvidenceError("source registry receipt does not bind its exact H0/H1 evidence instance")
    if report["instances"][0]["artifacts"] != [{
            "digest": raw_sha256(body), "name": "registry-reconciliation"
    }] or report["instances"][1]["artifacts"]:
        raise evidence.EvidenceError("source registry artifact must bind the H0 receipt and no unrelated H1 artifact")
    # The retained artifact itself never purports to execute an adapter.  Its
    # external H0/H1 instances only witness the static/synthetic collection.
    if (artifact["h0_static_emitter"]["executed_lane_count"] != 0 or
            artifact["h1_synthetic_admission"]["executed_lane_count"] != 0):
        raise evidence.EvidenceError("source registry artifact makes an impermissible execution claim")


def _semantic_manifest(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Bind manifest invariants and corruption refusals to one H0 evidence instance."""
    if gate["gate_id"] != "B-MANIFEST":  # pragma: no cover - registry invariant
        raise evidence.EvidenceError("manifest verifier received the wrong gate")
    identity = context["identity"]
    report = context["report"]
    scope = context["scope"]
    inputs = context["input_bodies"]
    if not isinstance(identity, dict) or not isinstance(report, dict) or not isinstance(scope, dict) or not isinstance(inputs, Mapping):
        raise evidence.EvidenceError("manifest verifier requires accepted release context")
    signed = {item["name"]: item for item in gate["artifacts"]}
    for name in ("invariant-report", "corrupt-fixture-matrix"):
        item = signed.get(name)
        if (item is None or item["media_type"] != "application/json" or
                item["digest"] != raw_sha256(bodies[name])):
            raise evidence.EvidenceError("manifest artifact does not match its exact signed artifact digest")
    instances = report["instances"]
    if len(instances) != 1:
        raise evidence.EvidenceError("manifest report requires one exact signed H0 evidence instance")
    instance = instances[0]
    if instance["lane"] != "H0-hermetic":
        raise evidence.EvidenceError("manifest report requires an H0-hermetic evidence instance")
    bindings = {item["name"]: item for item in scope["input_bindings"]}
    expected_sources = []
    for name in _MANIFEST_TEST_SOURCES:
        binding = bindings.get(name)
        if binding is None or inputs.get(name) is None or raw_sha256(inputs[name]) != binding["digest"]:
            raise evidence.EvidenceError("manifest test source is absent or drifted from the frozen scope")
        expected_sources.append({"digest": binding["digest"], "name": name, "path": binding["path"]})
    expected_materials = []
    for name in _MANIFEST_MATERIALS:
        binding = bindings.get(name)
        if binding is None or inputs.get(name) is None or raw_sha256(inputs[name]) != binding["digest"]:
            raise evidence.EvidenceError("manifest material is absent or drifted from the frozen scope")
        expected_materials.append({"digest": binding["digest"], "name": name, "path": binding["path"]})
    cases_binding = bindings.get("manifest-evidence-cases")
    cases_body = inputs.get("manifest-evidence-cases")
    if (cases_binding is None or cases_body is None or
            raw_sha256(cases_body) != cases_binding["digest"]):
        raise evidence.EvidenceError("manifest case manifest is absent or drifted from the frozen scope")
    case_specs = _read_manifest_evidence_cases(cases_body)
    case_manifest_digest = raw_sha256(cases_body)
    common_members = {
        "artifact_type", "candidate_identity_digest", "environment", "evidence_finished_at",
        "evidence_instance_id", "evidence_started_at", "gate_id", "manifest_materials", "name",
        "release", "schema_version", "selection", "test_sources", "case_manifest_digest",
    }
    invariant = _object(
        _artifact_document(bodies["invariant-report"], "B-MANIFEST", "invariant-report"),
        "manifest invariant report", common_members | {"matrix_digest", "node_results"},
    )
    matrix = _object(
        _artifact_document(bodies["corrupt-fixture-matrix"], "B-MANIFEST", "corrupt-fixture-matrix"),
        "manifest corrupt fixture matrix", common_members | {"cases"},
    )
    expected_identity = {
        "candidate_identity_digest": evidence.canonical_digest(identity), "gate_id": "B-MANIFEST",
        "release": RELEASE, "schema_version": GATE_ARTIFACT_SCHEMA,
    }
    for doc, artifact_type, name in (
        (invariant, "manifest-invariant-report", "invariant-report"),
        (matrix, "manifest-corrupt-fixture-matrix", "corrupt-fixture-matrix"),
    ):
        if (doc["artifact_type"] != artifact_type or doc["name"] != name or
                any(doc[key] != value for key, value in expected_identity.items())):
            raise evidence.EvidenceError("manifest artifact has the wrong candidate, gate, release or name")
        if (doc["evidence_instance_id"] != instance["id"] or
                doc["environment"] != instance["environment"] or
                doc["evidence_started_at"] != instance["started_at"] or
                doc["evidence_finished_at"] != instance["finished_at"]):
            raise evidence.EvidenceError("manifest artifact does not bind its exact signed H0 instance")
        if doc["test_sources"] != expected_sources or doc["manifest_materials"] != expected_materials:
            raise evidence.EvidenceError("manifest artifact does not bind the exact frozen source/material roster")
        if doc["case_manifest_digest"] != case_manifest_digest:
            raise evidence.EvidenceError("manifest artifact does not bind the exact frozen case manifest digest")
    expected_nodes = [_manifest_observed_result(spec) for spec in case_specs["invariants"]]
    node_selection = {
        "collected": len(expected_nodes), "deselected": 0, "failed": 0,
        "passed": len(expected_nodes), "selected": len(expected_nodes), "skipped": 0,
        "xfailed": 0, "xpassed": 0,
    }
    if invariant["node_results"] != expected_nodes or invariant["selection"] != node_selection:
        raise evidence.EvidenceError("manifest invariant node roster or counts do not reconcile")
    expected_cases = [{
        "id": case["id"],
        "members": [_manifest_observed_result(spec) for spec in case["members"]],
    } for case in case_specs["corruption_cases"]]
    case_count = sum(len(case["members"]) for case in case_specs["corruption_cases"])
    case_selection = {
        "collected": case_count, "deselected": 0, "failed": 0,
        "passed": case_count, "selected": case_count, "skipped": 0,
        "xfailed": 0, "xpassed": 0,
    }
    if matrix["cases"] != expected_cases or matrix["selection"] != case_selection:
        raise evidence.EvidenceError("manifest corruption case roster, observed result or digest does not reconcile")
    total_selection = {
        "collected": len(expected_nodes) + case_count, "deselected": 0, "failed": 0,
        "passed": len(expected_nodes) + case_count, "selected": len(expected_nodes) + case_count,
        "skipped": 0, "xfailed": 0, "xpassed": 0,
    }
    if instance["selection"] != total_selection or gate["selection"] != total_selection:
        raise evidence.EvidenceError("manifest signed H0 selection does not cover both evidence partitions")
    if invariant["matrix_digest"] != raw_sha256(bodies["corrupt-fixture-matrix"]):
        raise evidence.EvidenceError("manifest invariant report does not bind the exact corruption matrix digest")


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
        (python, str(shard)) for python in ("3.10", "3.11", "3.12") for shard in range(6)
    ]
    if topology != expected_topology:
        raise evidence.EvidenceError("H0 runner topology is not the frozen 3x6 offline matrix")
    if [environment["python"].rsplit(".", 1)[0] for environment in expected_environments] != \
            ["3.10", "3.11", "3.12"]:
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


def _matrix_source_report(
    resolver: ArtifactResolver, *, gate_id: str, identity: dict,
) -> dict:
    """Rehash and parse a prior gate's retained, signed-artifact report.

    Aggregate order validates and signature-checks B-HERMETIC-ALL and both P0
    source gates before C-PYTHON-MATRIX.  This second read is deliberately a
    narrow cross-gate reconciliation, not a new gate-record authority path.
    """
    record = resolver.record(gate_id, "gate-evidence")
    body = resolver.read(gate_id, "gate-evidence")
    if record["digest"] != raw_sha256(body):
        raise evidence.EvidenceError("python matrix source gate-evidence bytes do not match their index")
    return read_evidence_report(body, identity=identity, gate_id=gate_id)


def _matrix_source_artifacts(
    resolver: ArtifactResolver, *, gate_id: str, names: tuple[str, ...],
) -> list[dict]:
    artifacts = []
    for name in names:
        record = resolver.record(gate_id, name)
        body = resolver.read(gate_id, name)
        if record["digest"] != raw_sha256(body) or record["size"] != len(body):
            raise evidence.EvidenceError("python matrix source artifact bytes do not match their index")
        artifacts.append({"digest": record["digest"], "name": name})
    return artifacts


def _semantic_python_matrix(
    gate: dict, bodies: Mapping[str, bytes], **context: object,
) -> None:
    """Bind each accepted H0/P0 environment to retained source-gate evidence."""
    identity = context["identity"]
    scope = context["scope"]
    support = context["support"]
    resolver = context["resolver"]
    if not isinstance(identity, dict) or not isinstance(scope, dict) or not isinstance(support, dict) or \
            not isinstance(resolver, ArtifactResolver):
        raise evidence.EvidenceError("python matrix verifier requires accepted aggregate context")
    report = read_python_matrix_report(bodies["python-matrix-report"], identity=identity)
    bindings = {row["name"]: row["digest"] for row in scope["input_bindings"]}
    if report["support_matrix_digest"] != bindings.get("support-matrix") or \
            report["package_metadata_digest"] != bindings.get("package-metadata"):
        raise evidence.EvidenceError("python matrix report does not bind accepted support/package scope bytes")
    inputs = context["input_bodies"]
    if not isinstance(inputs, Mapping) or type(inputs.get("package-metadata")) is not bytes:
        raise evidence.EvidenceError("python matrix verifier requires bound package metadata bytes")
    if evidence._toml is None:  # pragma: no cover - dependency contract is separately tested
        raise evidence.EvidenceError("python matrix verifier has no TOML parser")
    try:
        package_metadata = evidence._toml.loads(inputs["package-metadata"].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise evidence.EvidenceError("python matrix package metadata is not parseable TOML") from exc
    project = package_metadata.get("project") if type(package_metadata) is dict else None
    if type(project) is not dict or project.get("requires-python") != ">=3.10,<3.13":
        raise evidence.EvidenceError(
            "python matrix support topology does not match exact published requires-python policy"
        )

    expected = [row for row in support["environments"] if row["lane"] in _PYTHON_MATRIX_LANES]
    if len(expected) != 6:
        raise evidence.EvidenceError("python matrix support topology is no longer the frozen six-row contract")
    expected_rows = [{"lane": row["lane"], "environment": _h0_environment(row)} for row in expected]
    if [{"lane": row["lane"], "environment": row["environment"]} for row in report["rows"]] != expected_rows:
        raise evidence.EvidenceError("python matrix rows do not cover the exact sorted accepted H0/P0 topology")

    h0_report = _matrix_source_report(resolver, gate_id="B-HERMETIC-ALL", identity=identity)
    build_report = _matrix_source_report(resolver, gate_id="C-PACKAGE-BUILD", identity=identity)
    install_report = _matrix_source_report(resolver, gate_id="C-PACKAGE-INSTALL", identity=identity)
    h0_expected = [_h0_environment(row) for row in expected if row["lane"] == "H0-hermetic"]
    p0_expected = [_h0_environment(row) for row in expected if row["lane"] == "P0-package-supply"]
    if [row["environment"] for row in h0_report["instances"]] != h0_expected or \
            any(row["lane"] != "H0-hermetic" for row in h0_report["instances"]):
        raise evidence.EvidenceError("python matrix H0 source report does not cover every accepted H0 environment")
    for source_name, source_report in (("build", build_report), ("install", install_report)):
        if [row["environment"] for row in source_report["instances"]] != p0_expected or \
                any(row["lane"] != "P0-package-supply" for row in source_report["instances"]):
            raise evidence.EvidenceError(
                f"python matrix {source_name} source report does not cover every accepted P0 environment"
            )

    test_record = resolver.record("B-HERMETIC-ALL", "test-report")
    test_body = resolver.read("B-HERMETIC-ALL", "test-report")
    if test_record["digest"] != raw_sha256(test_body) or test_record["size"] != len(test_body):
        raise evidence.EvidenceError("python matrix H0 test-report bytes do not match their index")
    test_report = _h0_artifact(
        test_body, name="test-report", artifact_type="h0-test-report", identity=identity,
        members={"collection_manifest_digest", "runs"},
    )
    runs = _array(test_report["runs"], "python matrix H0 test report.runs")
    runs_by_environment = {}
    for index, row in enumerate(runs):
        run = _object(row, f"python matrix H0 test report.runs[{index}]", {
            "environment", "evidence_instance_id", "fragments",
        })
        environment = _matrix_environment(run["environment"], "python matrix H0 run environment")
        fragments = _array(run["fragments"], "python matrix H0 run fragments")
        parsed_fragments = []
        for fragment_index, fragment_row in enumerate(fragments):
            fragment = _object(fragment_row, f"python matrix H0 fragment[{fragment_index}]", {
                "digest", "job_instance_id", "report",
            })
            fragment_body = evidence.canonical_json_bytes(fragment["report"])
            if fragment["digest"] != raw_sha256(fragment_body):
                raise evidence.EvidenceError("python matrix H0 fragment digest is not rehashed")
            parsed_fragments.append(evidence.read_h0_shard_outcome_report(fragment_body))
        if (len(parsed_fragments) != 6 or
                [fragment["shard_index"] for fragment in parsed_fragments] != list(range(6))):
            raise evidence.EvidenceError("python matrix H0 run does not retain the exact six fragments")
        first = parsed_fragments[0]
        if any(fragment["full_h0_roster"] != first["full_h0_roster"] for fragment in parsed_fragments):
            raise evidence.EvidenceError("python matrix H0 fragments disagree on the full roster")
        runs_by_environment[tuple(environment[field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        ))] = {"evidence_instance_id": run["evidence_instance_id"], "fragments": parsed_fragments}
    if len(runs_by_environment) != len(h0_expected):
        raise evidence.EvidenceError("python matrix H0 test report has duplicate or missing environments")

    build_artifacts = _matrix_source_artifacts(
        resolver, gate_id="C-PACKAGE-BUILD", names=("build-log", "package-inventory", "sdist", "wheel"),
    )
    install_artifacts = _matrix_source_artifacts(
        resolver, gate_id="C-PACKAGE-INSTALL", names=("install-inventory", "smoke-results"),
    )
    h0_instances = {tuple(row["environment"][field] for field in (
        "architecture", "isolation_profile", "os", "python", "runner_image",
    )): row for row in h0_report["instances"]}
    build_instances = {tuple(row["environment"][field] for field in (
        "architecture", "isolation_profile", "os", "python", "runner_image",
    )): row for row in build_report["instances"]}
    install_instances = {tuple(row["environment"][field] for field in (
        "architecture", "isolation_profile", "os", "python", "runner_image",
    )): row for row in install_report["instances"]}
    for row in report["rows"]:
        key = tuple(row["environment"][field] for field in (
            "architecture", "isolation_profile", "os", "python", "runner_image",
        ))
        if row["lane"] == "H0-hermetic":
            source = h0_instances.get(key)
            run = runs_by_environment.get(key)
            if source is None or run is None:
                raise evidence.EvidenceError("python matrix H0 row does not resolve an accepted source environment")
            h0 = row["h0"]
            selection = source["selection"]
            if (h0["evidence_instance_id"] != source["id"] or
                    run["evidence_instance_id"] != source["id"] or
                    h0["test_report_digest"] != test_record["digest"] or
                    h0["selection"] != selection or h0["fragment_count"] != len(run["fragments"]) or
                    h0["full_h0_roster"] != run["fragments"][0]["full_h0_roster"] or
                    selection["failed"] != 0 or selection["skipped"] != 0 or
                    selection["xfailed"] != 0 or selection["xpassed"] != 0 or
                    selection["passed"] != selection["selected"]):
                raise evidence.EvidenceError("python matrix H0 row does not reconcile its validated test run")
        else:
            p0 = row["p0"]
            build = build_instances.get(key)
            install = install_instances.get(key)
            if build is None or install is None or \
                    p0["build_evidence_instance_id"] != build["id"] or \
                    p0["install_evidence_instance_id"] != install["id"] or \
                    p0["build_artifacts"] != build_artifacts or p0["install_artifacts"] != install_artifacts:
                raise evidence.EvidenceError("python matrix P0 row does not reconcile exact source instances/artifacts")


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
    "B-DOCS-POLICY": _semantic_docs_policy,
    "B-MANIFEST": _semantic_manifest,
    "B-QUALITY": _semantic_quality,
    "B-COVERAGE": _semantic_coverage,
    "B-STATIC-SECURITY": _semantic_static_security,
    "B-DETERMINISM": _semantic_determinism,
    "C-SOURCE-REGISTRY": _semantic_source_registry,
    "C-PACKAGE-BUILD": _semantic_package_build,
    "C-PYTHON-MATRIX": _semantic_python_matrix,
    "C-NETWORK-BOUNDARY": _semantic_network_boundary,
    "C-NET-DENY": _semantic_network_denial,
    "C-PACKAGE-INSTALL": _semantic_package_install,
    "C-SBOM": _semantic_sbom,
    "C-VULNERABILITY": _semantic_vulnerability,
    "C-PROVENANCE": _semantic_provenance,
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
