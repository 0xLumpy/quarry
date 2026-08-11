# Quarry v0.3.9 — Canonical Reconciled Findings Register

**Date:** 2026-08-10

**Status:** canonical audit backlog for the supplied v0.3.9 snapshot

**Inputs:** [Codex full audit](AUDIT_REPORT.md), [independent audit](quarry-audit-claude.md), and [cross-reference/product-context revision](AUDIT_CROSS_REFERENCE.md)
**Deployment used for present-day severity:** single-operator CLI on a VPS. Notes explicitly identify risks that become more severe for shared workers, a daemon, collaboration, or multi-tenancy.

This register supersedes the earlier draft register IDs. `QR39-*` identifiers below are the stable canonical IDs for remediation and regression tracking.

## Product standard

> **Run broadly, preserve aggressively, fail transparently, and make every action and omission reproducible.**

Quarry is intentionally a high-scale, active bug-bounty framework. The objective is not to suppress useful authorized requests. Controls must preserve evidence, enforce declared engagement policy, bound host-threatening failure modes, and make omissions/remainders explicit.

## Accepted product decisions

These are deliberate product capabilities, not defects. Their guardrails remain actionable because accepted risk must still be accurately represented and reproducible.

| ADR | Accepted behavior | Required controls and residual work |
|---|---|---|
| ADR-039-01 | **Broad active Nuclei verification remains enabled by default** with `-etags intrusive,fuzz,dos,brute-force -s critical,high,medium`. No permanent allowlist, coverage-reducing default, or interactive per-run prompt is required. | Relabel it accurately; materialize one immutable/content-addressed template snapshot per run; point every chunk at that snapshot with update checks disabled; emit exact policy, engine, config, ignore, payload-helper, signature, selected-template and digest provenance; classify potentially state-changing semantics as versioned, non-blocking telemetry with an `unknown` class. See `QR39-014`. Authorization/consent fields record an operator assertion and scope revision; Quarry does not claim to verify legal authorization. |
| ADR-039-02 | **Private/RFC1918/CGNAT/ULA reach remains enabled by default.** Internal exposure is a supported hunting class. Users may disable it with `BLOCK_PRIVATE_TARGETS`. | Preserve the opt-out; record the authorization rule, every A/AAAA answer, special-use classification, redirect decision and actual selected peer where the transport exposes it. Directly observed known self/metadata answers are intended to be withheld, but connection-time rebinding/proxy gaps remain until `QR39-019` is fixed. No blanket default-deny is required. |
| ADR-039-03 | **Public Interactsh remains the default OOB provider.** Product policy requires users to be able to disable OOB or configure a self-hosted provider. | Self-hosting exists, but the snapshot has no single explicit switch that disables Quarry's SSRF callbacks and Nuclei OAST together; passive mode/phase omission/tool absence are only indirect avoidance. Add the unified opt-out in `QR39-040`. Surface provider/retention implications; keep tokens out of display/argv where possible; protect local maps/callbacks with `0700`/`0600`; retain raw callback proof. See `QR39-006`, `QR39-017`, `QR39-020`, and `QR39-021`. |
| ADR-039-04 | **Workload-scaled, potentially long time budgets are intentional.** Quarry must not impose a small universal ceiling that silently sacrifices high-scale coverage. | Apply the operator-configured deadline across execution, termination and drain; chunk every large lane; add meaningful-progress/stall detection; checkpoint durable remainder before stopping; provide an emergency operator ceiling. See `QR39-001` and `QR39-030`. |

## Evidence and status semantics

- `V` — reproduced by one of the two shipped characterization harnesses.
- `B` — measured/reproduced in a disposable audit benchmark or harness that is described in the full audit but is not shipped in the two test files.
- `S` — source-confirmed.
- `R` — corroborated by authoritative external material.
- `I` — the stated final impact includes an explicitly identified inference.

The shipped harnesses are:

- `audit_tests/test_verified_findings.py` — 15 collected cases;
- `audit_tests/test_cross_reference_findings.py` — 6 cases.

Final audit validation on Python 3.13.12:

```bash
PYTHONPATH=src pytest -q audit_tests/
# 21 passed
```

Passing means the undesirable v0.3.9 behavior was reproduced. It is not evidence that the behavior is correct, and it is not a statement about the intentionally omitted upstream test suite.

Unless a row is an accepted ADR, the register-level defaults are **Status: Open** and **Owner: Unassigned**. This file owns finding definitions, evidence, ADRs and stable IDs until a tracker becomes authoritative. On tracker import, add one stable issue URL per ID and generate/mirror status rather than manually maintaining two independent backlogs. The execution record must hold owner, confirmed target release, dependencies, acceptance test, migration/rollback plan and closure evidence.

Severity is contextual, not CVSS:

- **High:** blocks a defensible high-scale/production claim or can cause serious evidence, host, integrity, authorization, or recovery failure under a realistic prerequisite.
- **Medium:** material present-day defect with a narrower prerequisite/bounded impact, or a High blocker at the future daemon/collaboration boundary.
- **Low:** localized correctness, portability, hardening, or professionalism defect.

No Critical finding remains after applying ADR-039-01. Multiple High release-readiness defects remain.

---

## Priority 1 — release-readiness and declared high-scale blockers

These must be fixed on their stated v0.3.10 or v0.4 milestone before feature breadth, AI, collaboration, or the corresponding production/high-scale claim. `QR39-005` makes v0.3.x honest and bounded; `QR39-041` removes that core scale ceiling in v0.4.

| ID | Sev | Finding and evidence | Required outcome / acceptance | Target | Ver | Origin |
|---|---|---|---|---|---|---|
| QR39-001 | High | **Subprocess boundary loses or exhausts evidence.** `runner.run()` reads input files whole, uses strict text PIPEs, buffers complete stdout/stderr, can raise on non-UTF8, performs an unbounded post-timeout drain, lets launch/input/publication errors escape, and accepts but ignores `ok_empty`. `runner.py:453-484,546-669`. | Stream binary stdin/stdout/stderr to private staging artifacts; retain incremental digest/count plus bounded diagnostic tail; apply one configured deadline across execute/kill/drain; close escaped pipes after bounded grace; preserve partial bytes; return typed machinery/publication faults; enforce fixture RSS/output/deadline budgets. | v0.3.10 | V/S | Q-H08/Q-H09 |
| QR39-002 | High | **Campaign namespace corrupts latest-run and delta selection.** `Run.latest()` treats `recon/campaigns/` as a run; delta repeats the enumeration. `store.py:968-988`; `exports.py:29-47`. | One validated `list_runs()` excludes every reserved namespace, non-run directory and symlink. `status`, `report`, OOB and delta work after settlement. Add reserved-directory/property fixtures. | v0.3.10 | V/S | Q-H05 |
| QR39-003 | High | **Known gaps can finalize as `complete`.** Event-sink degradation is attached too late and ignored by verdict; checkpoint challenges are prose; missing Interactsh is recorded under a non-matching source name. `store.py:604-719,708-711,918-947`; `cli.py:969-995`; `phases/params.py:2238-2240`. | Introduce typed `Fault`/`Gap` records with `challenges_completeness`; calculate verdict only after every event/finalization fault is committed; model source-to-tool dependency edges explicitly. Fault injection must never produce a clean verdict. | v0.3.10 | V/S | Q-H07 |
| QR39-004 | High | **Hostile native responses have no byte/run-disk governor.** `stream_to_file` explicitly has no byte ceiling and native acquisitions can stream for hundreds of seconds. `contract.py:168-201`; `fetch.py:469-534`. | Enforce layered response/artifact/run/project budgets plus a live free-space reserve. Preserve bounded partial evidence and typed truncation/remainder. “Spill” must mean another configured volume/object store; writing elsewhere on the same endangered filesystem is not remediation. | v0.3.10 | S/R | Q-H03 |
| QR39-005 | High | **The core evidence path fully materializes corpus state.** Each entity log is folded completely on first access per `Run`, retained for its lifetime, and copied/materialized again by common reads/exports. Record/provenance merges also perform repeated linear membership. A 100k-row, 9.70 MiB fixture required roughly 93 MiB traced Python allocation. `store.py:131-199,235-242,334-367,507-535,566-582`; `exports.py:9-65`. | For v0.3.10, publish and enforce an exact supported corpus/RSS envelope and checkpoint/refuse new work beyond it with durable remainder. This closes only the truthfulness/host-continuity ticket; `QR39-041` removes the architectural ceiling. Gate peak RSS, ingest, reopen, query/export, disk amplification and crash recovery on versioned fixtures. | v0.3.10 | B/S | PERF-1; Q-M10 subset |
| QR39-006 | Medium | **Sensitive artifacts inherit umask.** Run/OSINT/OOB/normalized-secret/export data can be `0755`/`0644`, including full discovered secret values. Present severity assumes a dedicated operator VPS; this becomes High on shared workers/services. `store.py:383-439,562-564`; `osint.py:93-109,194-220`; `oob.py:148-232`; `exports.py:60-65`. | Create project/run/private evidence roots with descriptor-based `0700`/`0600`, no-follow/exclusive semantics; validate existing secrets/session ownership/mode; expose only intentionally redacted share views. Pass a permission matrix under umasks `000/002/022/077`. | v0.3.10 | V/S/R | Q-H04 |
| QR39-007 | High | **Installer verification and privileged use are separated by predictable shared paths.** `/tmp/go.tgz` and multiple fixed archive/clone paths permit symlink/TOCTOU races; root later reopens the verified pathname. `bootstrap.py:177-190`; `data/tools.yaml:140,168,219,245,462,478,555`. | Use a private `0700` operation directory, exclusive/no-follow files, stable descriptor/content identity, safe archive-member validation, unprivileged extraction and minimal privileged atomic swap. Never remove the current Go/runtime before the candidate is completely verified. | v0.3.10 | B/S/R/I | Q-H13 |
| QR39-008 | High | **Required installer failures and partial activation report success.** Bootstrap results are discarded; data/extras lack an aggregate result; activation can replace good payloads before final identity/receipt checks; no rollback. `bootstrap.py:117-192`; `cli.py:505-507,541-543`; `registry.py:284-287,481-548`. | Every step returns a typed required/optional result; any required failure is nonzero; stage executable, payload closure and receipt in one versioned directory; verify it; perform one atomic current-pointer swap; retain last-good rollback; lock concurrent installs. Fault injection must preserve the previous healthy install. | v0.3.10 | B/S | Q-H14 |
| QR39-009 | High | **Late OOB observations mutate a finalized run without revising its manifest/views.** Manifest count can remain zero while folded evidence contains one interaction. `cli.py:1177-1234`; `store.py:507-565`. | Finished base runs are immutable. Store delayed callbacks in manifested append-only supplements or a new revision; transactionally update the combined view version, counts, digests, reports and campaign verification. | v0.3.10 | V/S | Q-H06 |
| QR39-010 | High | **Selectors are unvalidated before side effects or can silently produce an empty successful selection.** `--phases typo` creates an empty `complete` run; invalid doctor/install selectors can select zero work and return success; duplicates repeat work; arbitrary ordering can starve dependent lanes. `cli.py:225-227,461-480,892-905`; `registry.py:190-191`. | Validate unknown/empty/duplicate/dependency-invalid selectors before any run/global mutation. Preserve canonical phase ordering unless an explicit advanced override supplies prerequisite state. Invalid input exits with the documented code and produces no run. | v0.3.10 | V/S | Q-H10; Q-H11 selector subset |
| QR39-011 | High | **Process exit status and machine output do not reliably encode the verdict already shown in manifests/prose.** `complete_with_gaps`, `doctor NOT READY`, campaign faults, OSINT degradation and machinery paths can render distinct warnings but return zero; several commands lack stable JSON. `cli.py:381-391,465-590,725-752,838-858,1009-1064`. | Implement the exit/result contract below. Human-friendly rendering is independent of process status. Ship versioned JSON output. If compatibility is required, provide a time-bounded legacy flag—not silent ambiguity. | v0.3.10 | S | Q-H11 |
| QR39-012 | High | **Settlement cannot reliably prove convergence or resume.** `decide()` checks `max_children` before fixed-point/terminal meaning; child one lacks a complete obligation roster; silence is not tracked by exact `(lane, unit, measure)`; interrupted campaigns with children are refused. `campaign.py:421-487`; `settle.py:52-55,106-123,161-177`. | Precompute typed obligations before child one; require known-zero/remainder/terminal/not-applicable per obligation; evaluate meaning before budget-to-continue; persist idempotent lease-owned transitions; resume after kill at every boundary. | v0.3.10 | B/S | Q-H12 |
| QR39-013 | Medium | **Literal redaction is not a confidentiality boundary and can corrupt telemetry.** Ordered substring replacement over-redacts benign strings, misses transformed/overlapping values, and affects events/manifests/digest/notifications—not canonical normalized observations/flat exports. `secrets.py:141-171`; `events.py:152-174`; `store.py:487-496`; `triage.py:425-441`. | Use typed sensitive values, per-tool minimal secret transport and schema-enforced private versus share/AI projections. Keep longest-first exact replacement only as defense in depth; reword absolute “never leaks” guarantees. | v0.3.10 | V/S | SEC-1/FUNC-1 |
| QR39-014 | Medium | **Accepted Nuclei execution is mislabeled and not reproducibly identified.** “Non-intrusive” is false for the possible request set; `_nuclei_templates_fp()` hashes three metadata strings; chunks can observe mutable shared templates. `phases/params.py:1-7,569-680,825-950,2371-2395`; `data/tools.yaml:523-535`; `docs/tools.md:71-78`; `docs/example.md:482-489`. | Preserve ADR-039-01 execution. Use the exact broad-active wording; preflight-update then materialize/lock one immutable snapshot; run every chunk explicitly against it with updates disabled; emit `nuclei-policy.json`; bind its digest to work/resume identity; version heuristic semantic inventory including `unknown`. | v0.3.10 | B/S/R | retired Q-C01 residual |
| QR39-015 | High | **DNS timeouts abandon live resolver threads.** A daemon is created around blocking `getaddrinfo`; timeouts return without stopping it; a large failing corpus accumulates work. High severity reflects Quarry's explicit high-scale contract. `netguard.py:125-179`. | Use a resolver with enforceable cancellation/deadlines or recyclable worker processes; bound total outstanding queries and corpus work; discard late completions and reclaim worker resources. Add stuck-resolver thread/process-count gates. | v0.3.10 | B/S | Q-M02 promoted for scale |
| QR39-016 | High | **Finalization is uncontained and non-resumable.** Export, delta, triage, digest, metrics and manifest publication occur after phase containment; one late error can leave a long high-scale run ambiguous. `cli.py:984-1007`. | Persist `created → running → finalizing → finished/finalization_failed`; commit base evidence independently; make every derived view idempotent and generation-addressed; resume finalization without rescanning. | v0.3.10 | S | Q-M16 promoted for scale |
| QR39-017 | Medium | **Runtime ignores verified tool identity and over-shares secrets.** Execution resolves PATH shadows; global `PDCP_API_KEY` and the ambient environment reach every child; provider tokens can be placed on argv. This becomes High on a shared/service worker. `registry.py:290-348`; `runner.py:335-336,558-590`; `secrets.py:214-219`; `phases/vertical.py:1413-1433`; `phases/params.py:543-552`; `oob.py:200-223,244-264`. | Resolve/freeze approved absolute executables and verify receipt/digest at plan/run start; spawn from a minimal environment; deliver each secret only to its consumer via private config/stdin/fd; persist a redacted display argv separately from execution arguments. | v0.3.10 | B/S/R | Q-H15 |
| QR39-018 | Medium | **Profiles/settings lack an exact type boundary.** Wrong YAML shapes leak raw errors; scalar list values iterate as characters; numeric coercions truncate; Python booleans pass some integer paths; `JS_AST` is absent from eager flag validation; unknown keys and some cap bypasses are accepted. `config.py:230-233,338-418,392-395`; `settings.py:249-290`. | Adopt a versioned exact schema with unknown-key rejection, ranges/dependencies and migrations; validate before run state; return path-specific `ProfileError`/configuration faults; require a conspicuous unsafe override for policy caps. | v0.3.10 | V/S | Q-H16 |
| QR39-040 | Medium | **The accepted public-OOB default lacks one explicit global opt-out.** `params.oob_probe` is default-on in active params runs; Nuclei OAST is separately active; `BLIND_XSS` controls only Dalfox's blind lane. `config.py:197-233`; `data/target.template.yaml:44-63`; `phases/params.py:543-552,640-653,2226-2258`. | Add one validated profile policy such as `OOB_ENABLED: false` that disables Quarry-issued callbacks, adds Nuclei's no-Interactsh control, and prevents blind-OOB lanes; retain self-host configuration independently. `quarry plan`, manifest and coverage must state disabled/self-hosted/public per owner. | v0.3.10 | S | ADR-039-03 control gap; Q-M15 |
| QR39-041 | High | **The v0.3.x capacity envelope does not remove whole-corpus materialization.** The market-leading high-scale claim remains blocked until live writes/reads stop retaining complete merged state. Same evidence as `QR39-005`. | Replace live `_records` retention and routine JSONL folding with the disk-backed indexed repository; status/query use indexes; exports/rebuilds are single-pass streaming with O(batch-size) memory and no duplicate full-corpus materialization. | v0.4 | B/S | PERF-1; Q-M10 core remediation |

---

## Priority 2 — v0.3.x tail and v0.4 correctness core

These remain part of the canonical backlog. They are not optional merely because their present-day severity is lower.

| ID | Sev | Finding and evidence | Required outcome / acceptance | Target | Ver | Origin |
|---|---|---|---|---|---|---|
| QR39-019 | Medium | **DNS approval is not bound to the connection.** Native fetch fails closed on indeterminate DNS but resolves once for policy and again in urllib; environment proxies add another resolver. External-tool guards both re-resolve later and intentionally pass indeterminate names. This becomes High on a worker with sensitive reachable control-plane services. `fetch.py:39-44,80-148,537-575`; `netguard.py:182-253`. | Preserve ADR-039-02. Bind approved addresses to actual peers while preserving original Host/SNI/certificate verification; revalidate redirects; define/disable proxy inheritance; add worker-level egress denial for known self/metadata/control-plane destinations. | v0.3.11 | S/R | SEC-2; Q-H02 |
| QR39-020 | Medium | **OOB token issuance rewrites the complete growing session for every candidate.** The 1,000-token shipped characterization serialized 82,895,990 bytes for a final 165,803-byte snapshot. `oob.py:148-159,316-334`; `phases/params.py:2241-2277`. | Use SQLite WAL or an append-only `0600` journal; group-commit each mapping batch durably **before** issuing its request batch; checkpoint/compact without losing the crash-correlation invariant. Gate write amplification and crash recovery. | v0.3.10 | V/S | PERF-2 |
| QR39-021 | Medium | **OOB attribution tokens have only 32 random bits.** After learning the session domain, an attacker can guess another live `(target,param)` token at scale; local generation collisions are already checked. `oob.py:282-334`. | Use at least 128 random bits or a run-bound HMAC; expire mappings; reject replay; detect guess/rate anomalies; retain raw callback evidence. | v0.3.10 | S/R | Q-M01 |
| QR39-022 | Medium | **URL authority canonicalization disagrees with scope IDNA policy.** Unicode URL hosts can fail against punycode apexes; percent-encoded authorities are excluded without counted reason. `normalize.py:210-230,243-261`; `config.py:91-143`. | One strict authority parser applies the profile IDNA policy; decode only unambiguous valid forms; preserve raw input; reject ambiguity fail-closed; aggregate typed omission counts and bounded samples. | v0.3.10 | V/S | FUNC-2 sharpened |
| QR39-023 | Medium | **Process globals and snapshot ledgers are unsafe for concurrent runs.** Event sink, tool cwd, cancellation, settings and acquisition state are global; generic Ledger permits lost updates. This is High at the daemon/collaboration boundary. `events.py:76-81`; `runner.py:77-82`; `settings.py:18-52`; `campaign.py:47-71`; `budget.py:750-767,991-1051`. | Until v0.4, isolate each run in its own OS process. Then pass explicit `RunContext`, use transactional unique keys, leases/fencing and compare-and-swap/append-only state. Two workers must not cross-route, cross-cancel or lose updates. | v0.4 | B/S | Q-H17 |
| QR39-024 | Medium | **Publication is atomic-looking but not durable/content-attested.** Reconciliation checks counts rather than content; PID-only temp names can collide; no file/dir fsync; JSONL has no torn-tail framing. `store.py:292-389,562-564`. | Manifest each log’s schema, digest, bytes and rows; use unique exclusive temps, file+directory fsync and locking, or transactional commits; define torn-tail recovery and generation hashes for every projection. | v0.4 | S | Q-M09 |
| QR39-025 | Medium | **Provider text can escape a commented OSINT profile into active YAML.** Newlines can inject active configuration. `osint.py:125-145`; `osint_report.py:86-113`. | Validate each candidate as its declared canonical type; reject controls/newlines; build a typed object; serialize with a YAML library; reject duplicate keys on load. | v0.3.11 | V/S | Q-M13 |
| QR39-026 | Medium | **Two execution control planes weaken registry enforcement.** Phase code contains 34 direct `exec_tool()` and 15 `run_contract()` calls plus native exceptions. `src/quarry_recon/phases/*.py`; boundary definitions in `runner.py` and `contract.py`. | Route work through one `ExecutionPlan`/`Executor` boundary that enforces source identity, policy, approved executable, lifecycle, artifacts, classification, normalization, faults and coverage. Complex/native lanes provide typed steps rather than bypasses. | v0.4 | S | Q-M08; ARCH-2 |
| QR39-027 | Medium | **Behavioral data refresh is mutable and non-transactional.** Moving resolver/wordlist/GF refs and non-atomic curl refreshes can change behavior; `curl -sSL` accepts HTTP error bodies and downloader launch `OSError` is not converted to a typed result. `bootstrap.py:54-64`; `data/bootstrap.yaml:178-220`. | Pin/hash appropriate static inputs; for fast-moving accepted inputs such as Nuclei, atomically version/content-address the selected current corpus rather than permanently freezing coverage; return typed launch/HTTP/content failures; validate grammar/cardinality/size; retain last-good data. | v0.3.11 | V/S/R | Q-M03/Q-M04 data subset |
| QR39-028 | Medium | **Receipts omit mutable payloads actually executed by wrappers.** JXScout wrappers can remain “healthy” while JS/native share payloads change. `data/tools.yaml:168,245`; `registry.py:320-326`. | Attest the complete runtime closure or package it as one immutable artifact; runtime admission verifies every executed payload digest, not only the wrapper. | v0.4 | S | Q-M05 |
| QR39-029 | Medium | **Pacing and artifact ownership are not engagement-global.** Native `_pace()` is per caller; identical fetches can reconcile then race publication without a lease. `fetch.py:47-50,469-534`. | Put shared rate/spend/resource limiters and artifact ownership leases in `RunContext`; external tools reserve declared capacity; identical acquisition has one owner and wait/reuse semantics. | v0.4 | S | Q-M11 |
| QR39-030 | Medium | **Unchunked lanes can receive enormous finite deadlines without progress semantics.** WAF and takeover pass whole corpora to workload-scaled timeout functions; 100k targets can compute roughly 278 days. `runner.py:263-278`; `phases/probe.py:2384-2395`; `phases/params.py:2331-2350`. | Preserve ADR-039-04. Chunk/checkpoint every large lane, define adapter-specific meaningful progress, and persist remainder before stall/emergency termination. Do not use stdout silence as a universal heartbeat; `QR39-001` separately owns post-kill drain. | v0.3.11 | V/S | PERF-3 |
| QR39-031 | Medium | **A new tool start retains the previous terminal generation.** Rendering can show success/failure while the next execution is running. `views.py:84-147`. | Key state by source/work-unit/generation; clear terminal fields on start; aggregate only generation-correct state. | v0.3.10 | V/S | Q-M07 |
| QR39-032 | Low | **Run/campaign identifiers are paths in disguise.** `../` IDs can escape storage boundaries. Present impact is local-operator-only; this becomes High at a service/API boundary. `store.py:466-478`; `campaign.py:554-558`. | Mint strict opaque IDs, verify resolved containment before mutation, reject symlink traversal, and authorize `workspace_id + object_id`, never caller paths. | v0.4 | V/S | Q-M14 |
| QR39-033 | Low | **`shell=True` remains a sudo-adjacent latent footgun.** Current strings are package-controlled, so no external injection path was confirmed; severity rises if manifests/plugins become externally extensible. `registry.py:152,570`; `bootstrap.py:47`. | Replace with list-form argv or structured installer primitives before manifests/plugins become externally extensible. | v0.4 | S | SEC-3 |
| QR39-034 | Low | **Untrusted target/provider values can manipulate Markdown and future HTML/AI consumers.** Present Markdown impact is bounded; this becomes High if an unsafe HTML/UI renderer is introduced. `triage.py:213-270`; `osint_report.py:27-69`. | Encode at each renderer, strip dangerous controls, prevent remote loads by default, and treat retrieved text as untrusted data in AI projections. Future HTML must use safe components, CSP and disabled remote loads. | v0.3.11 | S | Q-L01 |
| QR39-035 | Low | **Platform support claims conflict with implementation.** README claims best-effort macOS while Darwin is reported as Linux and artifacts/commands remain Linux/GNU/apt specific. `README.md:47`; `bootstrap.py:25,176`; `registry.py:366-372`. | Declare/test Linux-only for v0.3.10 or publish a real OS/arch capability matrix with artifacts, hashes and CI. | v0.3.10 | V/S | Q-M06 |
| QR39-036 | Low | **Exactly capped native bodies are indistinguishable from truncation.** `scoped_headers` reads exactly the limit. `fetch.py:537-575`. | Read `limit + 1`; record exact/truncated state and coverage consequence. | v0.3.10 | S | Q-L02 |
| QR39-037 | Low | **Arbitrary Python OOS regex can catastrophically backtrack.** Local profile control limits current impact; collaborative/imported configuration raises it to Medium. `config.py:124-130,317-323`. | Prefer exact/suffix/glob rules or a linear-time engine; cap pattern/input complexity and validate before a run. | v0.4 | S | Q-M12 |
| QR39-038 | Low | **Install dry-run mutates directories and `update:` registry metadata is dead.** `bootstrap.py:195-258`; `registry.py:96,176,375-396`; `cli.py:569-585`. | Dry-run must be side-effect free; either implement/version the update contract or remove the dead field/docs. | v0.3.10 | B/S | Q-L03 |
| QR39-039 | Medium | **Secondary projection/metrics algorithms amplify corpus cost.** Campaign union joins complete bodies, sweep duplicates/rehashes large sets, each tool scans the full process table, and `ru_maxrss` is a process-lifetime child high-water mark. Severity reflects the high-scale contract. `campaign.py:284-295`; `sweep.py:55-95,312`; `runner.py:25-53,597-603`; `metrics.py:14`. | Stream/partition union and sweep work, cache hashes, use one cgroup/central sampler, and label run-local metrics truthfully. Add these to the same fixed-corpus performance gate as `QR39-005`. | v0.4 | S | Q-M10 remainder |
| QR39-042 | Medium | **Python/build dependency closure is lower-bound-only and not hash-complete.** `pyproject.toml:1-23`; installer/build flow. | Generate supported-platform hash-complete locks/wheelhouse, pin the build backend, capture Go/module build identity, and publish SBOM plus build provenance. | v0.4 | S/R | Q-M03 dependency subset |
| QR39-043 | Medium | **Maintainability/professionalism debt is measurable and design references are broken.** The snapshot has 36 functions at least 100 lines, 14 at least 200, only 478/1,142 fully annotated functions, and five links into an absent `docs/design/` tree. Hotspots include `phases/crawl.py`, `probe.py`, `params.py`, and `vertical.py`; broken links originate in `README.md`, `docs/README.md`, `docs/campaigns.md`, and `docs/architecture.md`. | Restore or replace every design reference; preserve rationale in versioned ADRs; type public boundaries first; after contracts land, migrate/decompose lane hotspots with architecture fitness tests preventing execution/persistence/policy bypass. | v0.4 | S | Q-M17; ARCH-1 |

---

## Required CLI result and exit contract

Human presentation does not determine process success. The target contract is:

| Exit | Machine meaning |
|---:|---|
| 0 | Clean completion under the selected policy; no completeness-challenging gap or machinery fault |
| 2 | Invalid selector, profile, schema, path, or configuration |
| 3 | Completed with declared terminal/soft limits; evidence is usable but policy-selected work was intentionally bounded |
| 4 | Completed with gaps, unknown coverage, missing required dependency, or unresolved remainder |
| 5 | Machinery, persistence, installer, runner, or finalization failure |
| 6 | The requested top-level operation was refused before execution by scope/authorization/policy |
| 130 | Operator interruption |

The result model is compositional: `outcome = invalid | refused | failed | completed` and `coverage = clean | intentionally_bounded | gapped`. Exit precedence is deterministic:

1. operator interruption (`130`);
2. machinery/persistence/finalization failure after start (`5`);
3. preflight invalid input (`2`) or top-level refusal (`6`);
4. completed with gaps/unknown required coverage (`4`);
5. completed with intentional terminal limits/remainder (`3`);
6. clean completion (`0`).

Per-candidate off-scope redirects, self-address withholding, private-target opt-out and ordinary policy exclusions are `PolicyDecision` records; they do not turn an otherwise valid run into exit `6`. Policy exclusions resolved before planning can still yield clean completion, while planned work left incomplete is `3` or `4` according to whether the remainder is intentional/terminal or unknown/faulted.

`doctor NOT READY`, failed required installation, unsuccessful campaign termination and invalid selectors must not exit zero. Missing optional dependencies are declared policy limits; missing required dependencies are gaps or preflight failures. A report-only failure after the base evidence commit is exit `5` with resumable `finalization_failed`, not loss of the base run.

If a compatibility transition is needed, ship a clearly named, time-bounded legacy exit mode; do not require automation to parse colored prose. JSON mode writes no colored prose to stdout and emits `{schema_version, command, run_id, campaign_id, outcome, coverage, faults, gaps, exit_code, remediation}` with nullable IDs where no object was created.

---

## Architecture sequence — avoid the later rewrite

Do not split the phase monoliths before the contracts they must implement exist. Use a strangler migration:

1. **Land independent hotfixes and freeze golden fixtures.** Start with `QR39-001`, `002`, `004`–`008`, `010`, `013`–`015`, `017`, `018`, `020`–`022`, `031`, `035`, `036`, `038`, and `040`. These do not need the future repository to become correct.
2. **Define the minimum state contracts and repository interface.** `Entity`, `Observation`, `Relation`, `Artifact`, `Fault`, `Gap`, `Coverage`, `Remainder`, `PolicyDecision`, `CommandResult`, `RunState`, and `WorkUnit`; ship JSON Schema and migrations. This precedes fixes whose correctness depends on durable typed state.
3. **Repair state-dependent Priority 1 paths.** Implement verdict, OOB revision, campaign and finalization fixes (`QR39-003`, `009`, `011`, `012`, `016`) on those contracts rather than creating another transitional file format.
4. **Introduce explicit context.** `RunContext` carries workspace/engagement/run, actor, authorization revision, policy, event writer, cancellation domain, approved executables, secret broker, shared rate/spend/resource limiters, clock and repository.
5. **Separate plugin planning from execution.** A narrow `command(ctx) → argv` API is insufficient. Define `SourcePlugin` capabilities and an `ExecutionPlan`; executors own local processes, native HTTP, containers or future remote jobs; `ArtifactStore` owns bytes; streaming parsers emit through `EntitySink`. Declare secrets, RoE class, resources, retry/idempotency, progress, checkpoints and remainder.
6. **Introduce one authoritative transactional repository.** SQLite WAL is a credible single-host implementation: one batched writer, indexed entities/relations, revisions, leases, idempotent work and finalization state. Normalized repository commits are canonical; raw artifacts are immutable content-addressed evidence; JSONL/reports/search indexes are rebuildable projections. Commit protocol: stage+fsync artifact, compute digest, commit the DB reference/state transaction, then reconcile orphan staging objects after crashes.
7. **Migrate one lane at a time, then decompose files.** Only after boundaries exist should `crawl`, `probe`, `params`, and `vertical` split into per-lane modules.
8. **Add bounded DAG scheduling.** Backpressure, fair engagement queues, fenced leases, retries/idempotency, durable checkpoints and optional remote executors. Do not publish a community SDK before the internal contract survives migration.

### Relationships, collaboration and AI

- Model relationships as versioned temporal edges with canonical entity namespace/type, stable subject/object revision or digest, relation type, confidence semantics, observed time, validity interval, provenance, derivation version, alias/merge/split history and tombstones. A relational edge table is sufficient initially; a graph database is not required.
- Put `workspace_id`, `engagement_id`, authorization revision, actor, sensitivity and revision on raw artifacts, canonical rows, indexes, embeddings, caches and exports. Hide SQLite behind the repository boundary so PostgreSQL/RLS and distributed workers do not force a domain rewrite later.
- AI is **initially read-only** over tenant-filtered-before-retrieval, workspace-authorized redacted projections and must cite immutable evidence revisions/digests. A future action path is `proposal → deterministic policy check → explicit human approval or pre-authorized bounded automation policy → typed job broker → audited result`; grants have capability scope, expiry, budgets and idempotency. AI never receives raw shell or direct scanner authority.
- Treat target-fetched content as hostile prompt-injection data. Separate instructions from evidence, enforce schema outputs, reject invented evidence IDs, and record model-provider egress. Search/vector stores are derived, tenant-labeled and rebuildable—not authoritative; retention/deletion propagates to them, caches, exports and provider logs.

---

## Release plan and acceptance gates

### v0.3.10 — evidence truth and host continuity

Primary scope: `QR39-001` through `QR39-018`, plus `QR39-020`, `QR39-021`, `QR39-022`, `QR39-031`, `QR39-035`, `QR39-036`, `QR39-038`, and `QR39-040`.

Required gates:

1. Convert each audit characterization into a remediation-specific regression; do **not** mechanically invert every old assertion.
2. Binary runner fixtures preserve exact bytes, stay within a declared parent/worker RSS budget, and return inside configured deadline plus bounded grace even with escaped pipe holders.
3. Permission fixtures pass under umasks `000/002/022/077`; no sensitive artifact or session is group/other readable.
4. Large/infinite response and tool-output fixtures stop only at documented host/resource policy, retain partial evidence and durable remainder, and preserve the configured free-space reserve.
5. Every injected event, store, ENOSPC, install, launch, report and finalization fault yields the specified JSON verdict/exit and recoverable state.
6. Settlement kill/restart at every transition resumes without false fixed point; exact obligations cannot disappear through silence.
7. One Nuclei run uses one immutable corpus identity across every chunk; selected inventory and policy digest reproduce exactly without reducing the accepted request set.
8. Commit exact small/medium/large fixture manifests, reference VPS/hardware, tool/template identities and versioned numeric thresholds for wall time, request/coverage counts, peak RSS, artifact bytes, disk amplification, deadline grace, reopen/query/export latency and committed-data loss. No scale ticket closes on descriptive benchmarking alone.
9. DNS stuck-worker count returns to baseline; rebind/proxy/redirect fixtures never contact known self/metadata destinations while accepted private-target reach remains intact.
10. OOB mappings survive crashes immediately before and after request dispatch; no request can precede its durable mapping. Unified disable mode emits no Quarry, Nuclei or Dalfox callback.
11. Nuclei interruption/resume and a concurrent template-update attempt still use exactly one recorded corpus digest.
12. Machine-result golden tests cover every exit code and precedence combination without prose on JSON stdout.

### v0.3.11 — operational hardening within the supported envelope

Primary scope: `QR39-019`, `QR39-025`, `QR39-027`, `QR39-030`, and `QR39-034`. Until the shared limiter (`QR39-029`) lands, the supported envelope must state that engagement-global rate enforcement is not guaranteed across concurrent native/tool lanes and must constrain such concurrency accordingly.

### v0.4 — indexed single-host high-scale core

Deliver `QR39-023`, `024`, `026`, `028`, `029`, `032`, `033`, `037`, `039`, `041`, `042`, and `043`, plus the schemas, context and repository sequence above. Indexed status/query paths avoid whole-corpus scans where supported; complete exports/rebuilds are necessarily O(N) work but must be single-pass streaming with O(batch-size) memory and no duplicate full-corpus materialization. Old-store/schema migration, interrupted migration and rollback fixtures pass. Two concurrent workers on one workspace cannot cross-route events, violate leases or lose writes. Crash injection covers staged artifact write/fsync/digest, DB reference commit and orphan reconciliation.

### v0.5+ — distributed execution, collaboration and bounded AI

Before any shared/remote worker, add worker identity/authentication, scoped workspace/job capabilities, artifact authorization and audit. Single-tenant remote execution may precede full collaboration, but never those minimum controls. Then add partitioned workers with fenced leases and content-addressed artifacts, broader tenancy/authz/retention, read-only evidence-citing AI, and later policy-mediated typed actions. Publish the external plugin SDK after the internal conformance suite and compatibility policy are stable.

---

## Lossless provenance map

| Original finding | Canonical disposition |
|---|---|
| Q-C01 | ADR-039-01 + QR39-014; Critical withdrawn, residual Medium contract/reproducibility gap |
| Q-H01 | ADR-039-02; accepted default reach, with QR39-019 residual enforcement work |
| Q-H02 | QR39-019 |
| Q-H03 | QR39-004 |
| Q-H04 | QR39-006 |
| Q-H05 | QR39-002 |
| Q-H06 | QR39-009 |
| Q-H07 | QR39-003 |
| Q-H08/Q-H09 | QR39-001 |
| Q-H10 | QR39-010 |
| Q-H11 | QR39-010 selector subset + QR39-011 exit/result contract |
| Q-H12 | QR39-012 |
| Q-H13 | QR39-007 |
| Q-H14 | QR39-008 |
| Q-H15 | QR39-017 |
| Q-H16 | QR39-018 |
| Q-H17 | QR39-023 |
| Q-M01 | QR39-021 |
| Q-M02 | QR39-015 |
| Q-M03/Q-M04 | QR39-027 behavioral data + QR39-042 dependency/build closure |
| Q-M05 | QR39-028 |
| Q-M06 | QR39-035 |
| Q-M07 | QR39-031 |
| Q-M08 | QR39-026 |
| Q-M09 | QR39-024 |
| Q-M10 | QR39-005 v0.3.x capacity truth + QR39-041 core store remediation + QR39-039 remaining amplifiers |
| Q-M11 | QR39-029 |
| Q-M12 | QR39-037 |
| Q-M13 | QR39-025 |
| Q-M14 | QR39-032 |
| Q-M15 | ADR-039-03 plus QR39-040 explicit opt-out and QR39-006/017/020/021 guardrails |
| Q-M16 | QR39-016 |
| Q-M17 | QR39-043 + architecture sequence, especially steps 2–8 |
| Q-L01 | QR39-034 |
| Q-L02 | QR39-036 |
| Q-L03 | QR39-038 |
| Independent SEC-1/FUNC-1 | QR39-013 |
| Independent SEC-2 | QR39-019 |
| Independent SEC-3 | QR39-033 |
| Independent PERF-1 | QR39-005 + QR39-041 |
| Independent PERF-2 | QR39-020 |
| Independent PERF-3 | ADR-039-04 + QR39-030 |
| Independent ARCH-1/2/3 | QR39-043 + QR39-026 + architecture sequence |
| Independent FUNC-2 | QR39-022 |

## Net disposition

The accepted aggressive capabilities remain intact and configurable. No Critical finding remains. Quarry still has multiple High release-readiness defects in evidence transport, verdict truth, storage scale, installer integrity, campaign recovery and finalization. Correcting those before breadth—and establishing schemas/context/repository contracts before decomposition—is the shortest path to a market-leading framework without a second architectural rewrite.
