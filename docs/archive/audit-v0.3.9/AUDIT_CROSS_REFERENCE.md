# Quarry v0.3.9 — independent-audit cross-reference and revised disposition

**Date:** 2026-08-10  
**Documents compared:** [Codex audit](AUDIT_REPORT.md) and [independent audit](quarry-audit-claude.md)  
**Product context added by the owner:** Quarry is intentionally a high-scale, active bug-bounty framework. Broad evidence acquisition is a primary requirement; conservative defaults that materially suppress findings are not acceptable.

## Revised conclusion

The additional product context changes several **dispositions**, but it does not change the reproduced behavior.

Most importantly, I withdraw the Codex report's recommendation to stop or narrow the current main Nuclei execution and withdraw its designation as a release blocker. If Quarry is deliberately meant to run the current severity-scoped template set, that execution is an accepted product policy—not a code vulnerability. The appropriate action is to describe it accurately, record exactly what ran, and let engagement-specific policy refine it without slowing the default high-scale workflow.

The independent audit contributes one material finding absent from the original report and sharpens two scale findings that were previously grouped too broadly:

1. configured-secret redaction is an exact substring replacement, so it can corrupt benign recorded text and miss transformed credentials; and
2. OOB token issuance persists the complete growing session on every `(URL, parameter)` candidate, producing quadratic write amplification; while
3. the existing whole-store folding finding deserves **High** priority under Quarry's explicit high-scale contract, rather than the original Medium classification.

Conversely, the independent audit's “no high-severity defects” verdict is not supported by the complete snapshot. It explicitly sampled the largest phase modules and missed multiple deterministic core failures reproduced by the Codex harness: campaign directories breaking latest-run lookup, finalized OOB/manifest divergence, event loss yielding `complete`, unknown phases yielding empty successful runs, runner binary decoding/OOM/non-deadline behavior, installer false success and shared-temp races, campaign convergence/resume defects, and ledger lost updates. Those remain valid independently of risk appetite.

The balanced position is therefore:

- retain Quarry's aggressive evidence methodology;
- reclassify intentional reach/active behavior as policy choices rather than defects;
- fix correctness, resource, confidentiality, durability, and recovery bugs that cause evidence loss or false conclusions;
- make risk visible and machine-readable without adding blocking prompts to unattended runs.

## Nuclei: keep the execution, correct the contract

### What is factually true

Quarry currently runs:

```text
-etags intrusive,fuzz,dos,brute-force -s critical,high,medium
```

The installed v10.4.6 template corpus yielded 6,896 selected templates in list-only mode. Among them were:

- `springboot-h2-db-rce`, whose request changes `/actuator/env` and includes an H2 alias executing `whoami`;
- `thinkphp6-arbitrary-write`, whose request uses a path-like session identifier intended to create a PHP file; and
- `yonyou-u9-patchfile-upload`, which uploads and invokes an `.ashx` payload.

They do not carry any of Quarry's excluded tags. ProjectDiscovery's own review-bot guidance says templates modifying configuration/files should carry `intrusive`, so this is upstream metadata inconsistency, not proof that Quarry intentionally included declared-intrusive templates. The relevant official guidance is in ProjectDiscovery's [template review policy](https://github.com/projectdiscovery/nuclei-templates/blob/main/.review-bot); Nuclei officially supports tag/ID/template selection and a default ignore list ([running documentation](https://docs.projectdiscovery.io/opensource/nuclei/running)).

### Revised disposition

| Original disposition | Revised product-context disposition |
|---|---|
| Critical release blocker; stop broad scan and use an allowlist | **Accepted active policy**, with a **Medium documentation/control-plane gap** |
| “Non-intrusive” execution | **Broad active vulnerability verification; may issue state-changing requests, file writes, or command payloads on matching vulnerable targets** |
| Pin a permanently reviewed allowlist | Keep fast-moving official templates, but record the exact corpus version/digest and selected IDs so a run is reproducible |
| Require interactive arming | Do not block unattended high-scale operation; expose optional engagement policy and non-blocking warnings |

### Recommended change with no coverage reduction

Keep the command and current default behavior. Change the contract around it:

1. Rename user-facing descriptions in `params.py`, `tools.yaml`, `docs/tools.md`, and `docs/example.md` to an operationally exact label: **“Broad active vulnerability verification (medium–critical templates; excludes intrusive, fuzz, DoS, and brute-force tags). Matching vulnerable targets may experience state changes, file writes, or command execution. Authorized targets only.”** Do not use `medium` as a synonym for aggressiveness; in Nuclei it is a finding-severity filter.
2. Give this unchanged policy a machine-readable version such as `broad-active-v1`, and record `consent_basis: active-profile`. A second prompt or arming switch is not required if Quarry's documented `ACTIVE` profile is the engagement consent boundary.
3. Update templates once during preflight, atomically snapshot the chosen corpus, and list the exact selection with the same filters and `-duc`. Run every chunk against that snapshot with `-duc`, preventing Nuclei from changing the corpus after the run fingerprint is calculated. This does not change a single target request.
4. Emit a compact `nuclei-policy.json` containing the exact policy flags, engine version and executable digest, config/ignore digests, template release and snapshot digest, selected IDs/paths/file digests/signature state, selected count, concurrency/rate settings, OOB backend (never its token), consent basis, and timestamps. Bind its digest into resume/work-unit identity.
5. Add a non-blocking semantic inventory that labels templates `potentially_state_changing` when requests or metadata indicate configuration writes, upload/write/delete actions, command payloads, OAST, bodies, or unusual methods. Report counts and IDs in `quarry plan` and the manifest; do not filter them in the default profile.
6. Permit engagement-level refinements—additional excluded IDs/tags or stricter presets—without changing Quarry's high-coverage default. Make full per-request tracing opt-in because it can be enormous and sensitive; the compact selected-template inventory should be the default audit artifact.
7. Verify official signatures and record custom-template signer/trust state. `-dut` is appropriate only if the product contract excludes unsigned custom templates; signature verifies authorship/integrity, not harmlessness.

### The remaining Nuclei defect is reproducibility, not scan breadth

`_nuclei_templates_fp()` (`src/quarry_recon/phases/params.py:569-585`) hashes only three configuration metadata strings. It does not identify selected template files or contents, referenced payload helpers, Nuclei configuration/ignore state, signatures, or the engine executable. The fingerprint is calculated before chunk execution, while Nuclei may update public templates at execution time unless `-duc` is used. Consequently, chunks in one logical run can theoretically observe a different corpus from the one fingerprinted, and Quarry cannot later prove the exact execution set.

Nuclei's official [running documentation](https://docs.projectdiscovery.io/opensource/nuclei/running) documents `-tl`, update controls, `-duc`, template/error logging, resume, and request tracing. Freezing one preflight snapshot for the duration of a run preserves fast updates **and** high-scale reproducibility; it is not a permanent allowlist or a coverage reduction.

This preserves the data/evidence objective while preventing the label from promising a property that tag metadata does not enforce.

## Finding-by-finding cross-reference

### Findings added or sharpened by the independent audit

| Independent ID | Verification | Relationship to Codex audit | Disposition |
|---|---|---|---|
| SEC-1 / FUNC-1 | **Confirmed mechanism; independent impact overstated** | New. `secrets.redact()` performs ordered literal replacement for every configured value of at least six characters | Medium assurance/integrity. It alters telemetry/manifests/digests—not canonical normalized observations or flat exports—and misses transformed/overlapping values. Fix with structured secret transport and typed redacted views, not regex heuristics over evidence |
| SEC-2 | **Confirmed** | Same root as Q-H02 | Revised from High to Medium for a single-user authorized scanner; still close resolve→connect rebinding without narrowing coverage |
| SEC-3 | **Confirmed latent condition** | Complements Q-H13/Q-H14 | Low as command injection today because manifest strings are package-controlled; the concrete shared-temp/TOCTOU installer paths remain High |
| PERF-1 | **Confirmed** | Sharpens Q-M10 | **High under the declared high-scale requirement.** Routine live/reopen/export paths materialize the whole corpus and amplify memory roughly an order of magnitude in the characterization; use a disk-backed indexed repository and streaming projections |
| PERF-2 | **Confirmed and important at scale** | New | Medium. Preserve the current crash invariant—mapping durable before egress—with SQLite WAL or an append-only `0600` journal; group-commit a token batch before issuing that batch, then checkpoint/compact |
| PERF-3 | **Behavior confirmed; recommendation adjusted** | New nuance around time budgets; distinct from Q-H09's unbounded post-kill drain | No fixed low ceiling. Use progress/liveness detection, resumable chunks, and an operator emergency ceiling so a stalled tool is distinguishable from slow legitimate work |
| ARCH-1 | **Confirmed** | Same as Q-M17/hotspot metrics | Medium maintainability; split by lane behind a thin driver |
| ARCH-2 | **Confirmed** | Same as Q-M08 and target plugin architecture | High-leverage v0.4 investment |
| ARCH-3 | **Confirmed** | Same as the Codex target schema/relationship model | Prerequisite for query, AI, and collaboration |
| FUNC-2 | **Confirmed, plus a more material IDNA inconsistency** | New | Medium for complete active-lane loss on IDN programs. One strict URL-authority canonicalizer must apply the same IDNA policy as profile apexes; preserve rejected raw URLs and aggregate typed omission reasons/samples |

### Dynamic cross-reference results

The added characterization harness is [audit_tests/test_cross_reference_findings.py](audit_tests/test_cross_reference_findings.py). All six checks pass, meaning they reproduce current behavior:

```text
literal over-redaction:  "secretly secret" → "***ly ***"
transformed under-redaction: "abc%2Fdef" remains when the configured value is "abc/def"
1,000 OOB tokens: 1,000 complete indented snapshots, 82,895,990 serialized bytes
final OOB snapshot: 165,803 bytes (approximately 500× cumulative amplification)
100,000-target scaled Nuclei timeout: 24,000,000 seconds (approximately 278 days)
percent-encoded host: host_of_url("http://a%2ecom/") → "a%2ecom"
IDN mismatch: profile apex "faß.de" → "xn--fa-hia.de", but URL host remains "faß.de" and fails scope matching
```

The OOB measurement uses an in-memory replacement for `save_session` and matches its `indent=2` serialization; it measures serialization volume without writing those bytes to disk. The 100,000-target timeout is a direct function characterization, not a claim that every call passes 100,000 targets—main parameter Nuclei already chunks, while other large lanes such as WAF and takeover remain unchunked. The timeout is finite unless the operator sets zero; the defect is the absence of a meaningful overall/progress deadline and resumable remainder on every large lane, not that legitimate day-scale work must be forcibly shortened.

For store scaling, a 100,000-row, 9.70 MiB URL JSONL characterization required roughly 93 MiB of traced Python allocation during folding. A clean child-process repeat completed in 2.39 seconds with 115.81 MiB maximum RSS including interpreter/import baseline. Those numbers establish full materialization and substantial memory amplification on this fixture; they are not a universal throughput benchmark. A derived index alone is insufficient if `Run.add()` continues retaining every merged entity and routine exports continue rebuilding whole sets in memory.

The redaction finding also needs tighter impact language than the independent report used. `Run.add()` preserves canonical normalized observations, and flat exports consume them unchanged. Literal redaction affects audit events, records, manifests/policy notes, digest/report queue values, notifications, and some OSINT outcomes. A transformed-secret confidentiality leak is a plausible limitation, but this audit did not demonstrate a live provider echo carrying such a representation into a persisted sink. The concrete fix is typed sensitive values, minimal per-tool environments, non-argv transport, and a schema-enforced redacted share/AI projection; exact longest-first replacement can remain defense in depth, never the confidentiality guarantee.

### Important defects the independent audit did not cover

These findings remain because they were reproduced, not because of a conservative policy preference:

| Codex ID/theme | Evidence | Why product risk appetite does not remove it |
|---|---|---|
| Q-H05 latest-run/campaign collision | `Run.latest()` raises after `recon/campaigns/` exists; delta repeats enumeration | breaks ordinary commands and loses operator access to evidence |
| Q-H06 finalized OOB drift | manifest count remains zero after a late OOB observation | two authoritative views disagree |
| Q-H07 false `complete` | event-write loss and checkpoint/missing-dependency warnings can still finalize complete | aggressive scanning needs more truthful gaps, not fewer |
| Q-H08/H09 runner | non-UTF-8 crash, whole-stream memory amplification, escaped-child timeout delay | causes evidence loss, OOM, and hung high-scale runs |
| Q-H10 selectors | `--phases typo` creates an empty `complete` run | pure correctness failure |
| Q-H11 machine status | degraded/not-ready paths often exit zero | blocks dependable automation; a compatibility `--strict` mode is sufficient initially |
| Q-H12 campaign | final fixed point mislabeled, silence under-specified, interruption cannot resume | undermines Quarry's convergence moat |
| Q-H13/H14 installer | checksum/use race, false-success aggregation, no rollback | can compromise or break the scanner host |
| Q-H04 private evidence modes | run/secret artifacts inherit `0755`/`0644` under umask 022 | unnecessary local disclosure; `0700`/`0600` loses no recon coverage |
| Q-H15 runtime identity/env | PATH shadow executes and receives global PDCP secret | unnecessary supply-chain/credential exposure |
| Q-H16 config shapes | raw type errors and loose coercions | high-scale automation needs predictable validation |
| Q-H17 globals/ledger | process globals cross runs; two ledgers lose one writer | foundational blocker for service/collaboration |

## Where the independent audit is too categorical

The second report is useful but several conclusions should not be adopted verbatim:

1. **“Single choke point” is aspirational, not as-built.** A static count found 34 direct `exec_tool()` calls and 15 `run_contract()` calls, plus native/OOB exceptions. The registry and runner are strong, but runtime enforcement is not one uniform source adapter yet.
2. **Campaign persistence has strong ideas, not full transaction semantics.** Atomic-looking ledger/union publication and fail-closed re-read are strengths. However, writes lack durability fsync, generic ledger updates can be lost, campaign interruption is explicitly non-resumable, and silence/fixed-point ordering has reproduced logic defects.
3. **“No critical/high defects” reflects audit scope and severity philosophy.** The independent report sampled the three largest phase files and did not exercise the failure paths above. Its disclosure makes this understandable, but it cannot negate direct reproductions.
4. **Simple smell counts do not justify “near-zero smell.”** Zero bare `except` and zero mutable defaults are positive; 36 functions at least 100 lines, 14 at least 200, 73 high-branch-proxy functions, partial typing, process globals, and duplicated execution boundaries are material maintainability evidence.
5. **The competitive table overstates several positions.** Current reconFTW has `modules/`, `lib/`, `tests/`, architecture documentation, checkpoints/resume, asset JSONL, diff/report/logging, and published Bats unit/integration/security plus ShellCheck/shfmt targets. Its `tools.lock` is partial—11 explicit entries in the reviewed current file, with unlisted tools allowed to fall through to `@latest`—rather than simply “unpinned.” ProjectDiscovery tools may be efficient Go implementations, but “fastest” needs an apples-to-apples benchmark. Nuclei has a substantial template DSL and SDK surfaces, and Subfinder has provider/source extension points; their extensibility is not “N/A.” Public test/fuzz workflows show engineering controls, not exhaustive coverage. Competitors have stats, resume, scope/event graphs, and output telemetry, so Quarry's coverage model is unusually explicit—not literally the only accounting in the market. Quarry's direct pins are strong, but mutable data, transitive dependencies, wrapper payloads, runtime PATH drift, and installer races prevent a blanket “best supply-chain hygiene” claim.
6. **Several snapshot inferences are invalid.** The supplied copy deliberately omits the upstream suite and may omit repository/release metadata. It supports neither “single author/no releases” nor “unpublished tests.” Requirements should be phrased as a reproducible release/test contract, without claiming absent upstream activity.
7. **BBOT facts need current wording.** Its first-party documentation now says **100+ modules**, not 80+. A committed `uv.lock` improves repository/developer reproducibility, while published runtime dependencies are mostly constrained ranges; this is not universal transitive pinning for every PyPI/pipx install.
8. **“Collaboration is the campaign union generalized” is only partly true.** Reuse monotonic merge/provenance ideas, but multi-user collaboration also needs identity, object authorization, tenancy, conflict control, audit, retention/deletion, and encrypted secret boundaries. Campaign files are not a collaboration security model, and BBOT already represents parent/discovery relationships and graph/database outputs.

## Product-context severity recalibration

| Original finding | Revised disposition | Keep/change behavior? |
|---|---|---|
| Nuclei broad main scan | Accepted product capability + Medium labeling/reproducibility gap | **Keep execution**; accurately label, freeze per-run corpus, fingerprint/classify |
| Private/RFC1918 reach | Accepted offensive capability + Medium visibility/authorization risk | Keep configurable default if desired; record reach and provide engagement overrides |
| DNS rebinding | Medium hardening | Pin the checked destination/peer or enforce egress; no coverage reduction |
| Public Interactsh default | Accepted provider/privacy choice | Keep; surface provider/retention and protect local state |
| Tool time budgets with no maximum | Intentional coverage policy | Keep generous scaling; add stalled-progress detection and resumability |
| Unbounded hostile response bytes | High availability/evidence-continuity defect | Replace with adaptive disk governor/reserve and spill/partial evidence—not a small universal cap |
| CLI zero on gaps | Compatibility/automation design choice | Keep human default if desired; add stable JSON result and `--strict` exit contract |
| All deterministic data-integrity, runner, installer, permission, selector, and concurrency bugs | Unchanged | Fix before feature expansion |

## Revised roadmap for high-scale hunting

### v0.3.x — preserve coverage, stop losing or misrepresenting evidence

1. Fix latest-run/delta selection and finalized OOB revision consistency.
2. Make event/checkpoint/dependency gaps verdict inputs; add machine-readable results and optional strict exits.
3. Stream binary subprocess output directly to evidence files; bound only memory/tails, fix the post-kill deadline, and preserve partial bytes.
4. Add an adaptive disk governor: retain a configured free-space reserve, spill streams to disk, stop only when the run/project budget would endanger the host, and record exact truncation. Avoid a conservative small per-body default.
5. Make project/evidence/OOB files private without redacting discovered evidence.
6. Replace shared-temp installer paths, aggregate required failures, and retain last-good installs/data.
7. Replace OOB full-snapshot-per-token writes with WAL/journal group commits that make each mapping batch durable before its request batch; increase token entropy at the same time.
8. Replace substring redaction as the security guarantee: isolate per-tool secrets, use structured sensitive fields, and produce a typed redacted export/AI view. Never rewrite canonical raw evidence.
9. Keep Nuclei execution; version and reword the policy, atomically freeze one current template snapshot per run with `-duc`, record its full execution identity, and add non-blocking semantic risk telemetry.
10. Close native DNS rebinding by binding the validation to the connection or an egress policy while retaining authorized private-target support.
11. Publish honest corpus/RSS limits and fixed-fixture memory/disk benchmarks in v0.3.x; whole-corpus materialization is a High scale blocker even when correctness is otherwise intact.

### v0.4 — one explicit context and indexed evidence contract

1. Introduce `RunContext`, one source/execution adapter, strict configuration/entity/event/edge schemas, and per-tool secret environments.
2. Use SQLite for transactional control-plane state, leases, revisions, and indexes. Preserve immutable raw artifacts and append-only observations; keep JSONL as a portable export. For larger analytical projections, partitioned Parquet/DuckDB can complement—not replace—the transactional catalog.
3. Decompose large phases into lane modules implementing the source protocol.
4. Make campaign obligations explicit and resume every transition idempotently.
5. Benchmark on small/medium/large fixed corpora before changing concurrency or claiming relative speed.
6. Add an SBOM, release provenance, locked developer environment, and migration policy here—not only when Quarry becomes a service.

### v0.5+ — relationships, collaboration, and AI

Both reports agree on the central ordering: versioned schemas and an indexed query boundary must precede AI. Promote asset relations to temporal typed edges with provenance. AI receives a workspace-authorized, purpose-limited, redacted projection and returns evidence-citing suggestions; it does not get raw shell or unrestricted scanner capability. Collaboration may reuse campaign merge concepts, but it needs a separate tenant/identity/authorization and audit layer.

## First-party competitive source corrections

The market comparison was rechecked on 2026-08-10 against first-party material. The controlling source set is:

- reconFTW: [official repository](https://github.com/six2dez/reconftw), [v4.1 release](https://github.com/six2dez/reconftw/releases/tag/v4.1), [architecture](https://github.com/six2dez/reconftw/blob/main/docs/ARCHITECTURE.md), [test/lint targets](https://github.com/six2dez/reconftw/blob/main/Makefile), and [partial tools lock](https://github.com/six2dez/reconftw/blob/main/tools.lock);
- BBOT: [official repository](https://github.com/blacklanternsecurity/bbot), [current release](https://pypi.org/project/bbot/), [100+ module/event model](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/), [queue architecture](https://www.blacklanternsecurity.com/bbot/Stable/dev/architecture/), [tests](https://www.blacklanternsecurity.com/bbot/Stable/dev/tests/), [events](https://www.blacklanternsecurity.com/bbot/Stable/scanning/events/), and [outputs](https://www.blacklanternsecurity.com/bbot/Stable/scanning/output/);
- ProjectDiscovery: [Subfinder releases](https://github.com/projectdiscovery/subfinder/releases/latest), [httpx resource/output controls](https://docs.projectdiscovery.io/opensource/httpx/usage), [Nuclei runtime/resume/update controls](https://docs.projectdiscovery.io/opensource/nuclei/running), [Nuclei public workflows](https://github.com/projectdiscovery/nuclei/actions), [official template signing](https://docs.projectdiscovery.io/templates/reference/template-signing), and [Nuclei releases](https://github.com/projectdiscovery/nuclei/releases/latest).

These sources support maturity/control comparisons, not a universal speed ranking or test-coverage percentage. Third-party mirrors cited by the independent report are not used for authoritative competitive claims.

## Net assessment

With the owner's product requirement applied, the original audit was too conservative on Nuclei, private reach, and hard resource ceilings. The independent audit was too optimistic about correctness, transactionality, and competitor maturity. Their strongest shared conclusion is still the right one: Quarry's moat is evidence plus coverage truth, and v0.3.x should strengthen that moat rather than add breadth.

The practical standard is not “make Quarry safe by doing less.” It is:

> **Run broadly, preserve aggressively, fail transparently, and make every action and omission reproducible.**
