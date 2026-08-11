# Quarry — Code & Architecture Audit

**Subject:** `quarry-recon v0.3.9` — methodology-driven reconnaissance automation framework
**Scope:** 49 Python modules, 29,417 LOC (src) + data/docs
**Method:** full read of the control-plane/security core, sampled review of the three large phase modules, empirical harness (package installed in a venv, critical pure functions exercised with adversarial inputs)
**Date:** 2026-08-10
**Overall verdict:** Engineering quality **A−**. No critical or high-severity defects in the audited surface. Gaps are foundational-stability, scaling, and professionalism/distribution — appropriate to the version.

| | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 6 |
| Low / Info | 5 |

---

## 1. Executive summary

Quarry is a methodology-driven recon orchestrator: it drives ~38 external tools and ~66 sources through a single choke point, captures every tool run, classifies its outcome, and normalizes results into an append-only JSONL evidence store with provenance. Its defining idea — and its genuine competitive edge — is **honest coverage accounting**: a lane never reports "nothing found" when the truth is "a key was missing, a WAF blocked us, or a timeout cut us short." No mainstream competitor does this rigorously.

The code is **far above the norm for a v0.3 bug-bounty project**. Across the core I read, defensive engineering is consistent and deliberate: fail-closed scope and self-attack guards, strict input validation, a transactional campaign/union ledger, atomic writes with receipts, and near-zero code smell (0 bare `except:`, 0 mutable default args, ~784 docstrings). I found **no critical or high-severity defects** in the audited surface — no injection, no unsafe deserialization, no obvious scope-bypass.

The gaps that matter are **foundational-stability and scaling** issues appropriate to the version, plus **professionalism/distribution** gaps against org-backed competitors. The single most important structural risk is concentration: three phase files (`crawl`, `probe`, `params`) hold ~26% of the codebase and are hard to test in isolation. The store's in-memory fold is the scaling ceiling the roadmap already names.

**Bottom line:** correctness and security are already strong. Spend v0.3.x on decomposition, a query/schema layer, and packaging — not on new features. The moat is the evidence model; protect and expose it.

---

## 2. Scope & method

- **Read in full:** the control plane and security-critical core — `runner`, `contract`, `netguard`, `fetch`, `config`, `store`, `normalize`, `secrets`, `events`, `campaign`, `exports`, `oob`, plus the registry and data files.
- **Sampled, not line-audited:** the three large phase modules (`crawl` 2,718, `probe` 2,511, `params` 2,503 lines) — command construction and tool-input paths traced, but not every branch verified. Findings there are lower-confidence by disclosure.
- **Empirical harness:** installed the package in a venv and exercised the pure/critical functions (netguard IP classification, `host_of_url`, `canon_host_strict`, the scope matcher, Whoxy validators, store merge/fingerprint, secret redaction) with adversarial inputs to confirm behavior rather than infer it.
- **Not covered:** the project's own test suite was excluded from the snapshot; no statement is made about its real coverage. Live/integration behavior against real targets was not run.

---

## 3. Findings

Ordered by severity within type. IDs are stable references for tracking.

### Security

#### SEC-1 — Secret redaction is exact-substring only; the "keys never appear in logs" guarantee is best-effort — **Medium**

**Location:** `secrets.py:165` `redact()` · `secrets.py:142` `values()` (`len >= 6` filter)

`redact()` does a literal `str.replace(value, "***")` for each configured secret. This fails in two directions.

- **Under-redaction:** if a key ever appears in a transformed form (URL/percent-encoded, JSON-escaped, base64, or split across a wrapped line), the literal match misses it — yet the README promises "your keys never appear in run manifests, logs or recorded commands." That is a guarantee the mechanism cannot actually keep.
- **Over-redaction:** a short configured secret corrupts unrelated evidence.

**Verified** — with a 6-char configured secret `"secret"`:

```
redact("this is a secretly secret thing")  ->  "this is a ***ly *** thing"
```

The store, exports and notifications are the product. Silently rewriting a subdomain/URL because it contains a secret substring is a data-integrity defect in the very artifact Quarry sells.

**Fix:** treat redaction as a boundary, not a filter. (a) Never pass secrets on argv/stdout paths in the first place (already largely true) so redaction is defense-in-depth, not the guarantee; (b) redact on token boundaries and raise the length floor well above 6; (c) reframe the README claim as "configured credentials are stripped best-effort from recorded text" and state the limit. For the AI path, build an explicit AI-safe view type that can only be constructed from already-redacted material (see §6).

#### SEC-2 — DNS resolve→connect TOCTOU applies to Quarry's own native fetch path, not only the external tools — **Medium**

**Location:** `fetch.py:80,116,550` (`contact_state` → `urllib.request` open) · `netguard.py` module docstring

`fetch.py` guards a host with `netguard.contact_state()` (a live resolve + classification), then hands the *hostname* to `urllib.request`, which resolves **again** at connect time. A malicious in-scope host the attacker controls DNS for can answer with a public IP during the guard and a metadata/self IP at connect — the classic rebinding window. netguard's docstring explicitly accepts this residual for `nuclei/dalfox/arjun`, but does **not** mention that Quarry's own redirect/SSRF/CSP probes carry the same window. On a cloud VPS the payoff is the instance metadata endpoint.

**Mitigating:** likelihood is low (requires attacker-controlled fast-flux DNS on an in-scope name), and the guard already fails closed on unparseable/self answers. Confirmed: `is_self_attack_ip` returns `True` (withhold) for decimal/octal/IPv4-mapped forms.

**Fix:** resolve once inside the guard, pin the chosen IP, and connect to that IP with an explicit `Host:` header (a small custom opener), closing the window Quarry actually owns. At minimum, document `fetch.py` in the netguard residual-risk note so the claim matches the code.

#### SEC-3 — `shell=True` in the install/registry path — **Low**

**Location:** `registry.py:152`, `registry.py:570` · `bootstrap.py:47`

Version probes and install/update commands run via `subprocess.run(cmd, shell=True)`. Inputs come from the bundled, developer-controlled `data/tools.yaml`, so there is **no external-injection path today**. But it is a latent footgun: the day a tool entry interpolates a version, ref, or mirror URL fetched from anywhere dynamic, this becomes command injection during `quarry install` (a sudo-adjacent context).

**Fix:** move to list-form `subprocess.run([...])` with an explicit arg vector, or if a shell is genuinely required, keep a hard invariant + test that `tools.yaml` values are static and shell-metacharacter-free.

### Performance & scalability

#### PERF-1 — Store fold is whole-file, in-memory, per entity — the roadmap's own scaling ceiling — **Medium**

**Location:** `store.py:562` `_records_for` / `fold_observations` · `Run` keeps `{key: record}` dicts in RAM

Every entity's merged view is built by folding its entire append-only JSONL into a Python dict held for the run's lifetime, and re-folded on each open. For the target sizes Quarry advertises (README cites 80 GB+ runs, 100k+ hosts, millions of URLs), the single-process in-RAM merged dict plus full re-fold becomes the memory and time bound. This is exactly the "query layer over the store" the README names as the next milestone — correctly.

**Fix:** introduce an indexed backend (SQLite/DuckDB over the JSONL, or an on-disk key→offset index) so reads are bounded and the merged view is queried, not materialized. Keep JSONL as the source of truth; add the index as a derived cache. This also unblocks the query CLI and the AI read-API in one move.

#### PERF-2 — OOB token issuance rewrites the whole session file per token, in a loop → O(n²) disk I/O — **Medium**

**Location:** `oob.py:316` `issue_token(run=…)` → `save_session()` · called per `(url,param)` at `params.py:2266`

`issue_token(..., run=ctx.run)` calls `save_session()`, which serializes and atomically rewrites the entire `session.json` (including the whole growing `token_map`) on **every** token. Issued once per SSRF (url, param) candidate in a loop, this is O(n²) bytes written for n candidates — slow and disk-thrashing on a large parameter corpus, for a crash-safety benefit that a periodic flush would also provide.

**Fix:** persist the map append-only (one line per token) or debounce/batch the full write (every k tokens or every t seconds), keeping the crash-recovery property without the quadratic cost.

#### PERF-3 — Workload-scaled timeouts have no absolute ceiling — a hung tool on a huge scope can run unbounded — **Low**

**Location:** `runner.py:263` `scaled_timeout` (no upper cap by design) · `nuclei_timeout`, phases

`scaled_timeout` grows the per-tool deadline linearly with workload and deliberately imposes no upper bound ("scope size must never truncate coverage"). The tradeoff is real, but a genuinely wedged tool (kernel-level hang the tool's own timeout doesn't catch) on a 100k-unit scope receives a deadline of days. On an unattended VPS run that is a silent availability hole; only `Ctrl-C`/`cancel_all` recovers it.

**Fix:** keep the scaling but add an operator-set absolute ceiling (`config.yaml`: `max_tool_wall_seconds`) that caps the computed value, plus a liveness heartbeat (no stdout for N minutes → treat as hung), so coverage stays generous but a stuck process is reaped.

### Architecture & maintainability

#### ARCH-1 — Three phase modules hold ~26% of the codebase and can't be unit-tested in isolation — **Medium**

**Location:** `phases/crawl.py` (2,718) · `phases/probe.py` (2,511) · `phases/params.py` (2,503)

These files interleave tool invocation, output parsing, coverage accounting, scope/guard calls and store writes in long procedural flows. That density is the main obstacle to test coverage and to onboarding a second contributor, and it's where undetected branch-level bugs are most likely to live (this audit sampled rather than exhausted them).

**Fix:** decompose each phase into per-lane units behind a thin phase driver: one small module per source (e.g. `probe/httpx.py`, `probe/vhost.py`, `params/dalfox.py`) that declares its inputs, builds its command, and returns normalized entities + a coverage report. The driver just sequences them. This is a refactor, not a rewrite — the seams already exist at `run_contract` boundaries.

#### ARCH-2 — No formal source/plugin interface — adding a tool touches a large phase file, the registry and the normalizer — **Medium**

**Location:** `sources.yaml` + `registry.py` govern eligibility; behavior lives inline in phases; `normalize.py` per-tool

The registry cleanly governs *whether* a source may run, but *how* it runs is hand-written inside the phase modules, and its parser is a bespoke function in `normalize.py`. There is no single interface a new source implements. Compared with BBOT's module-class model (a new capability is one class with declared inputs/outputs/events), Quarry's extension cost is high — a barrier to community contribution, which is how the incumbents grew.

**Fix:** define a `Source` protocol: `declares(inputs, produces)`, `command(ctx) -> argv`, `parse(raw) -> Iterable[Entity]`, `coverage() -> report`. Register instances instead of editing phases. This pairs naturally with ARCH-1 and is the single highest-leverage move toward "market-leading."

#### ARCH-3 — Entity types lack versioned schemas / a query layer (acknowledged) — **Info**

**Location:** `store.py:36` `ENTITY_KEYS` (23 types, dict only) · README "a query layer … is the next milestone"

The 23 entity types are defined only by a key-field dict; there is no declared schema, field contract, or per-entity `schema_version` (the mechanism already exists for work-units — `events.py:28` — and should be extended to entities). Without it, downstream consumers (exports, digest, and future AI/collaboration readers) bind to an implicit shape.

**Fix:** add typed entity models (dataclass/pydantic) with a version stamp and a generated JSON Schema. Ship it beside `digest.json`. This is a prerequisite for both the query layer and safe AI consumption.

### Correctness (lower severity)

#### FUNC-1 — Redaction over-write can silently alter stored evidence text — **Low**

**Location:** `store.py:493` `record()` → `secrets.redact(cmd/note/stderr)`; same root as SEC-1

The correctness face of SEC-1: because redaction is applied to `cmd`, `note` and `stderr_tail` before they reach the manifest, a configured secret that collides with benign substrings rewrites the audit record itself. Fixing SEC-1 (boundary + length floor + token boundaries) closes this too. Called out separately because its *impact* is integrity of the evidence store, not confidentiality.

#### FUNC-2 — Percent-encoded URL hosts are dropped without a count — **Info**

**Location:** `normalize.py:210` `host_of_url` — no percent-decode; fails closed (good) but silently

Confirmed: `host_of_url("http://a%2ecom/") -> "a%2ecom"`, which no apex matches, so the URL is correctly treated out-of-scope and never contacted. The fail-closed behavior is right; the concern is that such inputs vanish with no omission counter — inconsistent with Quarry's own "count what you drop" principle. Count these as a normalization omission so coverage stays honest.

#### NOTE — What the audit confirmed is genuinely solid — **Strength**

**Location:** netguard, config, contract, campaign, store — verified by read + harness

Recorded so the picture is fair: self-attack classification fails closed on decimal/octal/IPv4-mapped IPs; scope matching resists sibling-domain and case tricks; the Whoxy validators reject every ambiguous envelope shape; store fingerprints are stable under self-merge and `adds_material` is exact; the campaign/union ledger is transactional with fail-closed re-read on any interruption. No injection, no unsafe deserialization (`yaml.safe_load` and JSON only), no shell exposure to recon data.

---

## 4. Competitive positioning

The market splits into two shapes. **reconFTW** is a Bash orchestrator — enormous reach, minimal internal structure, no evidence model. **BBOT** is a Python-asyncio framework with a real module/event-graph architecture, 80+ modules, and an organization (Black Lantern Security) behind it. The **ProjectDiscovery** tools (`subfinder`/`httpx`/`nuclei`) are single-purpose Go binaries — company-backed, exhaustively tested, huge communities. Quarry is closest to BBOT in ambition but distinct in thesis: where BBOT optimizes *recursive discovery*, Quarry optimizes *trustworthy, accounted output*.

| Dimension | Quarry v0.3.9 | reconFTW | BBOT | PD tools |
|---|---|---|---|---|
| **Language / model** | Python · subprocess orchestrator | Bash script | Python · asyncio modules | Go · single-purpose |
| **Code quality** | Excellent — defensive, 0 smell, documented | Low — shell, hard to reason about | Good — structured, tested | High — mature Go, tested |
| **Evidence / provenance** | Best-in-class — append-only + provenance + merge | Flat files | Event graph, good | Per-tool JSON |
| **Coverage honesty** | Unique — eligible/tested/omitted + "unknown" | None | Limited | None |
| **Extensibility** | Weak — no plugin interface (ARCH-2) | Config toggles | Strong — module classes | N/A (composed externally) |
| **Test coverage (observable)** | Rigorous harness config; suite not shipped here | Minimal | Substantial CI suite | Substantial CI suite |
| **Performance ceiling** | In-RAM fold (PERF-1); Python overhead | Bounded by wrapped tools | asyncio throughput | Native Go, fastest |
| **Supply-chain hygiene** | Pinned installs, no @latest | Unpinned tool pulls | Pinned deps | Released binaries |
| **Distribution / community** | Single author, source-only, no releases visible | Popular, community | Org-backed, PyPI | Company, massive |
| **Docs / UX** | Excellent — 18 docs, clear config split | README-level | Full doc site | Full doc sites |

**Where Quarry already leads:** evidence integrity, coverage honesty, supply-chain hygiene, and per-line documentation. **Where it lags:** extensibility, raw throughput, observable test coverage, and distribution/community. None of the lags are quality-of-thought problems — they're stage and resourcing problems, which is the good kind to have.

---

## 5. Phased roadmap

Prioritized for a v0.3.9 project: stabilize and expose the moat before adding surface.

### Phase 1 — Foundational stability & correctness (target: v0.3.x patch line · weeks)

- Fix redaction boundary + length floor, and re-word the README guarantee (SEC-1 / FUNC-1).
- Close or document the `fetch.py` rebinding window (SEC-2); move install shells to list-form (SEC-3).
- De-quadratic the OOB session persistence (PERF-2); add the absolute tool-timeout ceiling (PERF-3).
- Publish the test suite + a CI badge; commit to a coverage floor. This is the cheapest credibility win.

### Phase 2 — Decompose & formalize the boundaries (target: v0.4 · the structural investment)

- Split the three large phases into per-lane modules behind thin drivers (ARCH-1).
- Define and adopt the `Source` protocol; migrate existing lanes onto it (ARCH-2).
- Add versioned entity schemas + generated JSON Schema shipped beside `digest.json` (ARCH-3).

### Phase 3 — Query layer & scale (target: v0.4 → v0.5)

- Index the store (SQLite/DuckDB over JSONL) so reads are bounded, not materialized (PERF-1).
- Ship `quarry query` over that index — the README's named milestone.
- Validate on a deliberately large target to establish real memory/throughput envelopes.

### Phase 4 — AI & collaboration surface (target: v0.5+ · only after Phases 2–3)

- Expose the indexed store as a read-only API/MCP the LLM consumes — no shell, no raw store access.
- Enforce redaction by construction with an AI-safe view type; add PII tagging on OSINT entities.
- Extend the campaign union into a multi-operator merge with signed per-source provenance.

---

## 6. AI & "relationships": architecture guidance

The good news: Quarry's structured, provenance-carrying store is already an **ideal AI substrate** — better than anything the competitors expose. The work is to make consumption *safe and typed*, not to build a new data model. Four principles keep the future cheap:

- **The schema is the contract (ARCH-3 first).** An LLM agent should read versioned entities and a JSON Schema, never scrape reports. Do the schema layer before any AI feature; it's the interface.
- **Redaction as a type, not a hope (SEC-1).** The claim "secrets are never in AI prompts" must be enforced by construction: an `AISafeView` that can only be built from already-redacted material, so it's impossible to hand raw evidence to a prompt. Add PII tagging on OSINT/investigation entities — that surface handles person data, and any share/AI path must respect it.
- **"Relationships" = a typed graph you already half-have.** Entities already carry host→ip→url→port edges. Promote these to explicit typed edges with an identity/ownership layer, and the same structure serves graph queries, AI reasoning, and correlation. Don't bolt on a separate relationship store.
- **Collaboration = the campaign union, generalized.** The union is already a monotonic, provenance-preserving multi-run merge with a transactional ledger. Multi-operator collaboration is the same operation across operators — add per-source attribution and signed provenance rather than a new sync system. Privacy follows the schema + redaction boundaries above.

**The one-line strategy:** every AI/collaboration capability you want is a *consumer* of a typed, indexed, redaction-safe store. Build that store interface (Phases 2–3) and the AI work in Phase 4 is additive — no refactor, no privacy retrofit.

---

## Disclosures

Independent audit of a disposable snapshot. No critical/high defects were found in the audited surface; the three large phase modules were sampled, not exhaustively verified, and the project's own test suite was outside the snapshot — no claim is made about its coverage. Severities reflect impact on an authorized-testing tool run by its operator.

**Competitive sources.**
- BBOT — Black Lantern Security: https://github.com/blacklanternsecurity/bbot
- BBOT docs: https://www.blacklanternsecurity.com/bbot/Dev/scanning/advanced/
- reconFTW: https://sourceforge.net/projects/reconftw.mirror/
- Recon frameworks reference: https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/red-offensive/scanning-active-recon/recon-frameworks
