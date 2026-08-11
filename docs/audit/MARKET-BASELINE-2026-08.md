# Quarry market baseline — 2026-08

**Benchmark date:** 2026-08-11

**Quarry baseline:** `4e4825c6f2a6f2bd81d81da0f231f56845ffd6aa` (`0.3.9`)

**Status:** Phase 0 decision input; not a release claim or product ranking

## Executive conclusion

Quarry is not ready for a defensible “market-leading” claim at the audited revision. It already has a
valuable product direction—broad bug-bounty acquisition, explicit coverage and remainder accounting,
raw evidence retention, paid-evidence reuse, and a stricter intended distinction between fact, absence,
fault, and inference. However, the [current-HEAD ledger](CURRENT-HEAD.md) shows that several of those
properties are not yet true across all write, execution, recovery, and report paths.

There is no single upstream project Quarry should copy:

- **BBOT is the closest architectural benchmark** for a typed event/module ecosystem, recursive
  discovery, validated presets, lineage-rich events, and pluggable outputs.
- **reconFTW is the closest workflow benchmark** for broad bug-bounty methodology, operator-controlled
  modes, practical output organization, distributed execution hooks, checkpoints, and approachable
  configuration.
- **ProjectDiscovery's tools are the closest component benchmarks** for focused CLI contracts,
  streaming composition, structured output, explicit concurrency/rate controls, a community template
  ecosystem, and visible release/security engineering.
- **OWASP Amass and the Open Asset Model are the closest data-architecture benchmark** for typed assets,
  directed relationships, confidence/source metadata, a queryable asset database, and a durable engine
  boundary.

The competitive strategy should therefore be **composition with stronger truth guarantees**, not an
attempt to replace every specialist engine. Quarry can become the operator-facing evidence system that
binds exact ProjectDiscovery and other tool executions to immutable observations, occurrence-level raw
proof, typed relationships, truthful coverage, and reproducible reports. It cannot credibly occupy that
position until `v0.3.10` closes execution and repository integrity and `v0.3.11` closes report/provenance
loss.

This conclusion is an architectural inference from the sourced upstream capabilities and the locally
reproduced Quarry findings below. It is **not** a claim that one project discovers more assets, runs
faster, or uses fewer resources than another.

## Method and evidence limits

### What was compared

“Professionalism” is evaluated through observable engineering contracts:

| Dimension | Observable bar |
|---|---|
| Code and maintenance | Readable boundaries; validated configuration; documented architecture; tests plus lint/security/compatibility gates; finite supported environments |
| Extensibility | A contributor can add one capability through a declared interface with typed input/output, dependencies, policy, failure semantics, and conformance tests |
| Evidence and provenance | Stable record identity, source/acquisition lineage, timestamps, raw-proof references, explicit uncertainty, and reproducible derivation |
| Relationships | Typed, directed, temporal, source-attributed edges that do not silently grant scope or overwrite facts |
| Scale and resources | Explicit rates/concurrency, bounded queues and memory, backpressure, cancellation, durable remainder, and a measured support envelope |
| Output and UX | Validated configuration, an explainable execution plan, actionable human output, lossless machine output, safe rendering, and rebuildable projections |
| Release maturity | Versioned releases, tested package/install paths, security and contribution processes, integrity/provenance evidence, and honest compatibility notes |
| AI and collaboration | Task-scoped data views, input/output provenance, least privilege, tenant/project authorization, auditability, and human control over consequential actions |

The release bar is consistent with NIST's SSDF recommendation to provide release-integrity verification
and protect per-release provenance and component records; a written plan is not equivalent to that
evidence. [NIST SP 800-218, PS.2 and PS.3](https://doi.org/10.6028/NIST.SP.800-218)

### Evidence labels

- **Upstream fact** means a capability is stated in the project's current official documentation,
  repository, workflow, or release page. It does not mean this audit independently executed it.
- **Quarry fact** means current source, repository metadata, or a reproduced result recorded in
  [CURRENT-HEAD.md](CURRENT-HEAD.md).
- **Inference** means a Quarry-specific design conclusion drawn from those facts. Inferences are named as
  such and are not attributed to an upstream maintainer.

No upstream scanner was benchmarked against a target in this pass. No finding-yield, false-positive,
throughput, memory, or total-runtime ranking is made. Upstream words such as “fast,” “scalable,” or
“comprehensive” are treated as product descriptions unless backed here by a reproducible common
benchmark. GitHub stars, download counts, and repository age are deliberately excluded from the score.

### Version snapshot

The release pages identified the following latest releases at the benchmark date. A version is useful
for source selection; it is not proof of correctness or superiority.

| Project | Snapshot used | Official release source |
|---|---:|---|
| Quarry | `0.3.9` at `4e4825c` | local audited revision; no corresponding public release/tag evidence at this HEAD |
| BBOT | `3.0.1` | [BBOT releases](https://github.com/blacklanternsecurity/bbot/releases) |
| reconFTW | `v4.1` | [reconFTW releases](https://github.com/six2dez/reconftw/releases) |
| Subfinder | `v2.15.0` | [Subfinder releases](https://github.com/projectdiscovery/subfinder/releases) |
| httpx | `v1.10.0` | [httpx releases](https://github.com/projectdiscovery/httpx/releases) |
| Nuclei | `v3.11.1` | [Nuclei releases](https://github.com/projectdiscovery/nuclei/releases) |
| OWASP Amass | `v5.1.1` | [Amass releases](https://github.com/owasp-amass/amass/releases) |

## Accepted Quarry posture is outside the defect score

The following product choices are preserved exactly as recorded in the
[product contract](../governance/PRODUCT-CONTRACT.md). Competitive remediation must improve control and
truth around them, not reduce their acquisition value.

| Accepted decision | What remains a professional requirement |
|---|---|
| Broad active Nuclei verification | Record the exact engine, flags, configuration, template/helper corpus, exclusions, rates, and output; label it accurately as active verification |
| Private-address reach by default | Preserve the operator opt-out while excluding scanner-self, metadata, and unrelated control-plane destinations at the actual connection boundary |
| Public Interactsh by default | Disclose the provider boundary, retain correlated callback evidence, protect local credentials/maps, and prove each disable/alternate-provider path |
| Potentially long scale budgets | Preserve coverage while making work observable, cancellable, checkpointed, and truthful about incomplete or replayable remainder |

These decisions do not explain or excuse false success, evidence loss, unbounded aggregate memory, an
uncertified revision, or a report that invents a negative conclusion.

## Current upstream fact base

### BBOT 3.0.1

**Upstream facts.** BBOT documents an event-driven recursive system in which more than 100 modules consume
declared event types and emit new events for redistribution. Its stable documentation presents the
producer/consumer relationships directly and describes each module as a focused unit.
[BBOT: How it Works](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/)

The current event contract is substantially richer than a value-only feed. Documented fields include a
per-occurrence UUID, content-derived ID, scan ID, timestamp, scope description and distance, parent ID and
UUID, module and module sequence, discovery context/path, and the full parent chain. Findings carry
separate severity and confidence. BBOT explicitly uses these attributes to construct and query graph
views. [BBOT events](https://www.blacklanternsecurity.com/bbot/Stable/scanning/events/)

BBOT's module guide defines `watched_events`, `produced_events`, event filters, `handle_event()`, event
emission, setup outcomes, dependency installation, and custom module directories. Presets can be composed
from YAML, include other presets, select/exclude modules and flags, load extra module directories, and run
validation/conditions before a scan. Current BBOT 3.0 release notes say module options are Pydantic
validated and malformed configuration fails readably.
[Writing a BBOT module](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/),
[BBOT presets](https://www.blacklanternsecurity.com/bbot/Stable/dev/presets/),
[BBOT 3.0 release](https://github.com/blacklanternsecurity/bbot/releases/tag/v3.0.0)

The documented output surface includes newline-delimited JSON, human output, CSV, SQLite, relational and
document databases, Neo4j, web reports, webhooks, message systems, and a Python API. The JSON example
retains parent/module/scan/scope context rather than exporting only the discovered scalar.
[BBOT output](https://www.blacklanternsecurity.com/bbot/Stable/scanning/output/)

BBOT exposes global, secrets, and preset configuration layers and documents event batch size, module
threads, and module timeout controls. Its 3.0 release notes describe a shared rate-limited HTTP engine,
bounded DNS caches, response-body lifecycle work, and memory/CPU optimizations. Those are upstream claims
about BBOT's implementation, not results of a common Quarry benchmark.
[BBOT configuration](https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration/),
[BBOT 3.0 release](https://github.com/blacklanternsecurity/bbot/releases/tag/v3.0.0)

This is not a hard scale guarantee: BBOT's own sanity guide says scans are theoretically
memory-unbounded and warns that some recursive module combinations can produce queues that do not drain;
its memory threshold is described as a last-ditch ingress throttle.
[BBOT scan sanity guide](https://github.com/blacklanternsecurity/bbot/blob/v3.0.1/docs/scanning/scan_sanity.md)

The stable repository has separate workflows for tests, distribution tests, CodeQL, and benchmarks. The
test workflow runs lint, pytest, and coverage collection across Python 3.10–3.14. That is strong visible
process evidence, although this audit does not infer a coverage percentage or hermeticity from the
workflow's existence.
[BBOT workflows](https://github.com/blacklanternsecurity/bbot/tree/stable/.github/workflows),
[BBOT test workflow](https://github.com/blacklanternsecurity/bbot/blob/stable/.github/workflows/tests.yml)

**Quarry-relevant inference.** BBOT is the best near-term reference for Quarry's missing source-adapter
contract and occurrence lineage. Quarry should adopt the *shape* of a typed producer/consumer interface,
module conformance, and explicit discovery chains. It should not blindly replace its methodology phases
with unbounded recursion: Quarry's phase obligations, coverage denominators, and durable remainder are
useful differentiators. BBOT's public pages establish event lineage and many sinks; they do not by
themselves establish Quarry's desired raw-byte, sealed-run, certified-revision, and lossless-private-report
contract. Quarry can differentiate there after it actually enforces the contract.

### reconFTW v4.1

**Upstream facts.** reconFTW documents a broad bug-bounty pipeline covering OSINT, subdomains, web
analysis, vulnerability checks, ports, screenshots, notifications, Faraday export, and Ax/Axiom-style
distributed fleets. Its current repository describes an entry point split across focused shell modules,
health checks, dry-run support, incremental mode, adaptive rate limiting, checkpoints, structured logs,
and a configurable asset store and reports.
[reconFTW repository and architecture overview](https://github.com/six2dez/reconftw)

The official data-model guide documents a human-oriented directory tree, per-technique flat files,
Nuclei JSON, Nmap XML, `assets.jsonl`, logs, a hotlist, and function-completion markers under
`.called_fn/`. The official guide says an interrupted rerun skips functions with completed markers.
[reconFTW data model and I/O](https://docs.reconftw.com/guides/data-model)

The configuration surface exposes module enablement, API integrations, timeouts, rate limits, wordlists,
resolvers, notifications, distributed scanning, and output options. The current repository documents a
Bats unit/integration/security test layout plus `make test`, `make test-security`, `make test-all`, and
ShellCheck/shfmt targets; it also tracks contribution, security, code-of-conduct, and changelog material.
[reconFTW repository](https://github.com/six2dez/reconftw),
[post-install configuration](https://github.com/six2dez/reconftw/wiki/1.-Post-Installation-Guide)

Its `plugins/*.sh` hook dispatches named lifecycle events to a convention-based shell function; the
tagged release does not document a manifest, typed compatibility contract, dependency declaration, or
isolation model. The tagged Actions workflow runs unit/smoke coverage on push/PR and schedules broader
integration work, but does not invoke the separate security-test directory by default.
[reconFTW plugin hook](https://github.com/six2dez/reconftw/blob/v4.1/modules/core.sh),
[reconFTW test workflow](https://github.com/six2dez/reconftw/blob/v4.1/.github/workflows/tests.yml)

reconFTW also exposes AI reporting through a local-model helper. The documented controls include model
and report profile, per-file and per-category context limits, optional redaction, strict mode, and a
machine-readable analysis result. This demonstrates operator demand for AI-assisted reporting; the
official material reviewed here does not establish immutable observation/artifact citations or versioned
prompt/model/input-view identities for every AI assertion.
[reconFTW AI integration](https://github.com/six2dez/reconftw#-ai-integration)

The latest release is versioned and has a detailed changelog. This pass did not run its tests or derive
a line/branch-coverage percentage.
[reconFTW v4.1](https://github.com/six2dez/reconftw/releases/tag/v4.1)

**Quarry-relevant inference.** reconFTW is the most useful benchmark for breadth, operator vocabulary,
deployment expectations, and practical workflow documentation. Its documented flat-file/function-marker
model should not become Quarry's canonical store: a completion marker is weaker than Quarry's intended
semantic manifest and evidence commit, and aggregated flat files are not a substitute for occurrence
provenance. Quarry can exceed this bar through typed coverage, atomic recovery, and rebuildable reports—
but current `HEAD-01` through `HEAD-08` mean it does not do so reliably yet.

The AI feature is also a warning against coupling truncation or heuristic redaction to canonical/private
evidence. Quarry should use an explicitly derived, policy-labelled AI view; record omissions; require
stable evidence citations; and leave facts immutable.

### ProjectDiscovery: Subfinder, httpx, and Nuclei

**Upstream facts.** Subfinder's documented scope is deliberately narrow: passive subdomain enumeration
with stdin/stdout composition, a modular source design, provider configuration, global and per-provider
rate limits, resolver concurrency, time bounds, JSONL output, and optional collection of all contributing
sources. [Subfinder repository](https://github.com/projectdiscovery/subfinder),
[Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage)

httpx exposes a focused HTTP probing contract with typed probes and filters, configurable threads and
request rates, allow/deny CIDRs, redirect and resolver controls, resume, JSONL/CSV output, stored
responses, and optional inclusion of request/response bytes and redirect chains. Its repository also
documents library use. [httpx usage](https://docs.projectdiscovery.io/opensource/httpx/usage),
[httpx repository](https://github.com/projectdiscovery/httpx)

Nuclei's primary extension mechanism is a YAML DSL with unique template IDs, metadata, protocols,
requests, matchers, and extractors; workflows compose templates and share extracted values. Nuclei
documents explicit concurrency, bulk-size, and global request-rate controls; JSON/JSONL, Markdown, SARIF,
and multiple issue/database outputs; optional request/response retention; a report database; and scan
metrics. [Nuclei template structure](https://docs.projectdiscovery.io/templates/structure),
[Nuclei workflows](https://docs.projectdiscovery.io/templates/workflows/overview),
[running Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running)

The default public-template policy runs most community templates while keeping code, headless, and
fuzzing templates behind explicit flags and honoring the default ignore policy. Template signing is a
first-class integrity mechanism. Nuclei `v3.11.0` made signed JavaScript templates mandatory and describes
additional loader, file, network-policy, and code-template hardening; `v3.11.1` is the current patch
release in this snapshot.
[Nuclei running/template selection](https://docs.projectdiscovery.io/opensource/nuclei/running),
[template signing](https://docs.projectdiscovery.io/templates/reference/template-signing),
[Nuclei releases](https://github.com/projectdiscovery/nuclei/releases)

The Nuclei repository exposes workflows for tests, compatibility, fuzzing, `govulncheck`, performance
regression, documentation, and release automation. This is a stronger visible release-engineering surface
than Quarry's single positive-selection pytest workflow. It does not, without an artifact audit, prove
that every ProjectDiscovery release is reproducible or that every runtime corpus is pinned.
[Nuclei workflows](https://github.com/projectdiscovery/nuclei/tree/dev/.github/workflows)

ProjectDiscovery also exposes AI-assisted template creation in its cloud/editor surface. Its template API
schema includes AI metadata such as the model and prompt. This is adjacent to, not identical with, the
open-source CLI trust boundary.
[ProjectDiscovery template creation API](https://docs.projectdiscovery.io/api-reference/templates/create-template),
[Nuclei template introduction](https://docs.projectdiscovery.io/templates/introduction)

**Quarry-relevant inference.** These tools set the component-contract bar. Quarry should execute a
verified absolute binary and bind its exact config, flags, input digest, structured output, and—especially
for Nuclei—template/helper/signature corpus to each acquisition record. It should retain the tool's raw
structured output before normalization instead of collapsing it into a weaker schema.

The ProjectDiscovery tools are intentionally focused; their official documentation does not present one
cross-tool, occurrence-preserving relationship repository. That is Quarry's integration opportunity, not
evidence that Quarry is a better subdomain enumerator, HTTP engine, or vulnerability scanner.

Quarry's accepted broad Nuclei policy is not a competitive weakness. The open defect is failure to make
the broad run reproducible and to preserve its proof, plus control-flow paths where an empty Nuclei input
can skip independent parameter work. Reducing the template set would hide rather than solve those
problems.

### OWASP Amass v5.1.1 and the Open Asset Model

**Upstream facts.** OWASP describes Amass as a system comprising a collection engine, asset database, and
Open Asset Model. The OAM treats assets as typed first-class records and relations as typed, directed
connections. Its documentation describes source, timestamps, and confidence metadata and graph queries
across DNS, IP, netblock, ASN, certificate, organization, and contact structures.
[OWASP Amass project](https://owasp.org/www-project-amass/),
[OAM assets](https://owasp-amass.github.io/docs/open_asset_model/assets/),
[OAM relations](https://owasp-amass.github.io/docs/open_asset_model/relations/)

OAM's `SourceProperty` identifies the discovery plugin and confidence for an asset or relation. Amass
configuration provides explicit scan scope and seed fields, an engine and database boundary, active and
rigid-boundary controls, and per-transform TTL, confidence, priority, and exclusions. Its data-source
configuration supports multiple accounts per source and source/global TTLs.
[OAM SourceProperty](https://owasp-amass.github.io/docs/open_asset_model/properties/source_property/),
[Amass configuration](https://owasp-amass.github.io/docs/configuration/),
[Amass data sources](https://owasp-amass.github.io/docs/data_sources/data_sources/)

The `v5.1.1` release notes identify a repository interface, an engine REST API, and a dispatcher with a
durable backlog plus bounded in-memory work queue. The repository has separate Go, lint, Docker, and
GoReleaser workflows. These are directly relevant architecture and process markers; they are not a
common-corpus performance result.
[Amass v5.1.1](https://github.com/owasp-amass/amass/releases/tag/v5.1.1),
[Amass workflows](https://github.com/owasp-amass/amass/tree/main/.github/workflows),
[Amass Asset Database](https://github.com/owasp-amass/asset-db)

**Quarry-relevant inference.** Amass/OAM is the strongest benchmark in this set for Quarry's `v0.4`
relationship and indexed-store work. Quarry should define an explicit OAM mapping/export boundary and
reuse compatible vocabulary where semantics match. It should not make an evolving external model its
canonical evidence format, nor collapse an observation occurrence into a mutable asset node. Quarry needs
three distinct layers:

1. immutable artifact and observation occurrences;
2. typed, temporal, source-attributed relationships and asset projections; and
3. reports/search/API views rebuilt from a certified generation.

That separation lets Quarry retain stronger bug-bounty proof while gaining graph interoperability.
Organizational/person/contact relationships also require project authorization, retention, and privacy
policy before collaborative use. Most importantly, a relationship can suggest review; it must never
silently expand active authorization.

## Comparative assessment of Quarry HEAD

### Current strengths

These strengths are present in design and, to varying degrees, implementation. They should be preserved
through stabilization.

1. **Bug-bounty-specific breadth under one operator contract.** Quarry presents nine phases, 38 tools,
   66 registered sources, 23 observation kinds, OSINT preflight, install/doctor/policy/status/report
   commands, and a single project/run layout. That is closer to reconFTW's end-to-end operator value than
   to a single ProjectDiscovery CLI. [Quarry README](../../README.md)
2. **A more ambitious evidence lifecycle than ordinary flat-file orchestration.** Runs already separate
   creation metadata, raw artifacts, normalized JSONL, events, manifests, state, reports, campaign data,
   paid-source ledgers, and late-evidence revisions. Focused regressions have verified foundations such as
   typed fault records, finalization states, delayed-OOB revision routing, private file creation, and
   resolver-worker reclamation. [Current verified foundations](CURRENT-HEAD.md#verified-closures-and-verified-foundations)
3. **Explicit coverage and uncertainty vocabulary.** The intended distinction among eligible, tested,
   omitted, refused, failed, unknown, and remainder is stronger than a simple “file exists” or exit-zero
   workflow. This is a credible market differentiator once every lane conforms and reports reconcile it.
4. **High-scale acquisition is a product goal, not an afterthought.** Long budgets, paid-source reuse,
   workload scaling, checkpoint/revision concepts, and preservation of broad Nuclei work are appropriate
   for the target market. The correct repair is bounded ownership and durable remainder, not arbitrary
   small scans.
5. **A substantial diagnostic test corpus exists.** The current audit recorded an effective 5,458
   non-live passes across the host/sandbox split and 74 integration-selection passes. That is useful
   implementation evidence. It is not a line/branch coverage percentage and not yet one clean release
   transcript. [Evidence baseline](CURRENT-HEAD.md#evidence-baseline)
6. **The newly explicit evidence/AI contract is strategically sound.** Full-fidelity private evidence,
   Quarry-credential exclusion by construction, derived share/AI views, append-only model assessments,
   stable citations, and no direct model authority align with a defensible long-term trust boundary.
   [Product contract](../governance/PRODUCT-CONTRACT.md#evidence-and-credential-surfaces)

### Current professionalism and architecture gaps

| Dimension | Quarry fact at `4e4825c` | External bar | Disposition |
|---|---|---|---|
| Module/adapter boundary | `sources.yaml` describes 66 sources, but its own header says behavior wiring is incomplete; current inspection found unregistered owners and 37 direct runner/contract call sites frozen behind an allowlist | BBOT declares module inputs/outputs and dispatches typed events; Nuclei templates and Amass transforms have explicit extension contracts | **Lags; `v0.3.10` must reconcile ownership, `v0.3.11`/`v0.4` must establish the durable adapter API** |
| Evidence settlement | Raw/normalized/event layers exist, but a blocked drain, output cap, publication failure, or empty argv can yield incomplete or misleading success | Specialist tools expose structured/raw outputs; Quarry's own bar is stricter because it promises durable evidence | **Stop-ship (`HEAD-01`)** |
| Repository and recovery | Selected seal guards and revisions exist, but public mutation paths can alter a finished run; path containment, multi-revision composition, pointer-last certification, and semantic manifests are incomplete | Amass has a repository/API boundary; professional persistence requires one authority and reconstructible state | **Stop-ship (`HEAD-02`–`HEAD-04`)** |
| Provenance and relationships | Observation rows carry some provenance, but findings, screenshots, Nuclei/Dalfox proof, Shodan associations, and secret occurrences are reduced or disconnected; no first-class typed temporal relationship repository exists | BBOT exposes parent/discovery chains; OAM exposes typed directed relations with source/time/confidence | **Lags now; potentially differentiating after `v0.3.11`/`v0.4`** |
| Resource governance | Per-lane time/rate/worker controls, paid ledgers, and per-entity caps exist; aggregate memory/disk, cross-process reservation, corpus deadlines, and replayable refused work do not hold globally | BBOT documents module/batch controls and bounded caches; PD tools expose rate/concurrency; Amass `v5.1.1` records durable backlog plus a bounded memory queue | **Stop-ship for high-scale claims (`HEAD-06`)** |
| Network boundary | Scope matching and pre-resolution guards exist; connect-time self/metadata exclusion is not uniform across re-resolution, redirects, proxies, direct IPs, and CIDRs | A professional active framework must enforce the approved peer at the actual egress boundary | **Open (`HEAD-07`); accepted private reach remains unchanged** |
| Output/UX | One CLI, project layout, hotlist, digest, delta, flat exports, report rebuild, status, and policy preview are a strong concept | BBOT offers lineage-rich machine events plus many sinks; PD offers raw/JSONL/CSV/SARIF/Markdown; reconFTW offers approachable technique files and reports; Amass offers database queries | **Mixed concept, stop-ship correctness: false origin/WAF claims, omitted rows, lost proof, unsafe Markdown (`HEAD-08`)** |
| Configuration | Separate target, machine, and secrets files are understandable; source defaults/classes are documented | BBOT 3.0 validates config/presets with Pydantic; Amass validates transforms; focused PD CLIs expose one option contract | **Mixed; exact schema, ownership, unknown-key handling, and docs/runtime parity remain open** |
| Tests and CI | 84 `test_*.py` files exist, but CI selects only the `offline` marker; approximately 1,302 default non-live tests were outside that positive selection in the audit; no committed lint/type/coverage/static-security/dependency gate exists | BBOT exposes lint/test/coverage, distro, CodeQL, and benchmark workflows; Nuclei exposes test/fuzz/vulnerability/performance/compat/release workflows | **Strong local test volume, immature release gate (`HEAD-09`)** |
| Public release integrity | `pyproject.toml` declares MIT and version `0.3.9`; the audited tree had no tracked license text, security policy, contribution guide, changelog/release process, or tag, and no SBOM/provenance gate | The compared upstreams have versioned release pages and tracked public project/release machinery | **Stop-ship for professional distribution; planned gates are still `open`** |
| AI/collaboration | A rigorous contract and roadmap exist; there is no implemented AI assessment or tenant/project collaboration boundary in this release | reconFTW demonstrates local AI report demand; ProjectDiscovery exposes AI-assisted template creation; neither substitutes for Quarry's evidence-integrity requirements | **Promising design only; do not market as a current capability** |

### Where Quarry excels, lags, and intentionally deviates

**Excels in product intent:** truthful coverage, full-fidelity private evidence, retained paid evidence,
explicit late-evidence revisions, and the separation of fact from AI assessment are unusually strong goals
for a bug-bounty orchestrator. Quarry also aims to combine deeper manual-hunting inputs—JS, parameters,
proof, and review queues—rather than stop at asset enumeration.

**Lags in enforceable architecture:** BBOT has a real event/module contract where Quarry has a partly
declarative registry over phase-specific execution; OAM has a relationship/database boundary where
Quarry has flat observation folds and lossy report joins; ProjectDiscovery and BBOT expose broader visible
quality/release automation; and reconFTW currently presents a more complete public contributor/release
surface.

**Intentionally deviates in useful ways:** Quarry's ordered methodology phases and explicit coverage
obligations need not become BBOT-style unconstrained recursion. Its canonical evidence need not become
OAM's mutable current asset view. Its private reports must not inherit share-safe redaction. Its broad
Nuclei, private reach, public Interactsh, and long budgets must remain. These deviations are advantages
only when their controls and evidence are testable.

## Competitive deltas by roadmap phase

### `v0.3.10` — earn operational trust

This release should not chase more tools or AI. It must make existing acquisition and evidence claims
true. The authoritative work packages and gate mappings are in the
[v0.3.10 ledger](../releases/v0.3.10.md).

1. **One evidence-settlement result.** Every started process and stream ends in a typed terminal state;
   lost/capped/unpublished primary output cannot be success.
2. **One repository mutation authority.** Validate opaque IDs and containment, reject symlinks and
   unknown kinds, enforce sealed-base immutability, and route authorized late evidence to staged
   revisions.
3. **Certified recovery state.** Strict semantic manifest/campaign parsing, complete revision folding,
   artifact/view digest validation, and pointer-last publication must survive injected failure.
4. **Attested execution.** Stage and verify every install before activation; launch the verified absolute
   binary; bind configuration/templates/helpers; provide only declared credentials to each adapter.
5. **An honest scale envelope.** Publish measured supported fixtures and resource limits; make aggregate
   reservations cross-process; give large resolver and phase work corpus budgets; persist exact replayable
   remainder or declare terminal evidence loss.
6. **Connect-time protected destinations.** Keep private targets reachable while proving scanner-self,
   metadata, redirect, proxy, DNS-change, direct-IP, and CIDR exclusions at egress.
7. **Minimum truthful private output.** Remove unsupported WAF/origin negatives, preserve target-derived
   values and stable proof references, safely encode untrusted rendering, and reconcile every report row
   or typed omission.
8. **Professional release evidence.** Classify and run every non-live test; add package/install,
   lint/type/coverage/security/dependency, compatibility, fault, and performance gates; track the approved
   public license/security/contribution/release files; bind evidence to one exact candidate.

**Competitive outcome:** Quarry becomes a trustworthy early-stage orchestrator. It still should not claim
the module ecosystem of BBOT or relationship platform of Amass.

### `v0.3.11` — make evidence useful to a hunter

1. Define stable typed IDs for acquisition activity, artifact, observation occurrence, entity, relation,
   finding, assessment, and projection generation.
2. Preserve Nuclei request/response/extraction, Dalfox proof, screenshot target, provider intelligence,
   and every secret occurrence without heuristic redaction in the private surface.
3. Require every report item to cite its observation and artifact IDs. Reconcile all included and omitted
   observations with a typed reason; absence stays unknown unless coverage proves otherwise.
4. Replace truncating `digest.json` behavior with complete paged/indexed machine output and concise human
   queues that link to full evidence.
5. Establish a source-adapter lifecycle for setup, declared input/output, policy, invocation, result,
   coverage, remainder, and teardown. Migrate lanes through a conformance suite rather than another
   allowlist.
6. Add explicit private, share, and AI projection policies. A share/AI transform records every removed or
   changed field and never replaces canonical/private output.
7. Export compatible BBOT-like event lineage and an initial OAM mapping where semantics are exact; keep
   these rebuildable views, not canonical storage.

**Competitive outcome:** Quarry can differentiate from flat workflow output through occurrence-level
proof and from generic asset graphs through bug-bounty evidence fidelity.

### `v0.4` — build the indexed single-host platform

1. Introduce explicit `RunContext`, repository, executor, artifact-store, adapter, policy, and query
   interfaces.
2. Replace whole-corpus materialization with an indexed append-only observation store and certified
   derived generations.
3. Add typed, directed, temporal relationships with source, confidence/basis, scope status, and
   supersession. Relationship inference never mutates authorization.
4. Add a bounded DAG scheduler with admission control, backpressure, cross-process leases, heartbeat,
   idempotency, fair scheduling, cancellation, and durable remainder.
5. Publish an adapter SDK only after built-in adapters pass the same contract. A third-party module must
   not receive ambient credentials, arbitrary filesystem authority, or an unverified executable path.
6. Provide query/search/export APIs and an OAM compatibility layer without weakening raw occurrence
   provenance.

**Competitive outcome:** Quarry reaches the architectural class of BBOT's module system and Amass's
persistent graph while retaining its distinct evidence/recovery semantics.

### `v0.5+` — add collaboration and AI without corrupting truth

The [roadmap](../roadmap.md) correctly puts these features after the repository boundary. NIST's
Generative AI profile emphasizes declared purpose and deployment context, data-source/privacy risk, human
configuration, monitoring, and third-party risk; those concerns are especially acute for private target
evidence. [NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1)

Required order:

1. project/tenant identity, authorization revisions, encryption, retention, and audited artifact access;
2. a typed, policy-filtered AI input view with deterministic disclosure tests;
3. append-only assessments that cite observation/artifact IDs and record provider, model/version,
   prompt/template version, input-view ID, policy, time, and actor;
4. explicit human accept/reject records; and
5. only later, proposals for typed jobs through deterministic policy review and human approval.

An AI system must never silently change a fact, infer missing evidence as clean, read ambient vault data,
or receive direct shell/scanner authority. Local models and redaction toggles are useful deployment
choices, but they do not replace provenance, authorization, and data-purpose controls.

## Market-leading acceptance conditions

Quarry may eventually claim a leading *evidence-integrity and hunter-UX* position when all of the
following are demonstrated—not merely documented:

- Every acquisition owner is a registered adapter or reviewed core service; adding a source requires no
  phase-specific bypass and passes the same conformance suite.
- Every primary byte has a durable disposition, every observation has occurrence provenance, and every
  report item has stable proof references.
- Finished bases are immutable through every API, and any current projection can be reconstructed from a
  certified generation after crash injection.
- Small, medium, and accepted large fixtures meet reviewed correctness/resource thresholds with recorded
  hardware, identities, and complete outlier handling.
- The operator can see what will run, what ran, what did not run, what remains, why, with which policy and
  tool/template corpus, and at what evidence location.
- Private output is lossless; share/AI output is explicit, policy-labelled, auditable, and derived.
- Relationships are typed and explainable but never treated as authorization.
- One candidate commit passes every applicable gate in
  [RELEASE-GATES.md](../releases/RELEASE-GATES.md), and installable artifacts carry verifiable identity
  and provenance.
- Any speed, yield, false-positive, or memory claim is tied to a published reproducible benchmark rather
  than repository size, anecdotes, or an incomparable historical target run.

Until those conditions hold, the precise professional description is: **an ambitious `v0.3.9`
bug-bounty framework under foundational stabilization, with strong evidence-oriented design and material
current correctness, scale, extensibility, and release-engineering gaps.**

## Source set and refresh rule

Only official project documentation, project-controlled repositories/workflows/releases, OWASP, and NIST
were used for upstream claims. No vendor comparison blog, benchmark marketing page, social-media metric,
or third-party review was used as evidence.

This baseline is time-sensitive. Refresh the version table and re-check the linked stable/current docs
before a release decision, after an upstream breaking release, or before adopting an upstream schema.
Preserve this dated file so later changes remain auditable rather than silently rewriting the benchmark.
