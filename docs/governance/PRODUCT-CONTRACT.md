# Quarry product contract

**Status:** current intended behavior for the Phase 0 stabilization of `v0.3.9`

**Scope:** product behavior and architectural invariants, not proof of current implementation

Quarry is a high-scale reconnaissance and bug-bounty hunting framework for authorized security testing.
Its value is broad acquisition without sacrificing truthful coverage, evidence integrity, reproducibility,
or operator control.

## Authorization is the gate

- The operator-provided engagement scope is an assertion of authorization. Quarry does not establish
  legal permission and must not expand active scope from inference alone.
- Ownership, infrastructure association, certificate overlap, branding, and other relationships are
  supporting evidence. They can create review candidates; they do not grant authorization.
- Out-of-scope and related assets may be retained from passive observation as evidence but must not be
  actively contacted unless the operator explicitly adds them to authorized scope.
- Relationship records must be typed and retain their source, observation time, confidence or basis, and
  scope status. A relationship must not silently mutate scope.

## Accepted operating posture

The durable decision records are
[`ADR-039-01`](decisions/ADR-039-01-broad-nuclei.md),
[`ADR-039-02`](decisions/ADR-039-02-private-address-reach.md),
[`ADR-039-03`](decisions/ADR-039-03-public-interactsh.md), and
[`ADR-039-04`](decisions/ADR-039-04-scale-budgets.md).

The following are `accepted_by_design`, not defects to be removed during stabilization:

| Decision | Contract |
|---|---|
| Broad Nuclei execution | Quarry uses its selected broad active-verification template policy. It must be described accurately as active scanning, not generically as "non-intrusive." The exact executable, templates, exclusions, flags, rates, and corpus identity must be recorded. |
| Private-address reach | Authorized names resolving to private, CGNAT, or ULA addresses are reachable by default. Operators can disable this behavior for an engagement. |
| Public Interactsh | The public Interactsh service is the default OOB backend. Operators must be told that its operator can observe callbacks and must be able to disable OOB work or select a self-hosted backend. |
| Long budgets | Large workloads and long execution budgets are intentional. High-scale acquisition must not be shortened merely to appear safer or faster; it must remain bounded when configured, observable, cancellable, and truthful about unfinished work. |

Private-address reach does **not** authorize Quarry to contact the scanner host, loopback, link-local, or
cloud-metadata endpoints. Those exclusions are a separate invariant and remain enforced even when private
reach is enabled. Scope, rate limits, consent-sensitive modes, and self/metadata exclusion are independent
controls; no control may be inferred from another.

## Evidence integrity

Quarry separates acquisition, canonical records, and presentation:

1. Raw artifacts preserve the bytes and acquisition context received from a tool or target.
2. Normalized observations are the canonical semantic record, with stable identity and provenance back to
   their artifacts and acquisition activity.
3. Reports, exports, indexes, campaign unions, and future relationship graphs are derived views. They may
   be rebuilt; they are not allowed to overwrite or silently reinterpret canonical facts.

Canonical evidence is append-only after publication. Corrections, late callbacks, human decisions, and
new interpretations are new records or certified revisions that cite what they supplement or supersede.
They do not edit historical bytes in place. A finished base run is read-only through every write path.

Presentation escaping, safe encoding, and layout changes are allowed. Replacing, truncating, or masking an
evidence value is not a readability operation and must not occur in a full-fidelity private view.

## Evidence and credential surfaces

Quarry has four explicit output surfaces:

### 1. Canonical evidence

Raw artifacts and normalized observations retain target-derived data in full, including discovered
credentials, tokens, payloads, request and response material, and source context. Access controls and file
permissions protect this evidence; destructive redaction does not.

### 2. Private operator reports

Local reports are full-fidelity views of canonical evidence. A discovered target secret remains readable
and traceable to its occurrence. If a value equal to a Quarry credential is independently present in
target evidence, its target-derived occurrence remains evidence. Reports must clearly identify sensitive
content and be private by default.

### 3. Operational telemetry

Quarry-owned credentials, provider tokens, notification secrets, and OOB authentication values are not
evidence and must be excluded by construction from commands-as-recorded, events, diagnostics, manifests,
metrics, notifications, and ordinary logs. Typed invocation records should carry a credential reference or
presence flag, never a clear value later repaired by heuristic replacement. Each child process receives
only the credentials it requires.

### 4. Share and AI views

Sharing is an explicit export operation over an immutable source. A share view names its policy and records
which fields were removed, minimized, or transformed. It never replaces the private report or canonical
evidence.

An AI view is separately generated, typed, access-controlled, and minimized for the declared task. AI
systems initially produce append-only assessments, never facts. Every assessment must cite observation or
artifact IDs and record the model, model version, prompt/template version, input-view identity, and policy.
AI output must not silently modify evidence, disclose secret values, or invent facts for missing evidence.
Human acceptance or rejection is another attributed record, not an edit to the model output.

Future collaboration must add project or tenant authorization, audited access, retention, and encryption
boundaries before evidence is shared beyond the local operator.

## Absence, unknown, and coverage

Absence of a row, field, result, callback, or error is not evidence of absence.

- `observed_empty` is valid only when the eligible population and completed coverage are known.
- `not_run`, `ineligible`, `omitted`, `failed`, `timed_out`, `unavailable`, and `unknown` remain distinct.
- Missing booleans and classifications are unknown, not `false`.
- A source that cannot measure its work reports unknown coverage; it does not imply clean completion.
- A remainder is zero only when explicitly measured as zero. A missing remainder is unknown.
- Reports and AI assessments must preserve these states and may not turn uncertainty into a negative
  finding, a clean target, or a causal relationship.

A run verdict summarizes recorded coverage; it is not a claim that silent or uninstrumented lanes ran.
High-scale limits and interruptions must preserve replayable work or be reported as evidence loss.

## Reproducibility and derivation

Every material observation and report claim should be traceable through stable identifiers to its source,
artifact, acquisition activity, tool identity, applicable template or data corpus, policy, and run identity.
Derived views record the exact canonical generation from which they were built. A derivation that cannot
be reproduced is marked stale or unverifiable, not silently presented as current.

## Deferred prototype

The existing reporting and relationship prototype is retained as a research artifact. It is not part of
the current release contract, is not an authoritative database, and must not drive canonical schema or
storage changes during the Phase 0 integrity work. Revisit it after runner completion, repository sealing,
revision publication, campaign truthfulness, and evidence-surface boundaries are implemented and verified.
Its useful presentation ideas may then be rebuilt against typed, immutable inputs.
