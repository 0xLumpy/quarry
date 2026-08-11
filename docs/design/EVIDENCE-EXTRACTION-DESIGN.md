# Recon evidence extraction — the map/attack boundary, secret classification, and ownership

Reference for `src/quarry_recon/evidence.py`.

> **Status (audited 2026-08-11 at `4e4825c`): implementation rationale, not release closure.** The
> extraction and classification paths exist, but occurrence provenance and full-fidelity rendering are
> incomplete in some normalizers/reports. Current conformance is tracked by
> [`HEAD-08`](../audit/CURRENT-HEAD.md#head-08-truthful-lossless-private-reports-and-complete-provenance)
> and the [product contract](../governance/PRODUCT-CONTRACT.md).

## The map/attack boundary

This section governs Quarry's **native evidence-extraction probes**, not the separately accepted broad
Nuclei policy in [`ADR-039-01`](../governance/decisions/ADR-039-01-broad-nuclei.md). For these native
lanes, the rule is not “don't touch anything”; it is **don't accidentally perform impact** (Lumpy,
2026-07-02). They may collect evidence from unauthenticated, in-scope, non-mutating access: an exposed
`.env`, `.git/config` or config file is GET-fetched and its secret read and recorded. Recon must not
send attack payloads, use the credentials it finds, change state, bypass controls, or prove exploit
impact — that is `quarry-attack`.

Two probes sit right on the line and are allowed because they are non-mutating reads: GraphQL
introspection (a read per the spec) and the SSTI classification probe (a benign math eval that only
reads whether the engine evaluated it). Heap dumps are the opposite: a GET to `/actuator/heapdump`
forces the JVM to run a full stop-the-world GC and write a multi-GB dump before streaming, so the
request is itself impact. Recon detects heap-dump exposure from the `/actuator` index `_links` and never
requests it; deep-evidence mode is an explicit operator opt-in that downloads it.

## Discovered evidence is reported in full

The required boundary is that every discovered value remains complete on its entity and in every
full-fidelity private artifact. `secrets.mask` may build a short `preview` field beside the complete value
for recognition, never as a substitute. Storing only a preview would lose the finding—one artifact can
hold many values, and “grep the raw file” is not reporting the occurrence Quarry found.

Quarry's own configured credentials are a separate operational class and must be excluded from recordable
values by typed invocation boundaries. The current `secrets.redact` literal replacement is defense in
depth, not proof of that boundary. At the audited revision, some normalizers lose occurrence context and
some report paths mask or omit discovered values; those are open defects, not a change to this design.

## Secret classification: shape is not a claim

A detector match is retained whatever it looks like; classification decides *where* it is shown, never
*whether* it is kept. An unclassified match goes to the review queue with the reason it was not
promoted, makes no secrecy claim, and can be promoted later by the v0.4 skill layer — a change of queue,
not of what was kept.

The routing, and why each rule is gated the way it is:

| finding | queue | the claim, and why it needs a gate |
|---|---|---|
| provider-shaped token (AWS key, GitHub PAT, Stripe, JWT, PEM) | `secret` | the shape *is* the claim |
| `dotenv:KEY` on a secret-ish key | `secret` | key name plus a secret-shaped value |
| `json:key` under a symmetric algorithm | `secret` | signing key = verifying key, so publishing it is the leak |
| `json:key` under a signing parent, in a format that stores signing secrets | `secret` | `.NET` writes JWT keys under a bare `Key` in `appsettings.json` |
| `connection-string-password` | `secret` | a `password=` field beside a connection-string anchor |
| `bcrypt-hash` | `credential-hash` | a verifier, offline-crackable — proves the store leaked, is not the password |
| `signing-key` (signing context, no format/symmetric proof) | `signing-key` observation | a JWKS entry publishes this exact shape by design |
| `rails-master-key` and other format rules | `secret` | path-gated: 32 hex is a Rails key in `config/master.key` and an MD5 everywhere else |
| anything a detector matched and no rule promoted | `unclassified` observation | kept whole, no claim |

Rules that fire on a body alone cannot carry a path-specific claim, so they are gated on the source
path. A generic 64-hex "key" rule was exactly the false-positive this prevents and was removed
outright. The requested path and the answering path are both kept: the fetch follows redirects, so a
request for `/config/master.key` can be answered by `/checksums.txt`, and a format rule keyed on the
requested path would call that body a Rails master key. `location` is what we asked for, `final` is what
replied, and the finding is attributed to the host that answered.

### Connection strings

`password=` on its own appears in documentation, examples, query strings and ordinary prose, so calling
it a database credential needs a connection-string **anchor** (`Server`, `Data Source`, `Host`,
`User ID`…) in the same value. Fields are split first, because requiring the anchor to appear before the
password missed `Password=x;User ID=sa;Server=db`, a perfectly ordinary connection string. A
`password=` with no anchor is not dropped — it is kept as an unclassified observation with that reason.

The scan finds `=` anchors and expands a bounded window around each, rather than trying a lazy prefix at
every offset: the earlier pattern cost ~400 character tests per position and spent 99% of `mine()`'s
time on lines with no `=` — 3.7 s/MiB, measured 2026-08-06 once the byte cap stopped hiding it.

### Structural JSON classification

Where a body parses as JSON, a bare `key` field is classified by the object it actually lives in, not by
text proximity: a ±200-char window once promoted a public key to a secret because a neighbouring object
mentioned HS256. The nearest *named* ancestor is used, not the previous path component, so
`{"Jwt": [{"key": …}]}` classifies like `{"Jwt": {"key": …}}` — an array of signing configs is still
signing config. A structural finding carries its JSON path as provenance and no line number; reporting
the first text line that contains the same string points at a different field. Bodies that do not parse
(XML `web.config`, truncated or templated config) fall back to regex and stay observations only.

## Acquisition is separate from interpretation

The body is streamed to disk with no byte ceiling and published atomically, so the artifact holds
whatever arrived. Acquisition is bounded in **memory and time** (`STREAM_CHUNK`, `STREAM_DEADLINE_S`),
never in bytes: a `MAX_BODY` cap dropped an over-cap response entirely while the fetch counter still
claimed it was read, so the cap prevented no cost and only converted a fetched body into no evidence.

What stays bounded is interpretation. The regex/JSON pass holds the whole body as text, so `MAX_PARSE`
is the memory ceiling on *that* pass. Over it, the artifact is published whole and interpretation is
deferred — recorded, and re-runnable from the artifact with no second request. A file of any size is
mined by scanning it in overlapping windows (`_DEEP_SCAN_WINDOW` in RAM, `_DEEP_SCAN_OVERLAP` carried
between windows so a token on a boundary is not cut in half); this is how a multi-GB heap dump full of
ASCII credentials is mined without holding it as one string. The overlap bounds the longest value that
can survive a boundary and must be tuned above any pattern's length.

Membership is never the control either. A `urls[:50]` cap (removed 2026-08-05) silently dropped the 51st
exposed file, GraphQL endpoint, actuator base, OpenAPI document and framework candidate — never fetched,
never reported, and directly able to hide a secret-bearing file. Request *pressure* is `RATELIMIT.HTTP`,
which every fetch already goes through; what each lane owes is an honest count of what it looked at.

Deferral is `COVERAGE_CAP` but is not a soft limit: nobody chose the subset and the run genuinely did
not extract from the artifact. Keeping the artifact makes the omission *recoverable*, not clean.

## The ownership-transition log

An acquisition can be complete-and-owned, complete-but-unowned (the receipt could not be written), or
refused by the ownership state already on disk. An ownership problem opens, is resolved, and can open
again, which a mutable `resolved` boolean cannot express: the store never overwrites a non-empty scalar,
so once True it stayed True and a reopened refusal still rendered resolved. Each transition is therefore
its own append-only observation, keyed by the path it is about, and the current state is the latest one
derived at read time. It lives in the store, not in memory, so a repair in a new lifecycle still
resolves a row an earlier one left open.

The log is its own entity (`ownership_transition`), separate from `review`: when these rows lived beside
unclassified matches and API documents, a single unreadable line anywhere in that file froze ownership
transitions globally, and the report could not say whether a dropped row had been a transition or a
finding.

**Authority is global.** Three separate failures each used to read as "nothing ever happened": the store
could not read the log, a row did not validate (bad type, id, or fingerprint), or a key held two
transitions with the same sequence number. The last is *ambiguity*, not an ordering problem — picking a
winner by id would let lexicographic order decide whether a path is refused or ok — so such a key has no
current state and nothing is claimed for it. When the log is not trustworthy as a whole, no key has a
current state and nothing may be appended, because a new row would be written on top of a sequence known
to be incomplete. Whatever is found is reported, including the healthy case, so a repaired log clears the
unknown rather than leaving it standing.

A transition's identity is a full sha256 over canonical JSON of its material fields. Joining fields with
a delimiter let distinct states serialize identically (`disposition="a|b", raw_ref="c"` collided with
`disposition="a", raw_ref="b|c"`), and a truncated digest narrows it further; a typed object with
encoder-escaped separators cannot be forged by choosing a value that contains the delimiter.

## Coverage vocabulary in this module

- `evidence_fetches` — readable responses over eligible candidates. Attempted is not completed (a
  refused connection or TLS error happened after contact); a replay is satisfied from verified evidence
  with no request this lifecycle, so it is neither "attempted" nor "never requested".
- `evidence_ownership` / `evidence_durability` — the refusal and the unowned-but-complete cases, on the
  URL and the artifact respectively, each with a healthy counterpart so a repaired path clears the gap.
- `evidence_interpretation` — deferred mining, `COVERAGE_CAP` but recoverable.
- `ownership_state` — the health of the transition log itself.
