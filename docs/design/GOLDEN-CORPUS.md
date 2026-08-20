# Golden corpus contract

Status: Phase 0 design contract. The source sets named below are candidates until
their two-pass attestations and private alias registry exist. This document does
not claim that an historical run is correct, complete, safe to publish, or
representative of another framework.

## Purpose

Quarry needs regressions that reproduce failures seen in real runs without
turning engagement data into public test data. The golden corpus therefore has
two distinct jobs:

1. preserve immutable private inputs that can reproduce import, recovery,
   derivation, scale, and reporting defects; and
2. produce small, deterministic, wholly synthetic fixtures that are safe to
   commit and run in hermetic CI.

The private source is evidence, not a fixture directory. Tests and reports refer
to a logical corpus alias. They never embed, accept, print, or persist the
source's absolute path.

## Non-negotiable rules

- Never modify a source corpus. Do not rename, repair, normalize, redact,
  truncate, decompress, chmod, touch, delete, or write bookkeeping into it.
- Never follow a symlink while inventorying, attesting, selecting, or replaying
  a source. A symlink is metadata that may be recorded; its target is never an
  implicit corpus member.
- Full target evidence remains only in the private source. A replay reads that
  source through a read-only, no-follow boundary and writes only to a private
  disposable destination outside it.
- A committed fixture contains synthetic identities, synthetic secrets, and
  synthetic payloads only. A masked, hashed, encoded, or truncated real secret
  is still real data and is not acceptable in a committed fixture.
- Sanitization is schema-driven and fail-closed. Regex replacement over an
  arbitrary blob is not a disclosure boundary.
- Historical output is characterization evidence. Its presence does not prove
  that the producer, manifest, counts, verdict, or report was correct.
- BBOT and reconFTW material may inform event and report *shape* fixtures. It
  must not be used to claim comparative yield, correctness, speed, or coverage.
- A missing artifact proves only that it was not present in the attested tree.
  It does not, by itself, prove why it is absent.

## Corpus tiers and privacy classes

| Class | Contents | Storage and use | Publication |
|---|---|---|---|
| `P0-public-synthetic` | Hand-authored or deterministically generated identities, payloads, tokens, logs, and artifacts | May be committed and used by hermetic CI | Allowed after schema validation and disclosure review |
| `P1-private-provenance` | Alias mappings, source run identifiers, tree attestations, local mount identity, access history, and sanitizer decisions | Private, mode-restricted Phase 0 registry | Only opaque corpus IDs and non-sensitive aggregate results |
| `P2-private-target` | Target-derived raw evidence, normalized records, reports, logs, and discovered target secrets | Read-only source; private local replay only | Never committed or included in public CI artifacts |
| `P3-quarry-credential` | Quarry provider keys, OOB authentication values, notification tokens, and operator credentials | Must not be imported into the corpus system at all | Never |

Target-discovered secrets are `P2-private-target` evidence and remain lossless in
the source. Quarry-owned credentials are `P3-quarry-credential` configuration
and must be excluded by construction. The corpus tooling must not confuse these
two policies.

Public attestations use opaque names such as `corpus-a` and `corpus-b`. The map
from an opaque public name to a private alias is itself `P1-private-provenance`
and stays outside the repository. This permits publication of a test result and
fixture digest without publishing a target, local path, or run timestamp.

## Selected source cases

The owner-private registry maps each alias to a source-family identifier, an
already-open root descriptor, and an attested logical run ID. Exact target,
source-family, filesystem, timestamp, and run-ID mappings are deliberately not
tracked here. Code, test parameters, logs, and release evidence use only the
public alias.

| Public alias | Regression role | Permitted claims before replay validation |
|---|---|---|
| `quarry-complete-rich` | Large Quarry history with top-level lifecycle and report material | The case was selected for rich-layout characterization; `complete` in the alias is not a correctness verdict |
| `quarry-interrupted-events` | Quarry history lacking a published final manifest | Missing-final-manifest and report-recovery characterization only; do not claim the interruption cause or that all evidence is readable |
| `quarry-complete-legacy` | Later legacy-layout history with manifest/log material | Presence and historical shape only, until attestation and semantic checks pass |
| `quarry-orphan-no-metadata` | Legacy-layout history with phase subtrees but no regular top-level metadata | Orphan-layout handling only; do not infer whether execution completed |
| `quarry-evolution-legacy` | Ordered pair of earlier and later legacy histories | Schema and output evolution only; never a before/after quality score |

The exact ordered pair behind `quarry-evolution-legacy` stays in the private
registry. A replay receives that alias and two object descriptors; it never
receives historical run names or filesystem paths as test parameters.

The stored BBOT and reconFTW histories are shape references only. Any structure
borrowed from them must be represented by a new `P0-public-synthetic` fixture
with synthetic IDs and values. Neither stored history enters release scoring as
an outcome benchmark.

## Private alias registry

The alias registry is machine-readable, private, and separate from both this
repository and the source trees. Each entry must contain at least:

```json
{
  "schema_version": "quarry.corpus-alias.v1",
  "alias": "quarry-complete-rich",
  "privacy_class": "P2-private-target",
  "source_family": "<private-source-family>",
  "logical_run_id": "<private-logical-run-id>",
  "root_identity": {
    "device": 0,
    "inode": 0
  },
  "attestation_id": "sha256:<private-manifest-digest>",
  "access": "read-only-no-follow"
}
```

`root_identity` values above are placeholders describing the schema. Actual
values are local provenance and must not be committed. Resolution must return
an already-open directory descriptor after validating identity and access
policy. It must not return a pathname for callers to reopen.

The registry directory is owner-only. Registry creation and updates use an
exclusive, no-follow, atomic replacement. A registry entry cannot make a
source trusted: it is usable only when its current attestation matches.

## Two-pass no-follow attestation

An inventory is valid only after two independent descriptor-based passes agree.
The implementation must use the platform equivalents of `openat`,
`O_DIRECTORY`, `O_CLOEXEC`, `O_NOFOLLOW`, and `fstatat(...,
AT_SYMLINK_NOFOLLOW)` at every path component. A preliminary `realpath` or
`lstat` followed by a pathname open is not an equivalent race-resistant check.

### Pass A: candidate inventory

1. Open the registered root without following a link. Record its device,
   inode, type, owner, mode, link count, modification time, and change time.
2. Walk entries in a canonical bytewise order using directory descriptors.
   Reject `..`, absolute names, embedded separators, duplicate normalized
   names, and any entry that escapes the opened root.
3. Record directories and symlink nodes without dereferencing them. Exclude
   symlinks, devices, sockets, FIFOs, and other special objects from replay.
4. Open every selected regular file read-only and no-follow. Compare the
   pre-open entry identity with `fstat` on the open descriptor.
5. Stream the file through SHA-256. Do not execute, parse, decompress, repair,
   or memory-map it as part of attestation.
6. Re-run `fstat` before closing. Identity, type, size, modification time, and
   change time must be unchanged across the read.
7. Write the candidate manifest only into a new private staging directory,
   never into or beside the source.

Each file record contains the encoded relative name, object type, metadata,
size, and content digest. The private manifest also records excluded special
objects and the reason for exclusion. Its tree digest is SHA-256 over a
versioned canonical serialization of the sorted records, not over locale- or
JSON-implementation-dependent output.

### Pass B: independent verification

Close all Pass A descriptors. Reopen the registered root independently and
repeat the complete walk and hashing operation. Pass B must not consume Pass
A's open files or discovered pathname list as authority.

Pass B succeeds only when:

- root identity is unchanged;
- the complete entry set and exclusion set are identical;
- every recorded identity and metadata field agrees;
- every regular-file digest agrees; and
- the independently computed tree digests agree.

Any mismatch, open error, short read, permission change, disappearing entry,
new entry, replaced inode, or special object makes the attestation `failed`.
There is no best-effort corpus. Failure leaves the prior accepted attestation
unchanged and produces no replay result.

Every private replay verifies the accepted tree digest before reading and
rechecks the selected inputs after reading. For stronger host isolation, the
source should be exposed to the replay worker through a read-only bind mount or
equivalent sandbox. OS read-only isolation supplements, but does not replace,
the descriptor and digest checks.

## Replay boundary

A replay job receives an alias and a declared selection, never a path or glob.
It must:

- resolve and attest the alias before starting;
- run with network egress denied;
- expose the source read-only and use no source file as an output destination;
- create an owner-only disposable work/output root on a different path;
- bind the Quarry commit, package version, schema versions, configuration,
  selection, and dependency/tool digests to the result;
- record each source artifact by private corpus object ID and content digest,
  not by absolute path;
- keep stdout, stderr, reports, crash dumps, and test diagnostics private,
  because any of them may reproduce target evidence; and
- mark the result incomplete if any selected input, output, or attestation
  cannot be committed.

The replay's source-selection manifest is an allowlist. New files appearing in
an accepted source tree do not silently become test inputs; they require a new
attestation and an explicit selection revision.

## Deterministic synthetic fixture derivation

Public fixture derivation is a typed transformation, not redaction of a private
report. A versioned input schema identifies every field before any value is
read into an output record. Unknown fields, unknown schema versions, untyped
free-form extensions, or malformed records abort derivation.

For each supported schema, the transformer must define:

- which fields are retained, replaced, summarized, or omitted;
- stable within-fixture identity mappings that preserve equality and graph
  relationships without exposing hashes of source values;
- synthetic domains under `.invalid`, synthetic IP addresses from documented
  example ranges, and synthetic URL components;
- deterministic timestamp shifting or sequencing that preserves order without
  preserving engagement dates;
- format-valid synthetic secret values that preserve only the properties a
  parser test needs, plus synthetic secret occurrence/identity relationships;
- path replacement that preserves logical artifact relationships without a
  host name, user name, source root, or source run path;
- safe representations for request/response and binary artifacts; when a
  complete typed transform is unavailable, a hand-authored synthetic artifact
  replaces the source artifact rather than partially redacting it; and
- canonical output ordering, encoding, newline, and serialization rules.

The derivation record binds input alias and private attestation ID, transformer
commit and schema version, transformation-decision digest, output fixture
digest, and disclosure-review result. Only the output fixture and non-sensitive
derivation metadata may enter the repository. The private input alias,
attestation, and decision map stay outside it.

For the v0.3.10 public scope, only `C-CORPUS-SYNTHETIC` is selected. Its
`fixture_digest` is the canonical synthetic fixture-tree identity, and its
`attestation_digest` is the raw SHA-256 of a candidate-independent public
synthetic disclosure attestation. That attestation records two matching
derivation tree identities and passing schema/disclosure checks, but contains
no candidate identity, private alias, path, timestamp, or private attestation
reference. The signed `A-CORPUS` gate binds that fixed attestation to the
candidate. It makes no claim about the unselected private sources.

Determinism is checked by two clean derivations with isolated output roots. The
complete output trees must be byte-identical. A separate schema validation and
disclosure review must then confirm that:

- every output record conforms to its committed schema;
- every credential-shaped value is on the fixture's explicit synthetic-value
  inventory;
- no source identity, path, raw digest, timestamp, secret, or unclassified blob
  appears in the output; and
- no field was silently dropped because the transformer did not understand it.

A manual review is defense in depth; it cannot override a failed deterministic
or schema check.

## Assertions permitted by case

Tests must state the narrow observation they verify. Initial permitted scopes
are:

| Alias/case | Suitable assertions | Claims that require new evidence |
|---|---|---|
| `quarry-complete-rich` | Historical importer compatibility; bounded parsing; internal manifest/count/report disagreement detection; deterministic private projection | That the historical manifest is truthful, the scan was complete, or current Quarry produces the same yield |
| `quarry-interrupted-events` | Missing-final-manifest recognition; recovery without rescanning; event-prefix tolerance; honest incomplete verdict | The cause of interruption, completeness of the event log, or successful historical finalization |
| `quarry-complete-legacy` | Legacy schema recognition and explicit migration; small complete-layout replay | Semantic correctness until validation expectations are authored and pass |
| `quarry-orphan-no-metadata` | Orphan classification and refusal/recovery messaging without path guessing | Whether the original run succeeded, failed, or was intentionally stopped |
| `quarry-evolution-legacy` | Explicit schema/output compatibility decisions and deterministic migration deltas | Improvement, regression, coverage, or tool efficacy merely from differing trees |
| BBOT/reconFTW shape references | Synthetic parser/event/relationship fixture design | Any outcome, performance, coverage, or professionalism ranking |

An assertion discovered during exploration is not automatically a release gate.
It becomes one only after its expected semantics, fixture version, and
machine-readable evidence are reviewed and added to
[`RELEASE-GATES.md`](../releases/RELEASE-GATES.md).

## Lifecycle and change control

A corpus source is append-only at the registry level: a changed tree receives a
new attestation ID and cannot overwrite the old accepted record. Alias retargets
are reviewed changes and must retain the prior mapping history.

A committed fixture declares its fixture schema, generator version, and content
digest. Schema or generator changes require regeneration, deterministic-diff
review, and a new fixture version. Expected-output changes require a reasoned
review; "update goldens" is not sufficient justification.

Source retention, access revocation, and deletion are operator decisions outside
the repository. Deleting or losing a private source makes its private replay
gate `open` or `blocked`; a stale prior result must not be presented as a fresh
pass.
