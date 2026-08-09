# The dalfox XSS lane (`phases/params.py`)

Reference for the dalfox scanning lane. The source keeps one-line contracts; the rationale is here.

## Error codes split by what a retry would do

dalfox reports a per-target disposition. Collapsing them into one boolean makes a chunk either retry
for ever or be marked done over evidence nobody collected, so they are split:

- **RETRIABLE** — the environment failed and a later attempt may succeed (transport, timeout, a broken
  cost guard). The chunk is **not** execution-complete.
- **DETERMINISTIC** — the same input under the same config omits the same targets for ever. The chunk
  **is** execution-complete (retrying changes nothing); the omission is coverage and is reported as such.

Each deterministic code maps to the coverage kind that actually describes it (`timeout` was misleading
for both):

| code | meaning | coverage kind |
|---|---|---|
| `TRUNCATED_PER_HOST_CAP` | a hard ceiling truncated eligible input | `COVERAGE_CAP` |
| `CONTENT_TYPE_MISMATCH` | the tool declined it as unscannable content | `COVERAGE_TOOL_OMISSION` |

## The `--max-targets-per-host` cap

dalfox has its own membership cap (`--max-targets-per-host`, default 100): targets past it are dropped
and reported as `skipped` / `TRUNCATED_PER_HOST_CAP`. The lane passes a value that cannot truncate the
chunk it submitted, so the cap never decides Quarry's membership whatever `DALFOX_CHUNK` is; the meta
row is still parsed in case dalfox gains other states.

## dalfox 3.2.0 adoption

- `--dedup-urls signature` keys on method+host+path+parameter names and is counted in
  `meta.targets_deduplicated`, so it cannot hide what it collapsed. It is the same identity
  `_canonicalize_candidates` already computes (verified it does not collapse across scheme), so on this
  lane it finds almost nothing; it is a second net for callers feeding raw URLs, and the residual is
  reported rather than assumed.
- `--include-request` / `--include-response` carry the exact request that produced a finding and the
  response that proved it, stored whole as `request` / `response` — the finding is the product, auditable
  without re-running anything.
- `--scan-timeout` is deliberately **not** passed: a target whose injection stage it cuts is reported
  `status: "clean", incomplete: false` — byte-identical to a genuinely-scanned clean target. Quarry
  cannot report coverage it cannot observe, and that silent false negative is the failure the
  ceiling-honesty rule exists to prevent. Revisit if dalfox surfaces the cut in the artifact.
- Confidence and detection-method are their own axes in 3.2.0; the lane carries both rather than
  flattening to one tier (it does not store dalfox's `impact` field). `detection_method: "oob"` is a
  blind callback that actually arrived — the one observable proof the channel worked.

## Finding types

dalfox finding type -> (store klass, confidence tier, display name), kept distinct: a dalfox-verified
hit (V) outranks a reflection (R), and an AST-DOM static finding (A) is its own static evidence — none
collapses into another. `confirmed` stays False for all (Quarry owns impact validation). "V" is dalfox's
own verdict, which does not always establish DOM execution, so it is shown as "dalfox-verified", not
"DOM-verified".

## Blind / stored XSS credential handling

`--blind-oob` mints a fresh callback per payload and correlates each interaction back to
target/param/location/method/payload. The secret is **never** passed as `--blind-oob-secret` on argv
(world-readable through `/proc/<pid>/cmdline`): dalfox reads `scan.blind_oob_secret` from a `--config`
file, so the credential reaches it through an ephemeral 0600 file whose lifetime the caller owns — the
command builder must not create a file it cannot destroy.

## Meta-row validation

The meta row drives the verdict: `incomplete` decides whether a chunk may be marked resumably complete,
and `target_summary` names a skipped target. Both are validated strictly and fail closed — a
string `"true"`, a dict-valued `target_summary`, a negative count, or an **absent** field (3.2.0 always
emits both) invalidates the row, making the chunk PARTIAL/retryable rather than certifying it clean.
Membership is reconciled against the submitted batch by the lane, the only place that knows what was
submitted; `complete` alone is silent about targets that were never listed.

## Resumability

Execution completion and request coverage are separate facts. A chunk is execution-complete only when
the exit code and the parsed artifact **agree**: exit 0 with a valid empty artifact (no findings), or
exit 1 with valid findings. A hard exit (>=2), any exit/artifact disagreement, or a malformed artifact
makes the chunk PARTIAL and retryable — never silently done. (Exit 1 is a normal with-findings result,
not an error.)

Per-attempt artifacts are immutable, under `wu_<scan_wu>/attempt_<attempt_id>/`. A completion map (a
clean chunk -> its validated artifact path, controls skip) is kept separate from an append-only evidence
map (every attempt's artifact that produced output, controls aggregation). The verdict and the `matched`
count derive from the retained evidence across all attempts, deduped by finding id, so a finding kept in
a degraded attempt is never lost when a later retry comes back empty. A completion is trusted to skip a
chunk only if its recorded artifact still validates, is unchanged (sha256), still parses clean, and still
agrees with the recorded outcome; otherwise the chunk re-runs.
