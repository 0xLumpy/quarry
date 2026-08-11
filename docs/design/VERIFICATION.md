# Quarry verification key (historical partial index)

> **Status (audited 2026-08-11 at `4e4825c`): historical diagnostic documentation; not a release gate.**
> This page describes only checks 0–8 of a script that has since grown through check 146. The script mixes
> source-checkout assertions, optional host tools, and live-range contact; it permits `SKIP`. A pass from
> it cannot satisfy Quarry's current release contract.

The authoritative lane taxonomy, skip rules, isolation requirements, and promotion evidence are in
[`RELEASE-GATES.md`](../releases/RELEASE-GATES.md). Current release status is in the
[`v0.3.10` ledger](../releases/v0.3.10.md). Keep `scripts/verify-quarry.sh` as a useful historical and
developer diagnostic until its checks are classified and migrated; do not cite it as release closure.

The historical usage was targeted regression checks, one per shipped fix, run periodically instead of a
full pipeline. It remains useful for diagnostics, subject to the warning above.

```bash
bash scripts/verify-quarry.sh          # runs all checks, prints PASS/FAIL/SKIP, exits nonzero on FAIL
#
# `0xlumpy.cc` (RANGE_APEX) is the OPERATOR-OWNED test range domain — a deliberate fixture, not
# engagement data. It is safe to version and to publish; override with RANGE_APEX=<your-range>.
```

**Historical prerequisites:** the process can import the Quarry **source** (`QUARRY_SRC`, historically
defaulting to the original checkout's `src/`)
and, for DNS checks, reach the live range (`RANGE_APEX`, default `0xlumpy.cc`). DNS checks `SKIP`
(not fail) when `dnsx` is absent or the range is unreachable — so the offline checks still run
anywhere. Checks assert against the **source tree we edit**, not the pipx-installed build.

Historical recorded run: **2026-06-27 — PASS=9 FAIL=0 SKIP=0** (from the original box, range live).
It is not bound to the current candidate identity and is not current verification evidence.

---

## Checks

### [0] Source imports
`quarry_recon.{runner, phases.vertical, phases.params}` import cleanly. Catches syntax/refactor breakage.

### [1] gitleaks exit-code taxonomy — commit `d04a467` (offline)
`runner._classify` must treat gitleaks' "exit 1 = leaks found" as success **only when there is
output**, and never silently swallow a real error. Asserted cases:

| exit | stdout | ok_codes | expected |
|------|--------|----------|----------|
| 1 | has output | (0,1) | **success** |
| 1 | empty | (0,1) | **failed** (real gitleaks error, not masked) |
| 0 | empty | (0,1) | empty |
| 0 | has output | (0,1) | success |
| 2 | — | (0,1) | failed |
| 1 | empty | (0,) default | failed (other tools unchanged) |

### [2] Dangling-CNAME takeover detection — `vertical.py` (needs range)
A host with a CNAME but no A of its own = takeover candidate; A-resolving hosts must not be.
Runs `dnsx -cname` over `assets / admin / www .RANGE_APEX` and asserts **only `assets`** (the
CNAME→NXDOMAIN sim) is flagged dangling. Mirrors the `review.takeover_candidate` logic.

> Note: detection keys on "not A-resolved earlier this run." A name discoverable *only* by brute
> with a dangling CNAME isn't surfaced yet (needs CNAME-enum brute — see ROADMAP). This check
> covers the known-subdomain case the fix actually closes.

### [3] CSP-sibling discovery — `probe.py` (needs range)
httpx runs with `-irh`; the probe phase parses `header.content_security_policy` over **live
hosts** and adds in-scope siblings as subdomains (`sources:[csp]`). The first version asserted
`internal`; the current shell check uses the renamed `cf-edge-9d2c` fixture and discovers it from
**www's** CSP. (csprecon-over-apex in horizontal is kept but can't see this —
the CSP lives on www, not the bare apex.)

### [4] arjun → dalfox handoff — `params.py` (hermetic)
arjun discovers hidden params and writes param-bearing URLs (`.../v1/search?q=7101`), but the
output was previously written and never read. `params.py` now parses it into url + parameter +
`klass:xss` review entities, so dalfox gets a candidate. Asserts the parse turns an arjun URL
into a dalfox xss candidate. (arjun actually detecting `q` on the range was confirmed live.)

### [5] crawl-link host promotion — `crawl.py` (hermetic)
A host first seen via a crawl link (link-only needle, e.g. `s3-backup-7f3a`) must be registered
as a subdomain, not left only in the URL corpus. Asserts host extraction + in-scope gate for
the needle. (Test-1: katana fetched it 200 OK but it never became a discovered subdomain.)

### [6] gitleaks file-based report integration — `crawl.py` (needs gitleaks)
Runs gitleaks exactly as the phase does (`-r` a **real file**, not `/dev/stdout`) against a
fixture with fake secrets, asserts the report file is non-empty with findings. Catches the
`/dev/stdout`-writes-0-bytes breakage that the offline classify test (check 1) missed and that
cost the aws+jwt secrets on the Test-2 VPS run.

> Note: the range renamed `internal → cf-edge-9d2c` post-Test-1 so the CSP-only channel cannot be
> masked by a brute-findable name.

### [7] historical target-secret masking check — superseded as an acceptance criterion

This check asserts the old implementation's masked-preview plus fingerprint behavior for normalized
gitleaks/trufflehog/jsluice entities. That behavior is **not** Quarry's current evidence contract:
target-derived secret occurrences remain lossless in canonical evidence and full-fidelity private
operator reports. Quarry-owned credentials are instead excluded by construction from operational
telemetry and unrelated child environments. Share and AI views are separate explicit derivations and may
apply a recorded minimization policy.

The check may remain as characterization of the old representation, but it cannot pass `C-SECRETS` or a
report-integrity gate. Its replacement must use distinct synthetic canaries for target evidence and
Quarry credentials and verify every sink without destroying the target occurrence.

### [8] enrich phase wired in — `phases/__init__.py` (hermetic)
Late-discovered hosts (crawl links, CSP siblings) need a catch-up resolve/takeover/probe. The
`enrich` phase must run **after crawl, before params** and be importable. Asserts ORDER +
REGISTRY. (Test-2: `assets` was crawl-discovered but never got the takeover review because the
vertical CNAME pass ran before crawl — enrich closes that.)

---

## Adding verification now

New release assertions belong in the classified test lane and machine-readable gate named by
[`RELEASE-GATES.md`](../releases/RELEASE-GATES.md). A required check must not become green through
reachability `SKIP`. If a numbered shell check is still useful as a developer diagnostic, label its I/O
and prerequisites precisely and link it to—not substitute it for—the authoritative gate evidence.
