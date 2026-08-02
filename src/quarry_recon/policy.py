"""The BOUND REGISTRY — every ceiling Quarry applies, classified once.

Quarry's operator flags are separated by AXIS (`notes/FLAG-AXIS-PLAN.md`):

    waiting        `--timeout 0`      no OUTER process deadline, and nothing else
    volume         `--unbound`        coverage / throughput ceilings go to their unbounded meaning
    continuation   `--settle`         keep creating runs until no resumable work makes progress
    capability     (later presets)    breadth and intrusiveness, never a ceiling

A flag whose meaning is a hand-maintained list of side effects rots the moment someone adds a knob. So the
knobs are the data: ONE table drives `--unbound`, the startup policy print, the manifest record and a test
that FAILS when any bound in `src/` is unclassified. This module is pure data plus lookups — it is
deliberately imported by nothing yet (step 1 changes no behaviour).

Two classifications carry the weight.

AXIS says who may relax a bound:

    volume    a coverage / throughput ceiling `--unbound` may lift
    duration  a wall-clock deadline that belongs to `--timeout`
    money     structurally a coverage ceiling, but relaxing it SPENDS — a future `--spend-all`, never
              `--unbound`
    resource  blast radius, memory, sockets, parser sanity. Never relaxable by any flag: the scheduler
              reaches every chunk anyway, so lifting these buys coverage nothing and risks the host.

IDENTITY says what a CHANGE to the bound invalidates — the two persistence models Quarry actually has:

    none          nothing. A per-run throughput allowance: the durable rotation continues across a change,
                  and folding it into an identity would re-identify the source for no coverage reason.
    work_unit     the lane resumes by `events.work_unit`, so a bound that changes what ONE invocation may
                  cover MUST be in that unit or a bounded completion claims work it never did.
    partition     the bound changes how the corpus is SPLIT (`sweep.allocate`'s cap). The lane ledger
                  stays in use and a record belonging to a containing or contained slot is never certified
                  clean (`budget.RotationProgress.tier`), so a re-partitioned corpus is re-submitted.
    state_schema  changing it invalidates the state format itself; it is versioned, not relaxed.
"""
from __future__ import annotations

from dataclasses import dataclass

#: axes, in the order the policy print groups them
AXES = ("volume", "duration", "money", "resource")
IDENTITIES = ("none", "work_unit", "partition", "state_schema")
#: how the value is read: a PERFORMANCE knob through the strict parsers, or a module constant
READERS = ("strict_int", "budget_seconds", "module")


@dataclass(frozen=True)
class Bound:
    """One ceiling, and everything a flag or a report needs to know about it."""
    name: str
    axis: str
    reader: str
    lane: str                       # the source_id / lane it bounds, or the subsystem
    default: int                    # the value with no config and no flag
    identity: str
    persistence: str                # what a CHANGE invalidates, in one sentence
    relaxable: bool                 # may `--unbound` touch it
    unbounded_value: int | None = None   # the value that MEANS unbounded for this knob
    consumer_honours_unbounded: bool = False   # ...and whether the consumer already implements it
    held_reason: str = ""           # why a volume bound is NOT relaxable (printed, never silent)
    const: str | None = None        # "module:NAME" for a module constant, for the drift check
    note: str = ""


BOUNDS: tuple[Bound, ...] = (
    # ── lane wall-clock budgets: pure throughput, 0 = unbounded, rotation continues across a change ──
    *(Bound(name=n, axis="volume", reader="budget_seconds", lane=lane, default=0, identity="none",
            persistence="nothing — the lane's durable progress continues where it stopped",
            relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
            note="0 is already the default; a config file that bounds it is what `--unbound` lifts")
      for n, lane in (("A1D_BUDGET_S", "enrich.a1d_brute"),
                      ("ARJUN_BUDGET_S", "params.arjun"),
                      ("CONTENT_FFUF_BUDGET_S", "content.ffuf"),
                      ("JS_FETCH_BUDGET_S", "crawl.js_fetch"),
                      ("SOURCEMAP_BUDGET_S", "crawl.sourcemap"),
                      ("VHOST_BUDGET_S", "probe.vhost"),
                      ("WILDCARD_BUDGET_S", "vertical.wildcard_http"))),
    Bound(name="SHODAN_HOST_BUDGET_S", axis="money", reader="budget_seconds", lane="probe.shodan_host",
          default=0, identity="none",
          persistence="nothing — the lane's durable progress continues where it stopped",
          relaxable=False,
          held_reason="the lane SPENDS query credits; lifting its budget spends more, which belongs to a "
                      "future `--spend-all`, never to `--unbound`"),

    # ── coverage knobs read through the strict parser ────────────────────────────────────────────
    Bound(name="SUBFINDER_MAX_TIME", axis="volume", reader="strict_int", lane="vertical.subfinder",
          default=60, identity="work_unit",
          persistence="the per-apex resume key — subfinder folds its EFFECTIVE budget, so a bounded run "
                      "never claims an unbounded one's work",
          relaxable=True, unbounded_value=1440, consumer_honours_unbounded=True,
          note="minutes, and the unbounded value is 1440 rather than 0: upstream feeds -max-time into "
               "context.WithTimeout, where 0 CANCELS. Today `--timeout 0` also forces this — the axis "
               "model separates them (plan step 2)"),
    Bound(name="NUCLEI_MAX_HOST_ERROR", axis="volume", reader="strict_int", lane="params.nuclei",
          default=0, identity="work_unit",
          persistence="the scan's resume key — -mhe decides which hosts are scanned at all",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="Quarry's default is ALREADY full depth (-nmhe): a nonzero value is an operator-chosen "
               "bound, and `--unbound` returns it to 0"),
    Bound(name="WILDCARD_ZONES_PER_RUN", axis="volume", reader="strict_int",
          lane="vertical.wildcard_http", default=5, identity="none",
          persistence="nothing — the zone rotation is durable and continues across a change (98a77d4)",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="`quarry run --unbound` already sets this one"),

    # ── module-level selection bounds ────────────────────────────────────────────────────────────
    Bound(name="A1D_WORD_CAP", axis="volume", reader="module", lane="enrich.a1d_brute", default=2000,
          identity="partition", const="quarry_recon.phases.enrich:A1D_WORD_CAP",
          persistence="slot boundaries (`sweep.allocate`'s cap); the ledger stays in use and an inherited "
                      "record is never certified clean",
          relaxable=False,
          held_reason="HELD by policy: the strict `0` bypass is gated on tightening the active DNS "
                      "boundary to exact labels and on vocabulary usefulness tiers (Lumpy, 2026-08-01)"),
    Bound(name="A1D_WILDCARD_WORD_CAP", axis="volume", reader="module", lane="enrich.wildcard_a1d",
          default=2000, identity="partition",
          const="quarry_recon.phases.enrich:A1D_WILDCARD_WORD_CAP",
          persistence="slot boundaries; the differ's work unit carries the EFFECTIVE spend, so evidence "
                      "identity moves with it while the rotation does not",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True),
    Bound(name="WILDCARD_WORD_CAP", axis="volume", reader="module", lane="vertical.wildcard_http",
          default=5000, identity="partition", const="quarry_recon.phases.vertical:WILDCARD_WORD_CAP",
          persistence="slot boundaries; same ledger, same rule as the A1d spend",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True),
    Bound(name="CLOUD_NAME_CAP", axis="volume", reader="module", lane="horizontal.cloud_buckets",
          default=120, identity="work_unit", const="quarry_recon.cloud:_MAX_NAMES",
          persistence="the enumeration's resume key — the cap is folded in as `name_cap`",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=False,
          note="a MEMBERSHIP cut today (`all_names[:_MAX_NAMES]`, reported as a coverage gap). The "
               "consumer does not yet interpret 0, so widening this belongs to the `--unbound` step"),

    # ── resource controls: blast radius, memory, sockets, parser sanity. Never relaxable. ─────────
    *(Bound(name=n, axis="resource", reader="module", lane=lane, default=d, identity=ident,
            persistence=pers, relaxable=False, held_reason=held, const=const)
      for n, lane, d, ident, pers, held, const in (
          ("MAX_BATCH_WORDS", "sweep", 25000, "partition",
           "slot boundaries — it is one half of `alloc_cap`",
           "a per-invocation chunk size: it bounds one process's memory and blast radius, and the "
           "scheduler reaches every chunk anyway", "quarry_recon.sweep:MAX_BATCH_WORDS"),
          ("XNL_MAX_INPUT", "crawl.xnlinkfinder", 200 * 1024 * 1024, "work_unit",
           "the unit digest — the blob IS the unit identity",
           "the stdin blob is read into one process's memory",
           "quarry_recon.phases.crawl:XNL_MAX_INPUT"),
          ("XNL_WORDLIST_LIMIT", "crawl.xnlinkfinder", 10 * 1024 * 1024, "work_unit",
           "the unit's effective config (-owl/-os are skipped above it)",
           "-owl/-os are permutation timekillers on big input",
           "quarry_recon.phases.crawl:XNL_WORDLIST_LIMIT"),
          ("FETCH_MAX_BODY", "fetch", 2 * 1024 * 1024, "none",
           "nothing — a per-response read ceiling",
           "one response is read into memory", "quarry_recon.fetch:DEFAULT_MAX_BODY"),
          ("FETCH_MAX_REDIRECTS", "fetch", 5, "none", "nothing — a per-request hop ceiling",
           "a redirect chain is not coverage; an unbounded one is a loop",
           "quarry_recon.fetch:DEFAULT_MAX_REDIRECTS"),
          ("EVIDENCE_DEEP_MAX_BODY", "evidence", 64 * 1024 * 1024, "none",
           "nothing — a per-artifact read ceiling", "one artifact is read into memory",
           "quarry_recon.evidence:_DEEP_MAX_BODY"),
          ("EVIDENCE_OPENAPI_MAX_BODY", "evidence", 5 * 1024 * 1024, "none",
           "nothing — a per-document read ceiling", "one document is parsed in memory",
           "quarry_recon.evidence:_OPENAPI_MAX_BODY"),
          ("EVIDENCE_OPENAPI_MAX_PATHS", "evidence", 2000, "none",
           "nothing — a per-document parse ceiling", "one document's path table is held in memory",
           "quarry_recon.evidence:_OPENAPI_MAX_PATHS"),
          ("EVIDENCE_SSTI_MAX_PARAMS", "evidence", 10, "none", "nothing — a per-endpoint probe ceiling",
           "probe count per endpoint is request pressure, which is the rate axis' business",
           "quarry_recon.evidence:_SSTI_MAX_PARAMS"),
          ("PROVIDER_ERROR_BODY_LIMIT", "contract", 8192, "none",
           "nothing — how much of an error body is kept as evidence",
           "an error body is diagnostic text, not coverage",
           "quarry_recon.contract:_ERROR_BODY_LIMIT"),
          ("WHOXY_TOTAL_MAX_DIGITS", "contract", 15, "none", "nothing — a parser sanity ceiling",
           "a length guard on a provider-supplied number",
           "quarry_recon.contract:_WHOXY_TOTAL_MAX_DIGITS"),
          ("NETGUARD_MAX_WORKERS", "netguard", 16, "none", "nothing — local concurrency",
           "concurrency is pressure on this host, not coverage",
           "quarry_recon.netguard:_MAX_WORKERS"),
          ("BUDGET_MAX_S", "budget", 2592000, "none", "nothing — the strict parser's ceiling",
           "a parser range, not a policy: it bounds what a config VALUE may say",
           "quarry_recon.budget:_MAX_BUDGET_S"),
          ("NUCLEI_MHE_MAX", "params.nuclei", 100000, "none", "nothing — the strict parser's ceiling",
           "a parser range for NUCLEI_MAX_HOST_ERROR, not a policy of its own",
           "quarry_recon.phases.params:_NUCLEI_MHE_MAX"),
          ("SHODAN_RESERVE_MAX", "probe.shodan_host", 1000000, "none",
           "nothing — the strict parser's ceiling",
           "a parser range for the operator's credit reserve",
           "quarry_recon.phases.probe:_SHODAN_RESERVE_MAX"),
          ("SHODAN_BACKOFF_MAX_S", "probe.shodan_host", 300, "none", "nothing — retry backoff",
           "a retry ceiling: lifting it waits longer, it does not cover more",
           "quarry_recon.phases.probe:_SHODAN_BACKOFF_MAX_S"),
          ("CLOUD_SUFFIX_COUNT", "horizontal.cloud_buckets", 23, "work_unit",
           "the enumeration's resume key — the suffix set is coverage-affecting",
           "a fixed vocabulary, not a ceiling: it is data the operator edits, not a bound a flag lifts",
           "quarry_recon.cloud:_SUFFIXES"),
          ("DNS_PREVIEW_MAX", "triage", 200, "none", "nothing — a report preview length",
           "a rendering ceiling in the digest; the evidence keeps everything",
           "quarry_recon.triage:_DNS_PREVIEW_MAX"),
          ("UNSELECTABLE_DETAIL", "sweep", 20, "none",
           "nothing — how many structured detail rows a result carries",
           "a bound on a diagnostic list; the COUNTERS beside it are authoritative",
           "quarry_recon.sweep:_UNSELECTABLE_DETAIL"),
          ("TOOL_WORKER_CAPS", "settings", 300, "none", "nothing — local concurrency per tool",
           "concurrency is pressure on this host and on the target, never coverage",
           "quarry_recon.settings:_CAP"),
          ("DISK_MIN_GB", "bootstrap", 10, "none", "nothing — a pre-run free-space gate",
           "a host guard: a run that fills the disk loses evidence it already gathered",
           "quarry_recon.bootstrap:DISK_MIN"),
          ("EVIDENCE_MAX_BODY", "evidence", 2 * 1024 * 1024, "none",
           "nothing — a per-resource read ceiling", "one exposed resource is read into memory",
           "quarry_recon.evidence:MAX_BODY"))),

    # ── volume bounds that are NOT `--unbound`'s to lift ─────────────────────────────────────────
    Bound(name="EVIDENCE_MAX_FETCHES", axis="volume", reader="module", lane="evidence", default=50,
          identity="none", const="quarry_recon.evidence:MAX_FETCHES",
          persistence="nothing — evidence fetches are run-scoped",
          relaxable=False,
          held_reason="HELD pending measurement: it bounds ACTIVE fetches of exposed resources per "
                      "finding, so lifting it is request pressure at a target, and the fetch lane has no "
                      "rotation that would spread the remainder over later runs"),
    Bound(name="MAX_CONTENT_RECURSION", axis="volume", reader="module", lane="content", default=5,
          identity="work_unit", const="quarry_recon.config:MAX_CONTENT_RECURSION",
          persistence="the content lane's resume key — recursion depth is coverage-affecting config",
          relaxable=False,
          held_reason="an ENGAGEMENT setting, not a machine one: content-discovery depth is chosen in "
                      "target.yaml per engagement (depth 4-5 already warns), so a global flag is the "
                      "wrong place to raise it"),

    # ── state schema: versioned, never relaxed ───────────────────────────────────────────────────
    Bound(name="BUCKETS", axis="resource", reader="module", lane="sweep", default=256,
          identity="state_schema", const="quarry_recon.sweep:BUCKETS",
          persistence="the whole rotation: the bucket count IS slot identity, which is why SCHEMA is part "
                      "of the state path",
          relaxable=False,
          held_reason="slot IDENTITY, not a ceiling — changing it starts a new rotation, so it is "
                      "versioned rather than relaxed"),
    Bound(name="EXT_BITS", axis="resource", reader="module", lane="sweep", default=64,
          identity="state_schema", const="quarry_recon.sweep:EXT_BITS",
          persistence="the depth limit of a slot id's prefix extension",
          relaxable=False, held_reason="slot IDENTITY, same rule as BUCKETS"),
)

#: names that MATCH the bound-naming convention but are not ceilings at all — sentinels, string constants
#: and frozensets. Listed with a reason so the classification test can prove nothing was simply forgotten.
NOT_BOUNDS: dict[str, str] = {
    "quarry_recon.events:COVERAGE_CAP": "a coverage KIND string ('cap'), not a ceiling",
    "quarry_recon.contract:PROVIDER_RATE_LIMIT": "an error-class name",
    "quarry_recon.contract:PROVIDER_LIMITS": "the set of provider limit classes",
    "quarry_recon.phases.probe:SHODAN_OPERATOR_RESERVE": "a stop-reason name",
    "quarry_recon.phases.probe:SHODAN_UNKNOWN_WITH_RESERVE": "a stop-reason name",
    "quarry_recon.phases.probe:SHODAN_RESERVE_INVALID": "a stop-reason name",
    "quarry_recon.phases.probe:_STOP_LIMITS": "the set of stop-reason names",
    "quarry_recon.settings:PROFILES": "the concurrency profile names",
    "quarry_recon.contract:PROVIDER_QUOTA": "an error-class name",
    "quarry_recon.contract:_QUOTA_REASONS": "the measured provider strings that MEAN quota exhaustion",
    "quarry_recon.phases.vertical:_SUBFINDER_DEFAULT_MIN": "the DEFAULT of SUBFINDER_MAX_TIME, carried by "
                                                           "that bound's `default` field",
    "quarry_recon.phases.vertical:_SUBFINDER_UNBOUNDED_MIN": "the UNBOUNDED value of SUBFINDER_MAX_TIME, "
                                                             "carried by that bound's `unbounded_value`",
}


def by_name(name: str) -> Bound | None:
    return next((b for b in BOUNDS if b.name == name), None)


def knob(name: str) -> Bound | None:
    """The bound behind a PERFORMANCE key (`strict_int` / `budget_seconds`), if it is one."""
    b = by_name(name)
    return b if b is not None and b.reader in ("strict_int", "budget_seconds") else None


def relaxable() -> tuple[Bound, ...]:
    """Everything `--unbound` may lift, in registry order."""
    return tuple(b for b in BOUNDS if b.relaxable)


def held() -> tuple[Bound, ...]:
    """Volume bounds `--unbound` deliberately does NOT lift — printed with their reason, never silent."""
    return tuple(b for b in BOUNDS if b.axis in ("volume", "money") and not b.relaxable)
