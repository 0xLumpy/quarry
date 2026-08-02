"""The `--unbound` REGISTRY — the free-tool volume ceilings one run may lift.

`--unbound` is about USING WHAT WE ALREADY HAVE, not obtaining more. The boundary is POLICY OWNERSHIP, not
execution order — it holds however the phases are later reordered (Lumpy, 2026-08-02):

    ACQUISITION   provider enablement, balance, reserve and page policy decide what Quarry may OBTAIN.
    OWNERSHIP     once evidence is acquired and stored, Quarry HAS it.
    PROCESSING    `--unbound` may process all eligible RETAINED evidence through free downstream tools
                  without truncating it.

If Shodan's own policy buys five pages and those yield 100,000 names, `--unbound` does not buy page six —
and it does let the free downstream lanes work through all 100,000. It never raises a provider page budget,
reduces a credit reserve, enables a disabled provider, broadens scope, bypasses a contact guard, removes
rate / concurrency / resource protection, or implies `--timeout 0` (`notes/FLAG-AXIS-PLAN.md`).

So this table is deliberately NARROW. It holds free-tool COVERAGE / THROUGHPUT bounds that participate in
`--unbound`, plus the held exceptions that must be printed rather than silently skipped. Everything else —
resource guards, parser ranges, rate and concurrency, engagement settings, and every paid-provider control
— is an EXCLUSION with a reason, listed in `EXCLUDED` so the classification test can prove a ceiling was
reasoned about rather than forgotten. Paid-provider policy stays where it already lives: enablement,
balance, reserve and per-run page policy, separately authorised. This flag never reinterprets it.

`identity` says what a CHANGE to a bound invalidates — the two persistence models Quarry has:

    none          nothing. A per-run throughput allowance: the durable rotation continues across a change,
                  and folding it into an identity would re-identify the source for no coverage reason.
    work_unit     the lane resumes by `events.work_unit`, so a bound that changes what ONE invocation may
                  cover MUST be in that unit or a bounded completion claims work it never did.
    partition     the bound changes how the corpus is SPLIT (`sweep.allocate`'s cap). The lane ledger
                  stays in use and a record belonging to a containing or contained slot is never certified
                  clean (`budget.RotationProgress.tier`), so a re-partitioned corpus is re-submitted.

This module is pure data plus lookups — nothing imports it yet (step 1 changes no behaviour).
"""
from __future__ import annotations

from dataclasses import dataclass

IDENTITIES = ("none", "work_unit", "partition")
#: how the value is read: a PERFORMANCE knob through the strict parsers, or a module constant
READERS = ("strict_int", "budget_seconds", "module")
#: why a ceiling is NOT in this registry. Every one of these is a REASON, never a silent omission.
EXCLUSION_KINDS = (
    "provider",     # paid / external: enablement, balance, reserve and page policy own it, not a flag
    "resource",     # blast radius, memory, sockets, disk — the scheduler reaches every chunk anyway
    "parser",       # the range a config VALUE may hold; not a policy of its own
    "rate",         # pressure on the target or this host: the rate axis, never the volume one
    "engagement",   # chosen per engagement in target.yaml, not by a machine-wide flag
    "identity",     # slot / schema identity: versioned, never relaxed
    "not_a_bound",  # a sentinel, name or set that merely matches the naming convention
)
#: lanes on the ACQUISITION side: what they may obtain is decided by the provider's own enablement,
#: balance, reserve and page policy. Nothing here may ever enter the registry (test-enforced) — including
#: `probe.shodan_host`, whose endpoint is MEASURED FREE (`/shodan/host/{ip}`, zero-balance delta 0,
#: 2026-07-30). Being free is not why it is out; ownership is.
PROVIDER_LANES = ("probe.shodan_host", "probe.shodan_search", "vertical.shosubgo", "horizontal.whoxy",
                  "horizontal.censys", "vertical.chaos", "horizontal.securitytrails")


@dataclass(frozen=True)
class Bound:
    """One free-tool volume ceiling, and everything a flag or a report needs to know about it."""
    name: str
    reader: str
    lane: str                       # the source_id / lane it bounds
    default: int                    # the value with no config and no flag
    identity: str
    persistence: str                # what a CHANGE invalidates, in one sentence
    relaxable: bool                 # may `--unbound` lift it
    unbounded_value: int | None = None   # the value that MEANS unbounded for this knob
    consumer_honours_unbounded: bool = False   # ...and whether the consumer already implements it
    held_reason: str = ""           # why it is NOT lifted — PRINTED, never silent
    const: str | None = None        # "module:NAME" for a constant, for the drift check
    const_local: bool = False       # ...defined inside a function today, so it is read from the AST
    maximum: int | None = None      # the strict parser's range for a `strict_int` knob
    note: str = ""


BOUNDS: tuple[Bound, ...] = (
    # ── free-lane wall-clock budgets: pure throughput, 0 = unbounded, rotation continues ─────────
    *(Bound(name=n, reader="budget_seconds", lane=lane, default=0, identity="none",
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

    # ── free-lane coverage knobs read through the strict parser ──────────────────────────────────
    Bound(name="SUBFINDER_MAX_TIME", reader="strict_int", lane="vertical.subfinder", default=60,
          maximum=1440, identity="work_unit",
          persistence="the per-apex resume key — subfinder folds its EFFECTIVE budget, so a bounded run "
                      "never claims an unbounded one's work",
          relaxable=True, unbounded_value=1440, consumer_honours_unbounded=True,
          note="minutes, and the unbounded value is 1440 rather than 0: upstream feeds -max-time into "
               "context.WithTimeout, where 0 CANCELS. Today `--timeout 0` also forces it — the axis model "
               "separates them (plan step 2)"),
    Bound(name="NUCLEI_MAX_HOST_ERROR", reader="strict_int", lane="params.nuclei", default=0,
          maximum=100000, identity="work_unit",
          persistence="the scan's resume key — -mhe decides which hosts are scanned at all",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="Quarry's default is ALREADY full depth (-nmhe): a nonzero value is an operator-chosen "
               "bound, and `--unbound` returns it to 0"),
    Bound(name="WILDCARD_ZONES_PER_RUN", reader="strict_int", lane="vertical.wildcard_http", default=5,
          maximum=10000, identity="none",
          persistence="nothing — the zone rotation is durable and continues across a change (98a77d4)",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="`quarry run --unbound` already sets this one"),

    # ── free-lane selection bounds held as module constants ──────────────────────────────────────
    Bound(name="A1D_WILDCARD_WORD_CAP", reader="module", lane="enrich.wildcard_a1d", default=2000,
          identity="partition", const="quarry_recon.phases.enrich:A1D_WILDCARD_WORD_CAP",
          persistence="slot boundaries; the differ's work unit carries the EFFECTIVE spend, so evidence "
                      "identity moves with it while the rotation does not",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True),
    Bound(name="WILDCARD_WORD_CAP", reader="module", lane="vertical.wildcard_http", default=5000,
          identity="partition", const="quarry_recon.phases.vertical:WILDCARD_WORD_CAP",
          persistence="slot boundaries; same ledger, same rule as the A1d spend",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True),
    Bound(name="CLOUD_NAME_CAP", reader="module", lane="horizontal.cloud_buckets", default=120,
          identity="work_unit", const="quarry_recon.cloud:_MAX_NAMES",
          persistence="the enumeration's resume key — the cap is folded in as `name_cap`",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=False,
          note="free: unauthenticated HTTP probes of candidate bucket URLs, no key and no spend. Today it "
               "is a MEMBERSHIP cut (`all_names[:120]`, reported as a coverage gap) and the consumer does "
               "not yet interpret 0, so widening it belongs to the `--unbound` step"),

    Bound(name="SPA_CAP", reader="module", lane="crawl.katana_headless", default=10, identity="none",
          const="quarry_recon.phases.crawl:SPA_CAP", const_local=True,
          persistence="nothing — the headless pass has no durable rotation to continue",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=False,
          note="a HIDDEN membership cut on already-retained hosts (`_spa_all[:10]`, reported as a coverage "
               "gap): exactly the PROCESSING side. It is function-local today, so wiring it means "
               "promoting it to a module constant AND teaching the consumer 0 — the widening step's work"),

    Bound(name="MAX_ITERS", reader="module", lane="vertical.permute", default=3, identity="none",
          const="quarry_recon.phases.vertical:MAX_ITERS", const_local=True,
          persistence="nothing — the permutation loop is run-scoped",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=False,
          note="rounds of permutation over names ALREADY held. Calling it `--settle`'s business was wrong: "
               "entities are RUN-scoped (a new Run starts empty, pinned in the registry tests), so a later "
               "run replays rounds 1-3 and can never reach round 4 — depth would be permanently "
               "unreachable. The loop already stops when a round adds nothing new, so the unbounded "
               "meaning is exactly that convergence; the consumer must be taught to read 0 that way"),

    # ── the one HELD exception in v1 ─────────────────────────────────────────────────────────────
    Bound(name="A1D_WORD_CAP", reader="module", lane="enrich.a1d_brute", default=2000,
          identity="partition", const="quarry_recon.phases.enrich:A1D_WORD_CAP",
          persistence="slot boundaries (`sweep.allocate`'s cap); the ledger stays in use and an inherited "
                      "record is never certified clean",
          relaxable=False,
          held_reason="HELD by policy: the strict `0` bypass is gated on tightening the active DNS "
                      "boundary to exact labels and on vocabulary usefulness tiers (Lumpy, 2026-08-01)"),
)

#: Ceilings that are NOT `--unbound`'s, with the reason each is excluded. Keyed by "module:NAME" for a
#: module constant, or by the bare PERFORMANCE key for a knob read through the strict parsers.
EXCLUDED: dict[str, tuple[str, str]] = {
    # paid / external providers — enablement, balance, reserve and page policy own these
    "SHODAN_HOST_BUDGET_S": ("provider", "an ACQUISITION-side lane: external-provider policy retains "
                                         "ownership of what it may obtain. (The endpoint itself is "
                                         "MEASURED FREE — that is not the reason; ownership is.)"),
    "SHODAN_MAX_PAGES": ("provider", "the provider's own page policy — how much Quarry may OBTAIN"),
    "SHODAN_CREDIT_RESERVE": ("provider", "the operator's credit reserve: a spending control"),
    "WHOXY_PAGE_BUDGET": ("provider", "the provider's own per-run page policy"),
    "WHOXY_CREDIT_RESERVE": ("provider", "the operator's credit reserve: a spending control"),
    "PROVIDER_MAX_PAGES": ("provider", "bounded cursor pagination against an external provider"),
    "quarry_recon.phases.probe:_SHODAN_RESERVE_MAX": ("provider", "the operator's credit reserve"),
    "quarry_recon.phases.probe:_SHODAN_BACKOFF_MAX_S": ("provider", "provider retry backoff"),
    "quarry_recon.contract:_WHOXY_TOTAL_MAX_DIGITS": ("provider", "a Whoxy response sanity guard"),
    "quarry_recon.contract:_ERROR_BODY_LIMIT": ("provider", "how much of a provider error body is kept"),

    # engagement settings — chosen in target.yaml, per engagement
    "quarry_recon.config:MAX_CONTENT_RECURSION": ("engagement", "content-discovery depth is an engagement "
                                                                "choice (4-5 already warns), not a "
                                                                "machine-wide flag"),

    # resource guards — blast radius, memory, sockets, disk
    "quarry_recon.sweep:MAX_BATCH_WORDS": ("resource", "a per-invocation chunk size: one process's memory "
                                                       "and blast radius. The scheduler reaches every "
                                                       "chunk anyway"),
    "quarry_recon.phases.crawl:XNL_MAX_INPUT": ("resource", "the stdin blob is read into one process"),
    "quarry_recon.phases.crawl:XNL_WORDLIST_LIMIT": ("resource", "-owl/-os are permutation timekillers"),
    "quarry_recon.fetch:DEFAULT_MAX_BODY": ("resource", "one response is read into memory"),
    "quarry_recon.fetch:DEFAULT_MAX_REDIRECTS": ("resource", "a redirect chain is not coverage"),
    "quarry_recon.evidence:_DEEP_MAX_BODY": ("resource", "one artifact is read into memory"),
    "quarry_recon.evidence:_OPENAPI_MAX_BODY": ("resource", "one document is parsed in memory"),
    "quarry_recon.evidence:_OPENAPI_MAX_PATHS": ("resource", "one document's path table in memory"),
    "quarry_recon.evidence:MAX_BODY": ("resource", "one exposed resource is read into memory"),
    "quarry_recon.bootstrap:DISK_MIN": ("resource", "a run that fills the disk loses evidence it has"),
    "quarry_recon.triage:_DNS_PREVIEW_MAX": ("resource", "a digest preview length; evidence keeps all"),
    "quarry_recon.sweep:_UNSELECTABLE_DETAIL": ("resource", "a diagnostic list bound; the counters beside "
                                                            "it are authoritative"),

    # rate / concurrency — pressure on the target or on this host
    "ARJUN_TARGETS": ("rate", "how many arjun processes run at once (one per target, host-fair)"),
    "DALFOX_TARGETS": ("rate", "dalfox pool size"),
    "DALFOX_CHUNK": ("resource", "targets per dalfox invocation: one process's blast radius"),
    "KATANA_PARALLELISM": ("rate", "katana's own parallelism"),
    "NUCLEI_BULK_SIZE": ("rate", "nuclei requests in flight per template"),
    "NUCLEI_CHUNK_HOSTS": ("resource", "hosts per nuclei invocation: one process's blast radius"),
    "quarry_recon.evidence:MAX_FETCHES": ("rate", "active fetches per finding: request pressure at a "
                                                  "target, which the rate axis owns"),
    "quarry_recon.evidence:_SSTI_MAX_PARAMS": ("rate", "probes per endpoint is request pressure"),
    "quarry_recon.phases.crawl:MAX_JS": ("resource", "a 15 MB PER-ITEM guard on one downloaded file"),
    "quarry_recon.phases.crawl:MAX_MAP": ("resource", "a 20 MB PER-ITEM guard on one source map"),
    "quarry_recon.netguard:_MAX_WORKERS": ("rate", "local concurrency"),
    "quarry_recon.settings:_CAP": ("rate", "per-tool worker caps"),

    # parser ranges — what a config VALUE may say, not what the run does
    "quarry_recon.budget:_MAX_BUDGET_S": ("parser", "the strict parser's ceiling for lane budgets"),
    "quarry_recon.phases.params:_NUCLEI_MHE_MAX": ("parser", "the strict range of NUCLEI_MAX_HOST_ERROR"),
    "quarry_recon.phases.vertical:_SUBFINDER_DEFAULT_MIN": ("parser", "the DEFAULT of SUBFINDER_MAX_TIME, "
                                                                      "carried by that bound"),
    "quarry_recon.phases.vertical:_SUBFINDER_UNBOUNDED_MIN": ("parser", "the UNBOUNDED value of "
                                                                        "SUBFINDER_MAX_TIME, carried by "
                                                                        "that bound"),

    # slot / schema identity — versioned, never relaxed
    "quarry_recon.sweep:BUCKETS": ("identity", "the bucket count IS slot identity; SCHEMA is part of the "
                                               "state path for exactly this reason"),
    "quarry_recon.sweep:EXT_BITS": ("identity", "the depth limit of a slot id's prefix extension"),
    "quarry_recon.cloud:_SUFFIXES": ("identity", "a candidate vocabulary folded into the work unit, not a "
                                                 "ceiling a flag lifts"),

    # names, sentinels and sets that merely match the naming convention
    "quarry_recon.events:COVERAGE_CAP": ("not_a_bound", "a coverage KIND string ('cap')"),
    "quarry_recon.contract:PROVIDER_RATE_LIMIT": ("not_a_bound", "an error-class name"),
    "quarry_recon.contract:PROVIDER_QUOTA": ("not_a_bound", "an error-class name"),
    "quarry_recon.contract:PROVIDER_LIMITS": ("not_a_bound", "the set of provider limit classes"),
    "quarry_recon.contract:_QUOTA_REASONS": ("not_a_bound", "measured provider strings meaning quota"),
    "quarry_recon.phases.probe:SHODAN_OPERATOR_RESERVE": ("not_a_bound", "a stop-reason name"),
    "quarry_recon.phases.probe:SHODAN_UNKNOWN_WITH_RESERVE": ("not_a_bound", "a stop-reason name"),
    "quarry_recon.phases.probe:SHODAN_RESERVE_INVALID": ("not_a_bound", "a stop-reason name"),
    "quarry_recon.phases.probe:_STOP_LIMITS": ("not_a_bound", "the set of stop-reason names"),
    "quarry_recon.settings:PROFILES": ("not_a_bound", "the concurrency profile names"),
    "PROFILE": ("not_a_bound", "which concurrency profile is in force — a name, not a ceiling"),
    "WEB_PORT_PREFILTER": ("not_a_bound", "a feature toggle for the SYN web-port prefilter"),
}


def by_name(name: str) -> Bound | None:
    return next((b for b in BOUNDS if b.name == name), None)


def knob(name: str) -> Bound | None:
    """The bound behind a PERFORMANCE key (`strict_int` / `budget_seconds`), if it is one of ours."""
    b = by_name(name)
    return b if b is not None and b.reader in ("strict_int", "budget_seconds") else None


def relaxable() -> tuple[Bound, ...]:
    """Everything `--unbound` lifts, in registry order."""
    return tuple(b for b in BOUNDS if b.relaxable)


def held() -> tuple[Bound, ...]:
    """Registry bounds `--unbound` deliberately does NOT lift — printed with their reason, never silent."""
    return tuple(b for b in BOUNDS if not b.relaxable)


# ── the EFFECTIVE policy: what this run will actually apply, and where each value came from ──────────
def effective(bound: Bound) -> tuple[int, str]:
    """`(value, source)` for one bound. Source is `flag`, `config` or `default` — an operator reading a
    ceiling deserves to know WHO set it, not just what it is."""
    from . import budget, settings
    src = settings.source_of(bound.name) if bound.reader != "module" else "default"
    if bound.reader == "budget_seconds":
        return budget.budget_seconds(bound.name), src
    if bound.reader == "strict_int":
        return settings.strict_int(bound.name, default=bound.default,
                                   maximum=bound.maximum or bound.default), src
    if bound.const and not bound.const_local:
        import importlib
        mod, _, name = bound.const.partition(":")
        return int(getattr(importlib.import_module(mod), name)), src
    return bound.default, src        # a function-local constant: not configurable, only relaxable


def snapshot() -> list[dict]:
    """The whole effective policy, one row per registered bound. This is what gets printed at run start and
    persisted into the manifest: a run's ceilings are EVIDENCE, not shell history."""
    rows = []
    for b in BOUNDS:
        value, src = effective(b)
        rows.append({"name": b.name, "lane": b.lane, "value": value, "default": b.default,
                     "source": src, "relaxable": b.relaxable,
                     "unbounded": b.relaxable and value == b.unbounded_value,
                     "held_reason": b.held_reason})
    return rows


def render(rows: list[dict] | None = None) -> list[str]:
    """The operator-facing lines: what is unbounded, what a flag or config changed, and what is HELD with
    the reason it is held. A bound sitting at its default is summarised rather than listed — the point is
    what is DIFFERENT from the ordinary run, plus every exception we declined to lift."""
    rows = snapshot() if rows is None else rows
    out, plain, free = [], 0, 0
    for r in rows:
        if not r["relaxable"]:
            out.append(f"  HELD      {r['name']} = {r['value']} ({r['lane']}) — {r['held_reason']}")
        elif r["source"] == "default":
            plain += 1
            free += bool(r["unbounded"])         # unbounded because that IS the default, not by request
        elif r["unbounded"]:
            out.append(f"  UNBOUNDED {r['name']} ({r['lane']}) — by {r['source']}")
        else:
            out.append(f"  {r['source'].upper():<9} {r['name']} = {r['value']} "
                       f"({r['lane']}, default {r['default']})")
    if plain:
        out.append(f"  {plain} bound(s) at their default ({free} of them already unbounded)")
    return out
