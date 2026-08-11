"""The `--unbound` registry — the free-tool volume ceilings one run may lift.

`--unbound` processes all eligible retained evidence through free downstream tools without truncating
it. It never raises a provider page budget, reduces a credit reserve, enables a disabled provider,
broadens scope, bypasses a contact guard, removes rate / concurrency / resource protection, or implies
`--timeout 0`.

So this table is narrow: free-tool coverage / throughput bounds that participate in `--unbound`, plus
the held exceptions that must be printed rather than silently skipped. Everything else is an exclusion
with a reason in `EXCLUDED`, so the classification test can prove a ceiling was reasoned about rather
than forgotten.

`identity` says what a change to a bound invalidates:
    none          nothing — a per-run throughput allowance; the durable rotation continues.
    work_unit     the lane resumes by `events.work_unit`, so the bound must be in that unit or a bounded
                  completion claims work it never did.
    partition     the bound changes how the corpus is split; the ledger stays in use and an inherited
                  record is never certified clean, so a re-partitioned corpus is re-submitted.

Pure data plus lookups.
"""
from __future__ import annotations

from dataclasses import dataclass

IDENTITIES = ("none", "work_unit", "partition")
#: how the value is read: a PERFORMANCE knob through the strict parsers, or a module constant
READERS = ("strict_int", "budget_seconds", "module")
#: why a ceiling is not in this registry; each is a reason, never a silent omission.
EXCLUSION_KINDS = (
    "provider",     # paid / external: enablement, balance, reserve and page policy own it, not a flag
    "resource",     # blast radius, memory, sockets, disk — the scheduler reaches every chunk anyway
    "parser",       # the range a config value may hold; not a policy of its own
    "rate",         # pressure on the target or this host: the rate axis, never the volume one
    "engagement",   # chosen per engagement in target.yaml, not by a machine-wide flag
    "identity",     # slot / schema identity: versioned, never relaxed
    "continuation", # how many times a supervisor repeats a run — `--settle`'s business, not `--unbound`'s
    "not_a_bound",  # a sentinel, name or set that merely matches the naming convention
)
#: acquisition-side lanes: what they may obtain is owned by the provider's enablement/balance/reserve/
#: page policy, never a flag. A lane is here when Quarry owns the call, key or budget (ownership, not free).
PROVIDER_LANES = ("probe.favicon", "probe.cert", "probe.shodan_host", "vertical.censys",
                  "vertical.certspotter", "vertical.crtsh", "vertical.shosubgo", "vertical.github_subs",
                  "osint.whoxy")
#: ...and the ids above that are not in the source registry, listed exactly rather than by prefix.
PROVIDER_LANES_OUTSIDE_REGISTRY = ("osint.whoxy",)

#: bound lanes that are not registered sources, listed exactly. The OSINT preflight has no source
#: registry of its own; a lane's bound still appears in `quarry policy` and `--unbound` lifts it.
BOUND_LANES_OUTSIDE_REGISTRY = ("osint.asrank", "osint.rdap")

#: which door each acquisition lane executes through, declared so the acquisition closure can be checked
#: against real call sites rather than the mere existence of a gate.
PROVIDER_DOORS: dict[str, str] = {
    "probe.favicon": "run_providers",          # the shared Shodan credit coordinator
    "probe.cert": "run_providers",
    "probe.shodan_host": "run_provider",
    "vertical.censys": "run_provider",
    "vertical.certspotter": "run_provider",
    "vertical.crtsh": "run_provider",
    "vertical.shosubgo": "run_contract",       # an external binary we hand a key to
    # runs the tool directly (`exec_tool`), so neither registry gate covers it — it gates itself
    "vertical.github_subs": "direct_tool",
    "osint.whoxy": "direct_http",              # plain HTTP in `osint.py`, outside the source registry
}
DOORS = ("run_provider", "run_providers", "run_contract", "direct_http", "direct_tool")

#: every registered source, classified (the mechanism that finds an omission, not a hand-kept list):
#: quarry_provider = we call/key it; external_tool = its own config; target_facing = the target; local.
SOURCE_OWNERSHIP: dict[str, str] = {
    **{lane: "quarry_provider" for lane in
       ("probe.favicon", "probe.cert", "probe.shodan_host", "vertical.censys", "vertical.certspotter",
        "vertical.crtsh", "vertical.shosubgo", "vertical.github_subs")},
    **{lane: "external_tool" for lane in
       ("vertical.subfinder", "crawl.gau", "crawl.waymore_urls", "crawl.waymore_responses",
        "horizontal.caduceus", "horizontal.asnmap", "enrich.smap", "probe.smap", "params.oob_probe")},
    **{lane: "local" for lane in
       ("vertical.openintel", "horizontal.kaeferjaeger", "horizontal.mapcidr",
        "params.gf", "crawl.js_beautify", "crawl.jsluice_urls", "crawl.jsluice_secrets",
        "crawl.gitleaks", "crawl.trufflehog", "crawl.xnlinkfinder",
        "origin.correlation", "vertical.alterx_permute",
        # reads bundles already on disk and contacts nothing; the accepted-chunk fetch is
        # `crawl.js_fetch`, where the rate and budget live
        "crawl.jxscout_chunks",
        # analyses bundles already on disk, publishes an artifact, contacts nothing
        "crawl.jxscout_ast")},
    **{lane: "target_facing" for lane in
       ("content.ffuf", "crawl.js_fetch", "crawl.katana_headless", "crawl.katana_standard",
        "dns.dnsx_records", "enrich.a1d_brute", "enrich.dnsx_cname", "enrich.dnsx_resolve",
        "enrich.gowitness", "enrich.httpx", "enrich.nuclei_waf", "enrich.wildcard_a1d",
        "horizontal.cloud_buckets", "horizontal.revdns", "horizontal.tlsx_san", "params.arjun",
        "params.blind_xss", "params.dalfox", "params.dalfox_xss_fast", "params.nuclei_oast",
        "params.nuclei_scan", "params.nuclei_takeover", "params.redirect_confirm", "probe.ffuf_vhost",
        "probe.gowitness", "probe.httpx", "probe.naabu_infra", "probe.naabu_web", "probe.nmap_service",
        "probe.tlsx_certs", "vertical.puredns_brute", "vertical.puredns_resolve",
        "vertical.wildcard_http",
        # both active: the CSP lane fetches the apex through `fetch.scoped_headers` (guarded, paced), the
        # sourcemap lane fetches scoped `sourceMappingURL` targets.
        "horizontal.csp", "crawl.sourcemaps")},
}
OWNERSHIP_KINDS = ("quarry_provider", "external_tool", "target_facing", "local")


@dataclass(frozen=True)
class Bound:
    """One free-tool volume ceiling, and everything a flag or a report needs to know about it."""
    name: str
    reader: str
    lane: str                       # the source_id / lane it bounds
    default: int                    # the value with no config and no flag
    identity: str
    persistence: str                # what a change invalidates, in one sentence
    relaxable: bool                 # may `--unbound` lift it
    unbounded_value: int | None = None   # the value that means unbounded for this knob
    consumer_honours_unbounded: bool = False   # ...and whether the consumer already implements it
    held_reason: str = ""           # why it is not lifted — printed, never silent
    const: str | None = None        # "module:name" for a constant, for the drift check
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
                      ("SOURCEMAP_BUDGET_S", "crawl.sourcemaps"),
                      ("VHOST_BUDGET_S", "probe.ffuf_vhost"),
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
    Bound(name="NUCLEI_MAX_HOST_ERROR", reader="strict_int", lane="params.nuclei_scan", default=0,
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
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="free: unauthenticated HTTP probes of candidate bucket URLs, no key and no spend. Today it "
               "is a MEMBERSHIP cut (`all_names[:120]`, reported as a coverage gap) and the consumer does "
               "not yet interpret 0, so widening it belongs to the `--unbound` step"),

    Bound(name="ASRANK_ORGS", reader="module", lane="osint.asrank", default=10, identity="none",
          const="quarry_recon.osint:ASRANK_ORGS",
          persistence="nothing — the OSINT preflight has no durable rotation to continue",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="free: CAIDA ASRank is public, keyless and unmetered. It bounds how many MATCHING "
               "organisations one name search materialises; 0 pages through every match. The provider "
               "reports how many exist, so a withheld remainder is stated as OUR operator limit"),

    Bound(name="RDAP_LOOKUPS", reader="module", lane="osint.rdap", default=20, identity="none",
          const="quarry_recon.osint:RDAP_LOOKUPS",
          persistence="nothing — the OSINT preflight has no durable rotation to continue",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="free: unauthenticated RDAP lookups of addresses the apexes ALREADY resolve to (no key, "
               "no spend, no target contact beyond the DNS resolution that produced them). It was a "
               "MEMBERSHIP cut (`sorted(ips)[:20]`) with no remainder; now a throughput bound over the "
               "full eligible set in host-fair order, with the withheld remainder recorded as an "
               "operator limit"),

    Bound(name="JXSCOUT_ROUNDS", reader="module", lane="crawl.jxscout_chunks", default=3, identity="none",
          const="quarry_recon.phases.crawl:JXSCOUT_ROUNDS",
          persistence="NOTHING carries: entities are run-scoped, so a later run rediscovers the root "
                      "bundle and repeats rounds 1..N. A traversal the bound cut short is an unresolved "
                      "remainder (reported as one), never resumable progress",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="free: how DEEP the chunk->chunk traversal goes over bundles the run already downloaded. "
               "Fetching each accepted chunk is the JS lane's own rate/budget; this only decides how many "
               "rounds of ANALYSIS we do over evidence in hand. The brute-force knob is NOT here: "
               "guessing ids manufactures target requests, so it is engagement policy (MODES.JS_CHUNK_BRUTE)"),

    Bound(name="SPA_CAP", reader="module", lane="crawl.katana_headless", default=10, identity="none",
          const="quarry_recon.phases.crawl:SPA_CAP",
          persistence="nothing — the headless pass has no durable rotation to continue",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="a HIDDEN membership cut on already-retained hosts (`_spa_all[:10]`, reported as a coverage "
               "gap): exactly the PROCESSING side. It is function-local today, so wiring it means "
               "promoting it to a module constant AND teaching the consumer 0 — the widening step's work"),

    Bound(name="MAX_ITERS", reader="module", lane="vertical.alterx_permute", default=3, identity="none",
          const="quarry_recon.phases.vertical:MAX_ITERS",
          persistence="nothing — the permutation loop is run-scoped",
          relaxable=True, unbounded_value=0, consumer_honours_unbounded=True,
          note="rounds of permutation over names ALREADY held. Calling it `--settle`'s business was wrong: "
               "entities are RUN-scoped (a new Run starts empty, pinned in the registry tests), so a later "
               "run replays rounds 1-3 and can never reach round 4 — depth would be permanently "
               "unreachable. The loop already stops when a round adds nothing new, so the unbounded "
               "meaning is exactly that convergence; the consumer must be taught to read 0 that way"),

    # ── the one held exception ───────────────────────────────────────────────────────────────────
    Bound(name="A1D_WORD_CAP", reader="module", lane="enrich.a1d_brute", default=2000,
          identity="partition", const="quarry_recon.phases.enrich:A1D_WORD_CAP",
          persistence="slot boundaries (`sweep.allocate`'s cap); the ledger stays in use and an inherited "
                      "record is never certified clean",
          relaxable=False,
          held_reason="HELD by policy: the strict `0` bypass is gated on tightening the active DNS "
                      "boundary to exact labels and on vocabulary usefulness tiers (Lumpy, 2026-08-01)"),
)

#: ceilings that are not `--unbound`'s, with the reason each is excluded. Keyed by "module:name" for a
#: module constant, or by the bare PERFORMANCE key for a strict-parser knob.
EXCLUDED: dict[str, tuple[str, str]] = {
    # paid / external providers — enablement, balance, reserve and page policy own these
    "SHODAN_HOST_BUDGET_S": ("provider", "an ACQUISITION-side lane: external-provider policy retains "
                                         "ownership of what it may obtain. (The endpoint itself is "
                                         "MEASURED FREE — that is not the reason; ownership is.)"),
    "SHODAN_MAX_PAGES": ("provider", "the provider's own page policy — how much Quarry may OBTAIN"),
    "SHODAN_CREDIT_RESERVE": ("provider", "the operator's credit reserve: a spending control"),
    "SHODAN_PAGE_TTL_DAYS": ("provider", "how long a PURCHASED page may stand in for a fresh one. It "
                             "governs SPENDING (a shorter TTL buys more often), so it is the provider "
                             "axis and never `--unbound`'s — the flag authorises no purchase. Past the "
                             "TTL a page is kept as history, excluded from current coverage, and NOT "
                             "re-bought merely because time passed"),
    "WHOXY_PAGE_BUDGET": ("provider", "the provider's own per-run page policy"),
    "WHOXY_CREDIT_RESERVE": ("provider", "the operator's credit reserve: a spending control"),
    "PROVIDER_MAX_PAGES": ("provider", "bounded cursor pagination against an external provider"),
    "quarry_recon.phases.probe:_SHODAN_RESERVE_MAX": ("provider", "the operator's credit reserve"),
    "quarry_recon.phases.probe:_SHODAN_BACKOFF_MAX_S": ("provider", "provider retry backoff"),
    "quarry_recon.contract:_WHOXY_TOTAL_MAX_DIGITS": ("provider", "a Whoxy response sanity guard"),
    "quarry_recon.contract:_ERROR_BODY_LIMIT": ("provider", "how much of a provider error body is kept"),
    "quarry_recon.contract:_DETAIL_CHARS": ("provider", "a terminal REASON is one line; the body itself is "
                                            "kept whole by _ERROR_BODY_LIMIT above"),
    "quarry_recon.phases.vertical:CENSYS_READ_LIMIT": (
        "resource", "one provider response is read into memory; hitting it RAISES (`oversize`)"),
    "quarry_recon.phases.vertical:CRTSH_READ_LIMIT": (
        "resource", "one provider response is read into memory; hitting it RAISES (`oversize`)"),
    "quarry_recon.phases.vertical:CERTSPOTTER_READ_LIMIT": (
        "resource", "one provider response is read into memory; hitting it RAISES (`oversize`)"),
    "quarry_recon.pace:LOCK_WAIT_S": (
        "rate", "how long a request queues for its ACCOUNT's pacing slot before proceeding unpaced. It "
        "bounds waiting, never work: politeness must not become a hang"),
    "quarry_recon.pace:CLOCK_SKEW_S": (
        "not_a_bound", "tolerance for a shared wall-clock timestamp; beyond it the stamp is unusable"),
    "quarry_recon.phases.probe:_SHODAN_MIN_INTERVAL_S": (
        "rate", "the minimum gap between two SHODAN requests — pressure on a THIRD-PARTY API, not on a "
        "target (RATELIMIT.HTTP). It paces provider contact only; replaying owned evidence never waits"),
    "quarry_recon.phases.probe:SHODAN_PARSE_LIMIT": (
        "resource", "how large an artifact we PARSE in one process. The bytes are still acquired, owned "
        "and published beyond it — this bounds RAM, never what a paid response may contain"),
    "quarry_recon.phases.probe:SHODAN_READ_LIMIT": (
        "resource", "one provider response is read into memory. Hitting it RAISES (class `oversize`) and "
        "the page is reported as ours — it never drops rows from a page we keep"),
    "quarry_recon.shodan_sched:REJECTED_INLINE_LIMIT": (
        "not_a_bound", "the size at which a REFUSED paid response stops riding inside its rejection "
        "document and gets its own artifact instead. A layout choice: the bytes are kept whole either "
        "way, so nothing here bounds what is stored or what a lane may discover"),
    "quarry_recon.shodan_sched:MAX_REJECT_REASONS": (
        "not_a_bound", "how many objections a coverage REASON quotes. Prose in a telemetry line; the "
        "count is exact in `pages_rejected` and every refused response is kept on disk"),

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
    "quarry_recon.evidence:MAX_PARSE": ("resource", "the artifact is stored WHOLE either way; this is the "
                                        "ceiling on holding one as a str, above which interpretation is "
                                        "deferred and recorded, never dropped"),
    "quarry_recon.evidence:STREAM_CHUNK": ("resource", "bytes held in RAM while streaming to disk"),
    "quarry_recon.evidence:STREAM_DEADLINE_S": ("resource", "wall clock on a socket that never reaches "
                                                "EOF; the partial bytes are kept and the gap reported"),
    "quarry_recon.evidence:_DEEP_SCAN_WINDOW": ("resource", "bytes held in RAM per mining window over a "
                                                "stored artifact of any size"),
    "quarry_recon.evidence:_SHAPE_HIGH_MIN": ("resource", "a PRESENTATION threshold: shorter values "
                                              "sort below the interesting ones in the review queue and "
                                              "are retained exactly the same"),
    "quarry_recon.evidence:_DEEP_SCAN_OVERLAP": ("resource", "bytes carried between windows so a secret "
                                                 "on a boundary is not cut in half"),
    "quarry_recon.bootstrap:DISK_MIN": ("resource", "a run that fills the disk loses evidence it has"),
    "quarry_recon.sweep:_UNSELECTABLE_DETAIL": ("resource", "a diagnostic list bound; the counters beside "
                                                            "it are authoritative"),

    # acquisition + corpus envelopes — structural truthfulness/safety ceilings, not per-run volume knobs.
    # Overflow is refused with a durable remainder, never dropped; `--unbound` uses work a run already has.
    "quarry_recon.contract:_FREE_RESERVE_DEFAULT": ("resource", "the default free-space reserve kept on the "
                                                    "artifact filesystem; an always-on host guard"),
    "quarry_recon.contract:_LAYER_CAP_ATTR": ("not_a_bound", "a layer->attribute-name map naming which byte "
                                              "layer bound a stream, not a numeric ceiling"),
    "quarry_recon.envelope:MAX_BYTES_PER_KEY": ("resource", "the supported per-key corpus byte envelope; "
                                                "growth past it is refused with a durable remainder"),
    "quarry_recon.envelope:MAX_CORPUS_BYTES_PER_ENTITY": ("resource", "the supported per-entity corpus byte "
                                                          "envelope; overflow refused with a durable remainder"),
    "quarry_recon.envelope:MAX_KEYS_PER_ENTITY": ("resource", "the supported per-entity distinct-key envelope; "
                                                  "overflow refused with a durable remainder"),
    "quarry_recon.envelope:RSS_BUDGET_MB": ("resource", "resident-memory budget for the bounded finalize; work "
                                            "spills to on-disk sqlite past it, nothing dropped"),
    "quarry_recon.store:_MAX_LEDGER_KEY": ("resource", "a ledger key longer than this is damage, rejected "
                                           "before it is materialized"),
    "quarry_recon.store:_MAX_LEDGER_LINE": ("resource", "a ledger line longer than this is damage, rejected "
                                            "before it is materialized/parsed"),

    # parser ranges for the acquisition byte knobs
    "quarry_recon.contract:_ACQUIRE_BYTES_MAX": ("parser", "the strict parser's ceiling for the ACQUIRE_* "
                                                 "byte knobs (1 PiB)"),

    # continuation — the supervisor's own bounds. `--unbound` is about one run's volume; how many runs a
    # campaign creates, and when it gives up, is `--settle`'s question and carries its own named stops.
    "quarry_recon.campaign:MAX_CHILDREN": ("continuation", "children one campaign may create"),
    "quarry_recon.campaign:NO_PROGRESS_LIMIT": ("continuation", "idle children before a campaign stops"),

    # rate / concurrency — pressure on the target or on this host
    "ARJUN_TARGETS": ("rate", "how many arjun processes run at once (one per target, host-fair)"),
    "DALFOX_TARGETS": ("rate", "dalfox pool size"),
    "DALFOX_CHUNK": ("resource", "targets per dalfox invocation: one process's blast radius"),
    "KATANA_PARALLELISM": ("rate", "katana's own parallelism"),
    "NUCLEI_BULK_SIZE": ("rate", "nuclei requests in flight per template"),
    "NUCLEI_CHUNK_HOSTS": ("resource", "hosts per nuclei invocation: one process's blast radius"),
    "quarry_recon.evidence:_SSTI_MAX_PARAMS": ("rate", "probes per endpoint is request pressure"),
    "quarry_recon.phases.crawl:MAX_JS": ("resource", "a 15 MB PER-ITEM guard on one downloaded file"),
    "quarry_recon.phases.crawl:MAX_MAP": ("resource", "a 20 MB PER-ITEM guard on one source map"),
    "quarry_recon.phases.crawl:JXSCOUT_BRUTE_LIMIT": ("engagement", "chunk-id GUESSING manufactures "
        "requests for paths no bundle named, so it is chosen per engagement (MODES.JS_CHUNK_BRUTE, "
        "default 0) and `--unbound` may never lift it — that flag uses work a run already has"),
    "quarry_recon.config:MAX_JS_CHUNK_BRUTE": ("engagement", "the CEILING on that engagement knob"),
    "quarry_recon.osint:_ASN_MAX": ("not_a_bound", "the largest number a 32-bit AS number can BE — a "
                                                  "validity range for a provider value, not a ceiling on "
                                                  "how much work we do"),
    "quarry_recon.osint:_ASRANK_ASN_PAGE": ("resource", "how many member ASNs ONE request asks for; the "
                                                        "org's own `numberAsns` drives a follow-up query, "
                                                        "so membership is never truncated by it"),
    "quarry_recon.notify:_MAX_BULLETS": ("not_a_bound", "how many lines one NOTIFICATION prints before "
                                                      "pointing at the manifest: presentation, not "
                                                      "coverage — nothing is dropped from the evidence"),
    "quarry_recon.netguard:_MAX_WORKERS": ("rate", "local concurrency"),
    "quarry_recon.settings:_CAP": ("rate", "per-tool worker caps"),

    # parser ranges — what a config value may say, not what the run does
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


def _module_default(bound: Bound) -> int:
    """The default of a module-constant bound: the live constant where one exists, else the declared
    value for a function-local one. The registry's drift test keeps the two equal."""
    if bound.const and not bound.const_local:
        import importlib
        mod, _, const = bound.const.partition(":")
        return int(getattr(importlib.import_module(mod), const))
    return bound.default


def limit(name: str) -> int:
    """The effective value of a module-constant bound — its declared default unless a flag overrode it.

    A module constant cannot be read by `settings`, so a consumer honouring `--unbound` asks here instead
    of reading the constant directly; this adds only the flag layer on top."""
    from . import settings
    b = by_name(name)
    if b is None:
        raise KeyError(name)                       # an unregistered bound has no policy to apply
    default = _module_default(b)
    value, _src, _rej, _rs = settings.flag_int(
        name, default=default, maximum=max(default, b.unbounded_value or 0, 10 ** 9))
    return value


def unbound_overrides() -> dict:
    """What `--unbound` sets, straight from the registry: every relaxable bound at its unbounded value.

    An unregistered knob is not lifted, a held one keeps its bound with the reason printed, and provider
    controls are not here at all (they are excluded, with their own ownership)."""
    return {b.name: b.unbounded_value for b in BOUNDS if b.relaxable}


def relaxable() -> tuple[Bound, ...]:
    """Everything `--unbound` lifts, in registry order."""
    return tuple(b for b in BOUNDS if b.relaxable)


def held() -> tuple[Bound, ...]:
    """Registry bounds `--unbound` deliberately does not lift — printed with their reason, never silent."""
    return tuple(b for b in BOUNDS if not b.relaxable)


# ── the effective policy: what this run will actually apply, and where each value came from ──────────
def effective(bound: Bound) -> tuple[int, str, str | None, str | None]:
    """`(value, source, rejected, rejected_source)` for one bound.

    The source comes out of the same parse as the value: a value the strict parser refused is attributed
    to the default, and what was refused is reported rather than hidden behind an author it did not have."""
    from . import budget, settings
    if bound.reader == "budget_seconds":
        return settings.strict_int_with_source(bound.name, default=0, maximum=budget._MAX_BUDGET_S)
    if bound.reader == "strict_int":
        return settings.strict_int_with_source(bound.name, default=bound.default,
                                               maximum=bound.maximum or bound.default)
    # a module constant is not configurable but it is relaxable, so the same override-aware parse runs
    # over it, and the report shows a lifted cap as `flag` exactly like a knob.
    default = _module_default(bound)
    # flag-only: `config.yaml` has no say over a module constant
    return settings.flag_int(bound.name, default=default,
                             maximum=max(default, bound.unbounded_value or 0, 10 ** 9))


def snapshot() -> list[dict]:
    """The whole effective policy, one row per registered bound. Printed at run start and persisted into
    the manifest: a run's ceilings are evidence, not shell history."""
    rows = []
    for b in BOUNDS:
        value, src, rejected, rejected_src = effective(b)
        rows.append({"name": b.name, "lane": b.lane, "value": value, "default": b.default,
                     "source": src, "relaxable": b.relaxable,
                     "unbounded": b.relaxable and value == b.unbounded_value,
                     "rejected": rejected, "rejected_source": rejected_src,
                     "held_reason": b.held_reason})
    return rows


def render(rows: list[dict] | None = None) -> list[str]:
    """The operator-facing lines: what is unbounded, what a flag or config changed, and what is held with
    the reason. A bound at its default is summarised rather than listed — the point is what differs from
    the ordinary run, plus every exception we declined to lift."""
    rows = snapshot() if rows is None else rows
    out, plain, free = [], 0, 0
    for r in rows:
        if not r["relaxable"]:
            out.append(f"  HELD      {r['name']} = {r['value']} ({r['lane']}) — {r['held_reason']}")
        elif r["rejected"] is not None:
            # written, refused, and named: a value the parser threw away must not read as policy
            out.append(f"  DEFAULT   {r['name']} = {r['value']} ({r['lane']}) — the "
                       f"{r['rejected_source']} value {r['rejected']} was REJECTED by the strict parser")
        elif r["source"] == "default":
            plain += 1
            free += bool(r["unbounded"])         # unbounded because that is the default, not by request
        elif r["unbounded"]:
            out.append(f"  UNBOUNDED {r['name']} ({r['lane']}) — by {r['source']}")
        else:
            out.append(f"  {r['source'].upper():<9} {r['name']} = {r['value']} "
                       f"({r['lane']}, default {r['default']})")
    if plain:
        out.append(f"  {plain} bound(s) at their default ({free} of them already unbounded)")
    return out
