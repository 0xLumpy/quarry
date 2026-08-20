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
    "vertical.shosubgo": "run_provider",       # Quarry's in-process Shodan DNS API adapter
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
        "horizontal.caduceus", "horizontal.asnmap", "enrich.smap", "probe.smap")},
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
        "params.nuclei_scan", "params.nuclei_takeover", "params.oob_probe",
        "params.redirect_confirm", "probe.ffuf_vhost",
        "probe.gowitness", "probe.httpx", "probe.naabu_infra", "probe.naabu_web", "probe.nmap_service",
        "probe.tlsx_certs", "probe.nuclei_waf", "vertical.puredns_brute", "vertical.puredns_resolve",
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
    "quarry_recon.fetch:_MAX_NATIVE_SEND_CHUNK": (
        "resource", "the largest request-write slice admitted to one nonblocking native HTTP effect-fence "
                    "epoch; larger bodies are streamed through repeated bounded writes"),
    "quarry_recon.bootstrap:DISK_MIN": ("resource", "a run that fills the disk loses evidence it has"),
    "quarry_recon.sweep:_UNSELECTABLE_DETAIL": ("resource", "a diagnostic list bound; the counters beside "
                                                            "it are authoritative"),
    "quarry_recon.netguard:_MAX_INTERFACE_RECORDS": (
        "resource", "the bounded getifaddrs traversal used to refresh scanner-owned addresses before "
                    "each network decision; overflow refuses contact rather than accepting a prefix"),
    "quarry_recon.oos_regex:_MAX_OOS_PATTERN_BYTES": (
        "parser", "the shared profile/parent/broker OOS grammar byte ceiling; larger expressions are "
                  "refused before attacker-controlled hostname matching"),
    "quarry_recon.network_policy:_MAX_TRACE_BYTES": (
        "resource", "the canonical byte envelope for one durable network-policy trace row; oversize "
                    "truth is refused rather than truncated"),
    "quarry_recon.network_policy:_MAX_BROKER_POLICY_BYTES": (
        "resource", "the serialized child broker policy must leave room for its enclosing durable scope "
                    "trace and is refused before launch when it cannot"),
    "quarry_recon.network_policy:_MAX_EXECUTABLE_BYTES": (
        "resource", "the largest helper identity the parent may authorize for broker authentication; "
                    "larger launch identities are rejected before network authority"),
    "quarry_recon.network_policy:_MAX_NETWORK_HOSTS": (
        "resource", "the bounded exact host set a single external-tool launch may resolve and bind; "
                    "larger work must be split before any child is started"),
    "quarry_recon.network_broker:_MAX_SOCKADDR_BYTES": (
        "resource", "the allocation bound for one copied tracee sockaddr; an oversized address is "
                    "rejected before any broker-owned socket effect"),
    "quarry_recon.network_broker:_MAX_PROC_STATUS_BYTES": (
        "resource", "the allocation bound for one procfs thread-identity record; overflow refuses the "
                    "notification rather than trusting partial process identity"),
    "quarry_recon.network_broker:_MAX_DECISIONS": (
        "resource", "the bounded in-memory decision journal for one broker invocation; overflow makes "
                    "settlement incomplete and can never certify a truncated trace"),
    "quarry_recon.network_broker:_MAX_RECORD_BYTES": (
        "resource", "the allocation bound for one canonical broker decision record; oversize control "
                    "evidence is rejected rather than truncated"),
    "quarry_recon.network_broker:_MAX_DECISION_SUMMARY_BYTES": (
        "resource", "the finite component-local broker journal envelope; the backend remains incomplete "
                    "until a compact authenticated artifact summary replaces inline settlement rows"),
    "quarry_recon.network_broker:_MAX_EXECUTABLE_BYTES": (
        "resource", "the broker-side tracee executable read budget, matched to the parent-authorized "
                    "identity envelope before any body read"),
    "quarry_recon.network_broker:_MAX_EXECUTABLE_HASH_SECONDS": (
        "resource", "the finite per-identity hashing deadline checked with notification validity between "
                    "bounded regular-file reads"),
    "quarry_recon.network_broker:_MAX_SEND_BYTES": (
        "resource", "the maximum tracee payload copied for one emulated send; oversize input is refused "
                    "before the broker performs any network effect"),
    "quarry_recon.network_broker:_MAX_IOVECTORS": (
        "resource", "the allocation bound for one emulated sendmsg vector table; overflow is rejected "
                    "before copying payloads or contacting a peer"),
    "quarry_recon.network_broker:_MAX_CONTROL_BYTES": (
        "resource", "the parser bound used when rejecting ancillary sendmsg data; no accepted control "
                    "payload is truncated or forwarded"),
    "quarry_recon.network_broker:_MAX_RIGHTS_FDS": (
        "resource", "the kernel-compatible per-message SCM_RIGHTS descriptor allocation bound; overflow "
                    "is rejected before any local IPC effect"),
    "quarry_recon.network_broker:_MAX_INHERITED_FDS": (
        "resource", "the bounded pre-exec procfs descriptor inventory; overflow refuses the launcher "
                    "rather than leaving an inherited connected socket unaudited"),
    "quarry_recon.network_broker:_MAX_REAPED_DESCENDANTS": (
        "resource", "the bounded adopted-child settlement journal; overflow refuses completion rather "
                    "than losing daemon cleanup or exit-status evidence"),
    "quarry_recon.network_broker:_MAX_CONTROL_GRANTS": (
        "resource", "the bounded one-shot browser-control accept grant set; capacity exhaustion refuses "
                    "the connector before the accepted descriptor can reach Chromium"),
    "quarry_recon.network_broker:_MAX_NOTIFICATION_WORKERS": (
        "resource", "the finite per-invocation notification concurrency envelope; excess syscalls are "
                    "refused rather than starving accept/connect authority or allocating threads"),
    "quarry_recon.network_cdp:_MAX_CDP_HTTP_BYTES": (
        "resource", "the strict worker-owned DevTools HTTP upgrade header allocation bound; oversize "
                    "input is refused before a WebSocket session is established"),
    "quarry_recon.network_cdp:_MAX_CDP_MESSAGE_BYTES": (
        "resource", "the per-message WebSocket and Chromium-pipe parser bound; oversized CDP messages "
                    "fail the request-owned bridge without truncation"),
    "quarry_recon.network_cdp:_MAX_CDP_BUFFER_BYTES": (
        "resource", "the per-direction DevTools relay backpressure bound; overflow cancels the bridge "
                    "rather than accumulating unbounded controller or browser data"),
    "quarry_recon.network_cdp:_MAX_CDP_RECORDS": (
        "resource", "the bounded request-owned DevTools control journal; overflow marks the bridge "
                    "incomplete and synchronously cancels further control effects"),
    "quarry_recon.network_cdp:_MAX_CDP_RECORD_BYTES": (
        "resource", "the canonical allocation bound for one DevTools control record; oversize evidence "
                    "fails instead of being truncated"),
    "quarry_recon.network_cdp:_MAX_CDP_SUMMARY_BYTES": (
        "resource", "the finite component-local DevTools journal envelope pending authenticated streamed "
                    "artifact persistence before backend completion"),
    "quarry_recon.network_cdp:_MAX_CDP_FOREIGN_CLIENTS": (
        "resource", "the hostile unauthenticated DevTools accept-drain bound; exhaustion cancels the "
                    "bridge before a foreign client reaches Chromium"),
    "quarry_recon.network_cdp:_MAX_CDP_METHODS": (
        "resource", "the bounded distinct CDP method inventory returned with boundary evidence; excess "
                    "method diversity fails the bridge instead of losing certificate-policy truth"),
    "quarry_recon.network_dns:_MAX_DNS_MESSAGE_BYTES": (
        "resource", "the strict UDP/TCP DNS response allocation bound for the pinned browser proxy; "
                    "oversize replies are refused before address admission"),
    "quarry_recon.network_dns:_MAX_DNS_POINTERS": (
        "resource", "the DNS compression-pointer traversal bound; cycles or excess indirection refuse "
                    "the response rather than yielding a partial hostname"),
    "quarry_recon.network_dns:_MAX_DNS_RECORDS": (
        "resource", "the finite answer/authority/additional record parser bound for one explicit DNS "
                    "response; overflow refuses the request"),
    "quarry_recon.network_dns:_MAX_DNS_CNAME_DEPTH": (
        "resource", "the explicit per-request CNAME follow bound; exhaustion is indeterminate and no "
                    "upstream connection is attempted"),
    "quarry_recon.network_proxy:_MAX_PROXY_HEADER_BYTES": (
        "resource", "the private browser proxy's per-request header allocation bound; oversized input "
                    "is refused before DNS or upstream contact"),
    "quarry_recon.network_proxy:_MAX_PROXY_LINE_BYTES": (
        "resource", "the strict HTTP request/header line parser bound; an oversized line is refused "
                    "before authority classification"),
    "quarry_recon.network_proxy:_MAX_PROXY_AUTHORITY_BYTES": (
        "resource", "the bounded CONNECT/Host authority parser input; overflow is refused before DNS"),
    "quarry_recon.network_proxy:_MAX_PROXY_REQUEST_BODY_BYTES": (
        "resource", "the maximum browser request body streamed by one proxy request; larger requests "
                    "are refused without buffering or contacting an upstream"),
    "quarry_recon.network_proxy:_MAX_PROXY_CONNECTIONS": (
        "resource", "the finite invocation-local proxy connection/thread capacity; excess accepts are "
                    "closed and truthfully recorded rather than queued without limit"),
    "quarry_recon.network_proxy:_MAX_PROXY_RECORDS": (
        "resource", "the bounded proxy/DNS/peer decision journal; overflow marks settlement incomplete"),
    "quarry_recon.network_proxy:_MAX_PROXY_RECORD_BYTES": (
        "resource", "the canonical byte bound for one proxy decision; oversize evidence fails the "
                    "session rather than being truncated"),
    "quarry_recon.network_proxy:_MAX_PROXY_SUMMARY_BYTES": (
        "resource", "the finite component-local proxy/DNS journal envelope pending authenticated streamed "
                    "artifact persistence before backend completion"),
    "quarry_recon.network_proxy:_MAX_PROXY_BUFFER_BYTES": (
        "resource", "the per-direction streaming relay buffer bound; backpressure replaces unbounded "
                    "request or response accumulation"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_ROWS": (
        "resource", "the exact invocation-owned network decision row envelope; the next plan is refused "
                    "before an effect instead of producing an unauthenticated journal prefix"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_BYTES": (
        "resource", "the preallocated logical byte envelope for one invocation-owned network trace; "
                    "capacity is durably reserved before tool effects begin"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_ROW_BYTES": (
        "resource", "the canonical framing bound for one network trace row; oversize truth is refused "
                    "before its corresponding network effect"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_JSON_DEPTH": (
        "parser", "the recursion-safety grammar for one canonical network trace row or compact settlement"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_INTEGER_MAGNITUDE": (
        "parser", "the portable exact-integer domain of the canonical network trace schema"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_SETTLEMENT_BYTES": (
        "resource", "the compact terminal network-trace identity envelope embedded in the existing durable "
                    "settlement record; full decision rows remain in the authenticated artifact"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_COMPONENTS": (
        "resource", "the finite typed component inventory sharing one invocation trace; unknown or excess "
                    "component identities are refused rather than merged"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_RESERVED_ROWS": (
        "resource", "the maximum durable future-row reservation attached to one pre-effect plan; excess "
                    "work is refused before contact"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_RELPATH_BYTES": (
        "identity", "the bounded descriptor-relative identity of the private invocation trace artifact"),
    "quarry_recon.network_trace:NETWORK_TRACE_READ_CHUNK_BYTES": (
        "resource", "the bounded replay-validation read allocation; it does not truncate the authenticated "
                    "artifact byte envelope"),
    "quarry_recon.network_trace:NETWORK_TRACE_MIN_ALLOCATION_GRANULARITY": (
        "identity", "the minimum trusted filesystem allocation-unit identity accepted before aligned "
                    "network-trace tail deallocation"),
    "quarry_recon.network_trace:NETWORK_TRACE_MAX_ALLOCATION_GRANULARITY": (
        "resource", "the maximum trusted filesystem allocation unit used to bound aligned preallocation-tail "
                    "retention and deallocation"),

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

    # Phase 1 execution/repository infrastructure.  These limits protect identity, bounded control
    # parsing and ownership recovery; none controls how much eligible reconnaissance `--unbound` runs.
    "quarry_recon._fd_claims:MAX_CLAIM_ERRORS": (
        "resource", "the bounded in-memory fault journal for one descriptor claim; the terminal "
                    "disposition and dropped-fault counter remain explicit"),
    "quarry_recon._fd_claims:MAX_DROPPED_ERRORS": (
        "not_a_bound", "the saturation value of a diagnostic dropped-fault counter, not a limit on "
                       "descriptor fencing attempts or reconnaissance work"),
    "quarry_recon.privfs:_MAX_COMPONENTS": (
        "identity", "the structural grammar of one descriptor-relative managed path; overlong path "
                    "identities are rejected rather than partially traversed"),
    "quarry_recon.privfs:_MAX_COMPONENT_BYTES": (
        "identity", "the UTF-8 component grammar of a descriptor-relative managed path, not a volume "
                    "allowance"),
    "quarry_recon.privfs:_MAX_RELATIVE_PATH_BYTES": (
        "identity", "the encoded grammar of one descriptor-relative managed path, never a ceiling on "
                    "the evidence stored below a valid path"),
    "quarry_recon.privfs:_MAX_DESCRIPTOR_CLAIM_ERRORS": (
        "resource", "the private-filesystem alias for the bounded per-descriptor diagnostic journal; "
                    "ownership settlement is still exact"),
    "quarry_recon.privfs:_MAX_DESCRIPTOR_CLAIM_DROPPED": (
        "not_a_bound", "the private-filesystem alias for the diagnostic counter's saturation value, "
                       "not a work or recovery limit"),
    "quarry_recon.privfs:_MAX_WORKER_PID": (
        "identity", "the accepted operating-system PID domain for a stage-handoff correlation identity; "
                    "it does not bound child execution"),
    "quarry_recon.phases.vertical:SHODAN_DOMAIN_READ_LIMIT": (
        "resource", "the bounded acquisition-response allocation for one Shodan domain payload; an "
                    "oversized response is rejected rather than truncated or accepted as complete"),
    "quarry_recon.release_evidence:MAX_JSON_DEPTH": (
        "resource", "the recursion-safety bound for one untrusted release-evidence control record; a "
                    "deeper record is rejected and never treated as accepted evidence"),
    "quarry_recon.release_evidence:MAX_JSON_INTEGER": (
        "parser", "the exact scalar range accepted by the versioned release-evidence JSON contract, "
                  "not a reconnaissance or evidence-retention allowance"),
    "quarry_recon.release_evidence:MAX_RECORD_BYTES": (
        "resource", "the allocation bound for one versioned release-evidence control record; oversize "
                    "control input is rejected and does not truncate captured target evidence"),
    "quarry_recon.report_truth:MAX_PRIVATE_REPORT_INTEGER": (
        "parser", "the portable signed-integer range of the private-report v2 control fields, not a "
                  "reconnaissance volume allowance"),
    "quarry_recon.report_truth:MAX_PRIVATE_REPORT_BYTES": (
        "resource", "the allocation/publication envelope for one deterministic private report; "
                    "overflow fails finalization and never truncates the current evidence projection"),
    "quarry_recon.report_truth:MAX_REFERENCE_DEPTH": (
        "identity", "the structural grammar for a nested provenance/path reference; deeper identities "
                    "are rejected rather than partially traversed"),
    "quarry_recon.report_truth:MAX_REFERENCES_PER_OBSERVATION": (
        "resource", "the allocation bound for one observation's explicit artifact-reference roster; "
                    "overflow fails report finalization and is never silently omitted"),
    "quarry_recon.release_v310_08:MAX_V31008_GATE_REPORT_BYTES": (
        "resource", "the allocation bound for one descriptive report-performance evidence record; "
                    "oversize input is rejected and can never close the still-open performance gate"),
    "quarry_recon.release_v310_08:MAX_V31008_GATE_REPORT_TRIALS": (
        "resource", "the retained raw-trial count bound for one descriptive report-performance record; "
                    "overflow is rejected rather than summarized away"),
    "quarry_recon.release_evidence:MAX_TAXONOMY_RECORD_BYTES": (
        "resource", "the allocation bound for one versioned pytest-taxonomy artifact; oversize input is "
                    "rejected rather than truncated or accepted as complete release evidence"),
    "quarry_recon.resource_contract:MAX_RESOLVER_HOST_BYTES": (
        "resource", "the encoded per-host allocation bound in one accepted resolver corpus; an oversized "
                    "identity is rejected before resolution rather than truncated"),
    "quarry_recon.resource_contract:MAX_RESOLVER_HOSTS": (
        "resource", "the finite host-count support boundary for one resolver corpus; an overflow is "
                    "refused before contact and retained exactly only when the bounded payload fits"),
    "quarry_recon.resource_contract:MAX_RESOLVER_CORPUS_DEADLINE_SECONDS": (
        "resource", "the finite default wall-clock authority for one resolver corpus; late workers are "
                    "killed and cannot mutate the sealed result"),
    "quarry_recon.resource_contract:MAX_ACQUISITION_LEASE_WAIT_SECONDS": (
        "resource", "the finite default wait for cross-process filesystem and destination ownership; "
                    "expiry refuses the acquisition rather than writing without authority"),
    "quarry_recon.resource_contract:MAX_RESOLVER_RESULT_BYTES": (
        "resource", "the nonblocking per-worker resolver result frame allocation bound; an oversized "
                    "frame is rejected as invalid work output rather than partially decoded"),
    "quarry_recon.resource_contract:MAX_RESOLVER_REMAINDER_BYTES": (
        "resource", "the allocation bound for one exact durable resolver work record; an oversized "
                    "corpus is terminally refused rather than partially persisted as replayable"),
    "quarry_recon.run_manifest:MAX_JSONL_LINE_BYTES": (
        "resource", "the allocation bound for validating one immutable manifest-bound JSONL record; an "
                    "oversized row invalidates the manifest rather than being truncated or accepted"),
    "quarry_recon.run_manifest:MAX_JSON_DEPTH": (
        "resource", "the recursion-safety bound for one untrusted run-manifest document; deeper input is "
                    "rejected rather than partially interpreted"),
    "quarry_recon.run_manifest:MAX_JSON_INTEGER": (
        "parser", "the portable scalar range of the versioned run-manifest JSON contract, not a work or "
                  "evidence-volume allowance"),
    "quarry_recon.run_manifest:MAX_MANIFEST_BYTES": (
        "resource", "the allocation bound for one committed run-manifest control document; an oversized "
                    "manifest is rejected rather than truncated"),
    "quarry_recon.run_manifest:MAX_STRUCTURED_FILE_BYTES": (
        "resource", "the allocation bound for one manifest-bound structured control file; raw evidence "
                    "continues to be hashed as a stream"),
    "quarry_recon.run_manifest:MAX_BASE_FILES": (
        "resource", "the fail-closed file-count bound for authenticating one immutable run evidence tree; "
                    "overflow invalidates the manifest"),
    "quarry_recon.run_manifest:MAX_BASE_TREE_DEPTH": (
        "resource", "the fail-closed directory-recursion bound for one immutable run evidence tree; it "
                    "does not truncate an accepted inventory"),
    "quarry_recon.run_manifest:MAX_BASE_INVENTORY_BYTES": (
        "resource", "the streamed total-byte authentication bound for one immutable run evidence tree; "
                    "overflow refuses the manifest rather than accepting a prefix"),
    "quarry_recon.revision:MAX_REVISION_POINTER_BYTES": (
        "resource", "the pre-allocation bound for one strict revision control pointer; oversized pointer "
                    "bytes are rejected before JSON decoding"),
    "quarry_recon.revision:MAX_REVISION_SEGMENT_BYTES": (
        "resource", "the per-segment allocation/publication bound for late JSONL evidence; overflow makes "
                    "the revision unusable and is never accepted as a prefix"),
    "quarry_recon.revision:MAX_REVISION_SUPPLEMENT_BYTES": (
        "resource", "the aggregate byte envelope for all segments in one published revision chain; the "
                    "next revision is refused when it would exceed the complete supported chain"),
    "quarry_recon.revision:MAX_REVISION_RAW_FILE_BYTES": (
        "resource", "the per-file allocation bound for one revision-owned raw proof artifact; oversized "
                    "proof cannot be claimed by a valid revision"),
    "quarry_recon.revision:MAX_REVISION_RAW_TOTAL_BYTES": (
        "resource", "the aggregate byte envelope for all revision-owned raw proof artifacts referenced by "
                    "the effective late-evidence view"),
    "quarry_recon.revision:MAX_REVISION_RAW_FILES": (
        "resource", "the finite raw-proof reference count for one revision; overflow refuses the whole "
                    "claim set rather than retaining a prefix"),
    "quarry_recon.revision:MAX_REVISION_VIEW_FILE_BYTES": (
        "resource", "the per-file allocation bound while hashing a rebuildable private revision view"),
    "quarry_recon.revision:MAX_REVISION_VIEW_TOTAL_BYTES": (
        "resource", "the aggregate byte envelope while reconciling rebuildable private revision views"),
    "quarry_recon.revision:MAX_REVISION_VIEW_FILES": (
        "resource", "the finite object-count envelope while enumerating one private revision view tree"),
    "quarry_recon.revision:MAX_REVISION_TREE_DEPTH": (
        "resource", "the recursion/work bound for private revision raw and derived-view path trees"),
    "quarry_recon.revision:MAX_REVISION_ROOT_ENTRIES": (
        "resource", "the bounded no-follow inventory size of one revision authority directory; overflow "
                    "makes reads and further publication fail closed"),
    "quarry_recon.revision:MAX_REVISION_SEGMENTS": (
        "resource", "the finite segment-count envelope for one exact late-evidence chain; overflow is "
                    "refused rather than partially certified"),
    "quarry_recon.campaign:MAX_CAMPAIGN_LEDGER_BYTES": (
        "resource", "the fail-closed allocation bound for one versioned campaign control ledger; an "
                    "oversized ledger is refused rather than parsed or accepted as terminal truth"),
    "quarry_recon.campaign:MAX_CAMPAIGN_UNION_BYTES": (
        "resource", "the fail-closed streamed read bound for one immutable campaign-union generation; "
                    "overflow makes the union unusable rather than accepting a prefix"),
    "quarry_recon.release_h0:_MAX_BWRAP_STATUS_BYTES": (
        "resource", "the bounded parent read of one bubblewrap status control channel; overflow invalidates "
                    "the H0 diagnostic rather than truncating or accepting the status"),
    "quarry_recon.release_h0:_MAX_COMMAND_OUTPUT": (
        "resource", "the bounded output of one H0 prerequisite or tool query; overflow refuses the "
                    "diagnostic rather than treating partial output as authoritative"),
    "quarry_recon.release_h0:_MAX_ISOLATION_REPORT_BYTES": (
        "resource", "the bounded parent read of one H0 isolation control report; overflow invalidates the "
                    "diagnostic rather than truncating or accepting the report"),
    "quarry_recon.release_h0:_MAX_LOG_BYTES": (
        "resource", "the per-stream parent-memory and log-artifact guard for one H0 diagnostic; overflow "
                    "fails the diagnostic rather than publishing partial logs as complete"),
    "quarry_recon.runner_containment:DESCENDANT_LIMIT": (
        "not_a_bound", "a fixed containment failure-reason string naming a limit breach, not the limit "
                       "itself"),
    "quarry_recon.runner_containment:_MAX_CGROUP_COMPONENTS": (
        "identity", "the structural grammar of an authenticated cgroup membership path; an invalid "
                    "identity is refused"),
    "quarry_recon.runner_containment:_MAX_CGROUP_PATH_BYTES": (
        "identity", "the encoded grammar of an authenticated cgroup membership path, not a scan-volume "
                    "control"),
    "quarry_recon.runner_containment:_MAX_DESCENDANT_CGROUPS": (
        "resource", "a safety bound on adversarial descendant-cgroup traversal; crossing it fails "
                    "containment settlement rather than reporting the process tree clean"),
    "quarry_recon.runner_containment:_MAX_DESCENDANT_DEPTH": (
        "resource", "a safety bound on adversarial descendant-cgroup traversal depth; crossing it fails "
                    "containment settlement rather than omitting work"),
    "quarry_recon.runner_containment:_MAX_DESCENDANT_ENTRIES": (
        "resource", "a safety bound on directory entries inspected while settling a cgroup tree; "
                    "crossing it is a typed containment failure"),
    "quarry_recon.runner_containment:_MAX_EVENTS_TEXT": (
        "resource", "the bounded read of one kernel cgroup.events control file; oversize input fails "
                    "containment validation"),
    "quarry_recon.runner_containment:_MAX_PROC_TEXT": (
        "resource", "the bounded read of one procfs/cgroup control file; oversize input fails containment "
                    "validation"),
    "quarry_recon.runner_containment:_MAX_SAFE_DEADLINE": (
        "parser", "the strict numeric range accepted for an absolute monotonic containment deadline, "
                  "not a deadline chosen by policy"),
    "quarry_recon.runner_native:_MAX_POLICIES": (
        "resource", "the descriptor and staging blast-radius bound for one exact native-output policy "
                    "tuple; excess policies are refused in preflight, never silently dropped"),
    "quarry_recon.runner_native:_MAX_REPOSITORY_IDENTITY_BYTES": (
        "resource", "the bounded control-memory read for one authenticated repository identity; an "
                    "oversize identity is refused rather than treated as runnable output"),
    "quarry_recon.runner_protocol:MAX_ARGV_BYTES": (
        "resource", "the bounded control-memory footprint of one execution argv; an oversize request is "
                    "refused before launch"),
    "quarry_recon.runner_protocol:MAX_ARGV_ITEMS": (
        "resource", "the bounded item count of one execution argv; an oversize request is refused before "
                    "launch"),
    "quarry_recon.runner_protocol:MAX_DETAIL_BYTES": (
        "not_a_bound", "a compatibility alias of MAX_DIAGNOSTIC_BYTES and therefore no independent "
                       "execution or evidence ceiling"),
    "quarry_recon.runner_protocol:MAX_DIAGNOSTIC_BYTES": (
        "resource", "the bounded credential-safe diagnostic-code field in a control record, not captured "
                    "target evidence"),
    "quarry_recon.runner_protocol:MAX_ENV_BYTES": (
        "resource", "the bounded control-memory footprint of one child environment; an oversize request "
                    "is refused before launch"),
    "quarry_recon.runner_protocol:MAX_ENV_ITEMS": (
        "resource", "the bounded item count of one child environment; an oversize request is refused "
                    "before launch"),
    "quarry_recon.runner_protocol:MAX_EXIT_CODE": (
        "parser", "the upper scalar range accepted for a versioned protocol exit code, not a limit on "
                  "execution"),
    "quarry_recon.runner_protocol:MAX_EXIT_CODES": (
        "resource", "the bounded control-record set of accepted exit codes; excess values are refused "
                    "before launch"),
    "quarry_recon.runner_protocol:MAX_FRAME_BYTES": (
        "resource", "the allocation bound for one versioned runner control frame; oversize control input "
                    "is rejected and never treated as a clean settlement"),
    "quarry_recon.runner_protocol:MAX_JSON_DEPTH": (
        "resource", "the recursion-safety bound for an untrusted runner control document; a deeper frame "
                    "is rejected"),
    "quarry_recon.runner_protocol:MAX_JSON_INTEGER_DIGITS": (
        "parser", "the strict lexical range for an integer in a runner control document, not a work "
                  "allowance"),
    "quarry_recon.runner_protocol:MAX_JSON_NODES": (
        "resource", "the parser-work bound for one untrusted runner control document; a larger tree is "
                    "rejected"),
    "quarry_recon.runner_protocol:MAX_PATH_BYTES": (
        "identity", "the encoded grammar of one normalized path field in the versioned runner protocol; "
                    "it does not bound bytes stored at that path"),
    "quarry_recon.runner_protocol:MAX_PID": (
        "identity", "the accepted operating-system PID domain in the versioned execution identity, not "
                    "a process-count bound"),
    "quarry_recon.runner_protocol:MAX_SAFE_INTEGER": (
        "parser", "the exact numeric range accepted by the runner JSON and timeout parsers, not a policy "
                  "ceiling"),
    "quarry_recon.runner_protocol:MAX_STDIN_DATA_BYTES": (
        "resource", "the bounded in-band allocation for one stdin-data request; larger input must use the "
                    "out-of-band file-descriptor path or is refused before launch"),
    "quarry_recon.runner_protocol:MAX_TEXT_BYTES": (
        "resource", "the default control-field allocation bound in the versioned runner protocol, not a "
                    "limit on captured target evidence"),
    "quarry_recon.runner_protocol:MIN_EXIT_CODE": (
        "parser", "the lower scalar range accepted for a versioned protocol exit code, not a limit on "
                  "execution"),
    "quarry_recon.runner_supervisor:_MAX_SAFE_DEADLINE": (
        "parser", "the strict numeric range accepted for an absolute monotonic supervisor deadline, not "
                  "a deadline selected by policy"),
    "quarry_recon.runner_supervisor:_MAX_TRAILING_BYTES": (
        "not_a_bound", "the saturation value of a control-transcript byte counter after protocol failure, "
                       "not a read, evidence or execution ceiling"),
    "quarry_recon.runner_supervisor:_REAP_RESERVE_SECONDS": (
        "not_a_bound", "a partition of the caller's one existing settlement deadline reserved for forced "
                       "kill and reap, not an additional timeout"),
    "quarry_recon.store:_MAX_IDENTITY_BYTES": (
        "resource", "the bounded read of one untrusted repository identity document; oversize identity "
                    "data is rejected without materializing or mutating a run"),

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
