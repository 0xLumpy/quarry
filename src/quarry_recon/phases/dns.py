"""DNS-record enrichment phase (after vertical, before probe).

puredns stays the brute/validation path; this phase does NOT re-discover hosts. It runs ONE dnsx
pass over the known in-scope resolved set to pull the full useful record layer — A/AAAA/CNAME/MX/
NS/TXT/SOA/CAA + per-host ASN/CDN — as first-class `dns_record` entities with provenance. Placed
early so the DNS context (IPv6, org/DNS-provider, per-host ASN) feeds review/digest + human
decisions from probe onward, instead of being buried at the end of the run.

Overlap is justified as CONTEXT, not duplication: puredns = does-it-resolve; dnsx-enrich = what
records it has. asnmap (horizontal) expands a profile ASN/CIDR into scope; dnsx `-asn` tags each
resolved host with the ASN it sits in — complementary.

`enrich_hosts()` is the reusable core: the `dns` phase runs it over the full resolved set; `enrich`
runs it over late-discovered (crawl/CSP) hosts as a catch-up, so late hosts also get DNS metadata.
Wildcard-inherited records (A/AAAA/CNAME/TXT spread by a `*.apex` record) are filtered against a
per-apex baseline so they don't pollute every host.
"""
from __future__ import annotations

from uuid import uuid4

from .. import normalize
from ..runner import have, run as exec_tool, skipped

_RECORD_FLAGS = ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-caa", "-asn", "-cdn"]
# only these types are spuriously spread by a `*.apex` wildcard → filter them against the baseline.
# mx/ns/soa/caa/asn/cdn are zone-level / meaningful context — never wildcard-filtered.
_WILDCARD_TYPES = frozenset({"a", "aaaa", "cname", "txt"})
_WILDCARD_PROBE_FLAGS = ["-a", "-aaaa", "-cname", "-txt"]   # baseline only needs the filtered types


def _apex_of(host: str, apexes) -> str:
    h = host.lower().rstrip(".")
    for a in apexes:
        if h == a or h.endswith("." + a):
            return a
    return ".".join(h.split(".")[-2:])


def _dnsx_cmd(ctx, list_file, flags=None):
    cmd = ["dnsx", "-l", str(list_file), *(flags or _RECORD_FLAGS), "-json", "-silent"]
    if ctx.profile.dns_rate:                        # honor RATELIMIT.DNS (dnsx -rl = req/s)
        cmd += ["-rl", str(ctx.profile.dns_rate)]
    return cmd


def _wildcard_baseline(ctx, apexes: set, phase: str) -> dict:
    """Per-apex wildcard record set: resolve a random non-existent label and collect its records.
    Anything a real host shares with this baseline (for a wildcard-spread type) is inherited, not
    host-specific → filtered."""
    apexes = sorted(a for a in apexes if a)
    if not apexes:
        return {}
    probes = [f"quarry-wc-{uuid4().hex[:10]}.{a}" for a in apexes]
    pf = ctx.write_list(f"{phase}_wildcard_probe.txt", probes)
    out = ctx.run.raw_path(phase, "dnsx", "wildcard.jsonl")
    r = exec_tool("dnsx", _dnsx_cmd(ctx, pf, _WILDCARD_PROBE_FLAGS), raw_path=out, timeout=600)
    ctx.run.record(phase, r)
    baseline: dict = {}
    if r.raw_path and r.raw_path.exists():
        for e in normalize.dnsx_records(r.raw_path.read_text(), "dnsx-wildcard", str(out)):
            baseline.setdefault(_apex_of(e["host"], apexes), set()).add((e["type"], e["value"]))
    return baseline


def enrich_hosts(ctx, hosts, phase: str) -> int:
    """dnsx record enrichment over `hosts` → dns_record entities, wildcard-filtered. Returns the
    number of NEW records stored. Shared by the dns phase + enrich late-host catch-up."""
    scope = ctx.scope
    apexes = ctx.profile.apex_domains
    hosts = sorted(h for h in set(hosts)
                   if h and scope.in_scope(h) and not scope.is_oos(h))
    if not hosts:
        return 0
    wildcard = _wildcard_baseline(ctx, {_apex_of(h, apexes) for h in hosts}, phase)
    hf = ctx.write_list(f"{phase}_dns_hosts.txt", hosts)
    out = ctx.run.raw_path(phase, "dnsx", "records.jsonl")
    r = exec_tool("dnsx", _dnsx_cmd(ctx, hf), raw_path=out, timeout=ctx.http_timeout)
    ctx.run.record(phase, r)
    n = 0
    if r.raw_path and r.raw_path.exists():
        for e in normalize.dnsx_records(r.raw_path.read_text(), "dnsx-enrich", str(out)):
            if not (scope.in_scope(e["host"]) and not scope.is_oos(e["host"])):
                continue
            if e["type"] in _WILDCARD_TYPES and \
                    (e["type"], e["value"]) in wildcard.get(_apex_of(e["host"], apexes), ()):
                continue                            # wildcard-inherited — not host-specific
            if ctx.run.add("dns_record", e):
                n += 1
    return n


def run(ctx) -> None:
    if not have("dnsx"):
        ctx.run.record("dns", skipped("dnsx", "dnsx not installed"))
        return
    # RESOLVED hosts only. A no-A / dangling-CNAME host (known as `subdomain` but never resolved)
    # is intentionally NOT enriched here — dns_record is a resolved-asset metadata layer; the
    # CNAME/takeover signal for no-A hosts stays in vertical + enrich.
    in_scope = sorted(h for h in set(ctx.run.values("resolved"))
                      if h and ctx.scope.in_scope(h) and not ctx.scope.is_oos(h))
    if not in_scope:
        ctx.run.record("dns", skipped("dnsx", "no in-scope resolved hosts to enrich"))
        return
    n = enrich_hosts(ctx, in_scope, "dns")
    ctx.echo(f"  dns-enrich: +{n} record(s) over {len(in_scope)} host(s) (wildcard-filtered)")
