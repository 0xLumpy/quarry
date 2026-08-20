"""DNS-record enrichment: one dnsx pass over the in-scope resolved set → `dns_record` entities
(A/AAAA/CNAME/MX/NS/TXT/SOA/CAA + per-host ASN/CDN) with provenance. Does not re-discover hosts.

`enrich_hosts()` is the reusable core: the `dns` phase runs it over the full resolved set, `enrich`
over late-discovered hosts. Wildcard-inherited records (A/AAAA/CNAME/TXT spread by a `*.apex` record)
are filtered against a per-apex baseline.
"""
from __future__ import annotations

from uuid import uuid4

from .. import normalize
from ..runner import have, run as exec_tool, skipped
from ..runner_repository import RepositoryOutput

_RECORD_FLAGS = ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-caa", "-asn", "-cdn"]
# types a `*.apex` wildcard spuriously spreads → filtered against the baseline; zone-level types
# (mx/ns/soa/caa/asn/cdn) are meaningful context, never filtered.
_WILDCARD_TYPES = frozenset({"a", "aaaa", "cname", "txt"})
_WILDCARD_PROBE_FLAGS = ["-a", "-aaaa", "-cname", "-txt"]   # baseline only needs the filtered types


def _apex_of(host: str, apexes) -> str:
    # longest matching apex, not the first (order-independent): x.dev.example.com → dev.example.com,
    # so the wildcard baseline is computed against the right root.
    h = host.lower().rstrip(".")
    best = None
    for a in apexes:
        if (h == a or h.endswith("." + a)) and (best is None or len(a) > len(best)):
            best = a
    return best or ".".join(h.split(".")[-2:])


def _dnsx_cmd(ctx, list_file, flags=None):
    cmd = ["dnsx", "-duc", "-l", str(list_file), *(flags or _RECORD_FLAGS), "-json", "-silent"]
    if ctx.profile.dns_rate:                        # honor RATELIMIT.DNS (dnsx -rl = req/s)
        cmd += ["-rl", str(ctx.profile.dns_rate)]
    return cmd


def _wildcard_baseline(ctx, apexes: set, phase: str) -> dict:
    """Per-apex wildcard record set: resolve a random non-existent label per apex and collect its
    records. A real host's record matching this baseline is wildcard-inherited → filtered."""
    apexes = sorted(a for a in apexes if a)
    if not apexes:
        return {}
    probes = [f"quarry-wc-{uuid4().hex[:10]}.{a}" for a in apexes]
    pf = ctx.write_list(f"{phase}_wildcard_probe.txt", probes)
    out = ctx.run.raw_path(phase, "dnsx", "wildcard.jsonl")
    r = exec_tool(
        "dnsx", _dnsx_cmd(ctx, pf, _WILDCARD_PROBE_FLAGS),
        repository=ctx.run,
        stdout=RepositoryOutput.publish(*out.relative_to(ctx.run.dir).parts),
        stderr=RepositoryOutput.discard(), timeout=600,
        source_id="dns.dnsx_records",
    )
    ctx.run.record(phase, r)
    baseline: dict = {}
    if r.raw_path and r.raw_path.exists():
        for e in normalize.dnsx_records(r.raw_path.read_text(), "dnsx-wildcard", str(out)):
            baseline.setdefault(_apex_of(e["host"], apexes), set()).add((e["type"], e["value"]))
    return baseline


def enrich_hosts(ctx, hosts, phase: str) -> int:
    """dnsx record enrichment over `hosts` → dns_record entities, wildcard-filtered. Returns the
    number of new records stored. Shared by the dns phase and the enrich late-host catch-up."""
    scope = ctx.scope
    apexes = ctx.profile.apex_domains
    hosts = sorted(h for h in set(hosts)
                   if h and scope.in_scope(h) and not scope.is_oos(h))
    if not hosts:
        return 0
    wildcard = _wildcard_baseline(ctx, {_apex_of(h, apexes) for h in hosts}, phase)
    hf = ctx.write_list(f"{phase}_dns_hosts.txt", hosts)
    out = ctx.run.raw_path(phase, "dnsx", "records.jsonl")
    r = exec_tool(
        "dnsx", _dnsx_cmd(ctx, hf),
        repository=ctx.run,
        stdout=RepositoryOutput.publish(*out.relative_to(ctx.run.dir).parts),
        stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        source_id="dns.dnsx_records",
    )
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
    # resolved hosts only: dns_record is a resolved-asset metadata layer. No-A / dangling-CNAME hosts
    # keep their CNAME/takeover signal in vertical + enrich.
    in_scope = sorted(h for h in set(ctx.run.values("resolved"))
                      if h and ctx.scope.in_scope(h) and not ctx.scope.is_oos(h))
    if not in_scope:
        ctx.run.record("dns", skipped("dnsx", "no in-scope resolved hosts to enrich"))
        return
    n = enrich_hosts(ctx, in_scope, "dns")
    ctx.echo(f"  dns-enrich: +{n} record(s) over {len(in_scope)} host(s) (wildcard-filtered)")
