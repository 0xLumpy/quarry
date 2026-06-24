"""Phase 4: Probe / fingerprint / screenshots / ports.

httpx json (source of truth for live services) with the methodology's full flag set
(follow-redirects, asn, location, random-agent) at RoE rate limit + full-monty ports;
gowitness screenshots; naabu ports → nmap -sV service detection (only on in-scope CIDR);
optional smap passive (Shodan-backed) port scan.
"""
from __future__ import annotations

from .. import normalize
from ..runner import Status, have, run as exec_tool, skipped


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    if scope.passive_only:
        ctx.run.record("probe", skipped("httpx", "passive-only mode"))
        return

    hosts = ctx.run.values("resolved") or ctx.run.values("subdomain")
    hosts = scope.filter_hosts(hosts, active=True)
    if not hosts:
        ctx.run.record("probe", skipped("httpx", "no in-scope hosts to probe"))
        ctx.run.notes.append("probe: no hosts (run vertical first)")
        return
    hosts_file = ctx.write_list("probe_targets.txt", hosts)

    # ── httpx full fingerprint -> live services (methodology flag set) ──
    hx = ctx.run.raw_path("probe", "httpx", "httpx.jsonl")
    cmd = ["httpx", "-l", str(hosts_file), "-json", "-silent",
           "-ports", ",".join(str(p) for p in prof.ports),
           "-td", "-title", "-sc", "-cl", "-favicon", "-cdn", "-web-server",
           "-asn", "-location", "-ip", "-cname",
           "-follow-redirects", "-no-fallback", "-probe-all-ips", "-random-agent",
           "-t", "15"]
    if prof.http_rl:
        cmd += ["-rl", str(prof.http_rl)]
    r = exec_tool("httpx", cmd, raw_path=hx, timeout=ctx.http_timeout)
    ctx.run.record("probe", r)
    if r.raw_path:
        n = 0
        for e in normalize.httpx_json(r.raw_path.read_text(), "httpx", str(hx)):
            if scope.in_scope(e.get("host") or normalize.host_of_url(e["url"])):
                if ctx.run.add("live", e):
                    n += 1
                    for tech in e.get("tech") or []:
                        ctx.run.add("tech", {"id": f"{e['url']}|{tech}", "tech": tech,
                                             "url": e["url"], "sources": ["httpx"]})
        ctx.echo(f"  httpx: {n} live services ({r.status.value})")

    # ── WAF fingerprint (nuclei waf-detect templates over live hosts) ──
    # Recon-side only: identify WHICH WAF fronts each host (Cloudflare/Akamai/F5…).
    # Bypass tooling (nomore403/nowafpls/NewTowner) stays human/Burp work.
    if have("nuclei") and ctx.run.count("live"):
        waf_in = ctx.write_list("waf_targets.txt", ctx.run.values("live"))
        waf_out = ctx.run.raw_path("probe", "nuclei", "waf.jsonl")
        waf_cmd = ["nuclei", "-l", str(waf_in), "-tags", "waf", "-jsonl", "-o", str(waf_out)]
        if prof.http_rl:                       # else native default (empty = fast)
            waf_cmd += ["-rl", str(prof.http_rl)]
        r = exec_tool("nuclei", waf_cmd, timeout=ctx.http_timeout)
        ctx.run.record("probe", r)
        if waf_out.exists():
            import json as _json
            n = 0
            for line in waf_out.read_text().splitlines():
                try:
                    o = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                ex = o.get("extracted-results") or []
                name = (ex[0] if ex else None) or o.get("matcher-name") or "unknown"
                host = o.get("matched-at", o.get("host", ""))
                ctx.run.add("tech", {"id": f"{host}|waf:{name}", "tech": f"WAF:{name}",
                                     "url": host, "sources": ["nuclei-waf"]})
                n += 1
            ctx.echo(f"  waf: {n} hosts fingerprinted")

    # ── screenshots (write structured jsonl too for the asset DB) ──
    if prof.screenshots and ctx.run.count("live"):
        live_file = ctx.write_list("live.txt", ctx.run.values("live"))
        shot_dir = ctx.run.dir / "raw" / "probe" / "gowitness"
        shot_dir.mkdir(parents=True, exist_ok=True)
        r = exec_tool("gowitness",
                ["gowitness", "scan", "file", "-f", str(live_file),
                 "--screenshot-path", str(shot_dir), "--write-db", "--write-jsonl",
                 "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                timeout=ctx.http_timeout)
        ctx.run.record("probe", r)
        for img in shot_dir.glob("*.jpeg"):
            ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})
        for img in shot_dir.glob("*.png"):
            ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

    # ── ports: naabu (in-scope CIDR) → nmap -sV service detection ──
    if prof.portscan and prof.cidr:
        cidr_file = ctx.write_list("cidr.txt", prof.cidr)
        cmd = ["naabu", "-list", str(cidr_file), "-top-ports", "1000", "-silent"]
        if prof.portscan_rate:
            cmd += ["-rate", str(prof.portscan_rate)]
        pr = ctx.run.raw_path("probe", "naabu", "ranges.txt")
        r = exec_tool("naabu", cmd, raw_path=pr, timeout=ctx.http_timeout)
        ctx.run.record("probe", r)
        open_ports = {}
        if r.raw_path:
            for line in r.raw_path.read_text().splitlines():
                line = line.strip()
                if ":" in line:
                    ctx.run.add("port", {"id": line, "sources": ["naabu"]})
                    ip, _, port = line.rpartition(":")
                    open_ports.setdefault(ip, set()).add(port)
        # nmap -sV only on the ports naabu found open (methodology: don't full-scan)
        if open_ports and have("nmap"):
            ips_file = ctx.write_list("naabu_ips.txt", list(open_ports))
            ports_csv = ",".join(sorted({p for ps in open_ports.values() for p in ps}, key=int))
            nm = ctx.run.raw_path("probe", "nmap", "service.txt")
            r = exec_tool("nmap", ["nmap", "-sV", "-Pn", "-T4", "-iL", str(ips_file),
                                   "-p", ports_csv, "-oN", str(nm)], timeout=ctx.http_timeout)
            ctx.run.record("probe", r)
    elif prof.portscan:
        ctx.run.record("probe", skipped("naabu", "no in-scope CIDR — port scan skipped"))

    # ── smap: passive (Shodan-backed) port scan, no packets to target (optional) ──
    if have("smap") and ctx.run.count("live"):
        sm_in = ctx.write_list("smap_targets.txt",
                               [normalize.host_of_url(u) for u in ctx.run.values("live")])
        sm = ctx.run.raw_path("probe", "smap", "smap.txt")
        r = exec_tool("smap", ["smap", "-iL", str(sm_in)], raw_path=sm, timeout=600)
        ctx.run.record("probe", r)
