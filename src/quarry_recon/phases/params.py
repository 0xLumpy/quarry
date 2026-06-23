"""Phase 7: Params + lightweight scanning (deepened).

gf vuln-class buckets over the URL corpus -> ranked candidate queues; arjun param
discovery; non-intrusive nuclei with built-in interactsh OOB; dalfox XSS/open-redirect
on reflected/redirect candidates. Scanner output is NEVER a finding without manual
confirmation (design §7) — entities carry confirmed:false.
"""
from __future__ import annotations

import json

from .. import normalize
from ..runner import Status, have, run as exec_tool, skipped

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "rce", "ssti", "interestingparams"]


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope

    # in-scope URL corpus (always available from crawl, even passive)
    corpus = [u for u in ctx.run.values("url")
              if scope.in_scope(normalize.host_of_url(u)) and not scope.is_oos(normalize.host_of_url(u))]
    corpus_file = ctx.write_list("all_inscope_urls.txt", corpus)

    # ── gf vuln-class buckets -> review candidates ──
    if corpus and have("gf"):
        for pat in GF_PATTERNS:
            raw = ctx.run.raw_path("params", "gf", f"{pat}.txt")
            r = exec_tool("gf", ["gf", pat], input_file=corpus_file, raw_path=raw, timeout=120)
            ctx.run.record("params", r)
            if r.raw_path:
                for line in r.raw_path.read_text().splitlines():
                    u = line.strip()
                    if u:
                        ctx.run.add("review", {"id": f"{pat}:{u}", "klass": pat, "value": u,
                                               "sources": ["gf"]})
        ctx.echo(f"  gf candidates: {ctx.run.count('review')}")
    elif corpus:
        ctx.run.record("params", skipped("gf", "gf not installed / no ~/.gf patterns"))

    if scope.passive_only:
        ctx.run.record("params", skipped("nuclei", "passive-only mode"))
        ctx.run.record("params", skipped("dalfox", "passive-only mode"))
        return

    # ── subdomain takeover (nuclei takeover templates over resolved subs) ──
    if prof.takeover and have("nuclei"):
        subs = scope.filter_hosts(ctx.run.values("resolved") or ctx.run.values("subdomain"))
        if subs:
            tk_in = ctx.write_list("takeover_targets.txt", subs)
            tk_out = ctx.run.raw_path("params", "nuclei", "takeover.jsonl")
            r = exec_tool("nuclei", ["nuclei", "-l", str(tk_in), "-tags", "takeover",
                                     "-jsonl", "-o", str(tk_out), "-rl", str(prof.http_rl or 15)],
                          timeout=ctx.http_timeout)
            ctx.run.record("params", r)
            if tk_out.exists():
                import json as _json
                for line in tk_out.read_text().splitlines():
                    try:
                        o = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    ctx.run.add("finding", {"id": f"takeover:{o.get('matched-at', o.get('host'))}",
                                            "template": o.get("template-id", "takeover"),
                                            "severity": "high", "name": "possible subdomain takeover",
                                            "matched": o.get("matched-at", o.get("host", "")),
                                            "sources": ["nuclei-takeover"], "confirmed": False})

    live = [u for u in ctx.run.values("live") if scope.active_allowed(normalize.host_of_url(u))]
    if not live:
        ctx.run.record("params", skipped("nuclei", "no active-allowed live hosts"))
        return
    targets = ctx.write_list("nuclei_targets.txt", live)

    # ── nuclei (non-intrusive, OOB interactsh, severity-scoped) ──
    findings = ctx.run.raw_path("params", "nuclei", "findings.jsonl")
    log = ctx.run.raw_path("params", "nuclei", "nuclei.run.log")
    cmd = ["nuclei", "-l", str(targets), "-jsonl", "-o", str(findings),
           "-etags", "intrusive,fuzz,dos,brute-force",
           "-s", "critical,high,medium", "-stats", "-si", "30", "-c", "10"]
    if prof.http_rl:
        cmd += ["-rl", str(prof.http_rl)]
    r = exec_tool("nuclei", cmd, timeout=ctx.http_timeout)
    if r.stderr_tail:
        log.write_text(r.stderr_tail)
    ctx.run.record("params", r)
    if findings.exists():
        n = 0
        for line in findings.read_text().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = obj.get("template-id", "?")
            ctx.run.add("finding", {
                "id": f"{tid}|{obj.get('matched-at', obj.get('host',''))}",
                "template": tid, "severity": (obj.get("info") or {}).get("severity", "unknown"),
                "name": (obj.get("info") or {}).get("name"),
                "matched": obj.get("matched-at", obj.get("host", "")),
                "sources": ["nuclei"], "confirmed": False})
            n += 1
        ctx.echo(f"  nuclei: {n} candidate findings (UNCONFIRMED — manual validation required)")

    # ── arjun param discovery on param-less API endpoints (throttled) ──
    api_eps = sorted({u.split("?")[0] for u in corpus
                      if "?" not in u and any(s in u.lower() for s in
                      ("/api", "/rest", "/account", "/profile", "/search", "/user", "/order"))})[:40]
    if api_eps:
        aj_in = ctx.write_list("arjun_targets.txt", api_eps)
        aj_out = ctx.run.raw_path("params", "arjun", "arjun.txt")
        r = exec_tool("arjun", ["arjun", "-i", str(aj_in), "-oT", str(aj_out), "-t", "5", "-d", "1"],
                      timeout=ctx.http_timeout)
        ctx.run.record("params", r)
    else:
        ctx.run.record("params", skipped("arjun", "no param-less API endpoints found"))

    # ── dalfox on gf xss + redirect candidates (throttled) ──
    dalfox_in = [r["value"] for r in ctx.run.read("review") if r.get("klass") in ("xss", "redirect")]
    if dalfox_in and have("dalfox"):
        df_in = ctx.write_list("dalfox_in.txt", dalfox_in)
        df_out = ctx.run.raw_path("params", "dalfox", "dalfox.txt")
        r = exec_tool("dalfox", ["dalfox", "file", str(df_in), "--delay", "250", "-w", "5",
                                 "--skip-bav", "-o", str(df_out)], timeout=ctx.http_timeout)
        ctx.run.record("params", r)
        if df_out.exists():
            for line in df_out.read_text().splitlines():
                if line.strip().startswith("[POC]") or "PoC" in line:
                    ctx.run.add("finding", {"id": f"dalfox:{line[:80]}", "template": "dalfox-xss",
                                            "severity": "medium", "matched": line.strip(),
                                            "sources": ["dalfox"], "confirmed": False})
    else:
        ctx.run.record("params", skipped("dalfox", "no xss/redirect candidates"))
