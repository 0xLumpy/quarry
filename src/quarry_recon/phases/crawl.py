"""Phase 5: Crawl + URL/archive + JS mining (deepened).

katana (batched, RAM-safe) + gau + waymore (-mode U) -> url corpus; download JS,
beautify, dedup; jsluice urls+secrets; xnLinkFinder over the JS dir AND over waymore
RESPONSE dirs (-mode R + xnLinkFinder -orig = the "killer combo"); source-map recovery;
gitleaks + trufflehog secret scans.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import urllib.request
from pathlib import Path

from .. import normalize
from ..runner import Status, have, run as exec_tool, skipped

KEYHOST = ("login", "auth", "sso", "saml", "oauth", "api", "account", "register",
           "portal", "admin", "my-", "profile", "upload", "file", "id.")


def _collect_url(ctx, raw_text, source, raw_ref):
    n = 0
    for e in normalize.urls(raw_text, source, raw_ref):
        host = normalize.host_of_url(e["url"])
        if ctx.scope.in_scope(host) and not ctx.scope.is_oos(host):
            if ctx.run.add("url", e):
                n += 1
                if e["url"].lower().split("?")[0].endswith(".js"):
                    ctx.run.add("js_url", e)
    return n


def _synthetic(ctx, tool, lines, note=""):
    ctx.run.record("crawl", type("R", (), {
        "tool": tool, "status": Status.SUCCESS, "exit_code": 0, "duration": 0.0,
        "stdout_lines": lines, "note": note, "cmd": [tool], "stderr_tail": ""})())


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    roots = ctx.write_list("roots.txt", prof.apex_domains)

    live_urls = ctx.run.values("live")
    targets = ctx.write_list("crawl_targets.txt",
                             [u for u in live_urls if scope.in_scope(normalize.host_of_url(u))])

    # ── active crawl (katana) + store responses for xnLinkFinder (flags.md technique) ──
    kat_resp = ctx.run.dir / "raw" / "crawl" / "katana_resp"
    if not scope.passive_only and targets.stat().st_size:
        kat = ctx.run.raw_path("crawl", "katana", "katana.txt")
        kat_resp.mkdir(parents=True, exist_ok=True)
        cmd = ["katana", "-list", str(targets), "-jc", "-d", "2", "-kf", "all",
               "-c", "4", "-p", "3", "-timeout", "15", "-silent",
               "-srd", str(kat_resp)]   # store response dir -> mine with xnLinkFinder
        if prof.http_rl:
            cmd += ["-rl", str(prof.http_rl)]
        r = exec_tool("katana", cmd, raw_path=kat, timeout=ctx.http_timeout)
        ctx.run.record("crawl", r)
        if r.raw_path:
            ctx.echo(f"  katana: +{_collect_url(ctx, r.raw_path.read_text(), 'katana', str(kat))} urls")

        # headless SPA pass on JS-heavy / app hosts (RAM-heavy; opt-in via MODES.HEADLESS)
        if prof.headless:
            spa = sorted({u for u in targets.read_text().splitlines()
                          if any(k in u.lower() for k in
                          ("app", "portal", "dashboard", "account", "my-", "/app"))})[:10]
            if spa:
                spa_f = ctx.write_list("spa_targets.txt", spa)
                kh = ctx.run.raw_path("crawl", "katana", "headless.txt")
                r = exec_tool("katana", ["katana", "-list", str(spa_f), "-headless",
                                         "-system-chrome", "-jc", "-d", "2", "-c", "2", "-p", "1",
                                         "-timeout", "20", "-silent"] +
                                        (["-rl", str(prof.http_rl)] if prof.http_rl else []),
                              raw_path=kh, timeout=ctx.http_timeout)
                ctx.run.record("crawl", r)
                if r.raw_path:
                    ctx.echo(f"  katana headless SPA: +{_collect_url(ctx, r.raw_path.read_text(), 'katana-headless', str(kh))} urls")
    else:
        ctx.run.record("crawl", skipped("katana", "passive-only or no live targets"))

    # ── passive urls (gau) ──
    gau_raw = ctx.run.raw_path("crawl", "gau", "gau.txt")
    r = exec_tool("gau", ["gau", "--subs", "--threads", "5"] + prof.apex_domains,
                  stdin_data="\n".join(prof.apex_domains), raw_path=gau_raw, timeout=ctx.http_timeout)
    ctx.run.record("crawl", r)
    if r.raw_path:
        ctx.echo(f"  gau: +{_collect_url(ctx, r.raw_path.read_text(), 'gau', str(gau_raw))} urls")

    # ── archive URLs + RESPONSES (waymore -mode B) → xnLinkFinder over the dir ──
    # The documented "killer combo": -mode B downloads archived responses (not just URLs)
    # so xnLinkFinder mines them for extra links/params/secrets. -oijs saves inline JS.
    for d in prof.apex_domains:
        wdir = ctx.run.dir / "raw" / "crawl" / "waymore" / d
        wdir.mkdir(parents=True, exist_ok=True)
        wm = wdir / "waymore.txt"   # name xnLinkFinder auto-detects in the dir
        mode = "B" if not scope.passive_only else "U"
        # -ci d (1 capture/day) + -l <cap> bound response volume in automation;
        # runner timeout + checkpoint catch the rest. (No human --check-only pre-flight.)
        cmd = ["waymore", "-i", d, "-mode", mode, "-oU", str(wm), "-f", "-ci", "d", "-p", "3"]
        if mode == "B":
            cmd += ["-oR", str(wdir), "-oijs", "-l", str(prof.waymore_limit)]
        r = exec_tool("waymore", cmd, timeout=ctx.http_timeout)
        ctx.run.record("crawl", r)
        if wm.exists():
            _collect_url(ctx, wm.read_text(), "waymore", str(wm))
        # mine the response dir (only if responses were actually downloaded)
        if mode == "B" and have("xnLinkFinder") and len([p for p in wdir.iterdir() if p.name != "waymore.txt"]) > 1:
            _xnl(ctx, str(wdir), f"waymore-{d}", extra=["-orig", "-spo"], depth=3)

    # ── download JS, dedup, beautify ──
    js_urls = ctx.run.values("js_url")[:2000]
    js_dir = ctx.run.dir / "raw" / "crawl" / "js_files"
    js_dir.mkdir(parents=True, exist_ok=True)
    seen_hash = set()
    for u in js_urls:
        dest = js_dir / (hashlib.md5(u.encode()).hexdigest()[:16] + ".js")
        if dest.exists():
            continue
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read()
            if len(data) < 100:
                continue
            h = hashlib.md5(data).hexdigest()
            if h in seen_hash:
                continue
            seen_hash.add(h)
            dest.write_bytes(data)
        except Exception:
            continue
    js_files = list(js_dir.glob("*.js"))
    ctx.echo(f"  JS files downloaded: {len(js_files)}")

    # beautify in place (better extraction)
    if js_files and have("js-beautify"):
        for f in js_files:
            try:
                subprocess.run(["js-beautify", "-r", str(f)], capture_output=True, timeout=60)
            except Exception:
                pass

    # ── source-map recovery (append .map, scan for sourceMappingURL refs) ──
    if js_files:
        smaps = set()
        for f in js_files:
            txt = f.read_text(errors="replace")
            for line in txt.splitlines():
                if "sourceMappingURL=" in line:
                    smaps.add(line.split("sourceMappingURL=", 1)[1].strip())
        for u in ctx.run.values("js_url"):
            smaps.add(u.split("?")[0] + ".map")
        sm_raw = ctx.run.raw_path("crawl", "sourcemaps", "candidates.txt")
        sm_raw.write_text("\n".join(sorted(smaps)) + "\n")
        for s in smaps:
            ctx.run.add("review", {"id": f"sourcemap:{s}", "klass": "sourcemap", "value": s,
                                   "sources": ["sourcemap-scan"]})
        ctx.echo(f"  sourcemap candidates: {len(smaps)} (fetch .map -> unminified src)")

    # ── jsluice urls + secrets ──
    if js_files and have("jsluice"):
        blob = b"\n".join(f.read_bytes() for f in js_files)
        for sub, parser in (("urls", normalize.jsluice_urls), ("secrets", normalize.jsluice_secrets)):
            raw = ctx.run.raw_path("crawl", "jsluice", f"{sub}.jsonl")
            try:
                p = subprocess.run(["jsluice", sub, "-"], input=blob, capture_output=True,
                                   timeout=ctx.http_timeout)
                raw.write_bytes(p.stdout)
                _synthetic(ctx, f"jsluice-{sub}", p.stdout.count(b"\n"))
                for e in parser(p.stdout.decode("utf-8", "replace"), "jsluice", str(raw)):
                    if sub == "urls":
                        ctx.run.add("endpoint", {"value": e["url"],
                                                 **{k: v for k, v in e.items() if k != "url"}})
                    else:
                        ctx.run.add("secret", e)
            except Exception as ex:
                ctx.echo(f"    jsluice {sub}: {ex}")

    # ── xnLinkFinder over JS dir (links + params + secrets + wordlist) ──
    if js_files and have("xnLinkFinder"):
        _xnl(ctx, str(js_dir), "js", extra=[])

    # ── xnLinkFinder over katana's stored responses (flags.md: crawl-then-mine) ──
    if have("xnLinkFinder") and kat_resp.exists() and any(kat_resp.iterdir()):
        _xnl(ctx, str(kat_resp), "katana-resp", extra=["-orig"])

    # (waymore response mining happens per-apex above via -mode B + xnLinkFinder)

    # ── secret scanners on JS dir ──
    if js_files and have("gitleaks"):
        rep = ctx.run.raw_path("crawl", "gitleaks", "report.json")
        r = exec_tool("gitleaks", ["gitleaks", "detect", "--no-git", "-s", str(js_dir),
                                   "-r", str(rep), "-f", "json"], timeout=ctx.http_timeout)
        ctx.run.record("crawl", r)
        if rep.exists():
            try:
                for item in json.loads(rep.read_text() or "[]"):
                    ctx.run.add("secret", {"id": f"gitleaks:{item.get('RuleID')}:{item.get('Secret','')[:40]}",
                                           "kind": item.get("RuleID"), "data": item.get("Secret"),
                                           "file": item.get("File"), "sources": ["gitleaks"]})
            except json.JSONDecodeError:
                pass

    if js_files and have("trufflehog"):
        th = ctx.run.raw_path("crawl", "trufflehog", "out.jsonl")
        r = exec_tool("trufflehog", ["trufflehog", "filesystem", str(js_dir),
                                     "--json", "--no-update"], raw_path=th, timeout=ctx.http_timeout)
        ctx.run.record("crawl", r)
        if r.raw_path:
            for line in r.raw_path.read_text().splitlines():
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                det = o.get("DetectorName", "secret")
                raw_s = o.get("Raw", "")[:40]
                ctx.run.add("secret", {"id": f"trufflehog:{det}:{raw_s}", "kind": det,
                                       "data": o.get("Redacted") or raw_s,
                                       "verified": o.get("Verified", False), "sources": ["trufflehog"]})

    ctx.echo(f"  urls: {ctx.run.count('url')}  js: {ctx.run.count('js_url')}  "
             f"endpoints: {ctx.run.count('endpoint')}  params: {ctx.run.count('parameter')}  "
             f"secrets: {ctx.run.count('secret')}")


def _xnl(ctx, indir: str, tag: str, extra: list, depth: int = 0) -> None:
    roots = ctx.write_list("roots.txt", ctx.profile.apex_domains)
    safe_tag = tag.replace("/", "_").replace(".", "_")
    out_links = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_links.txt")
    out_params = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_params.txt")
    out_secrets = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_secrets.json")
    out_wl = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_wordlist.txt")
    cmd = ["xnLinkFinder", "-i", indir, "-sp", str(roots), "-sf", str(roots),
           "-o", str(out_links), "-op", str(out_params), "-os", str(out_secrets),
           "-owl", str(out_wl), "-inc", "-all", "-mfs", "0"] + list(extra)
    # depth>0 makes xnLinkFinder actually request found links — add UA spread, rate limit,
    # and stop-on-block flags (author's documented recommendation for deep dir crawls).
    if depth > 0:
        cmd += ["-d", str(depth), "-u", "desktop", "mobile", "-insecure",
                "-s429", "-s403", "-sTO", "-sCE"]
        if ctx.profile.http_rl:
            cmd += ["-rl", str(ctx.profile.http_rl)]
    r = exec_tool("xnLinkFinder", cmd, timeout=ctx.http_timeout)
    ctx.run.record("crawl", r)
    if out_params.exists():
        for line in out_params.read_text().splitlines():
            if line.strip():
                ctx.run.add("parameter", {"value": line.strip(), "sources": [f"xnLinkFinder-{tag}"]})
    if out_links.exists():
        for line in out_links.read_text().splitlines():
            if line.strip():
                ctx.run.add("endpoint", {"value": line.strip(), "sources": [f"xnLinkFinder-{tag}"]})
