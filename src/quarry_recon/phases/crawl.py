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

from .. import normalize, secrets
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
            # Register the host itself — a host first seen via a crawl link (e.g. a link-only
            # backup/canary host) is a real discovery. Without this it lives only in the URL
            # corpus and never counts as a discovered subdomain (so no host-level view, and it
            # misses the takeover/CNAME analysis). Dedups on host in the store.
            if host:
                ctx.run.add("subdomain", {"host": host, "sources": [source]})
    return n


def _synthetic(ctx, tool, lines, note=""):
    ctx.run.record("crawl", type("R", (), {
        "tool": tool, "status": Status.SUCCESS, "exit_code": 0, "duration": 0.0,
        "stdout_lines": lines, "note": note, "cmd": [tool], "stderr_tail": ""})())


def _safe_srcpath(name: str) -> str:
    """Sourcemap `sources` entry -> a safe relative path (drops webpack:// etc; no traversal)."""
    n = name.split("://", 1)[-1].replace("\\", "/")
    parts = [p for p in n.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "source"


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

    # ── 9.1 source-map UNPACK: detect .map refs, fetch, recover original source ──
    recov_dir = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered"
    MAX_MAP = 20 * 1024 * 1024     # 20 MB cap per sourcemap (RAM/disk guard)
    if js_files:
        import base64
        from urllib.parse import urljoin
        map_payloads = []          # (label, json_text) — both inline-data and fetched .map
        map_urls = set()           # in-scope http(s) .map candidates (for the review queue)
        for u in ctx.run.values("js_url"):
            dest = js_dir / (hashlib.md5(u.encode()).hexdigest()[:16] + ".js")
            if not dest.exists():
                continue
            refs = [line.split("sourceMappingURL=", 1)[1].strip()
                    for line in dest.read_text(errors="replace").splitlines()
                    if "sourceMappingURL=" in line]
            refs.append(u.split("?")[0] + ".map")               # conventional fallback
            for ref in refs:
                if ref.startswith("data:"):                     # inline base64 sourcemap
                    try:
                        raw = base64.b64decode(ref.split(",", 1)[1])
                        if len(raw) <= MAX_MAP:                  # size guard
                            map_payloads.append((u, raw.decode("utf-8", "replace")))
                    except Exception:
                        pass
                else:
                    m = urljoin(u, ref)
                    # fetching is ACTIVE — a malicious sourceMappingURL can point off-scope.
                    if ctx.scope.active_allowed(normalize.host_of_url(m)):
                        map_urls.add(m)
        for m in sorted(map_urls)[:100]:                        # bound number of fetches
            try:
                req = urllib.request.Request(m, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = resp.read(MAX_MAP + 1)               # bounded read
                if len(data) > MAX_MAP:
                    continue
                map_payloads.append((m, data.decode("utf-8", "replace")))
            except Exception:
                continue
        recovered = 0
        for label, text in map_payloads:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                continue
            # per-map subdir so two maps with the same source path don't overwrite each other
            mh = hashlib.md5(label.encode()).hexdigest()[:10]
            sources = obj.get("sources") or []
            for i, content in enumerate(obj.get("sourcesContent") or []):
                if not content:
                    continue
                out = recov_dir / mh / _safe_srcpath(sources[i] if i < len(sources) else f"src{i}.js")
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(content)
                recovered += 1
        sm_raw = ctx.run.raw_path("crawl", "sourcemaps", "candidates.txt")
        sm_raw.write_text("\n".join(sorted(map_urls)) + "\n")
        for s in sorted(map_urls):
            ctx.run.add("review", {"id": f"sourcemap:{s}", "klass": "sourcemap", "value": s,
                                   "sources": ["sourcemap-scan"]})
        ctx.echo(f"  sourcemaps: {len(map_urls)} .map candidate(s), recovered {recovered} source file(s)")

    # ── re-mine recovered source (jsluice + xnLinkFinder), provenance = sourcemap ──
    recov_files = [p for p in recov_dir.rglob("*") if p.is_file()] if recov_dir.exists() else []
    if recov_files and have("jsluice"):
        blob = b"\n".join(p.read_bytes() for p in recov_files)
        for sub, parser in (("urls", normalize.jsluice_urls), ("secrets", normalize.jsluice_secrets)):
            raw = ctx.run.raw_path("crawl", "jsluice-sourcemap", f"{sub}.jsonl")
            try:
                p = subprocess.run(["jsluice", sub, "-"], input=blob, capture_output=True,
                                   timeout=ctx.http_timeout)
                raw.write_bytes(p.stdout)
                _synthetic(ctx, f"jsluice-sourcemap-{sub}", p.stdout.count(b"\n"))
                for e in parser(p.stdout.decode("utf-8", "replace"), "jsluice-sourcemap", str(raw)):
                    if sub == "urls":
                        ctx.run.add("endpoint", {"value": e["url"],
                                                 **{k: v for k, v in e.items() if k != "url"}})
                    else:
                        d = e.pop("data", "")
                        basis = d or f"{e.get('kind', 'secret')}|{e.get('id', '')}"
                        e["preview"] = secrets.mask(d)
                        e["id"] = f"jsluice-sourcemap:{e.get('kind', 'secret')}:{secrets.fingerprint(basis)}"
                        ctx.run.add("secret", e)
            except Exception as ex:
                ctx.echo(f"    jsluice-sourcemap {sub}: {ex}")
    if recov_files and have("xnLinkFinder"):
        _xnl(ctx, str(recov_dir), "sourcemap", extra=[])

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
                        d = e.pop("data", "")          # don't store the raw secret in normalized
                        basis = d or f"{e.get('kind', 'secret')}|{e.get('id', '')}"
                        e["preview"] = secrets.mask(d)
                        e["id"] = f"jsluice:{e.get('kind', 'secret')}:{secrets.fingerprint(basis)}"
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
        # gitleaks writes its JSON report to the -r FILE and exits 1 when it FINDS leaks
        # (success, not error). Write a REAL file and classify on its contents — `-r /dev/stdout`
        # is non-portable (writes 0 bytes on some builds → lost findings + a bogus "failed").
        # No raw_path here: run() must not clobber the file gitleaks wrote with empty stdout.
        r = exec_tool("gitleaks", ["gitleaks", "detect", "--no-git", "-s", str(js_dir),
                                   "-r", str(rep), "-f", "json"],
                      ok_codes=(0, 1), timeout=ctx.http_timeout)
        items = []
        if rep.exists() and rep.stat().st_size:
            try:
                items = json.loads(rep.read_text() or "[]")
            except json.JSONDecodeError:
                items = []
        for item in items:
            sec = item.get("Secret", "")
            # fingerprint from the secret; fall back to rule+file+line so an empty Secret
            # can't collapse distinct findings to fingerprint("").
            basis = sec or f"{item.get('RuleID')}|{item.get('File')}|{item.get('StartLine')}"
            ctx.run.add("secret", {"id": f"gitleaks:{item.get('RuleID')}:{secrets.fingerprint(basis)}",
                                   "kind": item.get("RuleID"), "preview": secrets.mask(sec),
                                   "file": item.get("File"), "sources": ["gitleaks"]})
        # status from the report (gitleaks writes findings to the file + exits 1 on a find).
        # Keep the REAL RunResult — command / exit code / duration / stderr — for the audit
        # trail; only override status+note when the report actually shows findings.
        if items:
            r.status = Status.SUCCESS
            r.note = f"{len(items)} leak(s) found"
            r.stdout_lines = len(items)
        ctx.run.record("crawl", r)

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
                raw_s = o.get("Raw") or ""
                red = o.get("Redacted") or ""
                # fingerprint from Raw; if Raw is empty, fall back to detector + redacted +
                # source context so distinct findings don't collapse to fingerprint("").
                basis = raw_s or f"{det}|{red}|{o.get('SourceMetadata') or ''}"
                ctx.run.add("secret", {"id": f"trufflehog:{det}:{secrets.fingerprint(basis)}",
                                       "kind": det, "preview": red or secrets.mask(raw_s),
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
