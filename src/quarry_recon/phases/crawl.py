"""Phase 5: Crawl + URL/archive + JS mining (deepened).

katana (batched, RAM-safe) + gau + waymore (-mode U) -> url corpus; download JS,
beautify, dedup; jsluice urls+secrets; xnLinkFinder over the JS dir AND over waymore
RESPONSE dirs (-mode R + xnLinkFinder -orig = the "killer combo"); source-map recovery;
gitleaks + trufflehog secret scans.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from .. import events, fetch, normalize, secrets, settings
from ..runner import Status, have, run as exec_tool, skipped

# 9.2 deep-mine patterns over JS / recovered source — extraction only, no fetch.
# Each findall() yields the value to store (full match or capture group).
_WS_RX = re.compile(r"\bwss?://[A-Za-z0-9.\-_/:?=&%]+", re.I)                       # ws/wss endpoint URLs
_APIBASE_RX = re.compile(r"(?:baseURL|base_url|api[_-]?base|apiUrl|API_BASE|API_URL)"
                         r"\s*[:=]\s*[\"'`]([^\"'`]+)[\"'`]", re.I)                 # API base assignments
_GQL_RX = re.compile(r"[\"'`]([^\"'`]*?/(?:graphql|gql)\b[^\"'`]*)[\"'`]", re.I)    # GraphQL endpoint paths


def _deep_mine(ctx, files, tag: str) -> int:
    """Extract GraphQL / WebSocket / API-base endpoints from JS / recovered source. Tag-only,
    no fetch — these enrich the endpoint store with `kind` + provenance for later testing."""
    n = 0
    for f in files:
        try:
            txt = f.read_text(errors="replace")
        except Exception:
            continue
        for kind, rx in (("websocket", _WS_RX), ("api-base", _APIBASE_RX), ("graphql", _GQL_RX)):
            for val in {v.strip() for v in rx.findall(txt)}:
                if val and len(val) < 2048 and ctx.run.add(
                        "endpoint", {"value": val, "kind": kind, "sources": [f"deepmine-{tag}"]}):
                    n += 1
    return n

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


def _synthetic(ctx, tool, lines, note="", status=Status.SUCCESS):
    ctx.run.record("crawl", type("R", (), {
        "tool": tool, "status": status, "exit_code": 0, "duration": 0.0,
        "stdout_lines": lines, "note": note, "cmd": [tool], "stderr_tail": ""})())


def _jsluice_run(ctx, sub, files, raw, origin):
    """Chunked jsluice (step 4.1 Commit B): run `jsluice <sub> -j` PER FILE through the runner, so one
    huge/slow JS file times out ONLY itself (coverage_partial) instead of killing the whole batch, and
    we emit tool_progress (current_index/input_total) across files. Each per-file run goes through
    runner.run (exec_tool) — same wrapper Commit A introduced, so the timeout-0→None semantics carry
    over. Source-level tool_start/tool_finish bracket the per-file chunks; the caller emits the ledger
    after parsing. Returns (concatenated stdout text, overall Status). A chunk is 'degraded' if it ended
    in ANY non-clean status (FAILED/BLOCKED/PARTIAL/TIMED_OUT/SKIPPED); genuine EMPTY (a file with
    nothing to mine) is NOT degraded. Any degraded chunk makes the source PARTIAL — a failed chunk must
    never be reported as success."""
    sid = f"crawl.jsluice_{sub}"
    raw.parent.mkdir(parents=True, exist_ok=True)
    scratch = raw.with_suffix(".part")            # runner.run needs a file target; reused per chunk
    events.tool_start(sid, cmd=["jsluice", sub, "-j"], input_total=len(files), discovery_context=origin)
    t0 = time.monotonic()
    degraded = 0
    with raw.open("w", encoding="utf-8") as fh:
        for i, f in enumerate(files, 1):
            res = exec_tool("jsluice", ["jsluice", sub, "-j"], raw_path=scratch,
                            timeout=ctx.http_timeout,
                            stdin_data=f.read_bytes().decode("utf-8", "replace"))
            if res.status not in (Status.SUCCESS, Status.EMPTY):
                degraded += 1
                events.coverage_partial(sid, reason=f"{f.name}: {res.status.value}")
            if res.raw_path and scratch.exists():
                fh.write(scratch.read_text(encoding="utf-8", errors="replace"))
            events.tool_progress(sid, current_index=i, input_total=len(files),
                                 artifact_size=raw.stat().st_size)
    scratch.unlink(missing_ok=True)
    size = raw.stat().st_size if raw.exists() else None
    status = Status.PARTIAL if degraded else Status.SUCCESS
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded}/{len(files)} file(s) degraded" if degraded else None),
                       duration=round(time.monotonic() - t0, 2),
                       raw_ref=str(raw), artifact_size=size, discovery_context=origin)
    return (raw.read_text(encoding="utf-8", errors="replace") if raw.exists() else ""), status


JS_BEAUTIFY_TIMEOUT = 60          # per-file cap (local reformat) — preserves the pre-contract behavior


def _beautify_run(ctx, files):
    """Beautify JS UNDER CONTRACT (closes the last acceptance-bar debt: the last un-contracted reformat in
    phases). Mirrors _jsluice_run: `js-beautify -r <copy>` runs PER FILE through the runner (exec_tool), so
    one huge/slow minified file times out ONLY itself (coverage_partial) instead of stalling the loop;
    tool_progress is emitted across files.

    ORIGINAL-SAFE (fix): js-beautify rewrites its target in place, so a timeout mid-write would TRUNCATE
    the only downloaded copy and hand downstream a damaged file. We beautify a TEMP COPY and atomically
    replace the original only on SUCCESS/EMPTY; on ANY degradation the temp is deleted and the untouched
    original is kept — that is what makes the declared 'fallback: raw JS' real.

    OBSERVABLE (fix): each per-file RunResult's telemetry is aggregated (child CPU seconds, peak RSS,
    wall) and recorded ONCE via ctx.run.record, so manifest.json / metrics can explain js-beautify's
    resource use + degradation like any other contracted tool.

    Returns (beautified_ok, degraded, overall Status). A file is 'degraded' on ANY non-clean status
    (FAILED/BLOCKED/PARTIAL/TIMED_OUT/SKIPPED) — a failed reformat is never reported as success."""
    sid = "crawl.js_beautify"
    scratch = ctx.run.raw_path("crawl", "js_beautify", "run.log")   # discard stdout; -r mutates the file
    scratch.parent.mkdir(parents=True, exist_ok=True)
    events.tool_start(sid, cmd=["js-beautify", "-r"], input_total=len(files), discovery_context="js")
    t0 = time.monotonic()
    degraded = ok = 0
    cpu_total = 0.0
    rss_peak = 0.0
    for i, f in enumerate(files, 1):
        tmp = f.with_suffix(f.suffix + ".beauty")          # beautify a COPY, never the only original
        try:
            tmp.write_bytes(f.read_bytes())
            res = exec_tool("js-beautify", ["js-beautify", "-r", str(tmp)],
                            raw_path=scratch, timeout=JS_BEAUTIFY_TIMEOUT)
        except Exception:
            res = None
        cpu_total += getattr(res, "cpu_s", 0.0) or 0.0
        rss_peak = max(rss_peak, getattr(res, "peak_rss_mb", 0.0) or 0.0)
        swapped = False
        if res is not None and res.status in (Status.SUCCESS, Status.EMPTY) and tmp.exists():
            try:
                tmp.replace(f)                              # atomic swap-in only after a clean run
                swapped = True
                ok += 1
            except Exception:
                pass                                        # swap failed -> fall through to degraded/original-kept
        if not swapped:
            tmp.unlink(missing_ok=True)                     # degraded -> keep the untouched original
            degraded += 1
            reason = res.status.value if res is not None else "exception"
            events.coverage_partial(sid, reason=f"{f.name}: {reason}")
        events.tool_progress(sid, current_index=i, input_total=len(files))
    scratch.unlink(missing_ok=True)
    status = Status.PARTIAL if degraded else Status.SUCCESS
    dur = round(time.monotonic() - t0, 2)
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded}/{len(files)} file(s) degraded" if degraded else None),
                       duration=dur, discovery_context="js")
    # record an aggregate result so the manifest/metrics can explain resource use + degradation
    ctx.run.record("crawl", type("R", (), {
        "tool": "js-beautify", "status": status, "exit_code": None, "duration": dur,  # synthetic multi-proc: no single exit code
        "stdout_lines": ok, "cmd": ["js-beautify", "-r"], "stderr_tail": "",
        "note": f"{ok}/{len(files)} beautified" + (f", {degraded} degraded" if degraded else ""),
        "cpu_s": round(cpu_total, 2), "peak_rss_mb": round(rss_peak, 1)})())
    return ok, degraded, status


def _katana_scope_flags(scope) -> list[str]:
    """Translate Quarry's OOS host patterns into katana `-cos` (out-of-scope) URL regexes so katana never
    CRAWLS an excluded host. Katana defaults to registered-domain scope (`-fs rdn`) — it would otherwise
    follow a link to an OOS sibling and CONTACT it before Quarry's post-crawl `is_oos` filter drops the
    URLs. OOS is a HOST regex (`.search`'d on the host) while `-cos` matches the URL, so a leading `^`
    (anchored at host start) is re-anchored to the host position (`://`); unanchored patterns pass through
    (they may also match into the path, which only EXCLUDES more — it never causes contact)."""
    flags: list[str] = []
    for p in getattr(scope, "oos_patterns", ()):
        pat = getattr(p, "pattern", "")
        if not pat:
            continue
        if pat.startswith("^"):                     # host-start anchor -> right after scheme `://`
            pat = "://" + pat[1:]
        # a trailing `$` anchors the HOST end; in a URL the host ends at :/?# or end-of-string, so turn it
        # into a host-terminator (else `$` would demand the URL end at the hostname and a path/port/query
        # would ESCAPE the exclusion — the excluded host would still be crawled).
        if pat.endswith("$") and not pat.endswith("\\$"):
            pat = pat[:-1] + r"(?:[:/?#]|$)"
        # Quarry compiles OOS with re.IGNORECASE (config.py) — hosts are case-insensitive; carry that into
        # RE2 with `(?i)` so JOBS.example.com is excluded exactly as jobs.example.com is.
        flags += ["-cos", "(?i)" + pat]
    return flags


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
        # katana is network-bound — the old hard-coded `-c 4 -p 3` left a multi-core box idle. Scale the
        # crawl concurrency (-c) + parallel-host count (-p) via settings (I/O-based, config-tunable via
        # KATANA_CONCURRENCY / KATANA_PARALLELISM). (Headless SPA pass below stays low — it spawns chromium.)
        cmd = ["katana", "-list", str(targets), "-jc", "-d", "2", "-kf", "all",
               "-c", str(settings.workers("katana", 10)),
               "-p", str(settings.concurrency("KATANA_PARALLELISM", 10)),
               "-timeout", "15", "-silent",
               "-srd", str(kat_resp)]   # store response dir -> mine with xnLinkFinder
        cmd += _katana_scope_flags(scope)   # never crawl an OOS sibling (rdn scope would otherwise reach it)
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
                                        _katana_scope_flags(scope) +   # same OOS exclusion on the headless pass
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
    # Downloading JS is an ACTIVE fetch: gate on active_allowed (scope + OOS + passive-skip) and go
    # through the shared choke point (rate pace + bounded read + off-scope-redirect guard).
    MAX_JS = 15 * 1024 * 1024      # 15 MB cap per JS (RAM/disk guard; bundles are large but bounded)
    js_urls = ctx.run.values("js_url")[:2000]
    js_dir = ctx.run.dir / "raw" / "crawl" / "js_files"
    js_dir.mkdir(parents=True, exist_ok=True)
    seen_hash = set()
    for u in js_urls:
        if not ctx.scope.active_allowed(normalize.host_of_url(u)):
            continue
        dest = js_dir / (hashlib.md5(u.encode()).hexdigest()[:16] + ".js")
        if dest.exists():
            continue
        try:
            data, _final, status = fetch.scoped_get(ctx, u, max_body=MAX_JS)
            if data is None or status != 200 or not (100 <= len(data) <= MAX_JS):
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

    # beautify in place (better extraction) — UNDER CONTRACT (per-file via runner, source-level events)
    if js_files and have("js-beautify"):
        try:
            ok, degraded, bstatus = _beautify_run(ctx, js_files)
            events.ledger("crawl.js_beautify", beautified=ok, degraded=degraded,
                          input_total=len(js_files), status=bstatus.value)
        except Exception as ex:
            ctx.echo(f"    js-beautify: {ex}")

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
                # shared choke point: rate pace + bounded read + off-scope-redirect guard.
                data, _final, status = fetch.scoped_get(ctx, m, max_body=MAX_MAP)
                if data is None or status != 200 or len(data) > MAX_MAP:
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
        for sub, parser in (("urls", normalize.jsluice_urls), ("secrets", normalize.jsluice_secrets)):
            raw = ctx.run.raw_path("crawl", "jsluice-sourcemap", f"{sub}.jsonl")
            try:
                out, jstatus = _jsluice_run(ctx, sub, recov_files, raw, "sourcemap")
                _synthetic(ctx, f"jsluice-sourcemap-{sub}", out.count("\n"), status=jstatus)
                produced = 0
                for e in parser(out, "jsluice-sourcemap", str(raw)):
                    if sub == "urls":
                        ctx.run.add("endpoint", {"value": e["url"],
                                                 **{k: v for k, v in e.items() if k != "url"}})
                    else:
                        d = e.pop("data", "")
                        basis = d or f"{e.get('kind', 'secret')}|{e.get('id', '')}"
                        e["preview"] = secrets.mask(d)
                        e["id"] = f"jsluice-sourcemap:{e.get('kind', 'secret')}:{secrets.fingerprint(basis)}"
                        e["location"] = "raw/crawl/sourcemaps/recovered"   # recovered-source origin hint
                        ctx.run.add("secret", e)
                    produced += 1
                events.ledger(f"crawl.jsluice_{sub}",
                              produced={sub: produced}, consumed={"js_file": len(recov_files)})
            except Exception as ex:
                ctx.echo(f"    jsluice-sourcemap {sub}: {ex}")
    if recov_files and have("xnLinkFinder"):
        _xnl(ctx, str(recov_dir), "sourcemap", extra=[])

    # ── 9.2 deep-mine: GraphQL / WebSocket / API-base over JS + recovered source ──
    nd = _deep_mine(ctx, js_files, "js") + _deep_mine(ctx, recov_files, "sourcemap")
    if nd:
        ctx.echo(f"  deep-mine: +{nd} graphql/ws/api-base endpoint(s)")

    # ── jsluice urls + secrets ──
    if js_files and have("jsluice"):
        for sub, parser in (("urls", normalize.jsluice_urls), ("secrets", normalize.jsluice_secrets)):
            raw = ctx.run.raw_path("crawl", "jsluice", f"{sub}.jsonl")
            try:
                out, jstatus = _jsluice_run(ctx, sub, js_files, raw, "js")
                _synthetic(ctx, f"jsluice-{sub}", out.count("\n"), status=jstatus)
                produced = 0
                for e in parser(out, "jsluice", str(raw)):
                    if sub == "urls":
                        ctx.run.add("endpoint", {"value": e["url"],
                                                 **{k: v for k, v in e.items() if k != "url"}})
                    else:
                        d = e.pop("data", "")          # don't store the raw secret in normalized
                        basis = d or f"{e.get('kind', 'secret')}|{e.get('id', '')}"
                        e["preview"] = secrets.mask(d)
                        e["id"] = f"jsluice:{e.get('kind', 'secret')}:{secrets.fingerprint(basis)}"
                        ctx.run.add("secret", e)
                    produced += 1
                events.ledger(f"crawl.jsluice_{sub}",
                              produced={sub: produced}, consumed={"js_file": len(js_files)})
            except Exception as ex:
                ctx.echo(f"    jsluice {sub}: {ex}")

    # ── xnLinkFinder over JS dir (links + params + secrets + wordlist) ──
    if js_files and have("xnLinkFinder"):
        _xnl(ctx, str(js_dir), "js", extra=[])

    # ── xnLinkFinder over katana's stored responses (flags.md: crawl-then-mine) ──
    if have("xnLinkFinder") and kat_resp.exists() and any(kat_resp.iterdir()):
        _xnl(ctx, str(kat_resp), "katana-resp", extra=["-orig"])

    # (waymore response mining happens per-apex above via -mode B + xnLinkFinder)

    # ── secret scanners on JS dir + sourcemap-recovered sources ──
    # BOTH dirs must be scanned: a canary planted only in a recovered source (e.g. a stripe key in
    # app.js.map's sourcesContent) is missed if we scan js_files/ alone (Test-5). js_files gate
    # holds — no JS means no sourcemaps, nothing to scan.
    scan_dirs = [d for d in (js_dir, recov_dir)
                 if d.exists() and any(p.is_file() for p in d.rglob("*"))]
    if scan_dirs and have("gitleaks"):
        # gitleaks writes its JSON report to the -r FILE and exits 1 when it FINDS leaks
        # (success, not error). Write a REAL file and classify on its contents — `-r /dev/stdout`
        # is non-portable (writes 0 bytes on some builds → lost findings + a bogus "failed").
        # `-s` takes ONE source path, so scan each dir in turn (per-dir report keeps the audit trail).
        for sd in scan_dirs:
            rep = ctx.run.raw_path("crawl", "gitleaks",
                                   "report.json" if sd == js_dir else "report-sourcemap.json")
            r = exec_tool("gitleaks", ["gitleaks", "detect", "--no-git", "-s", str(sd),
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

    if scan_dirs and have("trufflehog"):
        # `filesystem` accepts multiple paths — hand it both dirs in one pass.
        th = ctx.run.raw_path("crawl", "trufflehog", "out.jsonl")
        r = exec_tool("trufflehog", ["trufflehog", "filesystem", *[str(d) for d in scan_dirs],
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


XNL_MAX_INPUT = 200 * 1024 * 1024      # cap the stdin blob so a huge dir can't blow RAM


def _xnl(ctx, indir: str, tag: str, extra: list, depth: int = 0) -> None:
    roots = ctx.write_list("roots.txt", ctx.profile.apex_domains)
    safe_tag = tag.replace("/", "_").replace(".", "_")
    out_links = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_links.txt")
    out_params = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_params.txt")
    out_secrets = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_secrets.json")
    out_wl = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_wordlist.txt")
    # xnLinkFinder v8.2: `-i <dir>` silently yields NOTHING (exit 0) and `-i <file>` is treated as a file
    # of DOMAINS to crawl — only STDIN parses file CONTENT offline (this silently produced 0 links/params
    # on every run). Concatenate the dir's files into a bounded blob and stream it via stdin (no -i).
    blob = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_input.txt")
    nbytes = 0
    capped = False
    with blob.open("w", encoding="utf-8", errors="replace") as bf:
        for f in sorted(Path(indir).rglob("*")):
            if not f.is_file():
                continue
            if nbytes >= XNL_MAX_INPUT:
                capped = True
                break
            try:
                data = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            bf.write(data)
            bf.write("\n")
            nbytes += len(data)
    cmd = ["xnLinkFinder", "-sp", str(roots), "-sf", str(roots),
           "-o", str(out_links), "-op", str(out_params), "-os", str(out_secrets),
           "-owl", str(out_wl), "-all", "-mfs", "0"] + list(extra)
    # depth>0 makes xnLinkFinder actually request the found links — add UA spread, rate limit, and
    # stop-on-block flags (author's documented recommendation for deep crawls).
    if depth > 0:
        cmd += ["-d", str(depth), "-u", "desktop", "mobile", "-insecure",
                "-s429", "-s403", "-sTO", "-sCE"]
        if ctx.profile.http_rl:
            cmd += ["-rl", str(ctx.profile.http_rl)]
    r = exec_tool("xnLinkFinder", cmd, timeout=ctx.http_timeout, input_file=blob)
    ctx.run.record("crawl", r)
    if capped:
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: input capped at {XNL_MAX_INPUT // (1024*1024)}MB (dir larger)")
    # SUSPICIOUS-EMPTY: real input but zero links AND zero params -> likely tool/version drift, not a
    # genuine empty. Flag it as partial coverage with the preserved input for diagnosis (v8.2 -i-dir bug).
    got = ((out_links.stat().st_size if out_links.exists() else 0)
           + (out_params.stat().st_size if out_params.exists() else 0))
    if nbytes > 512 and got == 0:
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: {nbytes}B input -> 0 links/params (capability drift? "
                                       f"input kept: {blob.name})")
    if out_params.exists():
        for line in out_params.read_text().splitlines():
            v = line.strip()
            if v and v != "<stdin>":                       # drop the stdin-source noise token
                ctx.run.add("parameter", {"value": v, "sources": [f"xnLinkFinder-{tag}"]})
    if out_links.exists():
        for line in out_links.read_text().splitlines():
            if line.strip():
                ctx.run.add("endpoint", {"value": line.strip(), "sources": [f"xnLinkFinder-{tag}"]})
