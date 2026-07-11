"""Phase 7: Params + lightweight scanning (deepened).

gf vuln-class buckets over the URL corpus -> ranked candidate queues; arjun param
discovery; non-intrusive nuclei with built-in interactsh OOB; dalfox XSS/open-redirect
on reflected/redirect candidates. Scanner output is NEVER a finding without manual
confirmation (design §7) — entities carry confirmed:false.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from .. import events, evidence, normalize, secrets, settings
from ..runner import RunResult, Status, have, nuclei_timeout, run as exec_tool, skipped

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "rce", "ssti", "interestingparams"]


def _apply_nuclei_oob(cmd: list[str]) -> list[str]:
    """Append self-hosted interactsh flags to a nuclei command (else nuclei's built-in public
    server). Shared by EVERY nuclei invocation so they all use the same OOB endpoint — no drift
    where one nuclei call silently uses the public server. `secrets.oob()` is the single source of
    truth for OOB config (future OOB consumers read it too)."""
    oob = secrets.oob()
    if oob.get("interactsh_server"):
        cmd += ["-iserver", str(oob["interactsh_server"])]
        if oob.get("interactsh_token"):
            cmd += ["-itoken", str(oob["interactsh_token"])]
    return cmd


def _nuclei_cmd(targets_file, out_file, prof) -> list[str]:
    """The nuclei main-scan command for one target file — identical flags for every chunk, only -l/-o
    differ (non-intrusive, severity-scoped, governor-scaled -c/-bs, shared OOB endpoint)."""
    cmd = ["nuclei", "-l", str(targets_file), "-jsonl", "-o", str(out_file),
           "-etags", "intrusive,fuzz,dos,brute-force",
           "-s", "critical,high,medium", "-stats", "-si", "30",
           "-c", str(settings.workers("nuclei", 25)),      # H2: core-scaled concurrency (rate stays separate)
           "-bs", str(settings.concurrency("NUCLEI_BULK_SIZE", 25))]   # hosts/template batch
    if prof.http_rl:
        cmd += ["-rl", str(prof.http_rl)]
    _apply_nuclei_oob(cmd)                                 # self-hosted interactsh (else public default)
    return cmd


def _nuclei_scan(ctx, live, findings, log, prof) -> RunResult:
    """Chunked nuclei main scan (step 4.2 Commit B). Split live hosts into NUCLEI_CHUNK_HOSTS-sized
    batches and scan SEQUENTIALLY — rate is target-wide (RoE), so parallel batches would blow the
    budget; chunking buys resume + progress + per-batch isolation, NOT speed (work is rate-bound and
    fixed: OTC = 448 hosts / 5.08M req / 7h41 @ 183rps, died at 93%). Each batch gets its own
    nuclei_timeout, so one slow batch -> coverage_partial instead of a whole-run kill. RESUME: a chunk
    is recorded done ONLY on clean completion (SUCCESS/EMPTY); a failed/timed-out/blocked batch is left
    retryable (not marked, not appended) so a killed run genuinely continues. The state is tied to the
    INPUT (hash of the ordered live list + chunk size) so a changed host set / chunk size invalidates it
    instead of skipping the wrong hosts. Emits source-level tool_start / tool_progress / tool_finish;
    returns a RunResult for the manifest."""
    sid = "params.nuclei_scan"
    chunk_n = max(1, settings.concurrency("NUCLEI_CHUNK_HOSTS", 50))
    batches = [live[i:i + chunk_n] for i in range(0, len(live), chunk_n)]
    state_f = ctx.run.raw_path("params", "nuclei", "chunks.state.json")
    # State is tied to the INPUT: a bare index is meaningless if the host list or chunk size changed
    # (chunk 0 would no longer be the same hosts). Hash the ordered live list + chunk size; a mismatch
    # ignores the stale state and starts fresh.
    input_hash = hashlib.sha256(("\n".join(live) + f"|{chunk_n}").encode("utf-8")).hexdigest()[:16]
    done: set[int] = set()
    if state_f.exists():
        try:
            prev = json.loads(state_f.read_text())
            if prev.get("input_hash") == input_hash and prev.get("chunk_size") == chunk_n:
                done = {int(x) for x in prev.get("done_chunks", [])}
        except Exception:
            done = set()

    def _save():
        state_f.write_text(json.dumps(
            {"input_hash": input_hash, "chunk_size": chunk_n, "done_chunks": sorted(done)}))

    if not done:
        findings.write_text("")                           # fresh (or invalidated) run: empty accumulator
    events.tool_start(sid, cmd=["nuclei", "-l", "<chunk>", "-jsonl"], input_total=len(live))
    t0 = time.monotonic()
    degraded = 0
    for ci, batch in enumerate(batches):
        seen = min((ci + 1) * chunk_n, len(live))
        if ci in done:                                    # resume: already CLEAN, findings on disk
            events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches), current_index=seen)
            continue
        bf = ctx.write_list(f"nuclei_targets_{ci}.txt", batch)
        cf = ctx.run.raw_path("params", "nuclei", f"findings_{ci}.jsonl")
        res = exec_tool("nuclei", _nuclei_cmd(bf, cf, prof),
                        timeout=nuclei_timeout(len(batch), ctx.http_timeout))
        if res.stderr_tail:
            with log.open("a", encoding="utf-8") as lf:
                lf.write(res.stderr_tail + "\n")
        if res.status in (Status.SUCCESS, Status.EMPTY):
            # ONLY clean chunks are durable: append their output ONCE, then mark done. A degraded chunk
            # is never appended (would duplicate on retry) and never marked done (stays retryable).
            if cf.exists():
                with findings.open("a", encoding="utf-8") as fh:
                    fh.write(cf.read_text(encoding="utf-8", errors="replace"))
            done.add(ci)
            _save()
        else:
            degraded += 1
            events.coverage_partial(sid, reason=f"chunk {ci + 1}/{len(batches)}: {res.status.value}")
            # cf left on disk for inspection; not appended, not marked done -> retried on next resume
        events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches), current_index=seen)
    status = Status.PARTIAL if degraded else Status.SUCCESS
    size = findings.stat().st_size if findings.exists() else None
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded}/{len(batches)} chunk(s) degraded" if degraded else None),
                       duration=round(time.monotonic() - t0, 2),
                       raw_ref=str(findings), artifact_size=size, discovery_context="params")
    lines = len(findings.read_text().splitlines()) if findings.exists() else 0
    return RunResult("nuclei", ["nuclei", "-l", "<chunked>"], status, 0,
                     round(time.monotonic() - t0, 2), findings if findings.exists() else None,
                     lines, note=f"{len(batches)} chunk(s), {degraded} degraded")


def _exposed_urls(ctx, scope) -> list[str]:
    """Exposed-sensitive-file URLs to fetch: nuclei exposure hits + 200 sensitive-path URLs,
    de-duped, in-scope + active-allowed (passive/OOS excluded via active_allowed)."""
    seen: set[str] = set()
    out: list[str] = []
    def consider(u):
        u = (u or "").strip()
        if not u or u in seen:
            return
        if evidence.SENSITIVE_FILE_RX.search(u) and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    for f in ctx.run.read("finding"):                 # nuclei matched-at (exposure templates)
        consider(f.get("matched"))
    for r in ctx.run.read("url"):                      # sensitive paths seen live (crawl/content)
        if r.get("status") in (None, 200, "200"):      # status 200 when known; archive/crawl URLs may have no status
            consider(r.get("url"))
    return out


def _graphql_urls(ctx, scope) -> list[str]:
    """Absolute in-scope GraphQL endpoint URLs to introspect: deep-mine `endpoint` kind=graphql +
    any /graphql|/gql URL. Relative values (no host, e.g. bare '/graphql' from JS) are skipped —
    introspection needs a concrete host, and active_allowed gates scope/OOS/passive."""
    seen: set[str] = set()
    out: list[str] = []
    def consider(u):
        u = (u or "").strip()
        if not u or u in seen or not u.lower().startswith(("http://", "https://")):
            return
        if re.search(r"/(?:graphql|gql)\b", u, re.I) and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    for e in ctx.run.read("endpoint"):
        if e.get("kind") == "graphql":
            consider(e.get("value"))
    for r in ctx.run.read("url"):
        consider(r.get("url"))
    return out


def _actuator_bases(ctx, scope) -> list[str]:
    """In-scope Spring Boot actuator base URLs to interrogate. Two candidate sources:
    (a) any observed URL containing `/actuator`, collapsed to its base; and
    (b) live hosts httpx fingerprints as Spring/Spring-Boot — `/actuator` is almost never linked, so
        the tech fingerprint IS the candidate signal (Test-6: mgmt was Spring but had no /actuator
        URL, so the probe never ran). Still candidate-driven — never blind onto every host."""
    seen: set[str] = set()
    out: list[str] = []
    def add_base(base: str):
        if base and base not in seen and scope.active_allowed(normalize.host_of_url(base)):
            seen.add(base)
            out.append(base)
    def consider_url(u):
        u = (u or "").strip()
        if not u or not u.lower().startswith(("http://", "https://")):
            return
        m = re.match(r"(?i)(https?://[^/]+/(?:[^?#]*?/)?actuator)\b", u)
        if m:
            add_base(m.group(1))
    for r in ctx.run.read("url"):
        consider_url(r.get("url"))
    for e in ctx.run.read("endpoint"):
        consider_url(e.get("value"))
    for f in ctx.run.read("finding"):
        consider_url(f.get("matched"))
    # (b) Spring/Boot-fingerprinted live hosts -> probe <origin>/actuator
    for t in ctx.run.read("tech"):
        if "spring" in str(t.get("tech", "")).lower():
            u = (t.get("url") or "").strip()
            if u.lower().startswith(("http://", "https://")):
                add_base(u.rstrip("/") + "/actuator")
    return out


_OPENAPI_RX = re.compile(
    r"(?i)(openapi\.(?:json|ya?ml)|swagger\.(?:json|ya?ml)|/v[23]/api-docs\b|/api-docs\b|"
    r"/swagger/v\d+/swagger\.json|/swagger\.json)")


def _openapi_urls(ctx, scope) -> list[str]:
    """Absolute in-scope OpenAPI/Swagger doc URLs to fetch+parse (openapi.json/yaml, swagger.json,
    /v2|/v3/api-docs, …), de-duped, active-allowed (passive/OOS excluded)."""
    seen: set[str] = set()
    out: list[str] = []
    def consider(u):
        u = (u or "").strip()
        if not u or u in seen or not u.lower().startswith(("http://", "https://")):
            return
        if _OPENAPI_RX.search(u) and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    for r in ctx.run.read("url"):
        consider(r.get("url"))
    for e in ctx.run.read("endpoint"):
        consider(e.get("value"))
    return out


def _framework_endpoint_candidates(ctx, scope) -> list[dict]:
    """Candidate-driven framework recon endpoints: for each live host, match its httpx tech against
    framework-endpoints.yaml and build the origin+path URLs to GET-probe. Only frameworks actually
    fingerprinted contribute (never blind onto every host), de-duped, active-allowed, bounded.
    Mirrors _actuator_bases — the tech fingerprint IS the candidate signal."""
    fw = evidence._framework_endpoints()
    seen: set[str] = set()
    out: list[dict] = []
    for l in ctx.run.read("live"):
        url = (l.get("url") or "").strip()
        m = re.match(r"(?i)(https?://[^/]+)", url)
        if not m:
            continue
        origin, host = m.group(1), normalize.host_of_url(url)
        if not scope.active_allowed(host):
            continue
        techs = " ".join(str(t) for t in (l.get("tech") or [])).lower()
        if not techs:
            continue
        for name, spec in fw.items():
            if not isinstance(spec, dict) or not any(
                    str(mt).lower() in techs for mt in (spec.get("match") or [])):
                continue
            for ep in (spec.get("endpoints") or []):
                path = ep.get("path") if isinstance(ep, dict) else str(ep)
                if not path:
                    continue
                cu = origin + path
                if cu in seen:
                    continue
                seen.add(cu)
                out.append({"url": cu, "framework": name,
                            "note": ep.get("note") if isinstance(ep, dict) else ""})
    return out[:200]


def _ssti_targets(ctx, scope) -> list[str]:
    """gf ssti candidate URLs that carry a query string, de-duped, active-allowed — the params to
    confirm the SSTI primitive on."""
    seen: set[str] = set()
    out: list[str] = []
    for r in ctx.run.read("review"):
        if r.get("klass") != "ssti":
            continue
        u = (r.get("value") or "").strip()
        if u and u not in seen and "?" in u and scope.active_allowed(normalize.host_of_url(u)):
            seen.add(u)
            out.append(u)
    return out


def _canonicalize_candidates(urls: list[str]) -> tuple[list[str], dict]:
    """Collapse XSS/redirect candidate URLs to unique (host, path, sorted param-NAMES) shapes, keeping
    ONE representative URL per shape. dalfox's reflected-XSS selection depends on the param SHAPE, not
    the specific values, so scanning one URL per shape covers the same surface at a fraction of the cost.
    The real problem was never 'dalfox is slow' — it was feeding it the same shape ~10x (measured on OTC:
    993 raw -> 106 shapes, 89.3% collapsed). Returns (representatives, stats) where stats =
    {raw_candidates, canonical_candidates, reduction_percent, top_collapsed}."""
    from urllib.parse import urlsplit, parse_qsl
    shapes: dict = {}
    for u in urls:
        s = urlsplit(u)
        # keep_blank_values: a blank redirect/XSS param (?next= / ?url=) is a REAL, distinct sink —
        # parse_qs() would drop it and silently collapse ?next=, ?url=, ?returnTo= into one shape.
        names = tuple(sorted({k for k, _ in parse_qsl(s.query, keep_blank_values=True)}))
        key = (s.netloc, s.path, names)
        shapes.setdefault(key, {"url": u, "count": 0})["count"] += 1
    reps = [v["url"] for v in shapes.values()]
    raw, canon = len(urls), len(reps)
    top = sorted(shapes.items(), key=lambda kv: -kv[1]["count"])[:5]
    stats = {
        "raw_candidates": raw,
        "canonical_candidates": canon,
        "reduction_percent": round(100 * (1 - canon / raw), 1) if raw else 0.0,
        "top_collapsed": [{"shape": f"{k[0]}{k[1]}?{'&'.join(k[2])}", "count": v["count"]}
                          for k, v in top if v["count"] > 1],
    }
    return reps, stats


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope

    # ── OpenAPI/Swagger docs -> endpoint+param corpus (BEFORE the corpus build so gf/nuclei/arjun
    #    see the extracted endpoints). Active fetch; active_allowed self-gates it off in passive. ──
    oa_urls = _openapi_urls(ctx, scope)
    if oa_urls:
        noa = evidence.parse_openapi(ctx, oa_urls)
        ctx.echo(f"  openapi: {len(oa_urls)} doc(s) parsed, +{noa} endpoint(s) into corpus")

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

    # ── subdomain takeover (nuclei takeover templates over known subs) ──
    if prof.takeover and have("nuclei"):
        # Union, not "resolved or subdomain": dangling-CNAME hosts (the takeover signal)
        # have no A record and live only in `subdomain` — they must still be checked.
        subs = scope.filter_hosts(sorted(set(ctx.run.values("resolved"))
                                         | set(ctx.run.values("subdomain"))))
        if subs:
            tk_in = ctx.write_list("takeover_targets.txt", subs)
            tk_out = ctx.run.raw_path("params", "nuclei", "takeover.jsonl")
            tk_cmd = ["nuclei", "-l", str(tk_in), "-tags", "takeover", "-jsonl", "-o", str(tk_out)]
            if prof.http_rl:                       # else native default (empty = fast)
                tk_cmd += ["-rl", str(prof.http_rl)]
            _apply_nuclei_oob(tk_cmd)              # same OOB endpoint as the main scan (no drift)
            r = exec_tool("nuclei", tk_cmd, timeout=nuclei_timeout(len(subs), ctx.http_timeout))
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
    # ── nuclei (non-intrusive, OOB interactsh, severity-scoped) — chunked + resumable (step 4.2 B) ──
    # The long-pole: OTC = 448 hosts / 5.08M req / 7h41 @ 183rps, died at 93%. Work is rate-bound, so we
    # do NOT gate templates or parallelize batches (would blow the RoE) — we chunk hosts for resume,
    # progress and per-batch isolation. See _nuclei_scan.
    findings = ctx.run.raw_path("params", "nuclei", "findings.jsonl")
    log = ctx.run.raw_path("params", "nuclei", "nuclei.run.log")
    ck = max(1, settings.concurrency("NUCLEI_CHUNK_HOSTS", 50))
    ctx.echo(f"  nuclei: {len(live)} host(s) in chunks of {ck} (resumable · per-chunk budget "
             f"{nuclei_timeout(min(ck, len(live)), ctx.http_timeout) // 60}m · rate-bound, sequential)")
    r = _nuclei_scan(ctx, live, findings, log, prof)
    ctx.run.record("params", r)
    if findings.exists():
        n = 0
        sev = {"critical": 0, "high": 0, "medium": 0}
        for line in findings.read_text().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = obj.get("template-id", "?")
            severity = (obj.get("info") or {}).get("severity", "unknown")
            ctx.run.add("finding", {
                "id": f"{tid}|{obj.get('matched-at', obj.get('host',''))}",
                "template": tid, "severity": severity,
                "name": (obj.get("info") or {}).get("name"),
                "matched": obj.get("matched-at", obj.get("host", "")),
                "sources": ["nuclei"], "confirmed": False})
            if severity in sev:
                sev[severity] += 1
            n += 1
        # terser than the old unconfirmed-validation note — the HOTLIST/digest already carry that
        # framing; here a severity breakdown is more useful at a glance.
        ctx.echo(f"  nuclei: {n} candidate findings · "
                 f"crit:{sev['critical']} high:{sev['high']} med:{sev['medium']}")
        events.ledger("params.nuclei_scan",
                      produced={"finding": n, **sev}, consumed={"target": len(live)})

    # ── exposed-resource fetch + secret extraction (recon evidence: unauth, in-scope, GET-only) ──
    # Map-don't-exploit line = "don't accidentally perform impact": an exposed .env/.git/config is
    # fetched and its secret read (redacted). No payloads, no creds used, no state change.
    exp_urls = _exposed_urls(ctx, scope)
    if exp_urls:
        ne = evidence.fetch_exposed(ctx, exp_urls)
        ctx.echo(f"  exposed-fetch: {len(exp_urls)} exposed resource(s), +{ne} secret(s) extracted")

    # ── GraphQL introspection probe (recon evidence: non-mutating read query, in-scope) ──
    gql_urls = _graphql_urls(ctx, scope)
    if gql_urls:
        ng = evidence.probe_graphql(ctx, gql_urls)
        ctx.echo(f"  graphql: {len(gql_urls)} endpoint(s) probed, {ng} with introspection enabled")

    # ── Actuator sensitive sub-path interrogation (recon evidence: GET-only, non-mutating) ──
    act_bases = _actuator_bases(ctx, scope)
    if act_bases:
        na = evidence.probe_actuator(ctx, act_bases)
        ctx.echo(f"  actuator: {len(act_bases)} base(s) probed, {na} with sensitive endpoints exposed")

    # ── framework-conditional recon endpoints (tech-matched debug/admin dashboards; GET-only) ──
    fw_cands = _framework_endpoint_candidates(ctx, scope)
    if fw_cands:
        nf = evidence.probe_framework_endpoints(ctx, fw_cands)
        ctx.echo(f"  framework-endpoints: {len(fw_cands)} candidate(s) probed, {nf} exposed (200)")

    # ── arjun param discovery on param-less API endpoints (throttled) ──
    api_eps = sorted({u.split("?")[0] for u in corpus
                      if "?" not in u and any(s in u.lower() for s in
                      ("/api", "/rest", "/account", "/profile", "/search", "/user", "/order"))})[:40]
    if api_eps:
        aj_in = ctx.write_list("arjun_targets.txt", api_eps)
        aj_out = ctx.run.raw_path("params", "arjun", "arjun.txt")
        # `-d` is a fixed inter-request delay in SECONDS. The old `-d 1` throttled EVERY request by
        # 1s across all targets and blew the wall timeout (Test-5, 1800s). Delay is a RATE control,
        # not a default — apply it ONLY when the program caps us (http_rl), same model as dalfox.
        # Concurrency (`-t`) stays put; unthrottled, arjun clears the target set inside the timeout.
        aj_cmd = ["arjun", "-i", str(aj_in), "-oT", str(aj_out),
                  "-t", str(settings.workers("arjun", 5))]   # was hard-coded -t 5; I/O-scaled + config-tunable
        if prof.http_rl:
            aj_cmd += ["-d", str(round(1.0 / max(1, prof.http_rl), 3))]
        r = exec_tool("arjun", aj_cmd, timeout=ctx.http_timeout)
        ctx.run.record("params", r)
        # Feed arjun's output forward (each line is a URL with the discovered param(s), e.g.
        # ".../v1/search?q=7101"). Without this the discovery was written to a file and dropped:
        # record provenance AND hand the param-bearing URL to dalfox so a hidden reflected param
        # actually gets XSS-tested.
        naj = 0
        if aj_out.exists():
            for line in aj_out.read_text().splitlines():
                u = line.strip()
                if "?" not in u:
                    continue
                base, qs = u.split("?", 1)
                ctx.run.add("url", {"url": u, "sources": ["arjun"]})
                for pair in qs.split("&"):
                    pname = pair.split("=", 1)[0]
                    if pname:
                        ctx.run.add("parameter", {"value": f"{base}?{pname}=",
                                                  "sources": ["arjun"]})
                ctx.run.add("review", {"id": f"arjun-param:{u[:100]}", "klass": "xss",
                                       "value": u, "host": normalize.host_of_url(u),
                                       "sources": ["arjun"]})
                naj += 1
        if naj:
            ctx.echo(f"  arjun: +{naj} param-bearing URL(s) -> dalfox candidates")
    else:
        ctx.run.record("params", skipped("arjun", "no param-less API endpoints found"))

    # ── dalfox on gf xss + redirect candidates — CANONICALIZED first (step 4.3.A) ──
    # The measured problem was NOT "dalfox is slow" — it was feeding it the same (host,path,param-set)
    # shape ~10x. Collapse to unique shapes BEFORE the tool sees them (OTC: 993 -> 106, 89.3%). No
    # dalfox behavior change yet (flags unchanged); the split/fast-flags are 4.3.B.
    dalfox_raw = [r["value"] for r in ctx.run.read("review") if r.get("klass") in ("xss", "redirect")]
    dalfox_in, canon = _canonicalize_candidates(dalfox_raw)
    if dalfox_in and have("dalfox"):
        ctx.echo(f"  dalfox: {canon['raw_candidates']} raw candidate(s) -> "
                 f"{canon['canonical_candidates']} canonical shape(s) "
                 f"({canon['reduction_percent']}% collapsed)")
        df_in = ctx.write_list("dalfox_in.txt", dalfox_in)
        df_out = ctx.run.raw_path("params", "dalfox", "dalfox.txt")
        # Concurrency (workers = local lanes) stays at dalfox's OWN default — not set here, so it
        # tracks the tool/machine, not the target (rate ≠ workers — they're separate axes).
        # `http_rl` controls RATE only: our installed dalfox has no `--rate-limit` flag, so emulate
        # via a per-request delay. (Newer dalfox adds a `--rate-limit` global req/s — switch to that
        # once it's available.) The old -w 5 --delay 250 idled + timed out.
        df_cmd = ["dalfox", "file", str(df_in), "--skip-bav", "-o", str(df_out)]
        # BLIND XSS: fire out-of-band beacons at the configured collector so a STORED/blind XSS that
        # never reflects in the response still calls home — parity with reconftw's XSS_SERVER → dalfox
        # -b. Opt-in via secrets.yaml `oob.blind_xss_url` (an interactsh-client URL or XSSHunter
        # collector); the interaction is caught in the operator's own listener, not dalfox's output.
        bx = secrets.oob().get("blind_xss_url")
        if bx:
            df_cmd += ["-b", str(bx)]
        if prof.http_rl:
            df_cmd += ["--delay", str(1000 // max(1, prof.http_rl))]
        r = exec_tool("dalfox", df_cmd, timeout=ctx.http_timeout)
        ctx.run.record("params", r)
        if df_out.exists():
            for line in df_out.read_text().splitlines():
                if line.strip().startswith("[POC]") or "PoC" in line:
                    # dalfox proves the PRIMITIVE (reflection), not an exploit. Per the boundary
                    # ruling ("probe hit != exploit proof"), frame it as a CANDIDATE: the raw POC
                    # line stays as evidence in `matched`, but the label says candidate + manual
                    # validation. Escalation/impact/report-ready PoC is the attack layer.
                    ctx.run.add("finding", {
                        "id": f"dalfox:{line[:80]}", "template": "xss-candidate",
                        "name": "reflected parameter — XSS/open-redirect candidate (manual validation required)",
                        "severity": "medium", "matched": line.strip(),
                        "sources": ["dalfox"], "confirmed": False})
        # 4.3.A ledger — the numbers matter more than the code here: make the input reduction explicit
        # so a reviewer sees dalfox scanned shapes, not duplicate URL-variants.
        events.ledger("params.dalfox",
                      produced={"canonical_candidates": canon["canonical_candidates"]},
                      consumed={"raw_candidates": canon["raw_candidates"]},
                      reduction_percent=canon["reduction_percent"],
                      top_collapsed=canon["top_collapsed"])
    elif dalfox_in:
        ctx.run.record("params", skipped("dalfox", "dalfox not installed"))
    else:
        ctx.run.record("params", skipped("dalfox", "no xss/redirect candidates"))

    # ── SSTI primitive-confirm probe (benign {{math}} eval; candidate output) ──
    # gf only name-matches ssti params; nothing else probes them. Confirm the PRIMITIVE with a
    # non-mutating math eval. (reflection/open-redirect primitives are already covered by dalfox.)
    ssti_urls = _ssti_targets(ctx, scope)
    if ssti_urls:
        ns = evidence.probe_ssti(ctx, ssti_urls)
        if ns:
            ctx.echo(f"  ssti: +{ns} SSTI primitive candidate(s) confirmed (manual validation required)")
