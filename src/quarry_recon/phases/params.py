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

from .. import events, evidence, fetch, netguard, normalize, oob, secrets, settings
from ..runner import (RunResult, Status, have, nuclei_timeout, reclassify_from_artifact, run as exec_tool,
                      scaled_timeout, skipped)

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "rce", "ssti", "interestingparams"]


def _arjun_urls(path):
    """FAIL-CLOSED read of arjun's -oT output (one param-bearing URL per line, e.g. `.../search?q=7101`).
    Returns the list of query-bearing URLs (the completion signal for the file-output adapter), or None
    when the file is missing/unreadable — so a chatty arjun stdout can't mask a missing/empty -oT as
    SUCCESS (the OTC false-success: 3954 stdout lines, no arjun.txt, 0 params)."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return [ln.strip() for ln in text.splitlines() if ln.strip() and "?" in ln]


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
    retryable so a killed run genuinely continues. Its OUTPUT is still KEPT — the aggregate is rebuilt
    idempotently from every per-chunk artifact (findings_<ci>.jsonl), so a WAF/timeout-degraded chunk's
    real findings are never discarded and a re-scan can't duplicate. The state is tied to the
    INPUT (hash of the ordered live list + chunk size) so a changed host set / chunk size invalidates it
    instead of skipping the wrong hosts. Emits source-level tool_start / tool_progress / tool_finish;
    returns a RunResult for the manifest."""
    sid = "params.nuclei_scan"
    chunk_n = max(1, settings.concurrency("NUCLEI_CHUNK_HOSTS", 50))
    batches = [live[i:i + chunk_n] for i in range(0, len(live), chunk_n)]
    state_f = ctx.run.raw_path("params", "nuclei", "chunks.state.json")
    # C07 inc4: resume validity is a WORK_UNIT that folds the coverage-affecting CONFIG (severity + excluded
    # tags + chunk size), not just the host list. The old input_hash keyed on hosts+chunk_size ALONE, so a
    # template-scope change (a different severity/etags) would wrongly RESUME done chunks — the same
    # skip-after-settings-change bug fixed for ffuf. Any coverage-affecting change now invalidates the state.
    _cfg = {"severity": "critical,high,medium", "etags": "intrusive,fuzz,dos,brute-force", "chunk": chunk_n}
    scan_wu = events.work_unit(sid, inputs={"hosts": live}, config=_cfg)
    done: set[int] = set()
    if state_f.exists():
        try:
            prev = json.loads(state_f.read_text())
            if prev.get("work_unit") == scan_wu:            # config-inclusive key: mismatch → fresh
                done = {int(x) for x in prev.get("done_chunks", [])}
        except Exception:
            done = set()

    def _save():
        state_f.write_text(json.dumps(
            {"work_unit": scan_wu, "chunk_size": chunk_n, "done_chunks": sorted(done)}))

    if not done:
        findings.write_text("")                           # fresh (or invalidated) run: empty accumulator
        for _old in state_f.parent.glob("findings_*.jsonl"):
            _old.unlink(missing_ok=True)                   # drop stale per-chunk artifacts from a prior input
    events.tool_start(sid, cmd=["nuclei", "-l", "<chunk>", "-jsonl"], input_total=len(live), work_unit=scan_wu)
    t0 = time.monotonic()
    degraded = 0

    def _completed_hosts():                               # UX #4: hosts in CLEANLY-done chunks only (NOT attempted)
        return sum(len(batches[j]) for j in done if j < len(batches))

    # C07 inc4: a source terminal ALWAYS fires (try/finally) even if the loop raises — the source lifecycle
    # (tool_start/tool_finish) is emitted here, per-CHUNK events carry a stable chunk work_unit (not the
    # loop index), and the resume record is chunks.state.json (keyed on scan_wu). No duplicate events.
    status = Status.SUCCESS
    try:
        for ci, batch in enumerate(batches):
            chunk_wu = events.work_unit(sid, inputs={"hosts": batch}, config=_cfg)
            # UX #2: progress BEFORE the chunk — status shows STARTING chunk ci+1, with CLEANLY-completed
            # host count; the per-chunk work_unit is the stable unit id (resume/audit key).
            events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches),
                                 current_index=_completed_hosts(), work_unit=chunk_wu)
            if ci in done:                                # resume: already CLEAN, findings on disk
                continue
            bf = ctx.write_list(f"nuclei_targets_{ci}.txt", batch)
            cf = ctx.run.raw_path("params", "nuclei", f"findings_{ci}.jsonl")
            res = exec_tool("nuclei", _nuclei_cmd(bf, cf, prof),
                            timeout=nuclei_timeout(len(batch), ctx.http_timeout))
            if res.stderr_tail:
                with log.open("a", encoding="utf-8") as lf:
                    lf.write(res.stderr_tail + "\n")
            # KEEP a chunk's findings regardless of status — real even if WAF/timeout-degraded. Mark DONE
            # only on a clean status; a degraded chunk stays retryable. The aggregate is rebuilt below from
            # per-chunk artifacts (idempotent — a re-scan overwrites its own findings_<ci>.jsonl).
            if res.status in (Status.SUCCESS, Status.EMPTY):
                done.add(ci)
                _save()
            else:
                degraded += 1
                events.coverage_partial(sid, reason=f"chunk {ci + 1}/{len(batches)}: {res.status.value}")
        # rebuild the aggregate IDEMPOTENTLY from every chunk artifact that produced output (clean OR degraded)
        with findings.open("w", encoding="utf-8") as fh:
            for ci in range(len(batches)):
                cf = ctx.run.raw_path("params", "nuclei", f"findings_{ci}.jsonl")
                if cf.exists() and cf.stat().st_size > 0:
                    fh.write(cf.read_text(encoding="utf-8", errors="replace"))
        status = Status.PARTIAL if degraded else Status.SUCCESS
    finally:
        events.tool_progress(sid, chunk_index=len(batches), chunk_total=len(batches),
                             current_index=_completed_hosts(), work_unit=scan_wu)   # final: cleanly completed
        size = findings.stat().st_size if findings.exists() else None
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
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
        # ORIGIN-aware key: scheme is part of the identity — http://h/p?x= and https://h/p?x= can be
        # different services / redirect chains, so they must NOT collapse. keep_blank_values: a blank
        # redirect/XSS param (?next= / ?url=) is a REAL distinct sink parse_qs() would silently drop.
        names = tuple(sorted({k for k, _ in parse_qsl(s.query, keep_blank_values=True)}))
        key = (s.scheme.lower(), s.netloc.lower(), s.path, names)
        shapes.setdefault(key, {"url": u, "count": 0})["count"] += 1
    reps = [v["url"] for v in shapes.values()]
    raw, canon = len(urls), len(reps)
    top = sorted(shapes.items(), key=lambda kv: -kv[1]["count"])[:5]
    stats = {
        "raw_candidates": raw,
        "canonical_candidates": canon,
        "reduction_percent": round(100 * (1 - canon / raw), 1) if raw else 0.0,
        "top_collapsed": [{"shape": f"{k[0]}://{k[1]}{k[2]}?{'&'.join(k[3])}", "count": v["count"]}
                          for k, v in top if v["count"] > 1],
    }
    return reps, stats


def _dalfox_cmd(batch_file, out_file, prof) -> list[str]:
    """dalfox FAST flags for the XSS reflection pass. The defaults were the timekiller: --max-cpu 1
    (single core) + param mining ON + headless ON. Quarry already discovers params (arjun/gf), so mining
    is redundant; headless (chromium per candidate) is the big cost. Bump --max-cpu off 1 (governor),
    keep -w, keep blind -b when configured (blind XSS coverage stays until 4.3.D gates it)."""
    cmd = ["dalfox", "file", str(batch_file), "-o", str(out_file),
           "--skip-bav", "--skip-mining-all", "--skip-headless",
           "--max-cpu", str(max(1, settings.concurrency("DALFOX_MAX_CPU", 4))),
           "-w", str(settings.workers("dalfox", 100))]
    bx = secrets.oob().get("blind_xss_url")
    if bx:
        cmd += ["-b", str(bx)]                             # blind/stored XSS OOB beacon (kept; 4.3.D gates)
    if prof.http_rl:
        # RoE rate. dalfox has no global-rate flag, but -w does NOT multiply a host's request rate:
        # file mode is SEQUENTIAL (runSingleMode — we set neither --mass nor --multicast) and the rate
        # limiter is per-host + mutex-serialized (every payload worker calls rl.Block(host)), so the
        # PAYLOAD stream to a host is paced to 1 request per --delay regardless of worker count. --delay is
        # therefore the RoE period; ceil(1000/rl) (not floor, which overshot) bounds that payload stream to
        # ≤ rl req/s. NOT a strict process-wide ceiling: dalfox recreates the limiter per target and fires
        # one bootstrap client.Do() before the limiter, so small bursts at target start/boundaries are
        # possible — strict aggregate enforcement needs a future outer/shared rate plane (C24). (Verified:
        # dalfox v2 cmd/file.go, pkg/scanning/{scan,scanning,ratelimit}.go.)
        cmd += ["--delay", str(-(-1000 // prof.http_rl))]   # -(-a//b) = ceil(a/b), no import
    return cmd


def _dalfox_xss_fast(ctx, cands, prof) -> RunResult:
    """params.dalfox_xss_fast (step 4.3.B): reflected-XSS scan over the CANONICALIZED xss candidates with
    the fast flags, in resumable chunks. Mirrors _nuclei_scan: input-hashed chunk state, mark done ONLY
    on clean completion (failed batch stays retryable), source-level tool_start/tool_progress/tool_finish
    + ledger. dalfox proves the reflection PRIMITIVE only -> finding klass xss-candidate, confirmed:false
    (the map-don't-exploit boundary holds). Findings go straight to the store (deduped by id)."""
    from urllib.parse import urlsplit, parse_qsl
    sid = "params.dalfox_xss_fast"
    chunk_n = max(1, settings.concurrency("DALFOX_CHUNK", 40))
    batches = [cands[i:i + chunk_n] for i in range(0, len(cands), chunk_n)]
    state_f = ctx.run.raw_path("params", "dalfox", "chunks.state.json")
    # C07 inc4: resume validity folds coverage-affecting config (scan mode + whether blind-XSS is armed +
    # chunk size), not just the candidate list — a change (e.g. blind -b now configured) re-runs done chunks.
    _cfg = {"mode": "fast-reflected", "blind": bool(secrets.oob().get("blind_xss_url")), "chunk": chunk_n}
    scan_wu = events.work_unit(sid, inputs={"cands": cands}, config=_cfg)
    done: set[int] = set()
    if state_f.exists():
        try:
            prev = json.loads(state_f.read_text())
            if prev.get("work_unit") == scan_wu:            # config-inclusive key: mismatch → fresh
                done = {int(x) for x in prev.get("done_chunks", [])}
        except Exception:
            done = set()

    def _save():
        state_f.write_text(json.dumps(
            {"work_unit": scan_wu, "chunk_size": chunk_n, "done_chunks": sorted(done)}))

    events.tool_start(sid, cmd=["dalfox", "file", "<chunk>", "--skip-mining-all", "--skip-headless"],
                      input_total=len(cands), work_unit=scan_wu)
    t0 = time.monotonic()
    degraded = produced = 0
    status = Status.SUCCESS
    try:
      for ci, batch in enumerate(batches):
        chunk_wu = events.work_unit(sid, inputs={"cands": batch}, config=_cfg)
        seen = min((ci + 1) * chunk_n, len(cands))
        if ci in done:                                    # resume: already CLEAN
            events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches), current_index=seen,
                                 work_unit=chunk_wu)
            continue
        bf = ctx.write_list(f"dalfox_xss_{ci}.txt", batch)
        cf = ctx.run.raw_path("params", "dalfox", f"dalfox_xss_{ci}.txt")
        res = exec_tool("dalfox", _dalfox_cmd(bf, cf, prof),
                        timeout=scaled_timeout(len(batch), ctx.http_timeout, 30))
        # KEEP a chunk's POCs regardless of status — a WAF/timeout-DEGRADED chunk still found real
        # reflections (the OTC run discarded 30 POC lines this way). Findings go straight to the store,
        # deduped on id, so re-scanning a degraded chunk on resume can't duplicate.
        if cf.exists():
            for line in cf.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().startswith("[POC]") or "PoC" in line:
                    s = line.strip()
                    # reflection = a CANDIDATE, not impact (attack layer proves impact) — and the UNIT is
                    # the SINK, not the payload. dalfox emits one POC per payload variant; canonicalize to
                    # (host, non-empty query-param names) so N payloads on one route collapse to ONE
                    # xss-candidate (raw chunk file keeps every variant as evidence). Neither the old
                    # first-80-chars (collapsed distinct sinks) nor a full-line hash (one finding per
                    # payload — 30 variants of one sink) is honest.
                    url = s.split("] ", 1)[-1].split(" ", 1)[0] if "] " in s else s
                    try:
                        u = urlsplit(url)
                        names = ",".join(sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True) if k}))
                        sink = f"{u.hostname or url}|{names}"
                    except Exception:
                        sink = s
                    if ctx.run.add("finding", {
                            "id": f"xss-candidate:{sink}", "template": "xss-candidate",
                            "name": "reflected parameter — XSS candidate (manual validation required)",
                            "severity": "medium", "matched": s, "confidence": "candidate",
                            "sources": ["dalfox"], "confirmed": False, "raw_ref": str(cf)}):
                        produced += 1
        if res.status in (Status.SUCCESS, Status.EMPTY):
            done.add(ci)
            _save()
        else:
            degraded += 1
            events.coverage_partial(sid, reason=f"chunk {ci + 1}/{len(batches)}: {res.status.value}")
        events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches), current_index=seen,
                             work_unit=chunk_wu)
      status = Status.PARTIAL if degraded else Status.SUCCESS
    finally:
        # C07 inc4: source terminal ALWAYS fires (even if the loop raised) — one source lifecycle, no dup.
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
                           reason=(f"{degraded}/{len(batches)} chunk(s) degraded" if degraded else None),
                           duration=round(time.monotonic() - t0, 2), discovery_context="params")
        events.ledger(sid, produced={"xss_candidate": produced}, consumed={"shape": len(cands)})
    return RunResult("dalfox", ["dalfox", "file", "<chunked-xss-fast>"], status, 0,
                     round(time.monotonic() - t0, 2), None, produced,
                     note=f"{len(batches)} chunk(s), {produced} candidate(s), {degraded} degraded")


_REDIR_PARAMS = {"url", "redirect", "redirect_url", "redirecturl", "redir", "redirect_uri", "return",
                 "returnto", "return_url", "returnurl", "next", "dest", "destination", "continue",
                 "goto", "target", "to", "out", "view", "u", "r", "link", "go", "checkout_url",
                 "login_url", "image_url", "window", "callback", "redirect_to"}
_REDIR_CANARY = "quarry-redirect-canary.example"   # reserved TLD; never followed/resolved


def _redirect_confirm(ctx, cands, prof) -> RunResult:
    """params.redirect_confirm (step 4.3.C): native open-redirect probe — NO dalfox, NO chromium. For
    each canonical candidate, inject a canary host into the redirect-ish param(s) and read the Location
    header WITHOUT following it (one scoped, rate-paced, non-mutating request each via
    fetch.redirect_location). If the app would send us to the canary HOST, it's an open-redirect
    CANDIDATE (confirmed:false — primitive, not impact). A relative/same-host Location is NOT a finding.
    Emits source-level events; returns a RunResult (stdout_lines = confirmed count) for the caller's
    ledger."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urljoin
    sid = "params.redirect_confirm"
    canary_url = f"https://{_REDIR_CANARY}/rc"
    events.tool_start(sid, cmd=["<native redirect probe>", "--no-follow"], input_total=len(cands))
    t0 = time.monotonic()
    confirmed = probed = degraded = 0
    for i, u in enumerate(cands, 1):
        host = normalize.host_of_url(u)
        if not ctx.scope.active_allowed(host):        # scoped: in-scope, not passive, not OOS
            continue
        s = urlsplit(u)
        pairs = parse_qsl(s.query, keep_blank_values=True)
        if not any(k.lower() in _REDIR_PARAMS for k, _ in pairs):
            continue
        newq = [(k, canary_url if k.lower() in _REDIR_PARAMS else v) for k, v in pairs]
        probe = urlunsplit((s.scheme, s.netloc, s.path, urlencode(newq), ""))
        probed += 1
        try:
            loc, status_code = fetch.redirect_location(ctx, probe, host)
        except Exception:
            degraded += 1
            continue
        # A Location header only redirects on a 3xx — a 200/201 that happens to echo one is NOT an open
        # redirect. urljoin resolves relative/protocol-relative Locations against the origin, so a
        # same-host redirect stays on-host (not a finding); only a 3xx whose Location HOST is our canary
        # confirms.
        if loc and 300 <= int(status_code or 0) < 400 \
                and normalize.host_of_url(urljoin(probe, loc)) == _REDIR_CANARY:
            confirmed += 1
            ctx.run.add("finding", {
                "id": f"open-redirect:{u[:90]}", "template": "open-redirect-candidate",
                "name": "open-redirect candidate — param redirects off-host (manual validation required)",
                "severity": "medium", "matched": f"{probe} -> Location: {loc}",
                "sources": ["redirect_confirm"], "confirmed": False})
        events.tool_progress(sid, current_index=i, input_total=len(cands))
    status = Status.PARTIAL if degraded else Status.SUCCESS
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded} probe error(s)" if degraded else None),
                       duration=round(time.monotonic() - t0, 2), discovery_context="params")
    return RunResult("redirect_confirm", ["<native redirect probe>"], status, 0,
                     round(time.monotonic() - t0, 2), None, confirmed,
                     note=f"{probed} probed, {confirmed} open-redirect candidate(s)")


_OOB_PARAMS = {"url", "uri", "dest", "destination", "redirect", "redirect_uri", "next", "continue",
               "return", "callback", "webhook", "target", "proxy", "fetch", "load", "site", "host",
               "domain", "feed", "image_url", "imageurl", "link", "out", "to", "u", "path", "file",
               "port", "open", "window", "data", "source", "src", "remote"}


def _oob_probe(ctx, scope, prof):
    """params.oob_probe (P2.3): Quarry-OWNED out-of-band probe. Opens an interactsh session, injects a
    per-(target,param) callback URL into the SSRF-ish params of the gf `ssrf` candidates (SCOPED +
    rate-paced + non-mutating GET via the shared fetch guard), polls the owned session, and records
    CORRELATED oob_interaction rows (source=params.oob_probe, target/param filled). A callback proves the
    SSRF / external-load PRIMITIVE reached out-of-band -> candidate, NOT impact (attack layer's job).
    Skips when passive-only / no interactsh-client / no SSRF-param candidates. Delayed callbacks are
    common — re-poll later with `quarry oob poll` (P2.4). Returns a RunResult or None."""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    if scope.passive_only:                          # record honest skips — the source is wired/default-on
        ctx.run.record("params", skipped("oob_probe", "passive-only mode"))
        return None
    if not have("interactsh-client"):
        ctx.run.record("params", skipped("oob_probe", "interactsh-client not installed"))
        return None
    raw = [r["value"] for r in ctx.run.read("review")
           if r.get("klass") == "ssrf" and scope.active_allowed(normalize.host_of_url(r.get("value", "")))]
    cands, _canon = _canonicalize_candidates(raw)
    probes = []                                    # (url, split, pairs, ssrf-param) — one token per param
    for u in cands:
        s = urlsplit(u)
        pairs = parse_qsl(s.query, keep_blank_values=True)
        for k, _v in pairs:
            if k.lower() in _OOB_PARAMS:
                probes.append((u, s, pairs, k))
    if not probes:
        ctx.run.record("params", skipped("oob_probe", "no SSRF-param candidates"))
        return None
    opened = oob.open_session(ctx.run, server=secrets.oob().get("interactsh_server"),
                              token=secrets.oob().get("interactsh_token"))
    if opened is None:
        ctx.run.record("params", skipped("oob_probe", "interactsh session did not open"))
        return None
    session, proc = opened
    sid = "params.oob_probe"
    events.tool_start(sid, cmd=["<oob probe>", "interactsh"], input_total=len(probes))
    t0 = time.monotonic()
    issued = added = correlated = 0
    try:
        for i, (u, s, pairs, k) in enumerate(probes, 1):
            # persist the mapping BEFORE the probe leaves (crash-safe: a later callback still correlates)
            token = oob.issue_token(session, sid, u, k, "ssrf-callback", run=ctx.run)
            cb = oob.callback_url(session, token, scheme="http")
            probe_url = urlunsplit((s.scheme, s.netloc, s.path,
                                    urlencode([(kk, cb if kk == k else vv) for kk, vv in pairs]), ""))
            issued += 1
            try:
                # NO-FOLLOW + header-only: if the target 302s to Location: <our-callback>, we must NOT
                # follow it — Quarry would fetch its OWN collector and fake an SSRF hit. The server-side
                # SSRF (if any) still fires from the request itself; we just don't self-trigger.
                fetch.redirect_location(ctx, probe_url, normalize.host_of_url(probe_url), timeout=10)
            except Exception:
                pass                               # a target that doesn't SSRF-fetch is the common case
            events.tool_progress(sid, current_index=i, input_total=len(probes))
        time.sleep(3)                              # brief window for a server-side callback to arrive
        for row in oob.poll_session(ctx.run, session):
            row.setdefault("raw_ref", session.get("log"))
            if ctx.run.add("oob_interaction", row):
                added += 1
                correlated += 1 if row.get("correlation") == "correlated" else 0
    finally:
        oob.close_session(proc)
    events.tool_finish(sid, status=Status.SUCCESS.value, duration=round(time.monotonic() - t0, 2),
                       discovery_context="params")
    events.ledger(sid, produced={"oob_interaction": added, "correlated": correlated},
                  consumed={"probe": issued})
    ctx.echo(f"  oob_probe: {issued} callback probe(s) -> {added} interaction(s) ({correlated} correlated)")
    return RunResult("oob_probe", ["<oob probe>"], Status.SUCCESS, 0, round(time.monotonic() - t0, 2),
                     None, added, note=f"{issued} probe(s), {added} interaction(s), {correlated} correlated")


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
        # netguard fresh-resolves these subs: RECORDS private/self leads, WITHHOLDS only scan-box/metadata
        # self-hits (private is scanned), and KEEPS authoritative-NXDOMAIN dangling hosts (allow_dangling) —
        # exactly the takeover signal — while a transient-indeterminate host still passes through.
        subs = netguard.guard_hosts(ctx, subs, phase="params.takeover", allow_dangling=True)
        if subs:
            tk_in = ctx.write_list("takeover_targets.txt", subs)
            tk_out = ctx.run.raw_path("params", "nuclei", "takeover.jsonl")
            tk_cmd = ["nuclei", "-l", str(tk_in), "-tags", "takeover", "-jsonl", "-o", str(tk_out)]
            # NB: nuclei has no connect-time IP deny (-eh excludes INPUT entries, not resolved IPs); the
            # scan-box/metadata protection for these subs is netguard.guard_hosts' fresh-resolve above.
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
    # FRESH self-attack guard right before the scan: `live` was resolved back in the probe phase (possibly
    # hours + a crawl/content phase ago), so re-check current resolution — a host that now points to the scan
    # box / metadata never reaches a nuclei chunk. Private targets stay allowed (recorded as leads).
    live = netguard.guard_urls(ctx, live, phase="params.nuclei_scan")
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
    _nchunks = (len(live) + ck - 1) // ck
    _budget = nuclei_timeout(min(ck, len(live)), ctx.http_timeout)
    # UX #1: 0 means unbounded (not "0m"). A sub-minute / non-round budget must not truncate to "0m"/whole
    # minutes — render exact m/s so a 45s or 90s ceiling reads honestly.
    if not _budget:
        _budget_txt = "unbounded"
    elif _budget < 60:
        _budget_txt = f"{_budget}s"
    elif _budget % 60:
        _budget_txt = f"{_budget // 60}m{_budget % 60}s"
    else:
        _budget_txt = f"{_budget // 60}m"
    _final = len(live) - (_nchunks - 1) * ck if _nchunks else 0
    ctx.echo(f"  nuclei: {len(live)} host(s) · {_nchunks} sequential chunk(s) of {ck}"
             + (f" (final {_final})" if _nchunks > 1 and _final != ck else "")
             + f" · per-chunk budget {_budget_txt} · checkpointed")   # UX #5: 'checkpointed' (no operator --resume yet)
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
    ARJUN_CAP = 40
    _api_all = sorted({u.split("?")[0] for u in corpus
                       if "?" not in u and any(s in u.lower() for s in
                       ("/api", "/rest", "/account", "/profile", "/search", "/user", "/order"))})
    _api_all = netguard.guard_urls(ctx, _api_all, phase="params.arjun")   # fresh-resolve: withhold scan-box/metadata, contact private
    api_eps = _api_all[:ARJUN_CAP]
    _n_api = len(_api_all)          # emit every run (omitted=0 clears a prior cap gap on rerun)
    events.coverage_partial("params.arjun", kind=events.COVERAGE_CAP, measure="api_endpoints",
                            eligible=_n_api, tested=min(_n_api, ARJUN_CAP), omitted=max(0, _n_api - ARJUN_CAP),
                            reason=f"arjun targets {min(_n_api, ARJUN_CAP)}/{_n_api} API endpoints (cap {ARJUN_CAP})")
    if api_eps:
        aj_in = ctx.write_list("arjun_targets.txt", api_eps)
        aj_out = ctx.run.raw_path("params", "arjun", "arjun.txt")
        aj_out.unlink(missing_ok=True)                     # stale -oT must not fake completion
        # RoE rate. The old `-d 1/rl` was NOT a breach: arjun forces threads=1 whenever a delay is set
        # (verified arjun __main__.py), so it paced correctly but SERIALLY. `--rate-limit` (verified -h)
        # is the better control — a global RPS cap that does NOT collapse threads, so concurrency (`-t`)
        # is preserved under the ceiling. Applied only when the operator sets http_rl. Coverage unchanged.
        aj_cmd = ["arjun", "-i", str(aj_in), "-oT", str(aj_out),
                  "-t", str(settings.workers("arjun", 5))]   # was hard-coded -t 5; I/O-scaled + config-tunable
        if prof.http_rl:
            aj_cmd += ["--rate-limit", str(prof.http_rl)]   # global RPS cap; keeps -t concurrency (unlike -d)
        r = exec_tool("arjun", aj_cmd, timeout=ctx.http_timeout)
        # arjun is a FILE-output tool (-oT); its status must come from the artifact, not its chatty stdout.
        # The OTC false-success: exit 0 + 3954 stdout lines but NO arjun.txt -> classified SUCCESS with 0
        # params. Reclassify from the parsed -oT via the shared adapter (0 params -> EMPTY, absent/unreadable
        # -> PARTIAL/keep-hard). Each -oT line is a param-bearing URL (e.g. ".../v1/search?q=7101").
        urls = _arjun_urls(aj_out)
        reclassify_from_artifact(r, None if urls is None else len(urls), label="arjun")
        ctx.run.record("params", r)
        # Feed arjun's output forward — record provenance AND hand the param-bearing URL to dalfox so a
        # hidden reflected param actually gets XSS-tested (without this it was written to a file + dropped).
        naj = 0
        for u in (urls or []):
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

    # ── vuln-primitive probes over the 4.3.A CANONICALIZED shapes, SPLIT by primitive ──
    # XSS reflection -> params.dalfox_xss_fast (dalfox, 4.3.B). Open-redirect -> params.redirect_confirm
    # (native Location probe, NO dalfox, 4.3.C). dalfox is no longer responsible for redirect at all.
    xss_raw = [r["value"] for r in ctx.run.read("review") if r.get("klass") == "xss"]
    redir_raw = [r["value"] for r in ctx.run.read("review") if r.get("klass") == "redirect"]
    xss_cands, xss_canon = _canonicalize_candidates(xss_raw)
    redir_cands, redir_canon = _canonicalize_candidates(redir_raw)
    # audit #1: dalfox is an external tool that CONTACTS these URLs — drop any whose host resolves internal /
    # can't be resolved. (redir_cands go through fetch.redirect_location, which resolve-guards each origin.)
    xss_cands = netguard.guard_urls(ctx, xss_cands, phase="params.dalfox")
    if not xss_cands and not redir_cands:
        ctx.run.record("params", skipped("dalfox", "no xss/redirect candidates"))
    # XSS reflection — dalfox fast path (needs dalfox)
    if xss_cands:
        if have("dalfox"):
            ctx.echo(f"  dalfox xss: {xss_canon['raw_candidates']} raw -> "
                     f"{xss_canon['canonical_candidates']} shape(s) "
                     f"({xss_canon['reduction_percent']}% collapsed)")
            ctx.run.record("params", _dalfox_xss_fast(ctx, xss_cands, prof))
        else:
            ctx.run.record("params", skipped("dalfox", "dalfox not installed"))
    # open-redirect — native single-request Location probe (4.3.C), no dalfox
    if redir_cands:
        r = _redirect_confirm(ctx, redir_cands, prof)
        ctx.echo(f"  redirect_confirm: {redir_canon['raw_candidates']} raw -> "
                 f"{redir_canon['canonical_candidates']} shape(s) -> {r.stdout_lines} confirmed candidate(s)")
        ctx.run.record("params", r)
        # ledger: raw redirect candidates -> canonical shapes -> confirmed open-redirect candidates
        events.ledger("params.redirect_confirm",
                      produced={"open_redirect_candidate": r.stdout_lines},
                      consumed={"raw_candidates": redir_canon["raw_candidates"],
                                "canonical_candidates": redir_canon["canonical_candidates"]},
                      reduction_percent=redir_canon["reduction_percent"])

    # ── SSTI primitive-confirm probe (benign {{math}} eval; candidate output) ──
    # gf only name-matches ssti params; nothing else probes them. Confirm the PRIMITIVE with a
    # non-mutating math eval. (reflection/open-redirect primitives are already covered by dalfox.)
    ssti_urls = _ssti_targets(ctx, scope)
    if ssti_urls:
        ns = evidence.probe_ssti(ctx, ssti_urls)
        if ns:
            ctx.echo(f"  ssti: +{ns} SSTI primitive candidate(s) confirmed (manual validation required)")

    # ── OOB probe (P2.3): Quarry-owned interactsh callback on SSRF-ish params (correlated evidence) ──
    oob_r = _oob_probe(ctx, scope, prof)
    if oob_r is not None:
        ctx.run.record("params", oob_r)
