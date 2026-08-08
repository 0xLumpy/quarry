"""Phase 7: Params + lightweight scanning (deepened).

gf vuln-class buckets over the URL corpus -> ranked candidate queues; arjun param
discovery; non-intrusive nuclei with built-in interactsh OOB; dalfox XSS/open-redirect
on reflected/redirect candidates. Scanner output is NEVER a finding without manual
confirmation (design §7) — entities carry confirmed:false.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import time
from bisect import insort
from dataclasses import dataclass, field
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from urllib.parse import urlsplit

from .. import budget, events, evidence, fetch, netguard, normalize, oob, secrets, settings
from ..runner import (RunResult, Status, cancel_all as runner_cancel_all, fresh_artifact_dir, have,
                      nuclei_timeout, reset_cancel as runner_reset_cancel, run as exec_tool,
                      scaled_timeout, skipped)

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "rce", "ssti", "interestingparams"]


def active_review_values(ctx, klass: str) -> list:
    """Review rows an ACTIVE lane may act on: the expected `klass` AND `scope.active_allowed`.

    review-B1.5br1#2: every active consumer of `review` filtered on its own klass, and most also asked
    `active_allowed` — but each did it inline, so the RoE guarantee was a convention repeated four times
    rather than a rule. Off-scope evidence (`related-host`) is RETAINED IN FULL and must never reach a
    lane that CONTACTS anything; that is what makes full retention passive. One helper, so a new active
    lane cannot select rows generically and quietly widen the boundary.

    Values are returned in store order; the caller still canonicalizes and guards its own targets."""
    out = []
    for r in ctx.run.read("review"):
        if r.get("klass") != klass:
            continue
        v = (r.get("value") or "").strip()
        if v and ctx.scope.active_allowed(normalize.host_of_url(v)):
            out.append(v)
    return out


def _arjun_base(url: str) -> "str | None":
    """The scheme://host[:port]/path identity of an absolute HTTP(S) URL, or None if it is not one.

    review#2 (A2): `"?" in line` is not a URL contract — `garbage?x=1` passed it and was ingested as a
    discovered parameter. A row must be an absolute http(s) URL with a real host before anything downstream
    treats it as one."""
    try:
        s = urlsplit(url.strip())
    except ValueError:
        return None
    if s.scheme not in ("http", "https") or not s.hostname:
        return None
    try:
        if s.port is not None and not (0 < s.port < 65536):
            return None
    except ValueError:                              # a non-numeric port raises here
        return None
    host = s.hostname.lower()
    port = f":{s.port}" if s.port is not None else ""
    return f"{s.scheme}://{host}{port}{s.path}"


def _arjun_rows(path, target: str) -> tuple:
    """Parse an -oT artifact BOUND TO ITS TARGET -> (rows, malformed). `rows` is None when there is no file.

    Every row must be an absolute http(s) URL, carry a query, and resolve to the SAME base URL we asked
    arjun to scan. review#2 (A2): without the target binding, an artifact naming a different host was
    accepted verbatim and its 'parameters' were ingested against a target we never requested — evidence
    laundering, and a scope escape if that host is out of scope.

    A malformed non-blank row makes the artifact NON-COMPLETABLE (the caller must not journal the target
    as done) while the rows that DO validate are still retained: partial corruption must not discard
    trustworthy siblings."""
    if path is None or not Path(path).exists():
        return None, 0
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, 0
    want = _arjun_base(target)
    rows, malformed = [], 0
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln:
            continue                                # blank padding is not corruption
        url = ln.split("\t", 1)[0].strip()          # POST/JSON rows are "<url>\t<params>"
        base = _arjun_base(url)
        if base is None or not urlsplit(url).query or want is None or base != want:
            malformed += 1
            continue
        rows.append(url)
    return rows, malformed


# ── arjun completion contract (probed against arjun 2.2.7, 2026-07-27) ────────────────────────────────
# Measured, not inferred. `main()` returns None on every ordinary path, so the EXIT CODE is not an
# execution oracle: a run whose every target was skipped still exits 0. Only arjun's own crash exits
# nonzero — and it crashes on any target answering 400/413/418/429/503 (`initialize()` calls
# `.status_code` on a dict) or on a transport error (`requester` returns `str(e)`, and the `type(...)
# == str` guard sits two lines AFTER the attribute access). That traceback is unhandled, so in a BATCHED
# invocation every remaining target is never scanned: measured 3 targets with a 429 second -> exit 1,
# `Scanning 1/3` last, target 3 silently lost. Hence one target per process (below).
_ARJUN_SCHEMA = 1                      # parser+contract version; folded into the resume identity
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_AJ_SCAN_RE = re.compile(r"^\[\*\]\s+Scanning\s+\d+/\d+:\s+(\S+)")
_AJ_SKIP_RE = re.compile(r"^\[-\]\s+Skipped\s+(\S+)\s+due to errors")
_AJ_FOUND = "Parameters found:"
_AJ_NONE = "No parameters were discovered."
# arjun prints this, then `return []` — which main() reports with the ORDINARY no-parameters line. The
# terminal line therefore LIES about a target it actually abandoned; treat it as a skip, never a clean zero.
_AJ_UNSTABLE = "Webpage is returning different content on each request. Skipping."


def _arjun_signals(text: str) -> dict:
    """The structured facts carried by arjun's stdout. Progress lines use `end='\\r'`, so splitlines()
    (which breaks on \\r too) is required to see the terminal line that follows them."""
    lines = [_ANSI_RE.sub("", ln).strip() for ln in (text or "").splitlines()]
    return {"scanned": [m.group(1) for ln in lines if (m := _AJ_SCAN_RE.match(ln))],
            "found": [ln for ln in lines if _AJ_FOUND in ln],
            "none": [ln for ln in lines if _AJ_NONE in ln],
            "skipped": [ln for ln in lines if _AJ_SKIP_RE.match(ln)],
            # the URL the skip line names, EXTRACTED — the caller binds it to the requested target, and
            # passing the whole line to a URL parser silently yields "not a URL" for every skip.
            "skipped_url": [m.group(1) for ln in lines if (m := _AJ_SKIP_RE.match(ln))],
            "unstable": [ln for ln in lines if _AJ_UNSTABLE in ln]}


def _arjun_verdict(exit_ok: bool, sig: dict, urls, *, target: str, malformed: int = 0) -> tuple:
    """FAIL-CLOSED per-target classification -> (verdict, detail). `urls` is `_arjun_rows()[0]`: the
    validated rows, or None when no -oT file exists.

    Completion is claimed ONLY when the exit code, the stdout terminal line and the artifact state all
    agree — AND all three are about the target we actually asked for. `Scanning i/N` proves a target was
    ATTEMPTED, never that it completed, so it is a precondition here and not evidence of success.
    Verdicts:
      success  -> complete, params found        · empty    -> complete, target genuinely has none
      skipped  -> degraded, retained, retryable · failed   -> nonzero exit; keep partial findings
      unknown  -> missing / duplicate / contradictory / OFF-TARGET signals; never a clean zero"""
    n_scan = len(sig["scanned"])
    terminal = len(sig["found"]) + len(sig["none"]) + len(sig["skipped"])
    if not exit_ok:
        # the traceback is the evidence; any -oT rows already exported stay valid (text_export appends
        # per target as params are confirmed), so findings survive but the target is NEVER complete.
        return "failed", "arjun exited nonzero (crash) — findings retained, target not complete"
    if n_scan != 1:
        return "unknown", f"expected exactly 1 target attempt on stdout, saw {n_scan}"
    # review#2 (A2): the stdout must be ABOUT the requested target. arjun prints the URL it was given
    # (main() captures `url` before initialize() rewrites request['url']), so a mismatch means this
    # output does not belong to this target and nothing in it may be attributed to it.
    want = _arjun_base(target)
    if want is None or _arjun_base(sig["scanned"][0]) != want:
        return "unknown", f"stdout reports scanning {sig['scanned'][0]!r}, not the requested target"
    if terminal != 1:
        return "unknown", f"expected exactly 1 terminal line, saw {terminal}"
    if sig["skipped"]:
        if not sig["skipped_url"] or _arjun_base(sig["skipped_url"][0]) != want:
            return "unknown", "the skip line names a different target than the one requested"
        return "skipped", "arjun skipped the target due to errors"
    if malformed:
        # partial corruption: the valid rows are still ingested by the caller, but an artifact we cannot
        # fully account for must never be journaled as this target's finished work.
        return "unknown", f"{malformed} malformed/off-target row(s) in the -oT artifact"
    if sig["none"]:
        if sig["unstable"]:
            return "skipped", "target returns different content per request — arjun abandoned it"
        if urls is not None:
            return "unknown", "terminal line reports no parameters but an -oT artifact exists"
        return "empty", "no parameters (clean, no artifact expected)"
    if not urls:
        return "unknown", "terminal line reports parameters but the -oT artifact is missing/empty"
    return "success", f"{len(urls)} param-bearing URL(s)"


def _arjun_manifest(dest: Path, url: str, verdict: str, channels: dict) -> tuple:
    """Publish the completion MANIFEST binding every evidence channel of one attempt, -> (path, digest)
    or (None, None).

    The manifest — not the -oT file — is the ledger's completion artifact, because an attempt has THREE
    evidence channels (stdout, stderr/traceback, optional -oT) and completion must cover all of them.
    Recording one channel while merely retaining the others would let a resume trust a verdict whose
    proof had since been truncated or replaced."""
    body = json.dumps({"schema": _ARJUN_SCHEMA, "url": url, "verdict": verdict,
                       "channels": dict(sorted(channels.items()))}, sort_keys=True).encode()
    dig = hashlib.sha256(body).hexdigest()
    return (dest, dig) if budget.publish_bytes(dest, body, digest=dig) else (None, None)


def _arjun_channels(ledger, url: str) -> "dict | None":
    """The validated channel paths for a COMPLETED target, or None when the attempt can no longer be
    trusted and must be redone.

    `Ledger.evidence()` returns only artifacts whose digest still matches, so requiring every channel the
    manifest names to appear there is what stops a half-remembered attempt from being resumed: alter or
    truncate any one channel and the whole completion is withdrawn, not silently narrowed."""
    man = ledger.artifact(url)
    if man is None:
        return None
    try:
        data = json.loads(man.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != _ARJUN_SCHEMA or data.get("url") != url:
        return None
    ch = data.get("channels")
    if not isinstance(ch, dict) or not ch:
        return None
    base = ledger.path.parent
    validated = set()
    for p in ledger.evidence(url):
        try:
            validated.add(str(p.relative_to(base)))
        except ValueError:
            continue
    out = {}
    for name, rel in ch.items():
        if not isinstance(rel, str) or rel not in validated:
            return None                    # a bound channel failed digest validation -> redo the target
        out[name] = base / rel
    return out


def _arjun_ingest(ctx, rows, params_path) -> int:
    """Feed a target's VALIDATED -oT rows forward — provenance AND the param-bearing URL handed to dalfox
    so a hidden reflected param actually gets XSS-tested (without this it was written to a file + dropped).

    review#5 (A2): every entity carries `raw_ref` to the artifact the evidence actually came from, per
    Quarry's traceability contract — a finding whose proof cannot be located is not reviewable."""
    ref = str(params_path) if params_path is not None else None
    n = 0
    for u in rows or []:
        base, qs = u.split("?", 1)
        # review#4 (A2): a truncated identity COLLIDES. Two long URLs sharing a 100-char prefix collapsed
        # into one review, silently discarding a distinct finding. Bind the id to the whole URL — the FULL
        # digest, so the identity matches what the comment claims (a 32-hex slice is 128-bit, not sha256).
        uid = hashlib.sha256(u.encode()).hexdigest()
        ctx.run.add("url", {"url": u, "sources": ["arjun"], "raw_ref": ref})
        for pair in qs.split("&"):
            pname = pair.split("=", 1)[0]
            if pname:
                ctx.run.add("parameter", {"value": f"{base}?{pname}=", "sources": ["arjun"],
                                          "raw_ref": ref})
        ctx.run.add("review", {"id": f"arjun-param:{uid}", "klass": "xss", "value": u,
                               "host": normalize.host_of_url(u), "sources": ["arjun"], "raw_ref": ref})
        n += 1
    return n


def _arjun_engine() -> str:
    """The VERIFIED identity of the arjun binary that will ACTUALLY run (registry health), folded into the
    resume work unit.

    review#3 (A2): returning a stable "" when identity could not be established let a shadowed, drifted or
    unidentifiable arjun resume another binary's completions — the exact hole `_dalfox_engine_id` already
    closes. An unverified engine now yields a per-run NONCE, so that run is NON-resumable: re-scanning is a
    safe superset, silently skipping targets we cannot prove ran on this binary is not."""
    try:
        from ..registry import health, load_tools
        t = next((x for x in load_tools() if x.bin == "arjun"), None)
        if t is not None:
            h = health(t)
            if h.get("ok") and h.get("identity"):
                return str(h["identity"])
    except Exception:
        pass
    return "unverified-" + os.urandom(8).hex()


_AJ_STATUS = {"success": Status.SUCCESS, "empty": Status.EMPTY,
              "skipped": Status.PARTIAL, "unknown": Status.PARTIAL}


def _arjun_rate_shares(rl: int, procs: int) -> list:
    """Partition a GLOBAL lane rate `rl` (req/s) across `procs` concurrent arjun processes.

    review#1 (A2): `--rate-limit` is PER PROCESS. Handing every worker the full `rl` would multiply the
    real rate at the target by the worker count — an RoE breach dressed as a rate cap. The shares are
    integers summing to EXACTLY `rl`, and no process may be given 0 (arjun treats that as unlimited), so
    a rate below the pool size reduces the POOL instead: concurrency yields to the rate, never the
    reverse. `rl` falsy = no operator cap = no flag at all and the pool runs unthrottled.

    review#1 (A2 r2): shares are returned LARGEST FIRST and slots are consumed in order, so a run that
    never fills the pool still uses the biggest share available. `procs` must already be the EFFECTIVE
    pool (see `_arjun_pool`) — partitioning across slots that cannot run strands the operator's rate."""
    if not rl:
        return [0] * max(1, procs)
    procs = max(1, min(procs, rl))
    base, extra = divmod(rl, procs)
    return [base + (1 if i < extra else 0) for i in range(procs)]


def _arjun_pool(configured: int, hosts: int, rl: int) -> int:
    """The EFFECTIVE number of concurrent arjun processes.

    review#1 (A2 r2): the pool was sized from config alone and the rate partitioned across it BEFORE
    knowing how many slots could ever run. One eligible host with rate 7 and pool 5 produced shares
    [2,2,1,1,1], ran strictly one at a time (one active target per host), and — taking the last slot
    first — used 1 req/s of the 7 the operator permitted. Bound the pool by the work that actually
    exists: at most one target per host means more slots than hosts are unusable by construction."""
    n = max(1, min(configured, max(1, hosts)))
    return max(1, min(n, rl)) if rl else n


def _arjun_exec(url: str, rate: int, threads: int, paths: tuple, timeout: int) -> dict:
    """Run ONE arjun process for ONE target and return everything the parent needs to classify it.

    Deliberately does NO ledger / event / store writes: those stay single-threaded in the parent, so the
    append-only journal, the coverage generation and the entity store keep exactly the ordering guarantees
    they were hardened for. A worker only produces facts."""
    out_f, std_f, err_f = paths
    out_f.unlink(missing_ok=True)          # our OWN fresh attempt file; a stale -oT must not fake output
    cmd = ["arjun", "-u", url, "-oT", str(out_f), "-t", str(threads)]
    if rate:
        cmd += ["--rate-limit", str(rate)]              # this process's SHARE of the global lane rate
    r = exec_tool("arjun", cmd, raw_path=std_f, stderr_path=err_f, timeout=timeout)
    try:
        text = std_f.read_text(encoding="utf-8", errors="replace") if std_f.exists() else ""
    except OSError:
        text = ""                          # unreadable stdout -> no signals -> unknown (fails CLOSED)
    rows, malformed = _arjun_rows(out_f, url)
    verdict, detail = _arjun_verdict(r.exit_code == 0, _arjun_signals(text), rows,
                                     target=url, malformed=malformed)
    return {"url": url, "result": r, "verdict": verdict, "detail": detail,
            "rows": rows, "malformed": malformed, "paths": paths}


def _arjun_zero_lifecycle(ctx, why: str) -> None:
    """Emit a COMPLETE zero-valued lifecycle, then record the skip.

    review#6 (A2): the no-input exit simply returned, so on a resumed lifecycle a PRIOR run's arjun
    coverage units stayed visible as current — the same defect the content/vhost lanes fixed by routing
    EVERY exit through an explicit generation."""
    for m in ("api_endpoints", "endpoints_tested", "state_persisted"):
        events.coverage_partial("params.arjun", measure=m, unit=m, eligible=0, tested=0, omitted=0,
                                reason=why)
    ctx.run.record("params", skipped("arjun", why))


def _arjun_lane(ctx, prof, corpus) -> None:
    """arjun param discovery, ONE TARGET PER PROCESS.

    A batched `-i` invocation cannot attribute completion per target, and arjun's unhandled `.status_code`
    crash on a 400/413/418/429/503 (or any transport error) aborts every REMAINING target in the file —
    measured: 3 targets, a 429 second, target 3 never scanned. Per-target isolation contains that to its
    own target, makes each URL independently classifiable, and makes the remainder resumable. Overhead is
    0.08 s interpreter start against a network-bound scan.

    Targets run CONCURRENTLY in a bounded pool (`ARJUN_TARGETS`, default 5), one process per target and at
    most one active target per HOST. review#1 (A2): isolation is about one process per target — forcing
    those processes to run one at a time was false conservatism that bought nothing when no rate is
    configured, and it contradicts Quarry's own rate-is-not-concurrency rule. When the operator DOES set
    RATELIMIT.HTTP it is a GLOBAL lane limit, partitioned across the workers by `_arjun_rate_shares`."""
    api_all = sorted({u.split("?")[0] for u in corpus
                      if "?" not in u and any(s in u.lower() for s in
                      ("/api", "/rest", "/account", "/profile", "/search", "/user", "/order"))})
    # fresh-resolve: withhold scan-box/metadata, contact private
    api_all = netguard.guard_urls(ctx, api_all, phase="params.arjun")
    if not api_all:
        _arjun_zero_lifecycle(ctx, "no param-less API endpoints found")
        return
    if not have("arjun"):
        # A1 invariant: an unavailable TOOL is COVERAGE_UNKNOWN, never a clean zero — we could not look,
        # so 0/0 would assert these endpoints have no hidden parameters.
        ctx.run.record("params", skipped("arjun", "arjun not on PATH"))
        events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN, measure="api_endpoints",
                                unit="api_endpoints", eligible=len(api_all), tested=0, omitted=len(api_all),
                                reason="arjun not installed — parameter discovery was not attempted")
        return
    threads = settings.workers("arjun", 5)
    engine = _arjun_engine()
    cfg_fp = events.work_unit("params.arjun", inputs={}, config={"engine": engine},
                              schema_version=_ARJUN_SCHEMA)
    state_base = ctx.run.dir / "raw" / "params"
    state_base.mkdir(parents=True, exist_ok=True)
    budget.prune_state(state_base, "params.arjun", cfg_fp)
    ledger = budget.Ledger(budget.state_path(state_base, "params.arjun", cfg_fp), lane="params.arjun")
    aj_budget = budget.Budget(budget.budget_seconds("ARJUN_BUDGET_S"))
    attempt_dir = fresh_artifact_dir(state_base / "arjun" / cfg_fp[:16])

    def _rank(u):
        """NEVER-ATTEMPTED work runs first. A target arjun skipped (or crashed on) is retried only after
        every untouched endpoint, so a permanent 'not a webpage' skip cannot consume a finite budget on
        every rerun and hide the remainder that was never looked at once."""
        return 0 if (ledger.has(u) or not ledger.evidence(u)) else 1

    ordered = budget.order_ranked_fair(api_all, rank=_rank, group=normalize.host_of_url)
    counts = {"success": 0, "empty": 0, "skipped": 0, "failed": 0, "unknown": 0}
    attempted = resumed = nfound = 0
    unpublished: list = []                   # trusted completions whose evidence could not be published

    # ── replay completed targets FIRST (no process, no budget cost) ──
    pending = []
    for u in ordered:
        if ledger.has(u):
            ch = _arjun_channels(ledger, u)
            if ch is not None:
                resumed += 1
                attempted += 1
                rows, _bad = _arjun_rows(ch.get("params"), u)
                nfound += _arjun_ingest(ctx, rows, ch.get("params"))
                continue
            # evidence no longer validates -> the completion is withdrawn and the target is redone
        pending.append(u)

    # ── bounded concurrent pool over the remainder ──
    # size the pool from the work that can ACTUALLY run concurrently (one target per host) BEFORE
    # partitioning the rate, or the operator's budget is split across slots that will never open.
    n_hosts = len({normalize.host_of_url(u) for u in pending})
    procs = _arjun_pool(max(1, settings.concurrency("ARJUN_TARGETS", 5)), n_hosts, prof.http_rl)
    shares = _arjun_rate_shares(prof.http_rl, procs)
    procs = len(shares)                      # a rate below the pool size SHRINKS the pool (never the rate)
    ctx.echo(f"  arjun: {len(api_all)} param-less API endpoint(s)"
             + (f", {resumed} resumed" if resumed else "")
             + f" · {procs} concurrent target(s)"
             + (f" @ {prof.http_rl} req/s global ({'+'.join(map(str, shares))})" if prof.http_rl else "")
             + (f" · budget {aj_budget.seconds}s" if not aj_budget.unbounded else ""))

    def _finish(res: dict) -> None:
        """Parent-side, SINGLE-THREADED: ledger, events and store writes for one completed target."""
        nonlocal nfound
        u, r, verdict = res["url"], res["result"], res["verdict"]
        uid = hashlib.sha256(u.encode()).hexdigest()
        out_f, std_f, err_f = res["paths"]
        counts[verdict] += 1
        # EVERY channel is bound as evidence BEFORE any completion claim, so a retained attempt can
        # never be remembered by one channel while another goes unverified.
        # review#2 (A2 r3): the digest is computed and CHECKED here rather than inside add_evidence.
        # `events.file_digest` returns "" for an unreadable file instead of raising, so the channel was
        # bound with an empty digest, the manifest still named it, `state_persisted` still read 1/1 — and
        # the next load rejected the unhashed channel and silently redid the target.
        channels, channels_ok = {}, True
        for name, p in (("stdout", std_f), ("stderr", err_f), ("params", out_f)):
            if not p.exists():
                continue
            dig = events.file_digest(p)
            if not dig:
                channels_ok = False              # unhashable evidence cannot back a completion claim
                continue
            ledger.add_evidence(u, p, digest=dig)
            channels[name] = str(p.relative_to(state_base))
        if verdict != "failed":
            r.status = _AJ_STATUS[verdict]
        elif r.status in (Status.SUCCESS, Status.EMPTY, Status.PARTIAL):
            # a NONZERO exit is never a clean or merely-degraded status. The generic classifier reads
            # arjun's traceback as a transport hiccup and returns PARTIAL, which understates a crash
            # that ended the process. Only a MORE specific hard status (TIMED_OUT / BLOCKED / SKIPPED)
            # survives — hardening the verdict, never laundering it.
            r.status = Status.FAILED
        r.note = f"arjun[{verdict}] {normalize.host_of_url(u)}: {res['detail']}"
        ctx.run.record("params", r)
        if verdict == "unknown":
            events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN,
                                    measure="target", unit=f"target:{uid[:16]}", eligible=1, tested=0,
                                    omitted=1, reason=f"{u}: {res['detail']}")
        elif verdict in ("skipped", "failed"):
            events.coverage_partial("params.arjun", reason=f"{u}: {verdict} — {res['detail']}")
        if verdict in ("success", "empty"):
            man, dig = (_arjun_manifest(attempt_dir / f"{uid}.attempt.json", u, verdict, channels)
                        if channels_ok else (None, None))
            if man is not None:
                ledger.record(u, man, digest=dig)
            else:
                # review#4 (A2 r2): the manifest (or a channel digest) could not be published, so this
                # TRUSTED completion is not durable — the target will be redone. ledger.save() knows
                # nothing about that, so without this counter `state_persisted` still reported 1/1 and
                # the operator read a resumable lane that will silently repeat work.
                unpublished.append(u)
        # rows that VALIDATED are ingested even from a non-completable attempt: partial corruption must
        # not discard trustworthy siblings, and a crashed target's exported params are real evidence.
        nfound += _arjun_ingest(ctx, res["rows"], out_f if out_f.exists() else None)

    def _paths(u: str) -> tuple:
        uid = hashlib.sha256(u.encode()).hexdigest()
        return (attempt_dir / f"{uid}.txt", attempt_dir / f"{uid}.out", attempt_dir / f"{uid}.err")

    queue = list(pending)
    active: dict = {}                        # future -> (url, host, slot)
    busy_hosts: set = set()
    free = list(range(procs))
    runner_reset_cancel()                    # a previous lane's latch must not cancel this one
    # review#2 (A2 r2): KeyboardInterrupt is delivered to the MAIN thread only. A tool running inside a
    # worker never reaches runner.run()'s interrupt branch, so its process keeps going and the pool's
    # __exit__ waits for it — unbounded under `timeout 0`. On Ctrl-C we stop submitting, reach into the
    # workers via the runner's live-process registry to tear every group down, let the futures unwind,
    # then RE-RAISE. future.cancel() alone cannot stop an already-running subprocess.
    interrupted = False
    # review#1 (A2 r3): NOT a `with` block. ThreadPoolExecutor.__exit__ is shutdown(wait=True), so leaving
    # the block after a cancellation re-blocks on any worker that did not unwind — the exact unbounded wait
    # the handler exists to avoid. Shutdown is explicit on each path instead.
    pool = ThreadPoolExecutor(max_workers=procs)
    try:
        while True:
            # SUBMIT: fill free slots with the first queued target whose host is not already active, so a
            # host with many endpoints never gets several concurrent processes pointed at it.
            while free and not aj_budget.exhausted():
                pick = next((i for i, u in enumerate(queue)
                             if normalize.host_of_url(u) not in busy_hosts), None)
                if pick is None:
                    break                    # every remaining target belongs to a currently-active host
                u = queue.pop(pick)
                # take the LOWEST free slot: shares are largest-first, so a partly-filled pool still runs
                # at the biggest rate available instead of stranding it on an unused slot.
                host, slot = normalize.host_of_url(u), free.pop(0)
                busy_hosts.add(host)
                attempted += 1
                active[pool.submit(_arjun_exec, u, shares[slot], threads, _paths(u),
                                   ctx.http_timeout)] = (u, host, slot)
            if not active:
                break                        # nothing running and nothing submittable -> done
            # the budget stops LAUNCHING new work; targets already in flight always finish.
            done, _ = wait(list(active), return_when=FIRST_COMPLETED)
            for fut in done:
                u, host, slot = active.pop(fut)
                busy_hosts.discard(host)
                insort(free, slot)               # keep slots ordered so the largest share is reused first
                try:
                    _finish(fut.result())
                except Exception as exc:     # a worker crash is OUR failure, not a target verdict
                    counts["unknown"] += 1
                    events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN,
                                            measure="target",
                                            unit=f"target:{hashlib.sha256(u.encode()).hexdigest()[:16]}",
                                            eligible=1, tested=0, omitted=1,
                                            reason=f"{u}: worker failed — {type(exc).__name__}: {exc}")
    except KeyboardInterrupt:
        interrupted = True
        # 1) HARVEST FIRST. A target that finished just before the interrupt has EARNED its completion;
        #    killing without harvesting threw it away and the resume repeated that whole scan. Only
        #    futures already done at THIS instant are harvested — anything completing later raced the
        #    kill and is reported as cancelled, never as a measured verdict.
        for fut in [f for f in list(active) if f.done()]:
            u, _host, _slot = active.pop(fut)
            try:
                _finish(fut.result())
            except Exception as exc:
                counts["unknown"] += 1
                events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN, measure="target",
                                        unit=f"target:{hashlib.sha256(u.encode()).hexdigest()[:16]}",
                                        eligible=1, tested=0, omitted=1,
                                        reason=f"{u}: worker failed — {type(exc).__name__}: {exc}")
        # 2) then tear down what is still running (ONE shared grace deadline across every group).
        killed = runner_cancel_all()
        for fut in list(active):
            fut.cancel()                     # only drops NOT-YET-STARTED work; the kill handles the rest
        wait(list(active), timeout=30)       # bounded: the groups are already dead
        # 3) HARVEST AGAIN. review#2 (A2 r4): a target that finished naturally BETWEEN the snapshot in (1)
        #    and process termination was previously declared unmeasured, throwing away a verdict — and its
        #    evidence — that had actually been reached. Harvesting is safe for killed runs too: completion
        #    demands the exit code, terminal line and artifact to AGREE, which a truncated kill cannot fake.
        for fut in [f for f in list(active) if f.done() and not f.cancelled()]:
            u, _host, _slot = active.pop(fut)
            try:
                _finish(fut.result())
            except Exception as exc:
                counts["unknown"] += 1
                events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN, measure="target",
                                        unit=f"target:{hashlib.sha256(u.encode()).hexdigest()[:16]}",
                                        eligible=1, tested=0, omitted=1,
                                        reason=f"{u}: worker failed — {type(exc).__name__}: {exc}")
        # 4) only what is still UNRESOLVED (or was cancelled before it ran) is unmeasured — looked at but
        #    never judged. An honest gap, not a clean zero, and absent from the ledger so a resume retries.
        for _fut, (u, _h, _s) in list(active.items()):
            counts["unknown"] += 1
            events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN, measure="target",
                                    unit=f"target:{hashlib.sha256(u.encode()).hexdigest()[:16]}",
                                    eligible=1, tested=0, omitted=1,
                                    reason=f"{u}: cancelled by operator before a verdict was reached")
        ctx.echo(f"    params.arjun: cancelled — terminated {killed} running arjun process(es), "
                 f"{len(active)} target(s) left unmeasured")
    finally:
        # NEVER wait on workers here: on the interrupt path their processes are already dead, and on every
        # other path the loop only exits once `active` is empty.
        pool.shutdown(wait=False, cancel_futures=True)
    # DURABILITY is the conjunction: the state file was written AND every trusted completion actually
    # published its evidence. Either failure means a resume redoes work, so both must reach the verdict.
    saved = ledger.save()
    persisted = saved and not unpublished
    if not persisted:
        ctx.echo("    params.arjun: completion state NOT persisted"
                 + (" (state file belongs to another lane)" if ledger.foreign else "")
                 + (f" ({len(unpublished)} completion(s) could not publish evidence)" if unpublished else ""))
    events.coverage_partial("params.arjun", kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit="state_persisted", eligible=1, tested=1 if persisted else 0,
                            omitted=0 if persisted else 1,
                            reason=("completion state persisted" if persisted else
                                    (f"{len(unpublished)} completed target(s) could not publish their "
                                     "evidence manifest; those targets WILL be redone" if unpublished else
                                     "completion state could not be persisted; a resume will redo this lane")))
    # SELECTION: of every eligible endpoint, how many did we get to at all? (the old ARJUN_CAP lived here)
    budget.report_selection("params.arjun", measure="api_endpoints", eligible=len(api_all),
                            attempted=attempted, budget=aj_budget, noun="endpoint", durable=persisted)
    # OUTCOME: of those attempted, how many reached a TRUSTED terminal state?
    budget.report_outcome("params.arjun", measure="endpoints_tested", attempted=attempted,
                          obtained=counts["success"] + counts["empty"] + resumed,
                          classes={k: v for k, v in (("skipped", counts["skipped"]),
                                                     ("crashed", counts["failed"]),
                                                     ("unknown", counts["unknown"])) if v},
                          noun="endpoint")
    left = len(api_all) - attempted
    ctx.echo(f"  arjun: {counts['success']} with params · {counts['empty']} none · "
             f"{counts['skipped']} skipped · {counts['failed']} crashed · {counts['unknown']} unknown · "
             f"{resumed} resumed · {nfound} param-bearing URL(s) -> dalfox candidates"
             + (f" · {left} left by budget — {'resumable' if persisted else 'NOT saved, will restart'}"
                if left else ""))
    if interrupted:
        # coverage and completion state for the work that DID finish are now recorded; only then does the
        # cancellation propagate, so a Ctrl-C costs the operator nothing already earned.
        raise KeyboardInterrupt


def _apply_nuclei_oob(cmd: list[str]) -> list[str]:
    """Append self-hosted interactsh flags to a nuclei command (else nuclei's built-in public
    server). Shared by EVERY nuclei invocation so they all use the same OOB endpoint — no drift
    where one nuclei call silently uses the public server. `secrets.oob()` is the single source of
    truth for OOB config (future OOB consumers read it too)."""
    oob = secrets.oob()
    if oob.get("callback_server"):
        cmd += ["-iserver", str(oob["callback_server"])]
        if oob.get("auth_token"):
            cmd += ["-itoken", str(oob["auth_token"])]
    return cmd


def _chunk_terminal(sid, chunk_wu, res, cf, *, status) -> None:
    """review#1: emit a chunk's TERMINAL event from a finally so a chunk NEVER stays 'started'. `status` is the
    chunk OUTCOME the caller promotes to the tool's status ONLY after ALL per-chunk bookkeeping (logging, state
    save, artifact parse, run.add) succeeded — it stays FAILED when execution OR any post-execution step raised,
    so a chunk whose processing was incomplete is never recorded SUCCESS."""
    reason = None
    if status == Status.FAILED.value:
        reason = (res.note if (res and res.note) else "chunk raised before completing bookkeeping")
    elif res:
        reason = res.note or None
    events.tool_finish(sid, work_unit=chunk_wu, status=status, reason=reason,
                       duration=round(res.duration, 2) if res else None,
                       raw_ref=str(cf) if cf.exists() else None)


def _nuclei_templates_fp() -> str | None:
    """review#6/#10: a coverage-affecting fingerprint of the INSTALLED nuclei template set, so a templates
    update (new/changed detections) invalidates the resume work_unit — else C10b would skip a chunk that a
    fresh template set would now flag differently. nuclei records its templates state in its config dir; read
    it (honoring NUCLEI_CONFIG / XDG / ~/.config) and fold the COMPLETE effective state — version AND the
    ignore-hash (a changed .nuclei-ignore alters which templates run even at the same version). Returns a
    stable JSON string of every present field, or None when the state cannot be read (the caller then makes
    the unit NON-RESUMABLE — an unknown template set must never be treated as unchanged)."""
    base = (os.environ.get("NUCLEI_CONFIG")
            or os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "nuclei"))
    cfg = Path(base) / ".templates-config.json"
    try:
        data = json.loads(cfg.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    parts = {k: str(data[k]) for k in
             ("nuclei-templates-version", "nuclei-templates-latest-version", "nuclei-ignore-hash")
             if isinstance(data, dict) and data.get(k)}
    return json.dumps(parts, sort_keys=True) if parts else None


_NUCLEI_MHE_DEFAULT = 0        # FULL DEPTH (-nmhe). nuclei's own default is 30, which SILENTLY drops a host
_NUCLEI_MHE_MAX = 100_000      # after 30 request errors — on the OTC run that cost 459,930 unsent requests.
_ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _nuclei_mhe() -> int:
    """`PERFORMANCE.NUCLEI_MAX_HOST_ERROR` — errors tolerated per host before nuclei SKIPS it (`-mhe`).
    Quarry's 0 means FULL DEPTH: no host is ever dropped for erroring (`-nmhe`), and that is the DEFAULT.
    Quarry is coverage-first — a host that errors is exactly the kind of host worth finishing, and nuclei's
    own default of 30 quietly turns a flaky target into an unscanned one. A nonzero value is an EXPLICITLY
    bounded coverage policy the operator opted into, never Quarry's normal behaviour.

    This is a COVERAGE policy, not a runtime knob — it decides which hosts get scanned at all, so it is
    folded into the resume fingerprint and a change re-scans rather than silently resuming a shallower
    generation. (It does cost wall-clock: the requests `-mhe` was suppressing now actually go out.)

    STRICT parse via the shared coverage-knob parser (settings.strict_int): an exact int (never a bool) or
    a clean int-string in 0.._NUCLEI_MHE_MAX; anything else — bool, float, negative, oversized, garbage —
    falls back to the default rather than inventing a policy from a typo."""
    return settings.strict_int("NUCLEI_MAX_HOST_ERROR",
                               default=_NUCLEI_MHE_DEFAULT, maximum=_NUCLEI_MHE_MAX)


def _nuclei_progress(text: str) -> dict:
    """Read nuclei's OWN stderr for what only nuclei can tell us (the OTC 20260725 lesson: a generic stderr
    signature conflates execution with coverage and gets BOTH wrong).

      1. `planned` / `requests` / `errors` — how much of the planned request budget it actually COVERED, from
         the LAST `-stats` line. This is the ONLY coverage oracle; absent, coverage is UNKNOWN. nuclei skips a
         host after `-mhe` errors, so a finished scan can still leave requests unsent — a COVERAGE gap, never
         an execution one.
      2. `completed` — whether nuclei's own terminal line `Scan completed in <dur>.` (with either
         `N matches found.` or `No results found.`) was recognized. review#P1.4: this is CORROBORATING
         TELEMETRY ONLY. It must never gate resumability — execution completion is `exit_code == 0`, full stop.
         Requiring this sentence meant a nuclei release that reworded only its terminal (while keeping the stats
         JSON) would mark every chunk retryable forever.

    stderr is ANSI-coloured, so strip escapes before matching. Counters are returned RAW (not clamped): an
    impossible triple must reach events.coverage_partial's validator and surface as coverage UNKNOWN rather
    than be quietly repaired into a plausible-looking lie."""
    completed, planned, requests, errors = False, None, None, None
    for line in (text or "").splitlines():
        s = _ANSI_RX.sub("", line).strip()
        if not s:
            continue
        if "scan completed in" in s.lower():
            completed = True
            continue
        if not (s.startswith("{") and s.endswith("}")):
            continue
        try:
            d = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not (isinstance(d, dict) and "requests" in d and "total" in d):
            continue
        try:                                       # nuclei emits these as STRINGS; last valid line wins
            planned, requests = int(d["total"]), int(d["requests"])
            errors = int(d["errors"]) if str(d.get("errors", "")).lstrip("-").isdigit() else None
        except (TypeError, ValueError):
            continue
    return {"completed": completed, "planned": planned, "requests": requests, "errors": errors}


def _nuclei_cmd(targets_file, out_file, prof, mhe: int) -> list[str]:
    """The nuclei main-scan command for one target file — identical flags for every chunk, only -l/-o
    differ (non-intrusive, severity-scoped, governor-scaled -c/-bs, explicit host-error policy, shared
    OOB endpoint)."""
    cmd = ["nuclei", "-l", str(targets_file), "-jsonl", "-o", str(out_file),
           "-etags", "intrusive,fuzz,dos,brute-force",
           "-s", "critical,high,medium", "-stats", "-si", "30",
           "-c", str(settings.workers("nuclei", 25)),      # H2: core-scaled concurrency (rate stays separate)
           "-bs", str(settings.concurrency("NUCLEI_BULK_SIZE", 25))]   # hosts/template batch
    cmd += ["-nmhe"] if mhe == 0 else ["-mhe", str(mhe)]   # 0 = full depth: never drop an erroring host
    if prof.http_rl:
        cmd += ["-rl", str(prof.http_rl)]
    _apply_nuclei_oob(cmd)                                 # self-hosted interactsh (else public default)
    return cmd


def _nuclei_scan(ctx, live, findings, log, prof) -> RunResult:
    """Chunked nuclei main scan (step 4.2 Commit B). Split live hosts into NUCLEI_CHUNK_HOSTS-sized
    batches and scan SEQUENTIALLY — rate is target-wide (RoE), so parallel batches would blow the
    budget; chunking buys resume + progress + per-batch isolation, NOT speed (work is rate-bound and
    fixed: OTC = 448 hosts / 5.08M req / 7h41 @ 183rps, died at 93%). Each batch gets its own
    nuclei_timeout, so one slow batch -> coverage_partial instead of a whole-run kill.

    RESUME is keyed on EXECUTION COMPLETION, not on a clean status — the two are independent facts. A chunk is
    done when the process EXITED 0 (it reached its own end; a kill leaves exit_code None, a crash nonzero).
    Degraded COVERAGE (host-error skips, WAF-blocked requests) is reported separately as structured request
    counters and does NOT make the chunk retryable; unmeasurable coverage is reported as coverage:unknown, never
    as complete. nuclei's `Scan completed in …` line is corroborating telemetry only — gating on it would let a
    reworded terminal lock resumability forever. The OTC 20260725 run proved why: at ~610k requests/chunk a generic stderr
    signature ALWAYS matched (one `i/o timeout` line is inevitable), so every chunk read PARTIAL, no chunk
    was ever recorded done, and `chunks` stayed `{}` — a resume would have repeated all 8.5 hours while the
    real gap (92.44% of planned requests sent, 459,930 skipped by `-mhe`) went unmeasured. A chunk that did
    NOT complete stays retryable. Its OUTPUT is still KEPT — the aggregate is rebuilt
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
    _tpl = _nuclei_templates_fp()                           # review#10: template SET is coverage-affecting
    mhe = _nuclei_mhe()                                     # host-error policy = WHICH hosts get scanned at all
    _cfg = {"severity": "critical,high,medium", "etags": "intrusive,fuzz,dos,brute-force", "chunk": chunk_n,
            "templates": _tpl if _tpl is not None else "unknown", "mhe": mhe}
    if _tpl is None:
        # review#6: template state UNKNOWN -> non-resumable. A per-run nonce makes scan_wu/chunk_wu differ every
        # run, so resume NEVER skips a chunk we cannot prove ran against the same templates (re-scan is a safe
        # superset; silently skipping on an unverifiable set is not).
        _cfg["_nonce"] = os.urandom(8).hex()
    scan_wu = events.work_unit(sid, inputs={"hosts": live}, config=_cfg)
    # review#4: a work_unit is NOT an execution attempt. Layout is wu_<scan_wu>/attempt_<attempt_id>/, and the
    # state maps each DONE chunk to the ARTIFACT PATH that produced it. A same-work-unit RETRY writes to a FRESH
    # attempt dir, so it can NEVER overwrite a prior attempt's chunk evidence; done chunks are read back from
    # their recorded paths. Raw attempt dirs are RETAINED (pruning is a separate explicit GC, never part of
    # publishing an aggregate — a publish must not delete raw evidence).
    wu_dir = state_f.parent / f"wu_{scan_wu}"
    wu_root = wu_dir.resolve()
    attempt_id = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()   # UNIQUE per execution attempt
    attempt_dir = wu_dir / f"attempt_{attempt_id}"        # created lazily, only if a chunk actually runs

    def _valid_entry(ci_str, rel, digests=None) -> bool:
        """review#1/#2: a loaded state entry is trusted to skip/aggregate a chunk ONLY if it is fully valid — a
        non-negative in-range index, and a RELATIVE path with no absolute/`..` escape that resolves INSIDE THIS
        work_unit's dir (review#2: not merely the nuclei dir — a corrupt path must not borrow ANOTHER work unit's
        artifact) AND whose filename is exactly this chunk's `findings_<ci>.jsonl`, pointing at a readable file.
        Anything else is dropped so the chunk RE-RUNS (an invalid/foreign artifact is never a silent skip).

        review#P3: path validity is not CONTENT validity. An artifact recorded as done, then truncated/edited/
        replaced on disk, satisfied every path check and was still trusted — so a resume skipped the chunk and
        aggregated whatever the file now says. Each recorded artifact therefore carries its sha256 and must
        still match. A state file with no digest for an entry (written by an older Quarry) fails CLOSED: the
        chunk re-runs. Re-running costs time; trusting an unverifiable artifact costs silent surface."""
        if not (isinstance(ci_str, str) and ci_str.isdigit() and 0 <= int(ci_str) < len(batches)):
            return False
        if not isinstance(rel, str) or not rel or os.path.isabs(rel) or ".." in Path(rel).parts:
            return False
        if Path(rel).name != f"findings_{int(ci_str)}.jsonl":   # must be THIS chunk's artifact, not another's
            return False
        p = state_f.parent / rel
        try:
            if not p.resolve().is_relative_to(wu_root):      # containment: under the CURRENT work-unit dir only
                return False
            if not p.is_file():                              # missing artifact -> NOT done (re-run)
                return False
            with open(p, "rb"):                              # readability
                pass
        except (OSError, ValueError):
            return False
        want = (digests or {}).get(rel)
        if not isinstance(want, str) or not want:
            return False                                     # no recorded digest -> unverifiable -> re-run
        try:
            if events.file_digest(p) != want:                # content changed since it was recorded
                return False
        except OSError:
            return False
        return True

    def _prev():
        if not state_f.exists():
            return None
        try:
            prev = json.loads(state_f.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(prev, dict):                       # review#7: [], null, or a scalar -> reject (rerun all)
            return None
        return prev if prev.get("work_unit") == scan_wu else None   # config-inclusive key: mismatch → fresh

    def _load_digests(prev) -> dict:                          # {rel: sha256} — content binding for every artifact
        m = (prev or {}).get("digests")
        if not isinstance(m, dict):
            return {}
        return {str(k): str(v) for k, v in m.items() if isinstance(k, str) and isinstance(v, str) and v}

    def _load_map(prev, digests) -> dict:                     # {ci: rel} — validated + digest-bound
        m = (prev or {}).get("chunks")
        if not isinstance(m, dict):
            return {}
        return {str(k): str(v) for k, v in m.items() if _valid_entry(str(k), v, digests)}

    def _load_evidence(prev, digests) -> dict:               # review#1: {ci: [rel, ...]} — a LIST, each validated
        m = (prev or {}).get("evidence")
        out: dict[str, list[str]] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                vals = v if isinstance(v, list) else [v]     # tolerate a legacy scalar
                kept = [str(x) for x in vals if _valid_entry(str(k), x, digests)]
                if kept:
                    out[str(k)] = kept
        return out

    def _load_coverage(prev, done: dict) -> dict:
        """{ci: {"planned": int, "requests": int}} — the request coverage a DONE chunk reported, persisted so a
        RESUME can re-emit it. Without this a resumed run re-emits counters only for the chunks it actually ran
        and the skipped ones read as zero-eligible, understating the run's real gap. Validated: an in-range
        index and two non-negative ints (an impossible pair is dropped, not repaired)."""
        m = (prev or {}).get("coverage")
        out: dict[str, dict] = {}
        if not isinstance(m, dict):
            return out
        for k, v in m.items():
            if not (isinstance(k, str) and k.isdigit() and 0 <= int(k) < len(batches)):
                continue
            if not isinstance(v, dict):
                continue
            p, r = v.get("planned"), v.get("requests")
            if all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (p, r)):
                out[k] = {"planned": p, "requests": r}
        # A coverage record is only meaningful for a chunk that COMPLETED — an entry for a chunk we are about
        # to RE-RUN is stale by definition, and keeping it would let last attempt's numbers stand in for this
        # one if the re-run finishes without a parseable stats line.
        return {k: v for k, v in out.items() if k in done}

    # done_map: chunks whose EXECUTION COMPLETED -> artifact (controls SKIP). evidence_map: for EVERY chunk that
    # produced output (complete OR not), the LIST of every preserved artifact across attempts (controls
    # AGGREGATION). review#1: a list, not a single pointer — PARTIAL(A) then PARTIAL(B) must keep BOTH, aggregate
    # + dedup all evidence. cov_map: per-chunk request coverage, so resume re-reports the gap it did not re-run.
    _p = _prev()
    digest_map: dict[str, str] = _load_digests(_p)            # {rel: sha256} — binds every recorded artifact
    done_map: dict[str, str] = _load_map(_p, digest_map)
    evidence_map: dict[str, list[str]] = _load_evidence(_p, digest_map)
    cov_map: dict[str, dict] = _load_coverage(_p, done_map)
    # drop digests whose artifact no longer survives validation, so the state file cannot grow a tail of
    # references to entries that are no longer trusted
    _kept_rels = set(done_map.values()) | {r for v in evidence_map.values() for r in v}
    digest_map = {k: v for k, v in digest_map.items() if k in _kept_rels}

    def _bind(rel, path) -> None:
        """Record an artifact's sha256 at the moment we trust it. A later resume re-verifies against this."""
        try:
            digest_map[rel] = events.file_digest(path)
        except OSError:
            digest_map.pop(rel, None)                         # cannot digest -> leave it unverifiable -> re-run

    def _add_evidence(ci_str, rel):                          # append-only, unique, per chunk
        lst = evidence_map.setdefault(ci_str, [])
        if rel not in lst:
            lst.append(rel)

    for _ci, _rel in done_map.items():                       # a done chunk's artifact is always also evidence
        _add_evidence(_ci, _rel)

    def _save():
        state_f.write_text(json.dumps(
            {"work_unit": scan_wu, "chunk_size": chunk_n, "chunks": done_map,
             "evidence": evidence_map, "coverage": cov_map, "digests": digest_map}))

    def _emit_coverage(ci: int, planned, requests, *, why: str) -> None:
        """Per-chunk REQUEST coverage as structured counters, one stable unit per chunk so the store's
        latest-per-unit reconciliation sums them into a single (source, "requests") rollup for the run.

        COVERAGE_TIMEOUT, not CAP: nothing here is OUR ceiling or the operator's chosen subset — the requests
        were lost in flight (target/network errors, or nuclei dropping a host once `-mhe` is exceeded, which is
        off by default). That is exactly the TIMEOUT bucket's policy contract: always feeds the verdict. The
        constant's name is narrower than its bucket; see the note on events.COVERAGE_TIMEOUT.

        Counters go through RAW — the validator flags an impossible triple as coverage UNKNOWN instead of us
        inventing a consistent-looking one."""
        if planned is None or requests is None:
            # review#P1.1: COVERAGE_UNKNOWN, not a reason-only event. A reason-only partial neither opens a
            # generation nor reaches the rollup, so an unmeasurable chunk read as fully covered and a PRIOR
            # run's counters kept standing in for it. Unknown must reach the verdict as a gap.
            events.coverage_partial(sid, kind=events.COVERAGE_UNKNOWN, unit=f"chunk_{ci}", measure="requests",
                                    reason=f"chunk {ci + 1}/{len(batches)}: {why} (request counters unavailable "
                                           f"— coverage UNMEASURED, not assumed complete)")
            return
        events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, measure="requests", unit=f"chunk_{ci}",
                                eligible=planned, tested=requests, omitted=planned - requests,
                                reason=(f"chunk {ci + 1}/{len(batches)}: {requests}/{planned} planned request(s) "
                                        f"sent ({why})"))

    events.tool_start(sid, cmd=["nuclei", "-l", "<chunk>", "-jsonl"], input_total=len(live), work_unit=scan_wu)
    t0 = time.monotonic()
    incomplete = 0                                        # chunks whose EXECUTION did not complete (retryable)

    def _completed_hosts():                               # UX #4: hosts in EXECUTION-COMPLETE chunks (NOT attempted)
        return sum(len(batches[j]) for j in (int(k) for k in done_map) if j < len(batches))

    # C07 inc4: a source terminal ALWAYS fires (try/finally) even if the loop raises. status starts FAILED
    # (an exception mid-loop must NOT emit a scan-level success) and is set to SUCCESS/PARTIAL only after the
    # loop + aggregate complete. Each executed chunk gets its OWN start+terminal (keyed on chunk_wu), and the
    # resume record is chunks.state.json (keyed on scan_wu). The source lifecycle is scan_wu; no duplicates.
    status = Status.FAILED
    try:
        for ci, batch in enumerate(batches):
            chunk_wu = events.work_unit(sid, inputs={"hosts": batch}, config=_cfg)
            # UX #2: progress BEFORE the chunk — status shows STARTING chunk ci+1, with CLEANLY-completed
            # host count; the per-chunk work_unit is the stable unit id (resume/audit key).
            events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches),
                                 current_index=_completed_hosts(), work_unit=chunk_wu)
            if str(ci) in done_map:                       # resume: EXECUTION already completed in a prior attempt
                _prior = cov_map.get(str(ci)) or {}        # (artifact recorded + preserved; do not re-run)
                _emit_coverage(ci, _prior.get("planned"), _prior.get("requests"),
                               why="resumed — coverage as first recorded")
                continue
            attempt_dir.mkdir(parents=True, exist_ok=True)   # lazy: only create the attempt dir if a chunk runs
            bf = ctx.write_list(f"nuclei_targets_{ci}.txt", batch)
            cf = attempt_dir / f"findings_{ci}.jsonl"        # review#4: THIS attempt's artifact (never overwrites a prior)
            ef = attempt_dir / f"stderr_{ci}.log"            # per-chunk FULL stderr: the completion/coverage oracle
            rel = f"wu_{scan_wu}/attempt_{attempt_id}/findings_{ci}.jsonl"   # recorded in state, relative to the state dir
            events.tool_start(sid, work_unit=chunk_wu, input_total=len(batch))   # this chunk's own lifecycle
            res = None
            chunk_status = Status.FAILED.value               # review#1: promoted ONLY after ALL bookkeeping below
            try:                                             # review#1: chunk terminal ALWAYS fires (finally)
                res = exec_tool("nuclei", _nuclei_cmd(bf, cf, prof, mhe),
                                timeout=nuclei_timeout(len(batch), ctx.http_timeout), stderr_path=ef)
                if res.stderr_tail:
                    with log.open("a", encoding="utf-8") as lf:
                        lf.write(res.stderr_tail + "\n")
                # Ask NUCLEI whether it finished, from its OWN terminal line in the FULL stderr (the 8-line tail
                # can be evicted by a trailing [INF] burst, so prefer the file and fall back only if it is absent).
                try:
                    _err = ef.read_text(encoding="utf-8", errors="replace") if ef.is_file() else res.stderr_tail
                except OSError:
                    _err = res.stderr_tail
                prog = _nuclei_progress(_err)
                # ── the split, in one line each ────────────────────────────────────────────────────────────
                # EXECUTION COMPLETE  <- res.exit_code == 0. NOTHING else. The process reached its own end; a
                #                        kill leaves exit_code None (TIMED_OUT) and a crash leaves it nonzero.
                # COVERAGE            <- the -stats counters. Absent -> coverage:unknown, never "complete".
                # `Scan completed in …` is CORROBORATING TELEMETRY only (it rides the reason string) — it must
                #                        NOT gate resumability.
                #
                # review#P1.4: requiring that sentence whenever ANY stats line was recognized left a second way
                # to lock resumability forever — a nuclei release that keeps the stats JSON but reworded only its
                # terminal would give completed=False, exit 0, and a chunk retryable on every future run: the
                # 8.5-hour bug again, through a PARTIAL format change. (review#P1.2 closed the same hole for the
                # status fallback; this is its twin.) Consequence worth naming: "we sent fewer requests than
                # planned" is now ALWAYS a coverage fact, never a resumability one — which is correct, because a
                # process that ran to its own end has no work left to resume.
                complete = res.exit_code == 0
                terminal_seen = bool(prog["completed"])      # telemetry: did we recognize nuclei's own terminal?
                planned, requests = prog["planned"], prog["requests"]
                # KEEP a chunk's findings regardless of outcome — real even if WAF/timeout-degraded.
                if complete:
                    if not cf.exists():
                        cf.touch()                           # review#1: explicit zero-byte artifact for a clean-EMPTY
                    done_map[str(ci)] = rel                  # execution complete -> controls SKIP
                    _add_evidence(str(ci), rel)              # ...and joins this chunk's evidence history
                    _bind(rel, cf)                           # content binding: a later edit invalidates the skip
                    if planned is not None and requests is not None:
                        cov_map[str(ci)] = {"planned": planned, "requests": requests}
                    _save()
                    _emit_coverage(ci, planned, requests,
                                   why=("exit 0" + ("" if terminal_seen else ", nuclei terminal not recognized")
                                        + (f", {prog['errors']} error(s)" if prog["errors"] is not None else "")))
                    # status now reflects EXECUTION, not a stderr signature: findings -> SUCCESS, none -> EMPTY.
                    chunk_status = (Status.SUCCESS if cf.stat().st_size > 0 else Status.EMPTY).value
                else:
                    incomplete += 1
                    _emit_coverage(ci, planned, requests,
                                   why=f"execution INCOMPLETE (exit {res.exit_code}, {res.status.value}) "
                                       f"— chunk stays retryable")
                    # review#1: a chunk that produced real output APPENDS to this chunk's evidence list
                    # (PARTIAL(A) then PARTIAL(B) keeps BOTH). A degraded/failed retry with NO output appends
                    # nothing, so an earlier attempt's findings are never erased.
                    if cf.exists() and cf.stat().st_size > 0:
                        _add_evidence(str(ci), rel)
                        _bind(rel, cf)
                        _save()
                    # never launder an incomplete execution into a clean status
                    chunk_status = (res.status if res.status not in (Status.SUCCESS, Status.EMPTY)
                                    else Status.PARTIAL).value
            finally:
                _chunk_terminal(sid, chunk_wu, res, cf, status=chunk_status)   # FAILED if exec OR bookkeeping raised
        # review#1/#2/#4: rebuild the aggregate into a TEMP file, then swap ATOMICALLY — the prior findings.jsonl
        # is only replaced once the new one is fully written, so a crash mid-rebuild leaves the old aggregate
        # intact. For each chunk, read EVERY preserved evidence artifact (all attempts, clean OR degraded — so a
        # later degraded/failed retry can't drop an earlier attempt's findings) and DEDUPLICATE lines. Falls back
        # to THIS attempt's file for a chunk just run but not yet recorded. Prior attempt dirs are RETAINED — NO
        # pruning here (a publish must never delete raw evidence; attempt-dir GC is a separate operation).
        tmp = findings.with_name(findings.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for ci in range(len(batches)):
                rels = list(evidence_map.get(str(ci)) or [])
                paths = [state_f.parent / r for r in rels] or [attempt_dir / f"findings_{ci}.jsonl"]
                seen_lines: set[str] = set()                  # dedup PER CHUNK (across its attempts) — never across
                for p in paths:                               # chunks, whose identical-looking lines are distinct hosts
                    if not (p.exists() and p.stat().st_size > 0):
                        continue
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        if line and line not in seen_lines:
                            seen_lines.add(line)
                            fh.write(line + "\n")
        os.replace(tmp, findings)
        # Scan STATUS tracks EXECUTION only. Degraded request coverage does NOT go here — it rides the
        # structured counters and reaches the operator through the run verdict (complete_with_gaps), so the
        # status stays a signal that can actually discriminate "a chunk needs re-running" from "the target
        # dropped some requests". Before this split every real-target run read PARTIAL and told us nothing.
        status = Status.PARTIAL if incomplete else Status.SUCCESS
    finally:
        events.tool_progress(sid, chunk_index=len(batches), chunk_total=len(batches),
                             current_index=_completed_hosts(), work_unit=scan_wu)   # final: execution-complete
        try:                                                 # review#1: a stat() raise must NOT defeat the scan terminal
            size = findings.stat().st_size
        except OSError:
            size = None
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
                           reason=(f"{incomplete}/{len(batches)} chunk(s) execution-incomplete (retryable)"
                                   if incomplete else None),
                           duration=round(time.monotonic() - t0, 2),
                           raw_ref=str(findings), artifact_size=size, discovery_context="params")
    lines = len(findings.read_text().splitlines()) if findings.exists() else 0
    _planned = sum(v["planned"] for v in cov_map.values())
    _sent = sum(v["requests"] for v in cov_map.values())
    if _planned:
        # Say WHICH chunks the percentage covers — nuclei may not report counters for every chunk, and an
        # unqualified "92.44%" over a subset would read as a whole-scan figure.
        _scope = ("" if len(cov_map) == len(batches)
                  else f" over {len(cov_map)}/{len(batches)} measured chunk(s)")
        ctx.echo(f"  nuclei coverage: {_sent}/{_planned} planned request(s) sent "
                 f"({100 * _sent / _planned:.2f}%, {_planned - _sent} skipped{_scope}; -mhe "
                 f"{'off (full depth)' if mhe == 0 else mhe})")
    return RunResult("nuclei", ["nuclei", "-l", "<chunked>"], status, 0,
                     round(time.monotonic() - t0, 2), findings if findings.exists() else None,
                     lines, note=f"{len(batches)} chunk(s), {len(done_map)} execution-complete, "
                                 f"{incomplete} retryable")


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
    for u in active_review_values(ctx, "ssti"):
        if u not in seen and "?" in u:
            seen.add(u)
            out.append(u)
    return out


def _dalfox_signature(u: str) -> tuple:
    """The identity dalfox deduplicates on under `--dedup-urls signature`: method+host+path+parameter
    NAMES. Every target we submit is a GET, so method is constant here — and this is deliberately the
    same key `_canonicalize_candidates` uses, because that is what makes the two agree."""
    from urllib.parse import urlsplit, parse_qsl
    sp = urlsplit(u)
    names = tuple(sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)}))
    return (sp.scheme.lower(), sp.netloc.lower(), sp.path, names)


def _dalfox_identity_fn(mode: str):
    """The identity dalfox is deduplicating on, PER MODE — and whether multiplicity matters.

    review#39 (Lumpy): the reconciliation applied signature semantics unconditionally, so a fully
    covered `exact` scan of `a?q=1` and `a?q=2` read as one signature reported twice and returned
    PARTIAL on every lifecycle — with no remainder, so it re-sent the whole batch for ever. `off` scans
    every input line, so multiplicity IS the identity there."""
    if mode in ("exact", "off"):
        return (lambda u: u), (mode == "off")                  # exact: the URL; off: URL x multiplicity
    # `signature`, and an UNKNOWN mode: the least demanding identity, so "never mentioned" means
    # never mentioned under ANY policy. What that identity cannot settle is handled separately as
    # UNDECIDABLE membership rather than being asserted either way (review#40, Lumpy).
    return _dalfox_signature, False


def _dedupe_owed(named, mode) -> list:
    """Collapse the targets dalfox NAMED as failed, under the identity THAT MODE scans by.

    review#44 (Lumpy): this used `dict.fromkeys`, i.e. the exact URL, while claiming "one signature
    identity owes one retry" — so `/a?q=1` and `/a?q=2`, one signature and both `SESSION_LOST`, were
    owed twice under `dedup_mode=signature`. The previous test only repeated an identical URL, which
    exact-URL dedup passes.

      off      every occurrence is its own scan          -> collapse nothing
      signature  method+host+path+param names            -> one retry per signature
      exact      the URL                                 -> one retry per URL
      unknown    no identity we can trust                -> collapse nothing (re-scanning is the safe
                                                            error; dropping an owed scan is not)"""
    if mode == "off" or mode not in _DALFOX_DEDUP_MODES:
        return list(named)
    key = _dalfox_signature if mode == "signature" else (lambda u: u)
    seen, out = set(), []
    for u in named:
        k = key(u)
        if k not in seen:
            seen.add(k)
            out.append(u)
    return out


def _dalfox_accounting(batch, art) -> "tuple[list, dict]":
    """Reconcile dalfox's `target_summary` against the batch we submitted — by MEMBERSHIP, under the
    mode dalfox SAYS it used. Returns `(owed_urls, info)` where `info` carries:

        retryable   membership failures a RETRY could cover — the chunk stays owed
        terminal    membership we cannot DECIDE — retrying changes nothing, and it is a coverage gap
        mode        the mode the reconciliation was performed under

    review#38 (Lumpy): comparing counts let `[a,b]` be answered by `[a,a]`, by `[a,c]`, or by nothing at
    all with `deduplicated=99`. So `expected` is the multiset of identities in the batch UNDER THE
    REPORTED MODE — exactly what dalfox scans — and the dedup count is DERIVED rather than believed.

    review#40 (Lumpy): an UNKNOWN mode has no identity to reconcile under, and signature is the LEAST
    demanding one — using it certified coverage that `exact`/`off` would have denied ("only a?q=1 was
    reported" is complete under signature and short under exact). Two facts are separated instead:
    anything missing even by SIGNATURE was never mentioned under any policy and is genuinely owed;
    anything present by signature but not as the exact URL is UNDECIDABLE — recorded as coverage-unknown
    and left terminal, because a retry under the same unknown policy produces the same ambiguity. An
    unreadable POLICY must not become either a clean claim or an endless retry."""
    from collections import Counter
    mode = art.dedup_mode
    keyfn, multiplicity = _dalfox_identity_fn(mode)
    known = mode in _DALFOX_DEDUP_MODES
    expected: dict = {}
    for u in batch:
        expected.setdefault(keyfn(u), []).append(u)
    reported = [keyfn(t) for t in art.summary_targets]
    rep_count = Counter(reported)
    foreign = [t for t, k in zip(art.summary_targets, reported) if k not in expected]

    retryable, terminal, owed, ambiguous = [], [], [], []
    if multiplicity:
        # `off` scans every input LINE: two identical lines owe two reports, and one report leaves one
        # occurrence unaccounted (review#40 — the set intersection could not see that).
        short = {k: len(v) - rep_count.get(k, 0) for k, v in expected.items()
                 if rep_count.get(k, 0) < len(v)}
        if short:
            names = [f"{expected[k][0]} x{n}" for k, n in list(short.items())[:20]]
            retryable.append(f"{sum(short.values())} submitted occurrence(s) were never reported under "
                             f"dedup_mode=off: " + ", ".join(names))
            owed = [u for k, n in short.items() for u in expected[k][:n]]
    else:
        unlisted = [k for k in expected if k not in rep_count]
        if unlisted:
            names = [expected[k][0] for k in unlisted]
            retryable.append(f"{len(unlisted)} submitted target(s) were never reported in any state: "
                             + ", ".join(names[:20])
                             + (f" (+{len(names) - 20} more)" if len(names) > 20 else ""))
            owed = [u for k in unlisted for u in expected[k]]
    if not known:
        # present by signature, but NOT as the exact URL dalfox would have had to scan under `exact`
        # or `off`. Whether those were covered is not knowable from this artifact.
        rep_urls = set(art.summary_targets)
        ambiguous = [u for u in batch if u not in rep_urls and _dalfox_signature(u) in rep_count]
        if ambiguous:
            terminal.append(f"dedup_mode is {mode}, so membership cannot be decided: "
                            f"{len(ambiguous)} submitted target(s) share a reported SIGNATURE but were "
                            f"not reported as themselves — covered under `signature`, short under "
                            f"`exact`/`off`: " + ", ".join(ambiguous[:20]))
    if foreign:
        retryable.append(f"{len(foreign)} reported target(s) were NOT in this batch: "
                         + ", ".join(foreign[:20]))
    if known:
        over = [k for k, n in rep_count.items()
                if k in expected and n > (len(expected[k]) if multiplicity else 1)]
        if over:
            retryable.append(f"{len(over)} target(s) reported more times than dedup_mode={mode} allows, "
                             f"which that mode should have collapsed")
        claimed = art.deduplicated
        derived = 0 if multiplicity else len(batch) - len(expected)
        if claimed is not None and claimed != derived:
            retryable.append(f"dalfox claims {claimed} target(s) collapsed; under dedup_mode={mode} "
                             f"this batch has {derived} duplicate(s)")
    return owed, {"retryable": retryable, "terminal": terminal, "mode": mode,
                  # the ambiguous TARGETS, not the sentence about them: a doubt is cleared per identity
                  # by an attempt that actually scanned it (review#42, Lumpy).
                  "ambiguous": ambiguous}


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


#: what the blind-XSS channel resolved to, so the DECISION is evidence and not an inference from flags
#: credential-transport files are named so a sweep can find them without guessing
_OOB_CRED_PREFIX = "quarry-dalfox-oob-"
_OOB_CRED_SUFFIX = ".cred.json"


def sweep_stale_oob_creds(max_age_s: float = 3600.0) -> int:
    """Remove credential-transport files a KILLED Quarry could not clean up. Returns how many went.

    A SIGKILL skips every `finally`, so the file outlives the process that needed it (review#18, Lumpy).
    Only files this module creates are touched — matched by prefix AND suffix inside the private 0700
    directory pattern, never a glob over somebody else's temp files — and only ones old enough that no
    live scan can still be using them."""
    import tempfile
    removed = 0
    root = Path(tempfile.gettempdir())
    try:
        for d in root.glob(_OOB_CRED_PREFIX + "*"):
            if not d.is_dir() or d.is_symlink():
                continue
            try:
                if time.time() - d.stat().st_mtime < max_age_s:
                    continue                       # a live scan may still hold it
                for f in d.glob("*" + _OOB_CRED_SUFFIX):
                    # a SYMLINK (dangling or not) is unlinked as the link it is: `is_file()` alone
                    # follows it and answers False for a dangling one, which left the litter for ever.
                    if f.is_symlink() or f.is_file():
                        f.unlink()
                        removed += 1
                d.rmdir()
            except OSError:
                continue                           # someone else's, or already gone
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return removed
    return removed


class OobCredentialError(RuntimeError):
    """The armed OOB channel's credential could not be transported. The scan does NOT run unauthenticated.

    review#19 (Lumpy): yielding None on failure meant `_dalfox_cmd` still emitted `--blind-oob=<server>`
    while dropping `--config` — so an operator who configured an AUTHENTICATED backend silently got a
    different configuration, which finishes cleanly with no callbacks and looks valid."""


def _make_oob_credential(secret: str):
    """Create the 0600 credential file and return (dir, path), or raise `OobCredentialError`.

    ACQUISITION ONLY. It is deliberately not a context manager: `shodan_host._open_lock` records what
    happens when one `try` covers both acquisition and the protected body — an exception thrown by the
    BODY is caught here, the generator yields a second time, and `contextlib` replaces the real failure
    with `RuntimeError: generator didn't stop after throw()`. The body's exceptions are none of this
    function's business (review#19, Lumpy)."""
    import tempfile
    d = path = None
    try:
        # 0700 and ours alone: `mkdtemp` refuses to reuse, so no other user can pre-create it
        d = Path(tempfile.mkdtemp(prefix=_OOB_CRED_PREFIX))
        path = d / ("cfg" + _OOB_CRED_SUFFIX)
        # O_EXCL|O_NOFOLLOW: an existing path — or a symlink planted at it — is REFUSED, never followed
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as fh:
            # dalfox reads TOML **or JSON**, so a SERIALIZER escapes the value rather than interpolation
            json.dump({"scan": {"blind_oob_secret": secret}}, fh)
        return d, path
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # `path` is passed so a REFUSED symlink is unlinked too — otherwise it and its directory
        # survive for ever, and the sweep cannot see through a dangling link either.
        _drop_oob_credential(d, path)
        raise OobCredentialError(f"the OOB credential could not be written: {e}") from e


def _drop_oob_credential(d, path) -> None:
    """Destroy exactly what one invocation created. Never raises."""
    try:
        # `unlink` on a SYMLINK removes the link, never its target — so a path we REFUSED to write
        # through is still cleaned up. Leaving it behind kept the planted link and its directory around
        # for ever, since the sweep cannot see through a dangling one either.
        if path is not None and (Path(path).is_symlink() or Path(path).is_file()):
            Path(path).unlink()
    except OSError:
        pass
    try:
        if d is not None:
            Path(d).rmdir()
    except OSError:
        pass


@contextlib.contextmanager
def blind_oob_credential(secret: str):
    """Yield a path to dalfox's `--config` carrying ONLY the OOB secret, then destroy it.

    review#18 (Lumpy): a 0600 file is right DURING execution and wrong afterwards. This one lived in the
    run's raw artifact tree, where it would have reached publication, manifests, exports, digests and
    resume artifacts — the credential becoming permanent local evidence. It lives OUTSIDE the run, and
    the `finally` covers success, timeout, a parse failure and any runner exception.

    Yields None only when there is NO secret to carry. A secret that cannot be written raises
    `OobCredentialError`: running the armed channel unauthenticated is a different scan than the one the
    operator configured."""
    if not secret:
        yield None
        return
    d, path = _make_oob_credential(secret)     # settled BEFORE the protected body — see `_make_…`
    try:
        yield path
    finally:
        _drop_oob_credential(d, path)


def _blind_oob_plan(prof) -> dict:
    """Decide the blind/stored-XSS OOB channel: {armed, channel, backend, server, secret, reason}.

    The contract (review#12, Lumpy), in order:

      * OFF unless `MODES.BLIND_XSS` explicitly arms it. A blind payload persists on the target and
        fires later in someone else's browser — a heavier engagement decision than a reflected probe.
      * A self-hosted `oob.callback_server` is used when present, with `auth_token` carried in an
        ephemeral 0600 `--config` file. The token is OPTIONAL: plenty of instances run open.
      * With no server configured the backend is the public interactsh pool — dalfox's own default, and
        the same posture as nuclei's OAST and Quarry's SSRF probes. ONE arming flag is the consent
        (Lumpy, 2026-08-06); a second gate for the common case just meant no blind XSS at all.

    CORRELATION is dalfox's either way: it mints the per-payload nonce, registers, polls, waits and maps
    the callback back to target/param/location/method/payload. Quarry imports it. The SERVER is a
    separate ownership question — ProjectDiscovery's pool on the public backend (its operator sees the
    raw callbacks), yours when `oob.callback_server` is set. `backend` in the returned plan is the
    field that answers it; do not read `armed` as "we own the channel" (review#19, Lumpy).

    There is exactly ONE channel — `--blind-oob`. No configuration adds a second one, so a finding has
    one callback lifecycle and one correlation owner.
    """
    o = secrets.oob() or {}
    if not getattr(prof, "blind_xss", False):
        return {"armed": False, "channel": "off", "backend": "", "server": "", "secret": "",
                "reason": "MODES.BLIND_XSS is off — the blind/stored-XSS channel was not armed"}
    server = str(o.get("callback_server") or "").strip()
    if server:
        return {"armed": True, "channel": "native", "backend": "self-hosted", "server": server,
                "secret": str(o.get("auth_token") or "").strip(),
                "reason": f"blind XSS armed on the configured callback server ({server}); "
                          f"correlation is owned by DALFOX and imported"}
    # No self-hosted server: dalfox's own default, the public interactsh pool. Stated, not warned about
    # — it is what nuclei's OAST and Quarry's own SSRF probes already do, and what an operator reaching
    # for Burp Collaborator does without ceremony (Lumpy, 2026-08-06).
    return {"armed": True, "channel": "native", "backend": "public", "server": "", "secret": "",
            "reason": "blind XSS armed on ProjectDiscovery's PUBLIC interactsh pool (set "
                      "`oob.callback_server` to use your own) — its operator sees the raw callbacks; "
                      "correlation is owned by DALFOX and imported"}


def _dalfox_cmd(batch_file, out_file, prof, batch_len: int = 0, cred_path=None) -> list[str]:
    """dalfox v3 (Rust) reflected-XSS scan (v0.3.8). v3 replaced the headless browser with static AST DOM
    analysis, so v2's --skip-headless timekiller is GONE; params are pre-discovered (arjun/gf), so --skip-mining
    stays. Output is structured JSONL to the -o file; -S keeps captured output minimal (status is read from the
    EXIT CODE, not stdout — see the scan loop). Concurrency is 2-DIMENSIONAL in v3: --workers is PER TARGET,
    --max-concurrent-targets is target parallelism — carrying v2's -w 100 forward would explode a 40-target
    chunk's fan-out, so BOTH are governed with CONSERVATIVE defaults (roughly v2's per-host blast radius, more
    hosts sequential) pending OTC measurement, and the global --rate-limit caps the aggregate rps when RoE is set."""
    # dalfox has its OWN membership cap: `--max-targets-per-host`, default 100. Targets past it are
    # dropped from the scan — reported honestly by dalfox (status `skipped`, error_code
    # TRUNCATED_PER_HOST_CAP) and, until review#13, thrown away by us. PREVENTATIVE (Lumpy): pass a
    # value that cannot truncate the chunk we submitted, so the cap can never decide our membership
    # whatever `DALFOX_CHUNK` is set to. The meta row is still parsed — dalfox may gain other states.
    per_host = max(1, int(batch_len or settings.concurrency("DALFOX_CHUNK", 40)))
    cmd = ["dalfox", "scan", "-i", "file", str(batch_file), "-o", str(out_file),
           "-f", "jsonl", "-S", "--skip-mining",
           # 3.2.0 adoption (MEASURED against the real binary, 2026-08-07):
           #
           # `--dedup-urls signature` keys on method+host+path+parameter NAMES and is COUNTED in
           # meta.targets_deduplicated, so it can never hide what it collapsed. It is the same identity
           # `_canonicalize_candidates` already computes — verified, including that it does NOT collapse
           # across SCHEME (http and https stay two targets, as ours does). So on this lane it should
           # find almost nothing left to collapse; it is here as a second net for any caller that feeds
           # raw URLs, and `targets_deduplicated` is reported so the residual is measurable rather than
           # assumed.
           "--dedup-urls", "signature",
           # the finding IS the product: carry the exact request that produced it and the response that
           # proved it, so a candidate is auditable without re-running anything. Measured field names:
           # `request` / `response`, both plain strings on the finding row.
           "--include-request", "--include-response",
           #
           # `--scan-timeout` is DELIBERATELY NOT PASSED (measured): a target whose injection stage it
           # cuts is reported `status: "clean", incomplete: false` — byte-identical to a target that was
           # genuinely scanned and found nothing. Quarry cannot report coverage it cannot observe, and a
           # silent false negative is exactly the failure `quarry-subfinder-ceiling-honesty` is about.
           # Revisit if dalfox surfaces the cut in the artifact.
           "--max-targets-per-host", str(per_host),
           "--workers", str(max(1, settings.workers("dalfox", 30))),          # per-target; v2 -w 100 NOT carried
           "--max-concurrent-targets", str(max(1, settings.concurrency("DALFOX_TARGETS", 4)))]  # OTC-tunable
    # BLIND / STORED XSS. `--blind-oob` is the channel: dalfox mints a fresh callback per PAYLOAD and
    # correlates each interaction back to target/param/location/method/payload, so a beacon names the
    # injection that produced it.
    plan = _blind_oob_plan(prof)
    if plan["armed"]:
        # ONE argv token when a server is given: the flag is `--blind-oob[=<domains>]`, so a separate
        # `=host` argument would be parsed as a TARGET, not as the backend.
        cmd += [f"--blind-oob={plan['server']}" if plan["server"] else "--blind-oob"]
        if plan["secret"] and cred_path is not None:
            # NEVER `--blind-oob-secret <token>`: argv is world-readable through /proc/<pid>/cmdline and
            # every process listing, and a display-level redaction does not fix that (review#17, Lumpy).
            # dalfox reads `scan.blind_oob_secret` from a `--config` file, so the credential reaches it
            # through an EPHEMERAL 0600 one whose lifetime the CALLER owns (review#18): the command
            # builder must not create a file it cannot destroy.
            cmd += ["--config", str(cred_path)]
    if prof.http_rl:
        # v3 has a REAL global rate cap (req/s, shared across workers AND targets) — supersedes v2's per-host
        # --delay math and its per-target-limiter caveat. Bound the aggregate stream directly to the RoE rate.
        cmd += ["--rate-limit", str(prof.http_rl)]
    return cmd


# dalfox v3 finding TYPE -> (store klass, confidence tier, display name). Kept DISTINCT (Lumpy): a Dalfox-verified
# hit (V) is higher-confidence than a reflection (R), and an AST-DOM static finding (A) is its own static-analysis
# evidence — none collapses into another. `confirmed` stays False for all (Quarry-owned impact validation only);
# "Dalfox-verified" (not "DOM-verified") — V is dalfox's own verdict, which doesn't always establish DOM execution.
_DALFOX_TIER = {
    "V": ("xss-verified", "verified", "XSS — Dalfox-verified (Quarry impact validation pending)"),
    "R": ("xss-candidate", "candidate", "reflected parameter — XSS candidate (manual validation required)"),
    "A": ("dom-xss-static", "dom-static", "DOM XSS (static AST, needs runtime confirmation)"),
}
_DALFOX_SRC_SINK = re.compile(r"\(Source:\s*(.*?),\s*Sink:\s*(.*?)\)")
_DALFOX_LINECOL = re.compile(r":(\d+):(\d+)\s*-\s")


def _dalfox_engine_id() -> str:
    """The VERIFIED identity of the dalfox binary that will ACTUALLY run (registry health) — folded into the
    resume work unit so a drifted / shadowed / manually-upgraded binary can't reuse another engine's chunks
    (review-r9#4). An unverified/unknown engine returns a per-run NONCE -> that run is NON-resumable (a re-scan
    is a safe superset; silently skipping chunks we can't prove ran on the same binary is not)."""
    try:
        from ..registry import load_tools, health
        t = next((x for x in load_tools() if x.bin == "dalfox"), None)
        if t is not None:
            h = health(t)
            if h.get("ok") and h.get("identity"):
                return str(h["identity"])
    except Exception:
        pass
    return "unverified-" + os.urandom(8).hex()


def _dstr(v) -> str:
    """A JSON field coerced to a stripped string ONLY if it is a scalar string — a list/dict/number returns ''
    (never str([...])). review-r9#3: essential fields are scalar-string validated, not blindly str()'d."""
    return v.strip() if isinstance(v, str) else ""


def _dalfox_identity(ftype: str, obj: dict) -> "str | None":
    """A canonical identity per finding so DISTINCT routes never collapse (review-r8#2). V/R key on
    scheme://host:port/path + location:param + method — /search?q and /admin?q are DISTINCT. A (AST-DOM) has no
    real param (dalfox writes param '-'), so it keys on its SOURCE/SINK + line:col (two sinks on one URL are
    distinct). Returns None (row rejected, never raises — review-r9#3) when a needed field is missing/non-scalar
    or the PoC URL is unparseable (incl. a bad :port that only raises on attribute access)."""
    poc = _dstr(obj.get("data"))
    if not poc:
        return None
    try:
        u = urlsplit(poc)
        host = (u.hostname or "").lower()
        port = u.port                                          # a bad port raises HERE (not at urlsplit) — guarded
    except ValueError:
        return None
    if not host:
        return None
    h = f"[{host}]" if ":" in host else host                   # review-r10#2: bracket IPv6 so [::1]:80 != [::1:80]
    base = f"{(u.scheme or 'http').lower()}://{h}{f':{port}' if port else ''}{u.path or '/'}"
    method = (_dstr(obj.get("method")) or "GET").upper()
    if ftype == "A":
        ev = _dstr(obj.get("evidence"))
        m, lc = _DALFOX_SRC_SINK.search(ev), _DALFOX_LINECOL.search(ev)
        if m:
            loc = f"{lc.group(1)}:{lc.group(2)}" if lc else ""
            disc = f"{loc}|{m.group(1).strip()}->{m.group(2).strip()}"
        else:
            disc = (ev or _dstr(obj.get("message_str")))[:120]
        return f"{base}|dom|{disc}|{method}" if disc else None
    param = _dstr(obj.get("param"))
    if param in ("", "-"):                                     # '-' is dalfox's no-param placeholder
        return None                                            # a V/R finding with no param is malformed
    return f"{base}|{_dstr(obj.get('location'))}:{param}|{method}"


def _dalfox_finding(obj) -> "dict | None":
    """Validate + build ONE finding record, or None if malformed. `type` must be a scalar string in {V,R,A}
    (unknown/non-scalar REJECTED, never silently reclassified as R); null JSON fields never become the string
    'None'; dalfox's own type/payload/evidence/PoC are preserved. `raw_ref` is added by the caller."""
    if not isinstance(obj, dict):
        return None
    ftype = _dstr(obj.get("type")).upper()
    if ftype not in _DALFOX_TIER:                              # V/R/A only (scalar string)
        return None
    ident = _dalfox_identity(ftype, obj)
    if ident is None:
        return None
    klass, confidence, name = _DALFOX_TIER[ftype]
    param = _dstr(obj.get("param"))
    param = None if param in ("", "-") else param
    poc = _dstr(obj.get("data")) or None
    return {"id": f"{klass}:{ident}", "template": klass, "name": name,
            "severity": (_dstr(obj.get("severity")) or "medium").lower(),
            "matched": _dstr(obj.get("message_str")) or poc or ident,
            "confidence": confidence, "sources": ["dalfox"], "confirmed": False,
            "dalfox_type": ftype, "param": param, "payload": obj.get("payload") if isinstance(obj.get("payload"), str) else None,
            "location": _dstr(obj.get("location")) or _dstr(obj.get("inject_type")) or None,
            "evidence": _dstr(obj.get("evidence")) or None, "poc": poc,
            "cwe": _dstr(obj.get("cwe")) or None,
            # 3.2.0 splits confidence / detection-method / impact into their own axes; carry them rather
            # than flattening to our single tier. `detection_method: "oob"` is a BLIND callback that
            # actually arrived — the one observable proof that channel worked.
            "detection_method": _dstr(obj.get("detection_method")) or None,
            "confidence_reason": _dstr(obj.get("confidence_reason")) or None,
            "inject_type": _dstr(obj.get("inject_type")) or None,
            # `--include-request/--include-response`: the exact request that produced the finding and the
            # response that proved it. Stored WHOLE — this is the evidence, not a preview of it — and
            # only when dalfox actually emitted a string (a missing one must not become "None").
            "request": obj.get("request") if isinstance(obj.get("request"), str) else None,
            "response": obj.get("response") if isinstance(obj.get("response"), str) else None,
            # correlation for an OOB hit is dalfox's: it minted the nonce, registered, polled and mapped
            # it back. Quarry imports that — it did not issue the token (review#12, Lumpy).
            **({"oob_owner": "dalfox"} if _dstr(obj.get("detection_method")) == "oob" else {})}


#: dalfox's own per-target error codes, split by WHAT A RETRY WOULD DO. review#13 (Lumpy): "retriable
#: remainder versus deterministic terminal omission" — collapsing both into one boolean is how a chunk
#: either retries for ever or is marked done over evidence nobody collected.
#:
#: RETRIABLE — the environment failed and a later attempt may succeed. The chunk is NOT done.
_DALFOX_RETRIABLE = frozenset({"CONNECTION_FAILED", "DNS_RESOLUTION_FAILED", "TLS_HANDSHAKE_FAILED",
                               "REQUEST_TIMEOUT", "SESSION_LOST"})
#: DETERMINISTIC — the same input under the same config omits the same targets, for ever. The chunk IS
#: execution-complete (retrying changes nothing); the omission is COVERAGE and is reported as such.
#:
#: Each maps to the coverage KIND that actually describes it, because the manifest is operator evidence
#: and `timeout` was misleading for both (review#16, Lumpy):
#:   TRUNCATED_PER_HOST_CAP  a hard ceiling truncated eligible input      -> COVERAGE_CAP
#:   CONTENT_TYPE_MISMATCH   the tool declined it as unscannable content  -> COVERAGE_TOOL_OMISSION
_DALFOX_TERMINAL_KIND = {"TRUNCATED_PER_HOST_CAP": events.COVERAGE_CAP,
                         "CONTENT_TYPE_MISMATCH": events.COVERAGE_TOOL_OMISSION}
_DALFOX_DETERMINISTIC = frozenset(_DALFOX_TERMINAL_KIND)


@dataclass(frozen=True)
class DalfoxArtifact:
    """What ONE dalfox JSONL artifact says about itself — as separate facts.

    review#13 (Lumpy): "don't reduce all metadata problems to one `artifact_ok=False`", because
    "valid artifact" and "complete scan" then become the same boolean again. They are different
    questions and the answers drive different machinery:

      readable    the artifact PARSES to our contract (one meta row first, counts agree, every row
                  valid). Drives resume validation: an unreadable artifact proves nothing.
      complete    dalfox says it finished the batch — `meta.incomplete` false and no target skipped.
      skipped     every target NOT scanned or not trusted, with dalfox's own reason.
      retriable   a later attempt could still cover those targets  -> the chunk is not done.
      deterministic  the same input+config omits them for ever      -> the chunk IS done, and the
                  omission is reported as coverage rather than retried into eternity.
    """

    readable: bool
    incomplete_flag: bool = False
    skipped: tuple = ()          # ((target, status, error_code), ...)
    total_requests: "int | None" = None
    deduplicated: "int | None" = None
    #: what dalfox says it ACTUALLY did about duplicates. We ask for `signature`; a build that ignored
    #: the flag, or a future default change, would silently scan a different target set than the one we
    #: think we asked for — so the artifact's own word is read rather than assumed (2026-08-07).
    #: every target dalfox ACCOUNTED FOR, whatever its disposition. review#37 (Lumpy): `complete` meant
    #: "no listed target was skipped", which is silent about targets that were never listed — an empty
    #: summary certified a whole batch. Membership is reconciled against the submitted batch by the lane,
    #: which is the only place that knows what was submitted.
    summary_targets: tuple = ()
    #: one of `_DALFOX_DEDUP_MODES`, or "unknown" when the artifact does not establish it.
    dedup_mode: str = "unknown"
    version: str = ""

    @property
    def complete(self) -> bool:
        """dalfox covered every target it was given — and SAID SO in a form we could read.

        review#36 (Lumpy): coverage was derived from two fields while the row carrying them might be
        malformed, so `{"incomplete": "true"}` produced `complete=True` on an artifact whose own meta
        could not be trusted. An unreadable claim is not a claim of coverage."""
        return self.readable and not self.incomplete_flag and not self.skipped

    @property
    def retriable(self) -> tuple:
        return tuple(x for x in self.skipped if x[2] in _DALFOX_RETRIABLE)

    @property
    def deterministic(self) -> tuple:
        return tuple(x for x in self.skipped if x[2] in _DALFOX_DETERMINISTIC)

    @property
    def unclassified(self) -> tuple:
        """A code we do not know. Treated as RETRIABLE by `execution_done` — an omission we cannot
        explain must not silently become a finished chunk."""
        return tuple(x for x in self.skipped
                     if x[2] not in _DALFOX_RETRIABLE and x[2] not in _DALFOX_DETERMINISTIC)

    @property
    def execution_done(self) -> bool:
        """Whether a RETRY of this exact chunk could cover anything more. Coverage is a separate fact:
        a chunk can be execution-done and still have omitted targets (see `deterministic`)."""
        return self.readable and not self.incomplete_flag and not self.retriable \
            and not self.unclassified

    def coverage_reason(self) -> str:
        """One line naming every disposition, for the operator and the coverage record."""
        bits = []
        if self.incomplete_flag:
            bits.append("dalfox flagged the RUN incomplete (a target's session died)")
        for label, rows in (("retriable", self.retriable), ("deterministic", self.deterministic),
                            ("unclassified", self.unclassified)):
            if rows:
                codes = sorted({r[2] or "?" for r in rows})
                bits.append(f"{len(rows)} target(s) {label}: {', '.join(codes)}")
        return "; ".join(bits) or "every target covered"


#: what dalfox can legitimately say it did about duplicates. review#35 (Lumpy): `str(x or "")` turned a
#: dict into `"{'mode': 'signature'}"` and an absent field into `""` — one is malformed input dressed as
#: a policy, the other is no claim at all. Anything not in this set is `unknown`: the findings are still
#: evidence, but WHICH TARGET SET produced them is not established, and the lane says so.
_DALFOX_DEDUP_MODES = frozenset({"signature", "exact", "off"})


def _dedup_mode(v) -> str:
    return v if isinstance(v, str) and v in _DALFOX_DEDUP_MODES else "unknown"


def _dalfox_meta(m: dict) -> "tuple[int | None, DalfoxArtifact | None]":
    """Read the meta row -> (findings_count, partially-built artifact). `None` count = unusable."""
    def _nonneg(v):
        # review#35 (Lumpy): these numbers become OPERATOR-FACING MEASUREMENT — "37 requests, 4 targets
        # collapsed" — so `-7` and `-3` were being summed and shown. A count that cannot be true is not
        # a count; it is an unreadable field, and `None` says exactly that.
        return v if type(v) is int and v >= 0 else None

    c = m.get("findings_count")
    count = _nonneg(c)                                        # STRICT int (not bool), non-negative
    # review#36 (Lumpy): these fields DRIVE THE VERDICT — `incomplete` decides whether the chunk may be
    # marked resumably complete, and `target_summary` is where a SKIPPED target is named. Both were
    # permissive: `"incomplete": "true"` is not `True`, so it read as "not incomplete", and a
    # dict-valued `target_summary` failed the `isinstance(list)` check and became "no targets skipped".
    # Malformed input must not be able to say a scan finished cleanly, so it invalidates the meta row
    # (count None -> artifact not readable -> chunk PARTIAL/retryable) rather than defaulting to clean.
    # review#37 (Lumpy): the checks only rejected these when PRESENT, so `{"findings_count": 0}` — no
    # `incomplete`, no `target_summary` — still certified a clean, resumably complete chunk. 3.2.0
    # always emits both (measured), so their ABSENCE is not "nothing to report", it is an artifact that
    # does not implement the contract this lane resumes on.
    malformed = False
    skipped, summary_targets = [], []
    ts = m.get("target_summary")
    if not isinstance(ts, list):
        malformed = True                                      # absent OR wrong type: no accounting at all
    else:
        for t in ts:
            if not isinstance(t, dict):
                malformed = True                              # a non-object row is not a target record
                continue
            status, target, code = t.get("status"), t.get("target"), t.get("error_code")
            if not isinstance(status, str) or not isinstance(target, str) \
                    or (code is not None and not isinstance(code, str)):
                malformed = True                              # never str()-coerced into a fake record
                continue
            # `findings` and `clean` are covered targets; anything else is not (dalfox's own words:
            # "the distinction that matters to a consumer: neither is `clean`")
            summary_targets.append(target)                # ACCOUNTED FOR, whatever the disposition
            if status in ("findings", "clean"):
                continue
            skipped.append((target, status, code or ""))
    inc = m.get("incomplete")
    if type(inc) is not bool:
        malformed = True                                      # absent OR wrong type
    if malformed:
        count = None
    return count, DalfoxArtifact(
        readable=True, incomplete_flag=inc is True, skipped=tuple(skipped),
        summary_targets=tuple(summary_targets),
        total_requests=_nonneg(m.get("total_requests")),
        deduplicated=_nonneg(m.get("targets_deduplicated")),
        dedup_mode=_dedup_mode(m.get("dedup_mode")),
        version=str(m.get("dalfox_version") or ""))


def scan_dalfox_jsonl(cf, sink=None) -> "tuple[int, DalfoxArtifact]":
    """FAIL-CLOSED, STREAMING parse of a dalfox v3 JSONL artifact -> (valid_finding_count, DalfoxArtifact).

    Every valid finding is handed to `sink` AS IT IS READ and never retained here. review#35 (Lumpy):
    with `--include-response` a finding carries a whole HTTP response, and the old shape read the entire
    file into a str, copied it again through `splitlines()`, and held every finding at once — so the
    artifact dalfox had already written successfully could OOM the process that came to read it, and do
    it again on resume. The bytes are preserved in full; what is bounded is how many of them we hold at
    the same time. That is the same split the acquisition side settled on: keep everything, hold one
    piece at a time.

    `artifact_ok` is False on ANY inconsistency: missing/unreadable file, a decode error, a meta row NOT
    in first position or MORE than one, a non-int/negative/bool findings_count (review-r10#3: bool
    subclasses int, so `type(x) is int`), finding-count != meta count, a torn/non-object line, an unknown
    type, or a row missing its identity fields. The caller ingests the valid findings but marks a not-ok
    chunk PARTIAL/retryable (never 'done'), so incomplete work can't be permanently skipped on resume.

    A DECODE ERROR is now per LINE rather than per file: the artifact is opened in binary and each line
    is decoded strictly, so one bad byte costs that row (and the artifact's `readable` verdict, exactly
    as before) instead of discarding every finding beside it.

    review#13 (Lumpy): the meta row is READ, not just counted. dalfox reports `incomplete` and a
    per-target `status`/`error_code`, so a batch where a target was SKIPPED used to parse as clean and
    become resumably complete. Those facts ride on the returned `DalfoxArtifact`: `readable` is the
    structural verdict this function always gave, and completeness is a separate question."""
    if not cf.exists():
        return 0, DalfoxArtifact(readable=False)
    kept, ok, meta_rows, meta_count, row_idx = 0, True, 0, None, 0
    in_sink = False                                           # see the OSError handler: whose failure it is
    art = DalfoxArtifact(readable=True)
    try:
        with open(cf, "rb") as fh:
            for raw_line in fh:
                try:
                    line = raw_line.decode("utf-8").strip()
                except UnicodeDecodeError:
                    ok = False; row_idx += 1; continue        # a bad byte costs THIS row, not the file
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    ok = False; row_idx += 1; continue        # torn line -> not trustworthy
                if not isinstance(obj, dict):
                    ok = False; row_idx += 1; continue
                if "meta" in obj:
                    meta_rows += 1
                    if row_idx != 0:                          # review-r10#3: meta must be the FIRST row
                        ok = False
                    m = obj.get("meta")
                    if isinstance(m, dict):
                        meta_count, art = _dalfox_meta(m)
                    if meta_count is None:
                        ok = False
                    row_idx += 1
                    continue
                try:
                    rec = _dalfox_finding(obj)
                except Exception:
                    rec = None                                # defensive: a row can NEVER abort the parse
                if rec is None:
                    ok = False                                # malformed/unknown row -> not trustworthy
                else:
                    kept += 1
                    if sink is not None:
                        # review#36 (Lumpy): the sink STORES the finding, and an OSError from that is a
                        # STORAGE failure, not an unreadable artifact — swallowing it returned
                        # `(0, readable=False)` while earlier rows had already landed, and the real
                        # failure disappeared. It is re-raised through the artifact-I/O boundary below.
                        in_sink = True
                        sink(rec)
                        in_sink = False
                    del rec                                   # one finding held at a time, not all of them
                row_idx += 1
    except OSError:
        if in_sink:
            raise                                             # the caller's failure, reported as its own
        return 0, DalfoxArtifact(readable=False)
    if meta_rows != 1:                                        # review-r10#3: EXACTLY one meta summary row
        ok = False
    if meta_count is not None and meta_count != kept:
        ok = False                                            # count mismatch -> torn/partial artifact
    # `readable` is the STRUCTURAL verdict; the dispositions dalfox reported ride along untouched, so a
    # torn artifact never masquerades as a complete scan and vice versa.
    return kept, dataclasses.replace(art, readable=ok)


def _sha256_file(p) -> str:
    """sha256 of a file, streamed. Used to prove a recorded completion artifact is UNCHANGED before a resume
    trusts it to SKIP its chunk (review-r11#1)."""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def _dalfox_xss_fast(ctx, cands, prof) -> RunResult:
    """params.dalfox_xss_fast (step 4.3.B): reflected-XSS scan over the CANONICALIZED xss candidates with
    the fast flags, in resumable chunks. Mirrors _nuclei_scan: input-hashed chunk state, mark done ONLY
    on clean completion (failed batch stays retryable), source-level tool_start/tool_progress/tool_finish
    + ledger. dalfox v3 emits structured JSONL (parsed below): findings are tiered by dalfox's own verdict
    (V verified / R reflected / A AST-DOM) into confidence, but stay confirmed:false — the map-don't-exploit
    boundary holds (Quarry-owned impact validation is separate). Findings go straight to the store (deduped by id)."""
    sid = "params.dalfox_xss_fast"
    # a SIGKILLed run skips every `finally`, so a credential-transport file can outlive the process that
    # needed it. Sweep before we make another one (review#18, Lumpy).
    sweep_stale_oob_creds()
    _plan_for_run = _blind_oob_plan(prof)     # resolved ONCE: the command, the identity and the report
    # EXECUTION facts about the OOB channel, distinct from the policy above: how many invocations this
    # lifecycle tried to launch with it, and how many actually did (review#20, Lumpy).
    _oob = {"attempted": 0, "launched": 0, "why": ""}
    chunk_n = max(1, settings.concurrency("DALFOX_CHUNK", 40))
    batches = [cands[i:i + chunk_n] for i in range(0, len(cands), chunk_n)]
    state_f = ctx.run.raw_path("params", "dalfox", "chunks.state.json")
    # C07 inc4 + review-r8#4/r9#4: resume validity folds EVERY coverage-affecting knob — the effective v3
    # contract: the VERIFIED EXECUTED engine identity (not just the configured pin — a drifted/shadowed binary
    # must not reuse old chunks; an unverified engine carries a nonce -> non-resumable), workers + target
    # concurrency + rate-limit (fan-out/pacing), a FINGERPRINT of the blind collector (never the raw URL), and
    # chunk size. `mode` v3-fast invalidates any in-progress v2 state.
    # `mode` carries the SCAN CONTRACT, not just the engine generation (review#36, Lumpy): the 3.2.0
    # adoption changed WHAT AN ARTIFACT CONTAINS (full request/response evidence) and WHICH TARGET SET
    # was scanned (signature dedup). A chunk completed before it is structurally valid and would be
    # accepted on resume — skipping work whose evidence we just decided we need. Changing this string
    # invalidates that state, which is exactly what should happen.
    _cfg = {"mode": "v3-fast-reflected+evidence+sigdedup", "engine": _dalfox_engine_id(),
            "workers": settings.workers("dalfox", 30),
            "targets": settings.concurrency("DALFOX_TARGETS", 4),
            "rate_limit": prof.http_rl,
            # THE OOB POLICY IS PART OF THE WORK'S IDENTITY (review#19, Lumpy): arming blind XSS after a
            # completed reflected scan must not reuse the old chunks and inject NO blind payload at all —
            # a lane that looks done and never ran what was just enabled. Switching backend
            # (public <-> self-hosted, or one server to another) has the same effect. The SERVER is
            # fingerprinted, never named: a work unit is reported and must not carry infrastructure, and
            # the token is not in here at all.
            "oob_channel": _plan_for_run["channel"],
            "oob_backend": _plan_for_run["backend"],
            "oob_server": (secrets.fingerprint(_plan_for_run["server"])
                           if _plan_for_run["server"] else None),
            "oob_authenticated": bool(_plan_for_run["secret"]),
            "chunk": chunk_n}
    scan_wu = events.work_unit(sid, inputs={"cands": cands}, config=_cfg)
    # review-r9#1/r10#1: nuclei's proven resume contract (not just its dir layout). Immutable per-attempt
    # artifacts wu_<scan_wu>/attempt_<id>/findings_<ci>.jsonl; a COMPLETION map (clean chunk -> validated
    # artifact path, controls SKIP) is kept separate from an append-only EVIDENCE map (every attempt's artifact
    # that produced output, controls AGGREGATION). A chunk is skipped ONLY if its recorded artifact still
    # validates (index in range · relative · no `..` · exact filename · resolves INSIDE this work_unit · readable
    # · re-parses); the source verdict + `matched` are derived from the RETAINED EVIDENCE (all attempts, deduped
    # by finding id), so a finding kept in a degraded attempt is never lost when a later retry comes back empty.
    wu_dir = state_f.parent / f"wu_{scan_wu}"
    wu_root = wu_dir.resolve()
    attempt_id = time.strftime('%Y%m%d-%H%M%S') + "-" + os.urandom(4).hex()
    attempt_dir = wu_dir / f"attempt_{attempt_id}"

    def _valid_entry(ci_str, rel) -> bool:
        if not (isinstance(ci_str, str) and ci_str.isdigit() and 0 <= int(ci_str) < len(batches)):
            return False
        if not isinstance(rel, str) or not rel or os.path.isabs(rel) or ".." in Path(rel).parts:
            return False
        if Path(rel).name != f"findings_{int(ci_str)}.jsonl":
            return False
        p = state_f.parent / rel
        try:
            if not p.resolve().is_relative_to(wu_root):      # containment: THIS work-unit's dir only
                return False
            if not p.is_file():
                return False
            with open(p, "rb"):
                pass
        except (OSError, ValueError):
            return False
        return True

    def _prev():
        if not state_f.exists():
            return None
        try:
            prev = json.loads(state_f.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(prev, dict):
            return None
        return prev if prev.get("work_unit") == scan_wu else None   # config-inclusive key: mismatch → fresh

    def _valid_completion(ci_str, entry) -> bool:
        # review-r11#1: a completion is trusted to SKIP a chunk only if its artifact is structurally valid AND
        # UNCHANGED (sha256 matches what we recorded) AND still PARSES CLEAN AND still AGREES with the recorded
        # outcome (EMPTY = no findings, SUCCESS = >=1). A completed artifact that later went missing/malformed/
        # tampered is dropped -> the chunk RE-RUNS (never a silent skip on stale evidence).
        if not isinstance(entry, dict):
            return False
        rel, outcome, sha = entry.get("rel"), entry.get("outcome"), entry.get("sha256")
        if outcome not in ("EMPTY", "SUCCESS") or not _valid_entry(ci_str, rel):
            return False
        p = state_f.parent / rel
        try:
            if _sha256_file(p) != sha:                       # unchanged since recorded
                return False
        except OSError:
            return False
        n_f, art = scan_dalfox_jsonl(p)                      # re-scans (as the comment promises); the
                                                             # findings themselves are not needed here
        # a recorded completion is only trusted when the artifact is still STRUCTURALLY sound and dalfox
        # itself had nothing left to retry on it
        return art.execution_done and ((outcome == "EMPTY" and not n_f)
                                       or (outcome == "SUCCESS" and n_f > 0))

    def _load_completion(prev) -> dict:                      # {ci: {rel, outcome, sha256}} — each FULLY validated
        m = (prev or {}).get("chunks"); out: dict[str, dict] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                if _valid_completion(str(k), v):
                    out[str(k)] = {"rel": str(v["rel"]), "outcome": v["outcome"], "sha256": v["sha256"]}
        return out

    def _valid_evidence(ci_str, entry) -> bool:
        # review-r12: an evidence artifact is aggregated only if structurally valid AND UNCHANGED (its recorded
        # sha256 still matches). A rejected/tampered artifact whose completion failed the digest must not sneak
        # its rows in through the evidence map. Valid rows from an ORIGINALLY malformed/degraded artifact are
        # still retained — as long as its bytes have not changed since we recorded it.
        if not isinstance(entry, dict):
            return False
        rel, sha = entry.get("rel"), entry.get("sha256")
        if not _valid_entry(ci_str, rel):
            return False
        p = state_f.parent / rel
        try:
            return _sha256_file(p) == sha
        except OSError:
            return False

    def _load_evidence(prev) -> dict:                        # {ci: [{rel, sha256}, ...]} — each digest-validated
        m = (prev or {}).get("evidence"); out: dict[str, list[dict]] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                kept = [{"rel": str(e["rel"]), "sha256": e["sha256"]}
                        for e in (v if isinstance(v, list) else [v]) if _valid_evidence(str(k), e)]
                if kept:
                    out[str(k)] = kept
        return out

    def _load_membership(prev) -> dict:
        """{ci: [reason, …]} — membership this lane could not DECIDE (an unreadable dedup policy).

        review#41 (Lumpy): it was emitted once and the chunk was recorded complete, so the next
        lifecycle skipped the chunk, re-derived nothing, and the fresh coverage generation retired the
        record — an unresolved doubt that quietly became a clean run."""
        m = (prev or {}).get("membership")
        out: dict[str, list] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                rows = [str(x) for x in v if isinstance(x, str) and x] if isinstance(v, list) else []
                if rows:
                    out[str(k)] = rows
        return out

    def _load_remainder(prev) -> dict:
        """{ci: [url, …]} — the targets a prior attempt still owes, and ONLY those.

        review#14 (Lumpy): a chunk that failed on one `SESSION_LOST` target used to re-run its whole
        input file, re-requesting every target that had already succeeded — someone else's site, hit
        again for nothing. dalfox names the affected URLs in `target_summary`, so the remainder can be
        exactly those."""
        m = (prev or {}).get("remainder")
        out: dict[str, list] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                urls = [str(u) for u in v if isinstance(u, str) and u] if isinstance(v, list) else []
                if urls:
                    out[str(k)] = urls
        return out

    def _load_terminal(prev) -> dict:
        """{ci: [{url, code}, …]} — omissions NO retry can close, accumulated across attempts.

        review#15 (Lumpy): a clean retry used to erase them. Attempt 1 truncates `b` and loses `c` to a
        dead session; attempt 2 re-runs `c` alone, succeeds, emits no omission — and `b`'s truncation
        vanished from the run entirely. A terminal gap is a FACT ABOUT THE TARGET SET, not about the
        attempt that happened to observe it, so it is persisted and re-reported every run."""
        m = (prev or {}).get("terminal")
        out: dict[str, list] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                rows = [{"url": str(x.get("url") or ""), "code": str(x.get("code") or "")}
                        for x in v if isinstance(x, dict) and x.get("url")] if isinstance(v, list) else []
                if rows:
                    out[str(k)] = rows
        return out

    _pv = _prev()
    completion: dict[str, dict] = _load_completion(_pv)      # controls SKIP (revalidated each run)
    evidence_map: dict[str, list[dict]] = _load_evidence(_pv)
    remainder: dict[str, list] = _load_remainder(_pv)         # controls WHAT a retry re-runs
    membership: dict[str, list] = _load_membership(_pv)       # UNDECIDABLE coverage, outliving attempts
    terminal: dict[str, list] = _load_terminal(_pv)           # gaps no retry can close — never cleared

    def _add_evidence(ci_str, rel, sha):                     # append-only, unique-by-rel, per chunk; digest recorded
        lst = evidence_map.setdefault(ci_str, [])
        if not any(e["rel"] == rel for e in lst):
            lst.append({"rel": rel, "sha256": sha})

    for _ci, _e in completion.items():                       # a clean chunk's artifact is always also evidence
        _add_evidence(_ci, _e["rel"], _e["sha256"])

    def _save():
        state_f.write_text(json.dumps(
            {"work_unit": scan_wu, "chunk_size": chunk_n, "chunks": completion, "evidence": evidence_map,
             "remainder": remainder, "terminal": terminal, "membership": membership}))

    # THE DECISION, recorded BEFORE execution — which is what it is: knowable up front, and it must
    # survive a run that raises anywhere in the loop (review#21, Lumpy). `omitted=0` keeps it inert in
    # the verdict: telemetry about a choice, never a coverage claim.
    events.coverage_partial(
        sid, kind=events.COVERAGE_SAMPLE, measure="blind_xss_policy", unit=f"{sid}.blind_oob.policy",
        eligible=1, tested=1, omitted=0,
        reason=(f"channel={_plan_for_run['channel']}"
                + (f" backend={_plan_for_run['backend']} owner=dalfox"
                   if _plan_for_run["armed"] else "")
                + f": {_plan_for_run['reason']}"))
    events.tool_start(sid, cmd=["dalfox", "scan", "-i", "file", "<chunk>", "-f", "jsonl", "--skip-mining"],
                      input_total=len(cands), work_unit=scan_wu)
    t0 = time.monotonic()
    degraded = produced = matched = 0                      # defined up-front: the finally ledger must not NameError
    #: what the scan COST and what dalfox COLLAPSED, accumulated across chunks. Defined here for the
    #: same reason as the counters above: the result note must not NameError on an early failure.
    cost = {"requests": 0, "deduplicated": 0, "dedup_disagreement": set()}
    tiers = {"xss-verified": 0, "xss-candidate": 0, "dom-xss-static": 0}   # if the loop raises before the aggregate
    status = Status.FAILED                                 # exception mid-loop must NOT emit scan-level success
    try:
      for ci, batch in enumerate(batches):
        chunk_wu = events.work_unit(sid, inputs={"cands": batch}, config=_cfg)
        seen = min((ci + 1) * chunk_n, len(cands))
        events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches), current_index=seen,
                             work_unit=chunk_wu)
        if str(ci) in completion:                         # resume: CLEAN in a prior attempt (revalidated on load)
            continue
        # RESUME ONLY WHAT IS OWED. A prior attempt that named its retriable targets re-runs those and
        # nothing else, so a chunk's successful targets are never re-requested (review#14, Lumpy). The
        # remainder is intersected with this run's batch: a candidate set that changed cannot smuggle a
        # URL back in, and a stale entry naming nothing simply falls back to the full chunk.
        # COUNTED, not set-membership (review#41, Lumpy): the state correctly stored two owed
        # occurrences of one URL under `dedup_mode=off`, and `set()` then selected all three originals —
        # so a retry re-requested a target that had already answered. The remainder is consumed.
        from collections import Counter as _Counter
        _owed_count = _Counter(remainder.get(str(ci), []))
        owed = []
        for u in batch:
            if _owed_count.get(u, 0) > 0:
                _owed_count[u] -= 1
                owed.append(u)
        batch = owed or batch
        if owed and len(owed) < len(batches[ci]):
            events.coverage_partial(
                sid, kind=events.COVERAGE_TIMEOUT, measure="dalfox_resume", unit=f"{sid}.chunk{ci}",
                eligible=len(batches[ci]), tested=len(batches[ci]) - len(owed), omitted=len(owed),
                reason=(f"chunk {ci + 1}/{len(batches)}: resuming {len(owed)} owed target(s) only — "
                        f"{len(batches[ci]) - len(owed)} already covered are NOT re-requested"))
        bf = ctx.write_list(f"dalfox_xss_{ci}.txt", batch)
        attempt_dir.mkdir(parents=True, exist_ok=True)     # created lazily, only if a chunk actually runs
        cf = attempt_dir / f"findings_{ci}.jsonl"          # IMMUTABLE per-attempt artifact (never overwritten)
        rel = f"wu_{scan_wu}/attempt_{attempt_id}/findings_{ci}.jsonl"
        events.tool_start(sid, work_unit=chunk_wu, input_total=len(batch))   # this chunk's own lifecycle
        res = None
        chunk_status = Status.FAILED.value                   # review#1: promoted ONLY after ALL bookkeeping below
        try:                                                 # review#1: chunk terminal ALWAYS fires (finally)
            # the credential exists ONLY around the exec: created here, destroyed in the context
            # manager's `finally` whether the run succeeds, times out, or raises (review#18, Lumpy).
            if _plan_for_run["armed"]:
                _oob["attempted"] += 1
            try:
                with blind_oob_credential(_plan_for_run["secret"]) as _cred:
                    res = exec_tool("dalfox", _dalfox_cmd(bf, cf, prof, len(batch), _cred),
                                    ok_codes=(0, 1),
                                    timeout=scaled_timeout(len(batch), ctx.http_timeout, 30))
                    # PROVEN by the runner, never inferred: "the credential is in hand" is readiness,
                    # and a missing binary, a cancelled launch or a Popen that raised must not read as a
                    # process that ran with the armed channel (review#21, Lumpy).
                    if _plan_for_run["armed"] and getattr(res, "started", False):
                        _oob["launched"] += 1
                    elif _plan_for_run["armed"]:
                        _oob["why"] = _oob["why"] or f"dalfox did not start ({res.note or res.status})"
            except OobCredentialError as e:
                # REFUSE, never fall back. Running the armed channel unauthenticated is a DIFFERENT scan
                # from the one the operator configured, and it finishes cleanly with no callbacks —
                # looking valid while proving nothing (review#19, Lumpy).
                degraded += 1
                _oob["why"] = _oob["why"] or f"credential transport failed ({e})"
                events.coverage_partial(
                    sid, kind=events.COVERAGE_TIMEOUT, measure="dalfox_targets",
                    unit=f"{sid}.chunk{ci}.credential", eligible=len(batch), tested=0,
                    omitted=len(batch),
                    reason=(f"chunk {ci + 1}/{len(batches)}: NOT SCANNED — the armed blind-XSS channel's "
                            f"credential could not be transported ({e}); refusing to run it "
                            f"unauthenticated"))
                chunk_status = Status.PARTIAL.value
                continue
            # dalfox v3 EXIT CONTRACT (measured): 0 = clean/no-findings, 1 = clean/WITH-findings, >=2 = error.
            # review-r9#2: exit code and parsed artifact must AGREE — CLEAN only for (0 + valid empty) or
            # (1 + valid findings). Any disagreement / hard exit / malformed artifact -> PARTIAL, retryable.
            # the findings are INGESTED below from the retained artifacts; here only the count and the
            # artifact's own verdict are needed, so nothing is held.
            n_findings, art = scan_dalfox_jsonl(cf)
            rc = res.exit_code
            # EXECUTION completion decides resume; COVERAGE is reported separately below. A chunk whose
            # only omissions are DETERMINISTIC is done — retrying it would omit exactly the same targets
            # for ever — and its gap is a counter, not a retry (review#13, Lumpy).
            # MEMBERSHIP RECONCILIATION (review#37, Lumpy). `execution_done` only says nothing dalfox
            # LISTED still needs retrying; it is silent about targets it never listed. With signature
            # dedup the expected accounting is (submitted - collapsed), so a shortfall means dalfox
            # never told us what happened to those URLs — and a chunk marked done over them would drop
            # them for ever. Unaccounted targets keep the chunk retryable.
            # review#38 (Lumpy): counting is not reconciling. `[a,b]` answered by `[a,a]`, by `[a,c]`,
            # or by an empty summary with `deduplicated=99` all balanced arithmetically and were marked
            # done. Membership is computed from the batch's OWN signatures — the identity dalfox
            # deduplicates on, which is the identity `_canonicalize_candidates` already uses — and every
            # disagreement is named.
            _owed_unlisted, _acct = _dalfox_accounting(batch, art)

            if _acct["retryable"]:
                events.coverage_partial(
                    sid, kind=events.COVERAGE_UNKNOWN, measure="dalfox_accounting",
                    unit=f"{sid}.chunk{ci}.accounting",
                    reason=(f"chunk {ci + 1}/{len(batches)}: dalfox's target accounting does not "
                            f"reconcile with the batch submitted — " + "; ".join(_acct["retryable"])
                            + "; the chunk stays RETRYABLE rather than done over it"))
            # UNDECIDABLE, not unfinished (review#40, Lumpy): a retry under the same unknown policy
            # produces the same ambiguity, so the chunk is execution-complete and the doubt is carried
            # as coverage. ACCUMULATED rather than emitted here (review#41): the chunk is recorded
            # COMPLETE, so a fresh lifecycle skips it and never re-derives the doubt, and the new
            # coverage generation would retire the old record.
            #
            # CLEARED PER IDENTITY (review#42, Lumpy): `pop()` cleared doubt about targets this attempt
            # never touched — a retry narrowed to the remainder, or an artifact we could not even read,
            # both wiped an unresolved question about the rest of the original batch. Only a target this
            # attempt actually SCANNED, and reconciled unambiguously, resolves.
            _prior = set(membership.get(str(ci), []))
            if art.readable:
                _prior -= {u for u in batch if u not in set(_acct["ambiguous"])}
            _amb_now = sorted(_prior | set(_acct["ambiguous"]))
            if _amb_now:
                membership[str(ci)] = _amb_now
            else:
                membership.pop(str(ci), None)
            clean = (art.execution_done and not _acct["retryable"]
                     and ((rc == 0 and not n_findings) or (rc == 1 and n_findings > 0)))
            cf_sha = _sha256_file(cf) if cf.exists() else None
            # what the scan COST and what it COLLAPSED — parsed since 4.3 and never surfaced, which made
            # the meta row half-read. Accumulated here and reported on the lane's result, so the residual
            # duplicate rate over our own canonicalizer is a MEASURED number at the next OTC run rather
            # than an assumption (2026-08-07).
            if type(art.total_requests) is int:
                cost["requests"] += art.total_requests
            if type(art.deduplicated) is int:
                cost["deduplicated"] += art.deduplicated
            if art.dedup_mode != "signature":
                # we asked for `signature`; the artifact says otherwise. Not a failure of THIS chunk —
                # the scan is what it is — but the target set is not the one we asked for, and an
                # operator reading "N targets scanned" deserves to know which policy produced it.
                cost["dedup_disagreement"].add(art.dedup_mode)
            # ACCUMULATE the gaps no retry can close, unioned by URL. A repeat observation does not
            # double-count and a CLEAN RETRY CANNOT ERASE an earlier one (review#15, Lumpy). The
            # coverage record is emitted once per chunk AFTER the loop, from this union — one record
            # per (source_id, unit) is what reconciliation keeps, and it must outlive the attempt.
            if art.deterministic:
                rows = terminal.setdefault(str(ci), [])
                have = {r["url"] for r in rows}
                rows.extend({"url": t[0], "code": t[2]} for t in art.deterministic
                            if t[0] and t[0] not in have)
            # a RETRIABLE/unknown omission is this attempt's story and is reported as it happens
            if art.retriable or art.unclassified or art.incomplete_flag:
                still = len(art.retriable) + len(art.unclassified)
                events.coverage_partial(
                    sid, kind=events.COVERAGE_TIMEOUT, measure="dalfox_pending",
                    unit=f"{sid}.chunk{ci}.pending", eligible=len(batch),
                    tested=max(0, len(batch) - still), omitted=still,
                    reason=f"chunk {ci + 1}/{len(batches)}: {art.coverage_reason()}")
            # WHAT THIS ATTEMPT STILL OWES: the targets dalfox named as retriable or unexplained, and
            # only those. Deterministic omissions are NEVER rescheduled — retrying omits exactly the same
            # targets for ever — and covered targets are not re-requested (review#14, Lumpy).
            # review#38 (Lumpy): a target dalfox never mentioned is owed too. Without it the remainder
            # held only the rows dalfox NAMED, so an unlisted target cleared the remainder and the next
            # lifecycle re-sent the whole batch — someone else's site, hit again for targets that had
            # already answered.
            # WHAT THE RETRY OWES, in the arithmetic of the mode dalfox reported.
            #
            # Under `off` each target_summary row IS an occurrence: three identical inputs where one
            # comes back SESSION_LOST owe 1 named failure + 2 never-reported = 3 scans, and any
            # set-dedup of either half collapses that to 1 (review#43, Lumpy). The two halves are
            # disjoint by construction — a NAMED row was reported, so it is not part of the unlisted
            # shortfall, which is computed from (expected - reported) counts.
            #
            # Under `signature`/`exact` one identity is one scan, so deduping is right there.
            _named_owed = _dedupe_owed([t[0] for t in (art.retriable + art.unclassified) if t[0]],
                                       art.dedup_mode)
            _key = _dalfox_identity_fn(art.dedup_mode)[0]
            _have = {_key(u) for u in _named_owed}
            owed_next = _named_owed + [u for u in _owed_unlisted
                                       if art.dedup_mode == "off" or _key(u) not in _have]
            if clean:
                completion[str(ci)] = {"rel": rel, "outcome": "SUCCESS" if n_findings else "EMPTY",
                                       "sha256": cf_sha}      # outcome + digest -> revalidated on resume
                remainder.pop(str(ci), None)                  # nothing owed once the chunk lands clean
                _add_evidence(str(ci), rel, cf_sha)          # ...and joins this chunk's evidence history
                _save()
            else:
                degraded += 1
                why = (f"exit {rc}" if rc not in (0, 1) else
                       "artifact malformed/mismatched" if not art.readable else
                       art.coverage_reason() if not art.execution_done else
                       f"exit {rc} disagrees with {n_findings} finding(s)")
                events.coverage_partial(sid, reason=f"chunk {ci + 1}/{len(batches)}: {why}")
                # A named remainder only when dalfox told us WHICH targets: an artifact we could not
                # read, or an exit-code disagreement, says nothing about individual targets, so the whole
                # chunk stays owed. Naming a subset there would silently drop the rest.
                if art.readable and owed_next:
                    remainder[str(ci)] = owed_next
                else:
                    remainder.pop(str(ci), None)
                if cf.exists() and cf.stat().st_size > 0:    # a degraded chunk WITH output keeps its evidence
                    _add_evidence(str(ci), rel, cf_sha)
                _save()
            chunk_status = (Status.SUCCESS if clean and n_findings
                            else Status.EMPTY if clean else Status.PARTIAL).value
        finally:
            _chunk_terminal(sid, chunk_wu, res, cf, status=chunk_status)   # FAILED if exec OR bookkeeping raised
      # review-r10#1/r11#2: DERIVE the verdict + telemetry from the RETAINED EVIDENCE (all attempts), not the
      # last per-chunk label. EVERY observation goes through Run.add() so C09 merges raw_refs / reconciles
      # conflicts across attempts (a later clean attempt's provenance must reach the store, not be dropped by a
      # pre-add dedup). A separate GLOBAL id set drives only the `matched` (distinct findings) counter; `produced`
      # counts NEW entities (Run.add True). Falls back to THIS attempt's file for a chunk just run but not yet
      # recorded. Verdict: any degraded this run -> PARTIAL; else any distinct finding -> SUCCESS; else EMPTY.
      # THE BLIND-XSS DECISION, every run, whichever way it went — armed or refused. Lumpy required the
      # backend to be recorded BEFORE execution; this is that record, and it is Quarry's own decision, so
      # it is fully knowable.
      #
      # What is NOT claimed: dalfox's session lifecycle. Registration, poll completion and the final wait
      # are written to its STDERR (`ceprintln!`), not to the JSONL artifact, and Quarry runs it under
      # `-S`. Asserting "registered" or "polled" from a stderr substring is exactly the oracle this
      # codebase stopped trusting. A callback that ARRIVES is observable — it lands as a `V` finding with
      # `detection_method: oob` — so findings prove the channel worked; their absence proves nothing.
      # TERMINAL COVERAGE, re-reported EVERY run from the persisted union — not from this attempt.
      # A gap no retry can close is a fact about the TARGET SET, so it must outlive the attempt that
      # observed it and reach a fresh process's manifest and verdict (review#15, Lumpy). `_save()` has
      # already persisted it, so the record survives even if this run adds nothing.
      _save()
      for _ci, _rows in sorted(membership.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
          if not _rows:
              continue
          # UNDECIDABLE membership is a fact about the TARGET SET under a policy we could not read, so
          # like a deterministic omission it must outlive the attempt that saw it and reach a fresh
          # process's verdict — the chunk itself is complete and will be skipped (review#41, Lumpy).
          _n = len(batches[int(_ci)]) if _ci.isdigit() and int(_ci) < len(batches) else len(_rows)
          events.coverage_partial(
              sid, kind=events.COVERAGE_UNKNOWN, measure="dalfox_membership",
              unit=f"{sid}.chunk{_ci}.membership",
              reason=(f"chunk {int(_ci) + 1 if _ci.isdigit() else _ci}/{len(batches)}: dalfox reported "
                      f"a dedup policy this lane cannot read, so membership cannot be decided for "
                      f"{len(_rows)} of {_n} submitted target(s) — covered under `signature`, short "
                      f"under `exact`/`off`: " + ", ".join(_rows[:20])
                      + (f" (+{len(_rows) - 20} more)" if len(_rows) > 20 else "")
                      + "; the chunk is NOT retried (the same policy would be as unreadable), and its "
                        "coverage is UNKNOWN rather than clean"))
      for _ci, _rows in sorted(terminal.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
          if not _rows:
              continue
          _n = len(batches[int(_ci)]) if _ci.isdigit() and int(_ci) < len(batches) else len(_rows)
          # ONE record per KIND, each on its own unit: a truncating ceiling and an unscannable
          # content-type are different dispositions, and reconciliation keeps the latest record per
          # (source_id, unit) — sharing a unit would drop one of them (review#16, Lumpy).
          _by_kind: dict = {}
          for _r in _rows:
              _by_kind.setdefault(
                  _DALFOX_TERMINAL_KIND.get(_r["code"], events.COVERAGE_TOOL_OMISSION), []).append(_r)
          for _kind, _krows in sorted(_by_kind.items()):
              _codes = sorted({r["code"] or "?" for r in _krows})
              events.coverage_partial(
                  sid, kind=_kind, measure="dalfox_targets",
                  unit=f"{sid}.chunk{_ci}.{_kind}", eligible=_n,
                  tested=max(0, _n - len(_krows)), omitted=len(_krows),
                  reason=(f"chunk {int(_ci) + 1}/{len(batches)}: {len(_krows)} target(s) permanently "
                          f"omitted ({', '.join(_codes)}) — no retry can cover them: "
                          + "; ".join(r["url"] for r in _krows)))
      produced = matched = 0
      tiers = {"xss-verified": 0, "xss-candidate": 0, "dom-xss-static": 0}
      seen_ids: set[str] = set()                            # GLOBAL — for the matched counter ONLY (not dedup)
      for ci in range(len(batches)):
        entries = list(evidence_map.get(str(ci)) or [])       # each already digest-validated on load
        # fall back to THIS run's just-written attempt file (trusted — we wrote it) for a chunk run but not recorded
        paths = [state_f.parent / e["rel"] for e in entries] or [attempt_dir / f"findings_{ci}.jsonl"]
        for p in paths:
            if not (p.exists() and p.stat().st_size > 0):
                continue
            # STREAMED into the store: one finding is held at a time, whatever the artifact weighs
            # (review#35, Lumpy). The counters below are closed over deliberately — the alternative is
            # a list of every finding with its full request and response in it.
            def _ingest(rec, _p=p):
                nonlocal matched, produced
                rec["raw_ref"] = str(_p)
                if rec["id"] not in seen_ids:
                    seen_ids.add(rec["id"]); matched += 1    # distinct finding first-seen
                if ctx.run.add("finding", rec):              # ALWAYS add -> provenance merge (raw_refs union)
                    produced += 1
                    tiers[rec["template"]] = tiers.get(rec["template"], 0) + 1
            scan_dalfox_jsonl(p, _ingest)
      status = Status.PARTIAL if degraded else (Status.SUCCESS if matched else Status.EMPTY)
    finally:
        # EXECUTION ACCOUNTING for the OOB channel, from a `finally` so an exception anywhere in the loop
        # still leaves what was ATTEMPTED on the record (review#21, Lumpy). It never masks that
        # exception: its own failure is swallowed, and the original propagates untouched.
        try:
            if _plan_for_run["armed"] and _oob["attempted"]:
                _missed = _oob["attempted"] - _oob["launched"]
                events.coverage_partial(
                    sid, kind=events.COVERAGE_TIMEOUT, measure="blind_xss_channel",
                    unit=f"{sid}.blind_oob", eligible=_oob["attempted"], tested=_oob["launched"],
                    omitted=_missed,
                    reason=(f"{_oob['launched']}/{_oob['attempted']} dalfox invocation(s) STARTED with "
                            f"the armed blind-XSS channel (backend={_plan_for_run['backend']}, "
                            f"owner=dalfox)"
                            + (f" — {_missed} did not: {_oob['why'] or 'see the chunk records'}"
                               if _missed else "")
                            + "; dalfox's registration/poll/final-wait are stderr-only under -S and are "
                              "NOT asserted here — an arriving callback is a `V` finding with "
                              "detection_method=oob"))
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass                       # accounting must never replace the failure it is describing
        # C07 inc4: source terminal ALWAYS fires (even if the loop raised) — one source lifecycle, no dup.
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
                           reason=(f"{degraded}/{len(batches)} chunk(s) degraded" if degraded else None),
                           duration=round(time.monotonic() - t0, 2), discovery_context="params")
        # ledger: NEW entities by tier (verified/candidate/dom-static kept distinct, review-r8#5) + matched
        # (all valid findings across retained evidence) tracked separately from produced (newly added).
        events.ledger(sid, produced={"xss_verified": tiers["xss-verified"],
                                     "xss_candidate": tiers["xss-candidate"],
                                     "dom_xss_static": tiers["dom-xss-static"], "matched": matched},
                      consumed={"shape": len(cands)})
    _cost = (f", {cost['requests']} request(s)" if cost["requests"] else "")
    _dedup = (f", {cost['deduplicated']} duplicate target(s) collapsed by dalfox"
              if cost["deduplicated"] else "")
    _dis = (f" [dalfox reports dedup_mode={'/'.join(sorted(cost['dedup_disagreement']))}, NOT the "
            f"`signature` we asked for — the target set these findings came from is not the one this "
            f"command specified]" if cost["dedup_disagreement"] else "")
    return RunResult("dalfox", ["dalfox", "scan", "-i", "file", "<chunked-xss-fast>"], status, 0,
                     round(time.monotonic() - t0, 2), None, produced,
                     note=(f"{len(batches)} chunk(s), {produced} new / {matched} matched, "
                           f"{degraded} degraded{_cost}{_dedup}{_dis}"))


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
    raw = active_review_values(ctx, "ssrf")
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
    opened = oob.open_session(ctx.run, server=secrets.oob().get("callback_server"),
                              token=secrets.oob().get("auth_token"))
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

    # ── arjun param discovery on param-less API endpoints — per-target, bounded, resumable (A2) ──
    # The ARJUN_CAP 40 membership cap is GONE: the full guarded endpoint set is processed in host-fair
    # order under ARJUN_BUDGET_S (0 = unbounded = default), and whatever a bounded run does not reach is
    # a counted, resumable remainder. See _arjun_lane for the measured completion contract.
    _arjun_lane(ctx, prof, corpus)

    # ── vuln-primitive probes over the 4.3.A CANONICALIZED shapes, SPLIT by primitive ──
    # XSS reflection -> params.dalfox_xss_fast (dalfox, 4.3.B). Open-redirect -> params.redirect_confirm
    # (native Location probe, NO dalfox, 4.3.C). dalfox is no longer responsible for redirect at all.
    # review-B1.5br1#2: these two selected on klass ALONE, so the RoE gate was left entirely to
    # netguard downstream. Scope policy and network policy are different questions; ask both.
    xss_raw = active_review_values(ctx, "xss")
    redir_raw = active_review_values(ctx, "redirect")
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
