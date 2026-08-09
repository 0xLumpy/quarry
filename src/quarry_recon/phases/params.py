"""Phase 7: params + lightweight scanning.

gf vuln-class buckets over the URL corpus -> ranked candidate queues; arjun param
discovery; non-intrusive nuclei with built-in interactsh OOB; dalfox reflected-XSS on
reflected candidates and a native Location probe for open-redirect candidates (dalfox
does not do redirect). Scanner output is stored as candidates (confirmed:false), never
as confirmed findings.
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
    """Review rows an active lane may act on: expected `klass` AND `scope.active_allowed`.

    Off-scope evidence (`related-host`) is retained in full but must never reach a lane that contacts
    anything. Values are returned in store order; the caller canonicalizes and guards its own targets."""
    out = []
    for r in ctx.run.read("review"):
        if r.get("klass") != klass:
            continue
        v = (r.get("value") or "").strip()
        if v and ctx.scope.active_allowed(normalize.host_of_url(v)):
            out.append(v)
    return out


def _arjun_base(url: str) -> "str | None":
    """The scheme://host[:port]/path identity of an absolute HTTP(S) URL, or None if it is not one."""
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
    """Parse an -oT artifact bound to its target -> (rows, malformed). `rows` is None when there is no file.

    Every row must be an absolute http(s) URL, carry a query, and resolve to the same base URL arjun was
    asked to scan. A malformed non-blank row makes the artifact non-completable (the caller must not
    journal the target as done) while validated rows are still retained."""
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


# arjun's exit code is not an execution oracle: a run whose every target was skipped still exits 0, and
# a batched run aborts every remaining target on the first crash. One target per process (see _arjun_lane).
_ARJUN_SCHEMA = 1                      # parser+contract version; folded into the resume identity
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_AJ_SCAN_RE = re.compile(r"^\[\*\]\s+Scanning\s+\d+/\d+:\s+(\S+)")
_AJ_SKIP_RE = re.compile(r"^\[-\]\s+Skipped\s+(\S+)\s+due to errors")
_AJ_FOUND = "Parameters found:"
_AJ_NONE = "No parameters were discovered."
# arjun prints this then reports the ordinary no-parameters line; treat it as a skip, never a clean zero.
_AJ_UNSTABLE = "Webpage is returning different content on each request. Skipping."


def _arjun_signals(text: str) -> dict:
    """The structured facts carried by arjun's stdout. Progress lines use `end='\\r'`, so splitlines()
    (which breaks on \\r too) is required to see the terminal line that follows them."""
    lines = [_ANSI_RE.sub("", ln).strip() for ln in (text or "").splitlines()]
    return {"scanned": [m.group(1) for ln in lines if (m := _AJ_SCAN_RE.match(ln))],
            "found": [ln for ln in lines if _AJ_FOUND in ln],
            "none": [ln for ln in lines if _AJ_NONE in ln],
            "skipped": [ln for ln in lines if _AJ_SKIP_RE.match(ln)],
            "skipped_url": [m.group(1) for ln in lines if (m := _AJ_SKIP_RE.match(ln))],   # URL only
            "unstable": [ln for ln in lines if _AJ_UNSTABLE in ln]}


def _arjun_verdict(exit_ok: bool, sig: dict, urls, *, target: str, malformed: int = 0) -> tuple:
    """Fail-closed per-target classification -> (verdict, detail). `urls` is `_arjun_rows()[0]`: the
    validated rows, or None when no -oT file exists.

    Completion is claimed only when the exit code, the stdout terminal line and the artifact state all
    agree, and all three are about the requested target. Verdicts:
      success  -> complete, params found        · empty    -> complete, target genuinely has none
      skipped  -> degraded, retained, retryable · failed   -> nonzero exit; keep partial findings
      unknown  -> missing / duplicate / contradictory / off-target signals; never a clean zero"""
    n_scan = len(sig["scanned"])
    terminal = len(sig["found"]) + len(sig["none"]) + len(sig["skipped"])
    if not exit_ok:
        # any -oT rows already exported stay valid, so findings survive but the target is never complete
        return "failed", "arjun exited nonzero (crash) — findings retained, target not complete"
    if n_scan != 1:
        return "unknown", f"expected exactly 1 target attempt on stdout, saw {n_scan}"
    # the stdout must name the requested target, else nothing in it may be attributed to it
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
        # valid rows are still ingested by the caller, but the target is not journaled as finished
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
    """Publish the completion manifest binding every evidence channel of one attempt -> (path, digest)
    or (None, None).

    The manifest, not the -oT file, is the ledger's completion artifact: an attempt has three evidence
    channels (stdout, stderr/traceback, optional -oT) and completion must cover all of them."""
    body = json.dumps({"schema": _ARJUN_SCHEMA, "url": url, "verdict": verdict,
                       "channels": dict(sorted(channels.items()))}, sort_keys=True).encode()
    dig = hashlib.sha256(body).hexdigest()
    return (dest, dig) if budget.publish_bytes(dest, body, digest=dig) else (None, None)


def _arjun_channels(ledger, url: str) -> "dict | None":
    """The validated channel paths for a completed target, or None when the attempt can no longer be
    trusted and must be redone.

    `Ledger.evidence()` returns only artifacts whose digest still matches; requiring every channel the
    manifest names to appear there withdraws the whole completion if any one channel was altered."""
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
    """Feed a target's validated -oT rows forward: provenance and the param-bearing URL handed to dalfox
    so a hidden reflected param gets XSS-tested. Every entity carries `raw_ref` to its source artifact."""
    ref = str(params_path) if params_path is not None else None
    n = 0
    for u in rows or []:
        base, qs = u.split("?", 1)
        uid = hashlib.sha256(u.encode()).hexdigest()   # full digest: the id must not collide on a prefix
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
    """The verified identity of the arjun binary that will actually run (registry health), folded into the
    resume work unit. An unverified engine yields a per-run nonce, making that run non-resumable."""
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
    """Partition a global lane rate `rl` (req/s) across `procs` concurrent arjun processes.

    arjun's `--rate-limit` is per process. Shares are integers summing to exactly `rl` with no process
    given 0 (arjun treats that as unlimited), so a rate below the pool size shrinks the pool instead.
    `rl` falsy means no flag and the pool runs unthrottled. Shares are returned largest first and slots
    consumed in order; `procs` must already be the effective pool (see `_arjun_pool`)."""
    if not rl:
        return [0] * max(1, procs)
    procs = max(1, min(procs, rl))
    base, extra = divmod(rl, procs)
    return [base + (1 if i < extra else 0) for i in range(procs)]


def _arjun_pool(configured: int, hosts: int, rl: int) -> int:
    """The effective number of concurrent arjun processes, bounded by the work that exists: at most one
    active target per host means more slots than hosts are unusable, and a rate below the pool shrinks
    it (see `_arjun_rate_shares`)."""
    n = max(1, min(configured, max(1, hosts)))
    return max(1, min(n, rl)) if rl else n


def _arjun_exec(url: str, rate: int, threads: int, paths: tuple, timeout: int) -> dict:
    """Run one arjun process for one target and return everything the parent needs to classify it.

    Does no ledger/event/store writes: those stay single-threaded in the parent so the append-only
    journal, coverage generation and entity store keep their ordering guarantees. A worker only
    produces facts."""
    out_f, std_f, err_f = paths
    out_f.unlink(missing_ok=True)          # fresh attempt file; a stale -oT must not fake output
    cmd = ["arjun", "-u", url, "-oT", str(out_f), "-t", str(threads)]
    if rate:
        cmd += ["--rate-limit", str(rate)]              # this process's share of the global lane rate
    r = exec_tool("arjun", cmd, raw_path=std_f, stderr_path=err_f, timeout=timeout)
    try:
        text = std_f.read_text(encoding="utf-8", errors="replace") if std_f.exists() else ""
    except OSError:
        text = ""                          # unreadable stdout -> no signals -> unknown (fails closed)
    rows, malformed = _arjun_rows(out_f, url)
    verdict, detail = _arjun_verdict(r.exit_code == 0, _arjun_signals(text), rows,
                                     target=url, malformed=malformed)
    return {"url": url, "result": r, "verdict": verdict, "detail": detail,
            "rows": rows, "malformed": malformed, "paths": paths}


def _arjun_zero_lifecycle(ctx, why: str) -> None:
    """Emit a complete zero-valued lifecycle, then record the skip, so a resumed lifecycle does not leave
    a prior run's arjun coverage units visible as current."""
    for m in ("api_endpoints", "endpoints_tested", "state_persisted"):
        events.coverage_partial("params.arjun", measure=m, unit=m, eligible=0, tested=0, omitted=0,
                                reason=why)
    ctx.run.record("params", skipped("arjun", why))


def _arjun_lane(ctx, prof, corpus) -> None:
    """arjun param discovery, one target per process.

    A batched `-i` invocation cannot attribute completion per target, and an arjun crash aborts every
    remaining target in the file; per-target isolation contains that, makes each URL independently
    classifiable, and makes the remainder resumable. Targets run concurrently in a bounded pool
    (`ARJUN_TARGETS`, default 5), one process per target and at most one active target per host. A set
    RATELIMIT.HTTP is a global lane limit, partitioned across the workers by `_arjun_rate_shares`."""
    api_all = sorted({u.split("?")[0] for u in corpus
                      if "?" not in u and any(s in u.lower() for s in
                      ("/api", "/rest", "/account", "/profile", "/search", "/user", "/order"))})
    # fresh-resolve: withhold scan-box/metadata, contact private
    api_all = netguard.guard_urls(ctx, api_all, phase="params.arjun")
    if not api_all:
        _arjun_zero_lifecycle(ctx, "no param-less API endpoints found")
        return
    if not have("arjun"):
        # an unavailable tool is COVERAGE_UNKNOWN, never a clean zero — we could not look
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
        """Never-attempted work runs first; a target arjun skipped or crashed on is retried only after
        every untouched endpoint, so a permanent skip cannot consume the budget and hide the remainder."""
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

    # size the pool from concurrent work (one target per host) before partitioning the rate, or the
    # operator's budget is split across slots that never open
    n_hosts = len({normalize.host_of_url(u) for u in pending})
    procs = _arjun_pool(max(1, settings.concurrency("ARJUN_TARGETS", 5)), n_hosts, prof.http_rl)
    shares = _arjun_rate_shares(prof.http_rl, procs)
    procs = len(shares)                      # a rate below the pool size shrinks the pool, not the rate
    ctx.echo(f"  arjun: {len(api_all)} param-less API endpoint(s)"
             + (f", {resumed} resumed" if resumed else "")
             + f" · {procs} concurrent target(s)"
             + (f" @ {prof.http_rl} req/s global ({'+'.join(map(str, shares))})" if prof.http_rl else "")
             + (f" · budget {aj_budget.seconds}s" if not aj_budget.unbounded else ""))

    def _finish(res: dict) -> None:
        """Parent-side, single-threaded: ledger, events and store writes for one completed target."""
        nonlocal nfound
        u, r, verdict = res["url"], res["result"], res["verdict"]
        uid = hashlib.sha256(u.encode()).hexdigest()
        out_f, std_f, err_f = res["paths"]
        counts[verdict] += 1
        # every channel is bound as evidence before any completion claim, and the digest is checked here:
        # an unhashable channel must not be named by the manifest and then rejected on the next load.
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
            # a nonzero exit is never clean or merely-degraded; only a more specific hard status
            # (TIMED_OUT / BLOCKED / SKIPPED) survives, so a crash is not understated as PARTIAL
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
                # the manifest or a channel digest could not be published, so this completion is not
                # durable and the target will be redone; ledger.save() cannot see that on its own
                unpublished.append(u)
        # validated rows are ingested even from a non-completable attempt: a crashed target's exported
        # params are real evidence, and partial corruption must not discard trustworthy siblings
        nfound += _arjun_ingest(ctx, res["rows"], out_f if out_f.exists() else None)

    def _paths(u: str) -> tuple:
        uid = hashlib.sha256(u.encode()).hexdigest()
        return (attempt_dir / f"{uid}.txt", attempt_dir / f"{uid}.out", attempt_dir / f"{uid}.err")

    queue = list(pending)
    active: dict = {}                        # future -> (url, host, slot)
    busy_hosts: set = set()
    free = list(range(procs))
    runner_reset_cancel()                    # a previous lane's latch must not cancel this one
    # KeyboardInterrupt reaches only the main thread, so a tool inside a worker keeps running: on Ctrl-C
    # stop submitting, tear the groups down via the runner's registry, then re-raise
    interrupted = False
    # not a `with` block: ThreadPoolExecutor.__exit__ is shutdown(wait=True), which would re-block on any
    # worker that did not unwind after a cancellation. Shutdown is explicit on each path instead.
    pool = ThreadPoolExecutor(max_workers=procs)
    try:
        while True:
            # fill free slots with the first queued target whose host is not already active, so a host
            # with many endpoints never gets several concurrent processes pointed at it
            while free and not aj_budget.exhausted():
                pick = next((i for i, u in enumerate(queue)
                             if normalize.host_of_url(u) not in busy_hosts), None)
                if pick is None:
                    break                    # every remaining target belongs to a currently-active host
                u = queue.pop(pick)
                # lowest free slot first: shares are largest-first, so a partly-filled pool runs at the
                # biggest rate available instead of stranding it on an unused slot
                host, slot = normalize.host_of_url(u), free.pop(0)
                busy_hosts.add(host)
                attempted += 1
                active[pool.submit(_arjun_exec, u, shares[slot], threads, _paths(u),
                                   ctx.http_timeout)] = (u, host, slot)
            if not active:
                break                        # nothing running and nothing submittable -> done
            # the budget stops launching new work; targets already in flight always finish
            done, _ = wait(list(active), return_when=FIRST_COMPLETED)
            for fut in done:
                u, host, slot = active.pop(fut)
                busy_hosts.discard(host)
                insort(free, slot)               # keep slots ordered so the largest share is reused first
                try:
                    _finish(fut.result())
                except Exception as exc:     # a worker crash is our failure, not a target verdict
                    counts["unknown"] += 1
                    events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN,
                                            measure="target",
                                            unit=f"target:{hashlib.sha256(u.encode()).hexdigest()[:16]}",
                                            eligible=1, tested=0, omitted=1,
                                            reason=f"{u}: worker failed — {type(exc).__name__}: {exc}")
    except KeyboardInterrupt:
        interrupted = True
        # 1) harvest first: a target that finished just before the interrupt keeps its completion. Only
        #    futures already done at this instant qualify; anything later is reported as cancelled.
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
        # 2) tear down what is still running (one shared grace deadline across every group)
        killed = runner_cancel_all()
        for fut in list(active):
            fut.cancel()                     # only drops not-yet-started work; the kill handles the rest
        wait(list(active), timeout=30)       # bounded: the groups are already dead
        # 3) harvest again: a target that finished naturally between (1) and process termination still
        #    has a real verdict. Safe for killed runs — completion demands three signals a kill can't fake.
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
        # 4) only what is still unresolved (or cancelled before it ran) is unmeasured: an honest gap,
        #    absent from the ledger so a resume retries it
        for _fut, (u, _h, _s) in list(active.items()):
            counts["unknown"] += 1
            events.coverage_partial("params.arjun", kind=events.COVERAGE_UNKNOWN, measure="target",
                                    unit=f"target:{hashlib.sha256(u.encode()).hexdigest()[:16]}",
                                    eligible=1, tested=0, omitted=1,
                                    reason=f"{u}: cancelled by operator before a verdict was reached")
        ctx.echo(f"    params.arjun: cancelled — terminated {killed} running arjun process(es), "
                 f"{len(active)} target(s) left unmeasured")
    finally:
        # never wait on workers here: on the interrupt path their processes are already dead, and on
        # every other path the loop only exits once `active` is empty
        pool.shutdown(wait=False, cancel_futures=True)
    # durability is the conjunction: the state file was written and every trusted completion published
    # its evidence. Either failure means a resume redoes work, so both must reach the verdict.
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
    # selection: of every eligible endpoint, how many did we get to at all?
    budget.report_selection("params.arjun", measure="api_endpoints", eligible=len(api_all),
                            attempted=attempted, budget=aj_budget, noun="endpoint", durable=persisted)
    # outcome: of those attempted, how many reached a trusted terminal state?
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
        # coverage and completion state for the finished work are recorded before the cancellation
        # propagates, so a Ctrl-C costs the operator nothing already earned
        raise KeyboardInterrupt


def _apply_nuclei_oob(cmd: list[str]) -> list[str]:
    """Append self-hosted interactsh flags to a nuclei command (else nuclei's built-in public server).
    Shared by every nuclei invocation so they all use the same OOB endpoint. `secrets.oob()` is the
    single source of truth for OOB config."""
    oob = secrets.oob()
    if oob.get("callback_server"):
        cmd += ["-iserver", str(oob["callback_server"])]
        if oob.get("auth_token"):
            cmd += ["-itoken", str(oob["auth_token"])]
    return cmd


def _chunk_terminal(sid, chunk_wu, res, cf, *, status) -> None:
    """Emit a chunk's terminal event from a finally so a chunk never stays 'started'. `status` is the
    chunk outcome, which the caller promotes only after all per-chunk bookkeeping succeeded; it stays
    FAILED when execution or any post-execution step raised."""
    reason = None
    if status == Status.FAILED.value:
        reason = (res.note if (res and res.note) else "chunk raised before completing bookkeeping")
    elif res:
        reason = res.note or None
    events.tool_finish(sid, work_unit=chunk_wu, status=status, reason=reason,
                       duration=round(res.duration, 2) if res else None,
                       raw_ref=str(cf) if cf.exists() else None)


def _nuclei_templates_fp() -> str | None:
    """A coverage-affecting fingerprint of the installed nuclei template set, so a templates update
    invalidates the resume work_unit. Reads nuclei's config dir (honoring NUCLEI_CONFIG / XDG / ~/.config)
    and folds version and the ignore-hash (a changed .nuclei-ignore alters which templates run at the same
    version). Returns a stable JSON string, or None when the state cannot be read (caller makes the unit
    non-resumable — an unknown template set must not be treated as unchanged)."""
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


_NUCLEI_MHE_DEFAULT = 0        # full depth (-nmhe); nuclei's own default of 30 drops a host after 30
_NUCLEI_MHE_MAX = 100_000      # request errors
_ANSI_RX = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _nuclei_mhe() -> int:
    """`PERFORMANCE.NUCLEI_MAX_HOST_ERROR`: errors tolerated per host before nuclei skips it (`-mhe`).
    0 is the default and means full depth (`-nmhe`) — no host is dropped for erroring. A nonzero value
    is a bounded coverage policy the operator opted into.

    This is a coverage policy, not a runtime knob: it is folded into the resume fingerprint so a change
    re-scans rather than resuming a shallower generation. Strict parse via settings.strict_int (an exact
    int in 0.._NUCLEI_MHE_MAX, never a bool); anything else falls back to the default."""
    return settings.strict_int("NUCLEI_MAX_HOST_ERROR",
                               default=_NUCLEI_MHE_DEFAULT, maximum=_NUCLEI_MHE_MAX)


def _nuclei_progress(text: str) -> dict:
    """Read nuclei's own stderr for what only nuclei can tell us.

      1. `planned` / `requests` / `errors` — the planned request budget actually covered, from the last
         `-stats` line. This is the only coverage oracle; absent, coverage is unknown. A finished scan can
         still leave requests unsent (host skipped after `-mhe` errors) — a coverage gap, not an execution one.
      2. `completed` — whether nuclei's terminal line `Scan completed in <dur>.` was recognized. This is
         corroborating telemetry only; it must never gate resumability (execution completion is exit_code == 0).

    stderr is ANSI-coloured, so strip escapes before matching. Counters are returned raw (not clamped): an
    impossible triple must reach events.coverage_partial's validator and surface as coverage unknown."""
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
        try:                                       # nuclei emits these as strings; last valid line wins
            planned, requests = int(d["total"]), int(d["requests"])
            errors = int(d["errors"]) if str(d.get("errors", "")).lstrip("-").isdigit() else None
        except (TypeError, ValueError):
            continue
    return {"completed": completed, "planned": planned, "requests": requests, "errors": errors}


def _nuclei_cmd(targets_file, out_file, prof, mhe: int) -> list[str]:
    """The nuclei main-scan command for one target file; identical flags for every chunk, only -l/-o
    differ (non-intrusive, severity-scoped, governor-scaled -c/-bs, explicit host-error policy, shared
    OOB endpoint)."""
    cmd = ["nuclei", "-l", str(targets_file), "-jsonl", "-o", str(out_file),
           "-etags", "intrusive,fuzz,dos,brute-force",
           "-s", "critical,high,medium", "-stats", "-si", "30",
           "-c", str(settings.workers("nuclei", 25)),      # core-scaled concurrency (rate stays separate)
           "-bs", str(settings.concurrency("NUCLEI_BULK_SIZE", 25))]   # hosts/template batch
    cmd += ["-nmhe"] if mhe == 0 else ["-mhe", str(mhe)]   # 0 = full depth: never drop an erroring host
    if prof.http_rl:
        cmd += ["-rl", str(prof.http_rl)]
    _apply_nuclei_oob(cmd)                                 # self-hosted interactsh (else public default)
    return cmd


def _nuclei_scan(ctx, live, findings, log, prof) -> RunResult:
    """Chunked nuclei main scan: split live hosts into NUCLEI_CHUNK_HOSTS batches and scan sequentially (rate
    is target-wide, so parallel batches would blow the budget). Chunking buys resume, progress and per-batch
    isolation, not speed.

    Resume is keyed on execution completion, not a clean status: a chunk is done when the process exited 0.
    Degraded coverage rides structured request counters and does not make the chunk retryable; unmeasurable
    coverage is coverage:unknown. The aggregate is rebuilt idempotently from every per-chunk artifact, so a
    degraded chunk's findings are never discarded and a re-scan cannot duplicate.
    """
    sid = "params.nuclei_scan"
    chunk_n = max(1, settings.concurrency("NUCLEI_CHUNK_HOSTS", 50))
    batches = [live[i:i + chunk_n] for i in range(0, len(live), chunk_n)]
    state_f = ctx.run.raw_path("params", "nuclei", "chunks.state.json")
    # resume validity is a work_unit that folds the coverage-affecting config (severity + excluded tags +
    # chunk size), not just the host list, so any coverage-affecting change invalidates the state
    _tpl = _nuclei_templates_fp()                           # template set is coverage-affecting
    mhe = _nuclei_mhe()                                     # host-error policy = which hosts get scanned
    _cfg = {"severity": "critical,high,medium", "etags": "intrusive,fuzz,dos,brute-force", "chunk": chunk_n,
            "templates": _tpl if _tpl is not None else "unknown", "mhe": mhe}
    if _tpl is None:
        # template state unknown -> non-resumable: a per-run nonce makes resume never skip a chunk we
        # cannot prove ran against the same templates
        _cfg["_nonce"] = os.urandom(8).hex()
    scan_wu = events.work_unit(sid, inputs={"hosts": live}, config=_cfg)
    # a work_unit is not an attempt (wu_<scan_wu>/attempt_<attempt_id>/); a same-work-unit retry writes a
    # fresh attempt dir and reads done chunks back from recorded paths.
    wu_dir = state_f.parent / f"wu_{scan_wu}"
    wu_root = wu_dir.resolve()
    attempt_id = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()   # unique per execution attempt
    attempt_dir = wu_dir / f"attempt_{attempt_id}"        # created lazily, only if a chunk actually runs

    def _valid_entry(ci_str, rel, digests=None) -> bool:
        """A loaded state entry is trusted to skip/aggregate a chunk only if it is fully valid: a
        non-negative in-range index; a relative path with no absolute/`..` escape resolving inside this
        work_unit's dir, whose filename is exactly this chunk's `findings_<ci>.jsonl`, pointing at a
        readable file; and whose recorded sha256 still matches its content. Anything else — including a
        missing digest (older state) — is dropped so the chunk re-runs, never a silent skip."""
        if not (isinstance(ci_str, str) and ci_str.isdigit() and 0 <= int(ci_str) < len(batches)):
            return False
        if not isinstance(rel, str) or not rel or os.path.isabs(rel) or ".." in Path(rel).parts:
            return False
        if Path(rel).name != f"findings_{int(ci_str)}.jsonl":   # must be this chunk's artifact
            return False
        p = state_f.parent / rel
        try:
            if not p.resolve().is_relative_to(wu_root):      # containment: this work-unit's dir only
                return False
            if not p.is_file():                              # missing artifact -> not done (re-run)
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
        if not isinstance(prev, dict):                       # [], null, or a scalar -> reject (rerun all)
            return None
        return prev if prev.get("work_unit") == scan_wu else None   # config-inclusive key: mismatch → fresh

    def _load_digests(prev) -> dict:                          # {rel: sha256} — content binding per artifact
        m = (prev or {}).get("digests")
        if not isinstance(m, dict):
            return {}
        return {str(k): str(v) for k, v in m.items() if isinstance(k, str) and isinstance(v, str) and v}

    def _load_map(prev, digests) -> dict:                     # {ci: rel} — validated + digest-bound
        m = (prev or {}).get("chunks")
        if not isinstance(m, dict):
            return {}
        return {str(k): str(v) for k, v in m.items() if _valid_entry(str(k), v, digests)}

    def _load_evidence(prev, digests) -> dict:               # {ci: [rel, ...]} — a list, each validated
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
        """{ci: {"planned": int, "requests": int}} — the request coverage a done chunk reported, persisted
        so a resume can re-emit it (else skipped chunks read as zero-eligible and understate the gap).
        Validated: an in-range index and two non-negative ints (an impossible pair is dropped)."""
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
        # a coverage record is only meaningful for a completed chunk: an entry for a chunk about to re-run is
        # stale, and keeping it would let the last attempt's numbers stand in for this one
        return {k: v for k, v in out.items() if k in done}

    # done_map: completed chunks -> artifact. evidence_map: every preserved artifact per chunk across
    # attempts (a list, so two partial attempts both survive). cov_map: per-chunk request coverage.
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
        """Per-chunk request coverage as structured counters, one stable unit per chunk so the store's
        latest-per-unit reconciliation sums them into a single (source, "requests") rollup for the run.

        COVERAGE_TIMEOUT, not CAP: the requests were lost in flight (target/network errors, or nuclei
        dropping a host once `-mhe` is exceeded), which is the TIMEOUT bucket's always-feeds-the-verdict
        contract. Counters go through raw so the validator can flag an impossible triple as unknown."""
        if planned is None or requests is None:
            # COVERAGE_UNKNOWN, not a reason-only event: a reason-only partial neither opens a generation
            # nor reaches the rollup, so an unmeasurable chunk must reach the verdict as a gap
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
    incomplete = 0                                        # chunks whose execution did not complete (retryable)

    def _completed_hosts():                               # hosts in execution-complete chunks (not attempted)
        return sum(len(batches[j]) for j in (int(k) for k in done_map) if j < len(batches))

    # the source terminal always fires (try/finally). status starts FAILED so an exception mid-loop cannot
    # emit a scan-level success, and is set to SUCCESS/PARTIAL only after the loop + aggregate complete.
    status = Status.FAILED
    try:
        for ci, batch in enumerate(batches):
            chunk_wu = events.work_unit(sid, inputs={"hosts": batch}, config=_cfg)
            # progress before the chunk, counting cleanly-completed hosts; the per-chunk work_unit is the
            # stable unit id (resume/audit key)
            events.tool_progress(sid, chunk_index=ci + 1, chunk_total=len(batches),
                                 current_index=_completed_hosts(), work_unit=chunk_wu)
            if str(ci) in done_map:                       # resume: execution already completed in a prior attempt
                _prior = cov_map.get(str(ci)) or {}        # (artifact recorded + preserved; do not re-run)
                _emit_coverage(ci, _prior.get("planned"), _prior.get("requests"),
                               why="resumed — coverage as first recorded")
                continue
            attempt_dir.mkdir(parents=True, exist_ok=True)   # lazy: only create the attempt dir if a chunk runs
            bf = ctx.write_list(f"nuclei_targets_{ci}.txt", batch)
            cf = attempt_dir / f"findings_{ci}.jsonl"        # this attempt's artifact (never overwrites a prior)
            ef = attempt_dir / f"stderr_{ci}.log"            # per-chunk full stderr: completion/coverage oracle
            rel = f"wu_{scan_wu}/attempt_{attempt_id}/findings_{ci}.jsonl"   # recorded in state, relative to state dir
            events.tool_start(sid, work_unit=chunk_wu, input_total=len(batch))   # this chunk's own lifecycle
            res = None
            chunk_status = Status.FAILED.value               # promoted only after all bookkeeping below
            try:                                             # chunk terminal always fires (finally)
                res = exec_tool("nuclei", _nuclei_cmd(bf, cf, prof, mhe),
                                timeout=nuclei_timeout(len(batch), ctx.http_timeout), stderr_path=ef)
                if res.stderr_tail:
                    with log.open("a", encoding="utf-8") as lf:
                        lf.write(res.stderr_tail + "\n")
                # ask nuclei whether it finished, from its terminal line in the full stderr (the 8-line tail
                # can be evicted by a trailing [INF] burst, so prefer the file and fall back only if absent)
                try:
                    _err = ef.read_text(encoding="utf-8", errors="replace") if ef.is_file() else res.stderr_tail
                except OSError:
                    _err = res.stderr_tail
                prog = _nuclei_progress(_err)
                # execution-complete is `exit_code == 0` only; coverage is the -stats counters (absent ->
                # unknown). `Scan completed in …` is corroborating telemetry and must not gate resumability.
                complete = res.exit_code == 0
                terminal_seen = bool(prog["completed"])      # telemetry: did we recognize nuclei's own terminal?
                planned, requests = prog["planned"], prog["requests"]
                # keep a chunk's findings regardless of outcome — real even if WAF/timeout-degraded
                if complete:
                    if not cf.exists():
                        cf.touch()                           # explicit zero-byte artifact for a clean-empty
                    done_map[str(ci)] = rel                  # execution complete -> controls skip
                    _add_evidence(str(ci), rel)              # ...and joins this chunk's evidence history
                    _bind(rel, cf)                           # content binding: a later edit invalidates the skip
                    if planned is not None and requests is not None:
                        cov_map[str(ci)] = {"planned": planned, "requests": requests}
                    _save()
                    _emit_coverage(ci, planned, requests,
                                   why=("exit 0" + ("" if terminal_seen else ", nuclei terminal not recognized")
                                        + (f", {prog['errors']} error(s)" if prog["errors"] is not None else "")))
                    # status now reflects EXECUTION, not a stderr signature: findings -> SUCCESS, none ->
                    # EMPTY.
                    chunk_status = (Status.SUCCESS if cf.stat().st_size > 0 else Status.EMPTY).value
                else:
                    incomplete += 1
                    _emit_coverage(ci, planned, requests,
                                   why=f"execution INCOMPLETE (exit {res.exit_code}, {res.status.value}) "
                                       f"— chunk stays retryable")
                    # a chunk that produced output appends to its evidence list; a degraded retry with no
                    # output appends nothing, so an earlier attempt's findings are never erased
                    if cf.exists() and cf.stat().st_size > 0:
                        _add_evidence(str(ci), rel)
                        _bind(rel, cf)
                        _save()
                    # never launder an incomplete execution into a clean status
                    chunk_status = (res.status if res.status not in (Status.SUCCESS, Status.EMPTY)
                                    else Status.PARTIAL).value
            finally:
                _chunk_terminal(sid, chunk_wu, res, cf, status=chunk_status)   # FAILED if exec or bookkeeping raised
        # rebuild the aggregate into a temp file, then swap atomically, so a crash mid-rebuild leaves the old
        # findings.jsonl intact; read every preserved evidence artifact per chunk and deduplicate lines
        tmp = findings.with_name(findings.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for ci in range(len(batches)):
                rels = list(evidence_map.get(str(ci)) or [])
                paths = [state_f.parent / r for r in rels] or [attempt_dir / f"findings_{ci}.jsonl"]
                seen_lines: set[str] = set()                  # dedup per chunk (across its attempts) — never across
                for p in paths:                               # chunks, whose identical-looking lines are distinct hosts
                    if not (p.exists() and p.stat().st_size > 0):
                        continue
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        if line and line not in seen_lines:
                            seen_lines.add(line)
                            fh.write(line + "\n")
        os.replace(tmp, findings)
                # scan status tracks execution only; degraded request coverage rides the structured counters
                # and reaches the operator through the run verdict
        status = Status.PARTIAL if incomplete else Status.SUCCESS
    finally:
        events.tool_progress(sid, chunk_index=len(batches), chunk_total=len(batches),
                             current_index=_completed_hosts(), work_unit=scan_wu)   # final: execution-complete
        try:                                                 # a stat() raise must not defeat the scan terminal
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
        # say which chunks the percentage covers — nuclei may not report counters for every chunk, and an
        # unqualified percentage over a subset would read as a whole-scan figure
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
    """In-scope Spring Boot actuator base URLs to interrogate, from two candidate sources:
    (a) any observed URL containing `/actuator`, collapsed to its base; and
    (b) live hosts fingerprinted as Spring/Spring-Boot — `/actuator` is almost never linked, so the
        tech fingerprint is the candidate signal. Candidate-driven, never blind onto every host."""
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
    Mirrors _actuator_bases — the tech fingerprint is the candidate signal."""
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
    names. Every target is a GET, and this is the same key `_canonicalize_candidates` uses, so the two
    agree."""
    from urllib.parse import urlsplit, parse_qsl
    sp = urlsplit(u)
    names = tuple(sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)}))
    return (sp.scheme.lower(), sp.netloc.lower(), sp.path, names)


def _dalfox_identity_fn(mode: str):
    """The identity dalfox deduplicates on, per mode -> (keyfn, multiplicity_matters). `off` scans every
    input line, so multiplicity is the identity there."""
    if mode in ("exact", "off"):
        return (lambda u: u), (mode == "off")                  # exact: the URL; off: URL x multiplicity
    # `signature` and an unknown mode use the least demanding identity, so "never mentioned" means never
    # mentioned under any policy; what it cannot settle is handled separately as undecidable membership
    return _dalfox_signature, False


def _dedupe_owed(named, mode) -> list:
    """Collapse the targets dalfox named as failed, under the identity that mode scans by:

      off       every occurrence is its own scan   -> collapse nothing
      signature method+host+path+param names       -> one retry per signature
      exact     the URL                            -> one retry per URL
      unknown   no identity we can trust           -> collapse nothing (re-scanning is safe; dropping
                                                      an owed scan is not)"""
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
    """Reconcile dalfox's `target_summary` against the submitted batch by membership, under the mode
    dalfox says it used. Returns `(owed_urls, info)` where `info` carries:

        retryable   membership failures a retry could cover — the chunk stays owed
        terminal    membership we cannot decide — retrying changes nothing, and it is a coverage gap
        mode        the mode the reconciliation was performed under
        ambiguous   targets covered under `signature` but short under `exact`/`off`

    `expected` is the multiset of identities in the batch under the reported mode, so the dedup count is
    derived rather than believed. An unknown mode has no identity to reconcile under: anything missing
    even by signature is genuinely owed, while anything present by signature but not as the exact URL is
    undecidable (recorded coverage-unknown and left terminal, since a retry would repeat the ambiguity)."""
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
        # `off` scans every input line: two identical lines owe two reports, and one report leaves one
        # occurrence unaccounted
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
        # present by signature, but not as the exact URL dalfox would have scanned under `exact`/`off`;
        # whether those were covered is not knowable from this artifact
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
                  # the ambiguous targets, not the sentence about them: a doubt is cleared per identity
                  # by an attempt that actually scanned it
                  "ambiguous": ambiguous}


def _canonicalize_candidates(urls: list[str]) -> tuple[list[str], dict]:
    """Collapse XSS/redirect candidate URLs to unique (scheme, host, path, sorted param-names) shapes,
    keeping one representative URL per shape. dalfox's reflected-XSS selection depends on the param shape,
    not the values, so scanning one URL per shape covers the same surface at a fraction of the cost.
    Returns (representatives, stats) where stats =
    {raw_candidates, canonical_candidates, reduction_percent, top_collapsed}."""
    from urllib.parse import urlsplit, parse_qsl
    shapes: dict = {}
    for u in urls:
        s = urlsplit(u)
        # origin-aware key: scheme is part of the identity (http and https can be different services), and
        # keep_blank_values keeps a blank redirect/XSS param (?next= / ?url=) that parse_qs() would drop
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
    """Remove credential-transport files a killed Quarry could not clean up; returns how many. Matched by
    prefix and suffix inside the private 0700 directory, and only ones too old for a live scan to be using.
    """
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
                    # unlink a symlink as the link it is: `is_file()` alone follows it and answers False
                    # for a dangling one
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
    """The armed OOB channel's credential could not be transported. The scan does not run unauthenticated
    (that would be a different configuration that finishes cleanly with no callbacks and looks valid)."""


def _make_oob_credential(secret: str):
    """Create the 0600 credential file and return (dir, path), or raise `OobCredentialError`.

    Acquisition only, deliberately not a context manager: the body's exceptions are not this function's
    business, and folding both into one `try` would let contextlib mask the real failure."""
    import tempfile
    d = path = None
    try:
        # 0700 and ours alone: `mkdtemp` refuses to reuse, so no other user can pre-create it
        d = Path(tempfile.mkdtemp(prefix=_OOB_CRED_PREFIX))
        path = d / ("cfg" + _OOB_CRED_SUFFIX)
        # O_EXCL|O_NOFOLLOW: an existing path — or a symlink planted at it — is refused, never followed
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as fh:
            # dalfox reads TOML or JSON, so a serializer escapes the value rather than interpolation
            json.dump({"scan": {"blind_oob_secret": secret}}, fh)
        return d, path
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        # `path` is passed so a refused symlink is unlinked too, else it and its directory survive forever
        _drop_oob_credential(d, path)
        raise OobCredentialError(f"the OOB credential could not be written: {e}") from e


def _drop_oob_credential(d, path) -> None:
    """Destroy exactly what one invocation created. Never raises."""
    try:
                                # `unlink` on a symlink removes the link, not its target, so a refused path is
                                # still cleaned up
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
    """Yield a path to dalfox's `--config` carrying only the OOB secret, then destroy it. It lives outside the
    run tree (so it never reaches publication), and the `finally` covers every exit. None when there is no
    secret; OobCredentialError when it cannot be written.
    """
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

    Off unless `MODES.BLIND_XSS` arms it; a self-hosted `oob.callback_server` is used when present, else
    the public interactsh pool. Correlation is dalfox's either way; `backend` says who owns the server, so
    `armed` is not "we own the channel". See docs/design/DALFOX-XSS-DESIGN.md.
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
    # no self-hosted server: dalfox's own default, the public interactsh pool — the same channel nuclei's
    # OAST and Quarry's SSRF probes already use
    return {"armed": True, "channel": "native", "backend": "public", "server": "", "secret": "",
            "reason": "blind XSS armed on ProjectDiscovery's PUBLIC interactsh pool (set "
                      "`oob.callback_server` to use your own) — its operator sees the raw callbacks; "
                      "correlation is owned by DALFOX and imported"}


def _dalfox_cmd(batch_file, out_file, prof, batch_len: int = 0, cred_path=None) -> list[str]:
    """dalfox v3 (Rust) reflected-XSS scan: static AST DOM analysis, no headless browser, `--skip-mining`
    (params are pre-discovered), JSONL to -o, status from the exit code. Concurrency is `--workers` per
    target and `--max-concurrent-targets` across targets; `--rate-limit` caps aggregate rps when RoE is set."""
    # dalfox's own membership cap `--max-targets-per-host` drops targets past it; the lane passes a value
    # that cannot truncate the submitted chunk.
    per_host = max(1, int(batch_len or settings.concurrency("DALFOX_CHUNK", 40)))
    cmd = ["dalfox", "scan", "-i", "file", str(batch_file), "-o", str(out_file),
           "-f", "jsonl", "-S", "--skip-mining",
           # `--dedup-urls signature`, counted in `targets_deduplicated` so it cannot hide what it collapsed —
           # the same identity `_canonicalize_candidates` computes.
           "--dedup-urls", "signature",
           # the finding is the product: carry the exact request that produced it and the response that proved
           # it (fields `request`/`response`), so a candidate is auditable without re-running anything
           "--include-request", "--include-response",
           # `--scan-timeout` is deliberately not passed: a cut injection reports `clean, incomplete:false`,
           # coverage we cannot observe.
           "--max-targets-per-host", str(per_host),
           "--workers", str(max(1, settings.workers("dalfox", 30))),          # per-target
           "--max-concurrent-targets", str(max(1, settings.concurrency("DALFOX_TARGETS", 4)))]  # tunable
    # blind / stored XSS: `--blind-oob` mints a fresh callback per payload and correlates each interaction
    # back to target/param/location/method/payload, so a beacon names the injection that produced it
    plan = _blind_oob_plan(prof)
    if plan["armed"]:
        # ONE argv token when a server is given: the flag is `--blind-oob[=<domains>]`, so a separate
        # `=host` argument would be parsed as a TARGET, not as the backend.
        cmd += [f"--blind-oob={plan['server']}" if plan["server"] else "--blind-oob"]
        if plan["secret"] and cred_path is not None:
            # never `--blind-oob-secret <token>` (argv is world-readable): dalfox reads it from a `--config`
            # file, an ephemeral 0600 file the caller owns.
            cmd += ["--config", str(cred_path)]
    if prof.http_rl:
        # v3's global rate cap (req/s, shared across workers and targets); bound to the RoE rate.
        cmd += ["--rate-limit", str(prof.http_rl)]
    return cmd


# dalfox finding type -> (store klass, confidence tier, display name), kept distinct; `confirmed`
# stays False (Quarry owns impact validation).
_DALFOX_TIER = {
    "V": ("xss-verified", "verified", "XSS — Dalfox-verified (Quarry impact validation pending)"),
    "R": ("xss-candidate", "candidate", "reflected parameter — XSS candidate (manual validation required)"),
    "A": ("dom-xss-static", "dom-static", "DOM XSS (static AST, needs runtime confirmation)"),
}
_DALFOX_SRC_SINK = re.compile(r"\(Source:\s*(.*?),\s*Sink:\s*(.*?)\)")
_DALFOX_LINECOL = re.compile(r":(\d+):(\d+)\s*-\s")


def _dalfox_engine_id() -> str:
    """The verified identity of the dalfox binary that will actually run, folded into the resume work unit so a
    drifted or shadowed binary cannot reuse another engine's chunks. An unverified engine returns a per-run
    nonce, making that run non-resumable.
    """
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
    """A JSON field coerced to a stripped string only if it is a scalar string; a list/dict/number returns ''."""
    return v.strip() if isinstance(v, str) else ""


def _dalfox_identity(ftype: str, obj: dict) -> "str | None":
    """A canonical identity per finding so distinct routes never collapse. V/R key on
    scheme://host:port/path + location:param + method; A (AST-DOM) keys on source/sink + line:col. Returns
    None (never raises) when a needed field is missing/non-scalar or the PoC URL is unparseable.
    """
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
    h = f"[{host}]" if ":" in host else host                   # bracket IPv6 so [::1]:80 != [::1:80]
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
            # 3.2.0 splits confidence and detection-method into their own axes; carry both (impact is not
            # stored). `detection_method: "oob"` is a blind callback that arrived — proof the channel worked.
            "detection_method": _dstr(obj.get("detection_method")) or None,
            "confidence_reason": _dstr(obj.get("confidence_reason")) or None,
            "inject_type": _dstr(obj.get("inject_type")) or None,
            # `--include-request/--include-response`: the exact request and the response that proved the
            # finding, stored whole (the evidence, not a preview), only when dalfox emitted a string
            "request": obj.get("request") if isinstance(obj.get("request"), str) else None,
            "response": obj.get("response") if isinstance(obj.get("response"), str) else None,
                        # correlation for an OOB hit is dalfox's: it minted the nonce, registered, polled and
                        # mapped it back; Quarry imports that and did not issue the token
            **({"oob_owner": "dalfox"} if _dstr(obj.get("detection_method")) == "oob" else {})}


#: retriable per-target error codes (the environment failed, the chunk is not done).
#: See docs/design/DALFOX-XSS-DESIGN.md.
_DALFOX_RETRIABLE = frozenset({"CONNECTION_FAILED", "DNS_RESOLUTION_FAILED", "TLS_HANDSHAKE_FAILED",
                               "REQUEST_TIMEOUT", "SESSION_LOST"})
#: deterministic per-target error codes (same omission for ever; the chunk is done, the omission is
#: coverage). See docs/design/DALFOX-XSS-DESIGN.md.
_DALFOX_TERMINAL_KIND = {"TRUNCATED_PER_HOST_CAP": events.COVERAGE_CAP,
                         "CONTENT_TYPE_MISMATCH": events.COVERAGE_TOOL_OMISSION}
_DALFOX_DETERMINISTIC = frozenset(_DALFOX_TERMINAL_KIND)


@dataclass(frozen=True)
class DalfoxArtifact:
    """What one dalfox JSONL artifact says about itself, as separate facts: readable (parses to our
    contract), complete, skipped, retriable, deterministic. See docs/design/DALFOX-XSS-DESIGN.md.
    """

    readable: bool
    incomplete_flag: bool = False
    skipped: tuple = ()          # ((target, status, error_code), ...)
    total_requests: "int | None" = None
    deduplicated: "int | None" = None
    #: what dalfox says it did about duplicates, read from the artifact, not assumed. `complete` is silent
    # about targets never listed, so membership is reconciled against the submitted batch by the lane
    summary_targets: tuple = ()
    #: one of `_DALFOX_DEDUP_MODES`, or "unknown" when the artifact does not establish it.
    dedup_mode: str = "unknown"
    version: str = ""

    @property
    def complete(self) -> bool:
        """dalfox covered every target it was given, and said so in a readable form: an unreadable meta row is
        not a claim of coverage.
        """
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


#: what dalfox can legitimately say it did about duplicates; anything else is `unknown` — the findings
#: are still evidence, but which target set produced them is not established
_DALFOX_DEDUP_MODES = frozenset({"signature", "exact", "off"})


def _dedup_mode(v) -> str:
    return v if isinstance(v, str) and v in _DALFOX_DEDUP_MODES else "unknown"


def _dalfox_meta(m: dict) -> "tuple[int | None, DalfoxArtifact | None]":
    """Read the meta row -> (findings_count, partially-built artifact). `None` count = unusable."""
    def _nonneg(v):
        # these numbers are operator-facing measurement ("37 requests, 4 targets collapsed"), so a count that
        # cannot be true is not a count: `None` says exactly that rather than showing a negative
        return v if type(v) is int and v >= 0 else None

    c = m.get("findings_count")
    count = _nonneg(c)                                        # STRICT int (not bool), non-negative
    # these fields drive the verdict (`incomplete`, `target_summary`), so both are validated strictly and
    # fail closed: a bad or absent field makes the chunk PARTIAL.
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
    """Fail-closed, streaming parse of a dalfox v3 JSONL artifact -> (valid_finding_count, DalfoxArtifact).

    Every valid finding is handed to `sink` as it is read and never retained (a finding can carry a whole
    response). `artifact_ok` is False on any inconsistency, and the caller marks a not-ok chunk
    PARTIAL/retryable. See docs/design/DALFOX-XSS-DESIGN.md.
    """
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
                    if row_idx != 0:                          # meta must be the first row
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
                        # the sink stores the finding; an OSError from that is a storage failure, not an
                        # unreadable artifact, so it is re-raised through the I/O boundary below
                        in_sink = True
                        sink(rec)
                        in_sink = False
                    del rec                                   # one finding held at a time, not all of them
                row_idx += 1
    except OSError:
        if in_sink:
            raise                                             # the caller's failure, reported as its own
        return 0, DalfoxArtifact(readable=False)
    if meta_rows != 1:                                        # exactly one meta summary row
        ok = False
    if meta_count is not None and meta_count != kept:
        ok = False                                            # count mismatch -> torn/partial artifact
    # `readable` is the STRUCTURAL verdict; the dispositions dalfox reported ride along untouched, so a
    # torn artifact never masquerades as a complete scan and vice versa.
    return kept, dataclasses.replace(art, readable=ok)


def _sha256_file(p) -> str:
    """sha256 of a file, streamed. Proves a recorded completion artifact is unchanged before a resume trusts
    it to skip its chunk.
    """
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def _dalfox_xss_fast(ctx, cands, prof) -> RunResult:
    """params.dalfox_xss_fast: reflected-XSS scan over the CANONICALIZED xss candidates with
    the fast flags, in resumable chunks. Mirrors _nuclei_scan: input-hashed chunk state, mark done ONLY
    on clean completion (failed batch stays retryable), source-level tool_start/tool_progress/tool_finish
    + ledger. dalfox v3 emits structured JSONL (parsed below): findings are tiered by dalfox's own verdict
    (V verified / R reflected / A AST-DOM) into confidence, but stay confirmed:false — the map-don't-exploit
    boundary holds (Quarry-owned impact validation is separate). Findings go straight to the store (deduped by id)."""
    sid = "params.dalfox_xss_fast"
    # a SIGKILLed run skips every `finally`, so a credential-transport file can outlive the process;
    # sweep before we make another.
    sweep_stale_oob_creds()
    _plan_for_run = _blind_oob_plan(prof)     # resolved ONCE: the command, the identity and the report
    # execution facts about the OOB channel, distinct from the policy above: how many invocations this
    # lifecycle tried to launch the armed channel, and how many actually did.
    _oob = {"attempted": 0, "launched": 0, "why": ""}
    chunk_n = max(1, settings.concurrency("DALFOX_CHUNK", 40))
    batches = [cands[i:i + chunk_n] for i in range(0, len(cands), chunk_n)]
    state_f = ctx.run.raw_path("params", "dalfox", "chunks.state.json")
    # resume validity folds every coverage-affecting knob (engine identity, workers, concurrency, rate,
    # blind-collector fingerprint, chunk size, `mode`).
    _cfg = {"mode": "v3-fast-reflected+evidence+sigdedup", "engine": _dalfox_engine_id(),
            "workers": settings.workers("dalfox", 30),
            "targets": settings.concurrency("DALFOX_TARGETS", 4),
            "rate_limit": prof.http_rl,
            # the OOB policy is part of the work's identity, so arming blind XSS or switching backend must not
            # reuse old chunks; the server is fingerprinted, never named, and never the token
            "oob_channel": _plan_for_run["channel"],
            "oob_backend": _plan_for_run["backend"],
            "oob_server": (secrets.fingerprint(_plan_for_run["server"])
                           if _plan_for_run["server"] else None),
            "oob_authenticated": bool(_plan_for_run["secret"]),
            "chunk": chunk_n}
    scan_wu = events.work_unit(sid, inputs={"cands": cands}, config=_cfg)
    # nuclei's proven resume contract: a completion map (controls skip) kept separate from an append-only
    # evidence map (controls aggregation), so a finding in a degraded attempt survives a later empty retry
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
        # a completion skips a chunk only if its artifact is valid, unchanged (sha256), still parses, and
        # agrees with the recorded outcome; otherwise the chunk re-runs
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
        n_f, art = scan_dalfox_jsonl(p)                      # re-scans as the docstring promises
                                                                                     # a completion is trusted only when the artifact is still sound and dalfox had nothing left
                                                                                     # to retry (see the docstring)
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
        # an evidence artifact is aggregated only if structurally valid and unchanged (sha256); valid rows
        # from an originally-degraded artifact are still retained, as long as its bytes have not changed
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
        """{ci: [reason, …]} — membership this lane could not decide (an unreadable dedup policy)."""
        m = (prev or {}).get("membership")
        out: dict[str, list] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                rows = [str(x) for x in v if isinstance(x, str) and x] if isinstance(v, list) else []
                if rows:
                    out[str(k)] = rows
        return out

    def _load_remainder(prev) -> dict:
        """{ci: [url, …]} — the targets a prior attempt still owes, and only those (dalfox names them in
        `target_summary`).
        """
        m = (prev or {}).get("remainder")
        out: dict[str, list] = {}
        if isinstance(m, dict):
            for k, v in m.items():
                urls = [str(u) for u in v if isinstance(u, str) and u] if isinstance(v, list) else []
                if urls:
                    out[str(k)] = urls
        return out

    def _load_terminal(prev) -> dict:
        """{ci: [{url, code}, …]} — omissions no retry can close, accumulated across attempts. A terminal gap is
        a fact about the target set, so it is persisted and re-reported every run.
        """
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

    # the decision, recorded before execution (knowable up front) and surviving a run that raises anywhere.
    # `omitted=0` keeps it inert in the verdict: telemetry about a choice, never a coverage claim.
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
        # resume only what is owed: a prior attempt's retriable targets re-run, intersected with this run's
        # batch. Counted, not set-membership, so two owed occurrences of one URL are both owed.
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
        chunk_status = Status.FAILED.value                   # promoted only after all bookkeeping below
        try:                                                 # chunk terminal always fires (finally)
            # the credential exists ONLY around the exec: created here, destroyed in the context
                        # the manager's `finally`, whether the run succeeds, times out, or raises
            if _plan_for_run["armed"]:
                _oob["attempted"] += 1
            try:
                with blind_oob_credential(_plan_for_run["secret"]) as _cred:
                    res = exec_tool("dalfox", _dalfox_cmd(bf, cf, prof, len(batch), _cred),
                                    ok_codes=(0, 1),
                                    timeout=scaled_timeout(len(batch), ctx.http_timeout, 30))
                    # proven by the runner, never inferred: a missing binary, a cancelled launch or a Popen
                    # that raised must not read as a process that ran with the armed channel
                    if _plan_for_run["armed"] and getattr(res, "started", False):
                        _oob["launched"] += 1
                    elif _plan_for_run["armed"]:
                        _oob["why"] = _oob["why"] or f"dalfox did not start ({res.note or res.status})"
            except OobCredentialError as e:
                # refuse, never fall back: running the armed channel unauthenticated is a different scan that
                # finishes cleanly with no callbacks — looking valid while proving nothing
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
            # dalfox v3 exit contract: 0 = clean/no-findings, 1 = clean/with-findings, >=2 = error. Exit code
            # and parsed artifact must agree, or the chunk is PARTIAL/retryable; findings are ingested below.
            n_findings, art = scan_dalfox_jsonl(cf)
            rc = res.exit_code
                        # execution completion decides resume, coverage is reported separately: membership is
                        # reconciled from the batch's own signatures.
            _owed_unlisted, _acct = _dalfox_accounting(batch, art)

            if _acct["retryable"]:
                events.coverage_partial(
                    sid, kind=events.COVERAGE_UNKNOWN, measure="dalfox_accounting",
                    unit=f"{sid}.chunk{ci}.accounting",
                    reason=(f"chunk {ci + 1}/{len(batches)}: dalfox's target accounting does not "
                            f"reconcile with the batch submitted — " + "; ".join(_acct["retryable"])
                            + "; the chunk stays RETRYABLE rather than done over it"))
                                                # undecidable, not unfinished: a retry under the same unknown policy repeats
                                                # the ambiguity, so the chunk is complete.
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
            # what the scan cost and what it collapsed, accumulated and reported on the lane's result, so the
            # residual duplicate rate over our own canonicalizer is a measured number, not an assumption
            if type(art.total_requests) is int:
                cost["requests"] += art.total_requests
            if type(art.deduplicated) is int:
                cost["deduplicated"] += art.deduplicated
            if art.dedup_mode != "signature":
                                # we asked for `signature` and the artifact says otherwise: not this chunk's failure,
                                # but the target set is not the one we asked for, and an operator deserves to know
                cost["dedup_disagreement"].add(art.dedup_mode)
                        # accumulate the gaps no retry can close, unioned by URL; emitted once per chunk after the
                        # loop, and outlives the attempt
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
                                                # what this attempt owes: targets dalfox named retriable, plus ones it never
                                                # mentioned.
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
                # a named remainder only when dalfox told us which targets: an unreadable artifact or an exit-
                # code disagreement says nothing about individual targets, so the whole chunk stays owed
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
            # derive the verdict from the retained evidence across all attempts, not the last label:
            # any degraded -> PARTIAL, else any finding -> SUCCESS, else EMPTY.

                        # dalfox's session lifecycle is not claimed from its stderr; a callback that arrives is a
                        # `V` finding, so findings prove the channel and their absence nothing
      _save()
      for _ci, _rows in sorted(membership.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
          if not _rows:
              continue
          # undecidable membership is a fact about the target set under a policy we could not read, so like a
          # deterministic omission it outlives the attempt and reaches a fresh verdict; the chunk is complete
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
          # one record per kind, each on its own unit: a truncating ceiling and an unscannable content-type
          # are different dispositions, and reconciliation keeps the latest per (source_id, unit)
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
        # fall back to THIS run's just-written attempt file (trusted — we wrote it) for a chunk run but not
        # recorded
        paths = [state_f.parent / e["rel"] for e in entries] or [attempt_dir / f"findings_{ci}.jsonl"]
        for p in paths:
            if not (p.exists() and p.stat().st_size > 0):
                continue
            # streamed into the store, one finding held at a time whatever the artifact weighs; the
            # alternative is a list of every finding with its full request and response
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
        # execution accounting for the OOB channel, from a `finally` so an exception still leaves what was
        # attempted on the record; its own failure is swallowed and the original propagates untouched
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
        # source terminal always fires (even if the loop raised) — one source lifecycle, no dup
        events.tool_finish(sid, status=status.value, work_unit=scan_wu,
                           reason=(f"{degraded}/{len(batches)} chunk(s) degraded" if degraded else None),
                           duration=round(time.monotonic() - t0, 2), discovery_context="params")
        # ledger: NEW entities by tier (verified/candidate/dom-static kept distinct) + matched
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
    """params.redirect_confirm: native open-redirect probe — NO dalfox, NO chromium. For
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
        # a Location header only redirects on a 3xx; urljoin resolves it against the origin, so a same-host
        # redirect stays on-host (not a finding). Only a 3xx whose Location host is our canary confirms.
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
                                # no-follow + header-only: if the target 302s to Location: <our-callback> we must not
                                # follow it, or Quarry fetches its own collector; the server-side SSRF still fires
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
        # netguard fresh-resolves these: records private/self leads, withholds only scan-box/metadata self-
        # hits, and keeps authoritative-NXDOMAIN dangling hosts (the takeover signal)
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
    # fresh self-attack guard right before the scan: `live` was resolved hours ago, so re-check current
    # resolution — a host now pointing at the scan box / metadata never reaches a nuclei chunk
    live = netguard.guard_urls(ctx, live, phase="params.nuclei_scan")
    if not live:
        ctx.run.record("params", skipped("nuclei", "no active-allowed live hosts"))
        return
    # ── nuclei (non-intrusive, OOB interactsh, severity-scoped) — chunked + resumable ──

    # the long-pole. Work is rate-bound, so templates are not gated and batches are not parallelized (that
    # would blow the RoE); hosts are chunked for resume, progress and per-batch isolation. See _nuclei_scan.
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

    # map-don't-exploit: an exposed .env/.git/config is fetched and its secret read; no payloads, no creds
    # used, no state change
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

    # ── arjun param discovery on param-less API endpoints — per-target, bounded, resumable ──

    # the full guarded endpoint set is processed host-fair under ARJUN_BUDGET_S (0 = unbounded default);
    # whatever a bounded run does not reach is a counted, resumable remainder. See _arjun_lane.
    _arjun_lane(ctx, prof, corpus)

    # ── vuln-primitive probes over the canonicalized shapes, split by primitive ──

    # XSS reflection -> params.dalfox_xss_fast; open-redirect -> params.redirect_confirm (native —
    # dalfox is no longer responsible for redirect). These select on scope and network policy both.
    xss_raw = active_review_values(ctx, "xss")
    redir_raw = active_review_values(ctx, "redirect")
    xss_cands, xss_canon = _canonicalize_candidates(xss_raw)
    redir_cands, redir_canon = _canonicalize_candidates(redir_raw)
    # dalfox contacts these URLs, so drop any whose host resolves internal or cannot be resolved
    # (redir_cands go through fetch.redirect_location, which resolve-guards each origin)
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
    # open-redirect — native single-request Location probe, no dalfox
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

    # gf only name-matches ssti params; confirm the primitive with a non-mutating math eval (reflection
    # and open-redirect are covered by dalfox)
    ssti_urls = _ssti_targets(ctx, scope)
    if ssti_urls:
        ns = evidence.probe_ssti(ctx, ssti_urls)
        if ns:
            ctx.echo(f"  ssti: +{ns} SSTI primitive candidate(s) confirmed (manual validation required)")

    # ── OOB probe (P2.3): Quarry-owned interactsh callback on SSRF-ish params (correlated evidence) ──
    oob_r = _oob_probe(ctx, scope, prof)
    if oob_r is not None:
        ctx.run.record("params", oob_r)
