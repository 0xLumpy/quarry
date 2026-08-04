"""Phase 5: Crawl + URL/archive + JS mining (deepened).

katana (batched, RAM-safe) + gau + waymore (-mode U) -> url corpus; download JS,
beautify, dedup; jsluice urls+secrets; xnLinkFinder over the JS dir AND over waymore
RESPONSE dirs (-mode R + xnLinkFinder -orig = the "killer combo"); source-map recovery;
gitleaks + trufflehog secret scans.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit as _urlsplit, urlunsplit as _urlunsplit

from .. import (budget, cgroup, events, fetch, normalize, policy, registry, remainder,
                secrets, settings)
from ..contract import registered, run_contract
from ..runner import Status, have, reclassify_from_artifact, run as exec_tool, skipped

# 9.2 deep-mine patterns over JS / recovered source — extraction only, no fetch.
# Each findall() yields the value to store (full match or capture group).
_WS_RX = re.compile(r"\bwss?://[A-Za-z0-9.\-_/:?=&%]+", re.I)                       # ws/wss endpoint URLs
_APIBASE_RX = re.compile(r"(?:baseURL|base_url|api[_-]?base|apiUrl|API_BASE|API_URL)"
                         r"\s*[:=]\s*[\"'`]([^\"'`]+)[\"'`]", re.I)                 # API base assignments
_GQL_RX = re.compile(r"[\"'`]([^\"'`]*?/(?:graphql|gql)\b[^\"'`]*)[\"'`]", re.I)    # GraphQL endpoint paths


def _gitleaks_report(rep):
    """FAIL-CLOSED parse of a gitleaks -f json report: returns list[dict] of findings for a VALID artifact,
    or None when there is NO trustworthy report (missing / unreadable / malformed / non-list root / non-dict
    row) — never .get()s a bad row, never raises (OSError/UnicodeError/JSON error all -> None)."""
    try:
        if rep.exists() and rep.stat().st_size:
            data = json.loads(rep.read_text() or "[]")
            if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                return data
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    return None


def _gitleaks_status(r, rep):
    """gitleaks file-output adapter (T1.3): validate the report, set r.status via the shared matrix
    (runner.reclassify_from_artifact — clean=SUCCESS/EMPTY only; degraded never laundered), return the
    validated findings or None."""
    if r.status == Status.SKIPPED:
        return None                                        # never ran -> no report to ingest
    items = _gitleaks_report(rep)
    reclassify_from_artifact(r, None if items is None else len(items), label="gitleaks")
    return items


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


def _js_download(ctx):
    """The crawl JS-download LANE: fetch every active-allowed JS URL, host-fair, under a throughput budget,
    resumably. Extracted from run() so the cap-lottery fix is testable on its own — driving the whole crawl
    phase to assert a fetch order would test everything except the thing that broke.

    Returns (ledger, raw_dir). The LEDGER is the interface: it maps each obtained URL to the immutable raw
    artifact holding that URL's body. Downstream lanes must ask it rather than re-deriving a filename.

    ARTIFACTS ARE IMMUTABLE and CONTENT-ADDRESSED (review#1/#3). Two consequences, both of them fixes:
      - the raw response is never rewritten, so beautification (which replaces its target) cannot invalidate
        the ledger's digests. It used to: every resume re-fetched everything because the digest recorded at
        fetch time no longer matched the beautified file. Beautifying happens on DERIVED copies.
      - a body served identically at two URLs maps to ONE file and BOTH URLs get an entry pointing at it.
        The old md5(url) naming plus a content-dedup `continue` left the duplicate with no artifact and no
        entry, so its relative `sourceMappingURL` was never resolved — two origins sharing a bundle yielded
        only one origin's sourcemap, and the duplicate was re-fetched on every resume."""
    # Downloading JS is an ACTIVE fetch: gate on active_allowed (scope + OOS + passive-skip) and go
    # through the shared choke point (rate pace + bounded read + off-scope-redirect guard).
    MAX_JS = 15 * 1024 * 1024      # 15 MB PER-ITEM guard (RAM/disk); bounds one file's cost, not which files
    # No JS_CAP. The old `_js_eligible[:2000]` is exactly the cap-lottery defect: a flat slice of a
    # store-ordered list let a couple of JS-heavy hosts eat the whole budget, and which hosts won depended on
    # discovery order — `influx1.eco.tsi-dev` went 433/439 -> 0/439 between two runs of the same target and
    # took its secrets with it. Now: FULL eligible set, host-fair order, a throughput budget that defaults to
    # UNBOUNDED, and a resumable per-URL ledger for whatever a bounded run did not reach.
    #
    # eligible = ACTIVE-ALLOWED JS only (count AFTER gating, not before): in passive mode active_allowed is
    # empty, so eligible collapses to 0 and we never report a phantom tested for URLs we won't fetch.
    eligible = [u for u in ctx.run.values("js_url")
                if ctx.scope.active_allowed(normalize.host_of_url(u))]
    raw_dir = ctx.run.dir / "raw" / "crawl" / "js_files"
    raw_dir.mkdir(parents=True, exist_ok=True)
    # state lives OUTSIDE js_files/: that dir is scanned by gitleaks/trufflehog and mined by xnLinkFinder,
    # so a ledger inside it would inject its own recorded URLs into the URL corpus and offer its sha256
    # digests to the secret scanners as high-entropy strings.
    ledger = budget.Ledger(raw_dir.parent / "js_fetch.state.json", lane="crawl.js_fetch")
    js_budget = budget.Budget(budget.budget_seconds("JS_FETCH_BUDGET_S"))
    # review#5: fairness is computed over PENDING work only. Ordering the whole eligible set interleaves a
    # host's hundreds of ALREADY-DONE URLs through the sequence, so its genuinely-new remainder lands late
    # and a bounded run can be consumed by other hosts before ever reaching it.
    resumed = [u for u in eligible if ledger.has(u)]
    pending = budget.order_fairly([u for u in eligible if not ledger.has(u)],
                                  lambda u: normalize.host_of_url(u))
    attempted, obtained = len(resumed), len(resumed)     # a validated completion counts as both
    fail: dict[str, int] = {}
    persisted = True
    try:
        for u in pending:
            if js_budget.exhausted():
                break                                   # checked BETWEEN items — never mid-write
            attempted += 1
            try:
                data, _final, status = fetch.scoped_get(ctx, u, max_body=MAX_JS)
                if data is None:
                    fail["not_contacted"] = fail.get("not_contacted", 0) + 1
                    continue                            # off-scope redirect / scan-box guard
                if status != 200:
                    fail[f"http_{status}"] = fail.get(f"http_{status}", 0) + 1
                    continue
                if not (100 <= len(data) <= MAX_JS):
                    fail["size_guard"] = fail.get("size_guard", 0) + 1
                    continue
                digest = hashlib.sha256(data).hexdigest()
                dest = raw_dir / (digest + ".js")        # CONTENT-addressed (FULL sha256, not a 64-bit prefix)
                if not budget.publish_bytes(dest, data, digest=digest):
                    fail["write_failed"] = fail.get("write_failed", 0) + 1
                    continue                             # never record an artifact we could not prove landed
                obtained += 1
                ledger.record(u, dest, digest=digest)    # ...and EVERY url gets an entry, duplicates included
            except Exception:
                fail["error"] = fail.get("error", 0) + 1
                continue
    finally:
        # review#2: a Ctrl-C / kill mid-lane must not discard completed network work. record() journals every
        # completion, so worst-case loss is bounded either way.
        persisted = ledger.save()
        if not persisted:                           # review#3 (r6): persistence CAN fail — say so
            _persistence_gap(ctx, "crawl.js_fetch", ledger, len(eligible))
        else:
            events.coverage_partial("crawl.js_fetch", kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                                    unit="state_persisted", eligible=1, tested=1, omitted=0,
                                    reason="completion state persisted")
    # SELECTION (did the budget stop us short?) and OUTCOME (did the target give us what we asked for?) are
    # separate facts with separate causes. The outcome number was invisible before: OTC attempted 2000 JS URLs
    # and obtained 628, then 1321 — a 69%/34% in-flight loss rate nobody could see.
    budget.report_selection("crawl.js_fetch", measure="js_urls", eligible=len(eligible),
                            attempted=attempted, budget=js_budget, noun="JS URL", durable=persisted)
    budget.report_outcome("crawl.js_fetch", measure="js_fetched", attempted=attempted,
                          obtained=obtained, classes=fail, noun="JS URL")
    left = len(eligible) - attempted
    ctx.echo(f"  JS files downloaded: {obtained}/{attempted} attempted obtained"
             + (f" ({len(resumed)} resumed)" if resumed else "")
             + (f", {left} left by budget — {'resumable' if persisted else 'NOT saved, will restart'}"
                if left else ""))
    return ledger, raw_dir


def _persistence_gap(ctx, lane: str, ledger, eligible: int) -> None:
    """Report that a lane's completion state could NOT be persisted.

    review#3 (r6): both lanes called `ledger.save()` and discarded the result. When the state file belongs to
    another lane the save is refused, so nothing is durable — yet the lane still reported its remainder as
    "resumable" and every future run redoes the whole lane. An un-persisted lane is a coverage gap: the work
    happened, but no future run can build on it."""
    ctx.echo(f"    {lane}: completion state NOT persisted"
             + (" (state file belongs to another lane)" if getattr(ledger, "foreign", False) else ""))
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit="state_persisted", eligible=1, tested=0, omitted=1,
                            reason=(f"completion state for {eligible} item(s) could not be persisted"
                                    + (" — the state path is owned by a different lane"
                                       if getattr(ledger, "foreign", False) else "")
                                    + "; a resume will redo this lane"))


def _stage_dir(active):
    """A FRESH, provably-empty staging directory beside `active`.

    review#5 (r5): staging was a PID-only path cleaned with `rmtree(..., ignore_errors=True)` and then reused —
    so a file surviving an earlier failed attempt could ride into the active tree. The name is unique per
    attempt and `mkdir()` is exclusive, so a leftover directory makes staging FAIL rather than be inherited."""
    for _ in range(8):
        cand = active.with_name(f"{active.name}.gen-{os.getpid()}-{os.urandom(4).hex()}")
        try:
            cand.mkdir(parents=True)
            return cand
        except FileExistsError:
            continue
        except OSError:
            return None                       # permission / disk / anything else: no stage, no publication
    return None


#: how many ROUNDS of chunk discovery one run performs. A chunk can name another chunk, so this bounds
#: the DEPTH of that traversal — throughput over work we already hold, which is what `--unbound` lifts
#: (0 = until no new chunk appears). It never decides WHICH chunks are eligible.
JXSCOUT_ROUNDS = 3
#: integers the analyzer may GUESS when a bundle's loader concatenates an identifier it cannot resolve.
#: 0 = never guess, and that is the default forever: every guess is a NEW REQUEST to the target for a path
#: the bundle never named (MEASURED on upstream's own corpus: 543 derived candidates vs 24 498 at 3000 —
#: 98% enumeration). So this is an ENGAGEMENT decision in `target.yaml`, never a flag: `--unbound` uses the
#: work a run already has and may not manufacture contact. Registered as EXCLUDED for exactly that reason.
JXSCOUT_BRUTE_LIMIT = 0
#: the engine, installed beside its whole pinned tree (GPL-3.0, invoked as a separate program).
JXSCOUT_SHIM = "jxscout-chunks"
#: the file the shim execs. Bound explicitly, because the shim is a two-line wrapper and the sandbox
#: mounts an ALLOW-LIST rather than the host root.
JXSCOUT_ENGINE = Path.home() / ".local" / "share" / "quarry" / "jxscout-chunk-discoverer.cjs"
#: `__webpack_require__.p = "…"` — the loader's public path. The analyzer evaluates only the chunk-name
#: function, so a candidate comes back WITHOUT this prefix; reading it here is what turns
#: `static/js/143.hash.chunk.js` into the URL that actually serves.
_WEBPACK_PUBLIC_PATH = re.compile(r"""\.p\s*=\s*["']([^"']{0,200})["']""")


#: the analyzer's ceilings, measured by the contract probe (`scripts/probe-jxscout-chunks.py`):
#: the largest legitimate bundle in upstream's own corpus needs ~931 MB, so the heap sits above that and
#: the address space above the heap — a cap under the legitimate corpus reports gaps on ordinary files.
_JXSCOUT_HEAP_MB = 2048
_JXSCOUT_ADDRESS_SPACE_MB = 4096
#: what the analyzer may WRITE. A memory cap does not bound what a program PRINTS, and the runner reads
#: stdout into THIS process — so the output is bounded at the source, in the child, by a file limit.
_JXSCOUT_OUTPUT_MB = 64
#: how much of the analyzer's stderr we READ back for a diagnostic. The file is bounded; our memory is
#: only bounded by reading a tail rather than the whole thing.
_JXSCOUT_STDERR_TAIL = 4096


#: everything the analyzer needs to EXECUTE, and nothing else. `--ro-bind / /` stopped writes and left
#: every readable file on the host available to code we are deliberately evaluating: Quarry's own
#: `secrets.yaml`, SSH material, prior engagements' evidence, the source tree. Read-only is not
#: unavailable, and the sandbox has to hold even if the interpreter itself is escaped.
_JXSCOUT_RUNTIME_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache",
                          "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives")


def _jxscout_sandbox(cmd: list, out_file, err_file) -> list:
    """Wrap the analyzer in every containment the probe proved necessary, or return nothing.

    It does not merely parse: it EVALUATES the bundle's chunk-name function through an interpreter
    (MEASURED: a plain counting loop inside that function runs until something stops it — 120 s+ with no
    memory growth, so a wall clock is the only thing that ends it). Isolation alone is not containment:

        filesystem       an ALLOW-LIST — the runtime, the pinned engine, the one input bundle, and THIS
                         invocation's private scratch. HOME, /etc secrets, /root, /var, the project tree
                         and every other bundle's evidence are simply not in the namespace. The writable
                         path is per-invocation on purpose: a shared output directory would let one
                         hostile bundle rewrite, truncate or delete another's artifacts
        environment      `--clearenv`: Quarry exports provider keys into its own env (PDCP_API_KEY), and
                         an inherited env is a credential handed to target code
        network          `--unshare-all`, no network namespace
        address space    `ulimit -v`, above the legitimate corpus
        JS heap          NODE_OPTIONS, so V8 fails gracefully before the hard limit
        OUTPUT           `ulimit -f` on FILES the child writes — the runner captures both streams into
                         Quarry's own memory, where no child limit applies
        wall clock       the runner's timeout

    Without bwrap the lane does not run at all; refusing is the safe direction."""
    if not shutil.which("bwrap"):
        return []
    engine = shutil.which(cmd[0])
    bundle = cmd[1] if len(cmd) > 1 else None
    if not engine or not bundle:
        return []
    scratch = str(Path(out_file).parent)
    args = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv", "--chdir", "/",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in _JXSCOUT_RUNTIME_PATHS:
        args += ["--ro-bind-try", path, path]
    args += ["--ro-bind", engine, engine,                     # the shim and, through it, the pinned tree
             "--ro-bind", str(JXSCOUT_ENGINE), str(JXSCOUT_ENGINE),
             "--ro-bind", str(bundle), str(bundle),           # THE one input
             "--bind", scratch, scratch,                      # THIS call's scratch, and nothing else
             "--setenv", "NODE_OPTIONS", f"--max-old-space-size={_JXSCOUT_HEAP_MB}",
             "--setenv", "PATH", "/usr/bin:/bin",
             # the shim resolves the engine through $HOME. The VARIABLE is set; the directory is not
             # mounted — only the one engine file inside it is, so this names a path and grants nothing.
             "--setenv", "HOME", str(Path.home())]
    inner = ("ulimit -v %d; ulimit -f %d; exec %s > %s 2> %s"
             % (_JXSCOUT_ADDRESS_SPACE_MB * 1024, _JXSCOUT_OUTPUT_MB * 2048,
                " ".join(shlex.quote(c) for c in [engine] + list(cmd[1:])),
                shlex.quote(str(out_file)), shlex.quote(str(err_file))))
    return args + ["sh", "-c", inner]


def _jxscout_public_path(text: str) -> str:
    """The loader's public path, or "". Never absolute-URL, never traversal: a bundle is untrusted input,
    and a `p` of `https://evil/` or `../../` would move the fetch off the origin we resolved against."""
    m = _WEBPACK_PUBLIC_PATH.search(text)
    p = (m.group(1) if m else "").strip()
    if not p or "://" in p or p.startswith("//") or ".." in p:
        return ""
    return p if p.startswith("/") else "/" + p


def _jxscout_resolve(js_url: str, candidate: str, public_path: str) -> str | None:
    """The candidate's URL, resolved against the bundle that named it.

    The analyzer returns what the loader COMPUTES (`static/js/143.hash.chunk.js`), not a URL: no scheme,
    no host, and no public path — that prefix lives in a different expression it never evaluates. So the
    origin comes from the bundle's own URL (PORT INCLUDED — upstream's own resolver drops it via
    `Hostname()`), the prefix from the bundle's text, and the query string is preserved because a chunk
    path may legitimately carry one (`app_Login.js?id=8dc7d97f`).
    """
    cand = (candidate or "").strip()
    if not cand or len(cand) > 2048 or any(c in cand for c in "\r\n\t \"'<>"):
        return None
    if cand.startswith(("http://", "https://")):
        return cand                                    # already absolute: scope decides, not us
    if cand.startswith("//"):
        return None                                    # protocol-relative: an origin we never resolved
    parts = _urlsplit(js_url)
    if not parts.scheme or not parts.netloc:
        return None
    if cand.startswith("/"):
        path = cand                                    # root-relative: the public path is already in it
    else:
        path = (public_path.rstrip("/") + "/" + cand) if public_path else \
            (parts.path.rsplit("/", 1)[0] + "/" + cand)
    path, _, query = path.partition("?")
    if ".." in path:
        return None                                    # never let a bundle walk us out of its own tree
    return _urlunsplit((parts.scheme, parts.netloc, "/" + path.lstrip("/"), query, ""))


def _jxscout_analyze(ctx, artifact, limit: int, timeout: int = 60) -> tuple:
    """`(candidates, disposition, result)` for ONE bundle — THROUGH the runner, so the invocation is
    recorded like every other tool (status, cpu/rss, stderr tail) instead of being a raw subprocess this
    phase hides.

    Dispositions are the point. A memory or output kill can be entirely SILENT (measured), so an empty
    result is only an answer when the process ended cleanly — and even then it is an ambiguous one: the
    parser is error-TOLERANT, so a bundle it could not understand exits 0 with nothing, exactly like a
    bundle that genuinely declares no chunks."""
    stem = Path(artifact).stem[:32]
    # a PRIVATE scratch per invocation. One shared output directory meant bundle N's evaluated code could
    # rewrite, truncate or delete bundle N-1's artifacts — inventing candidates attributed to another
    # bundle, inside the very evidence trail the sandbox exists to protect. Mutually untrusted executions
    # get mutually invisible directories, and the run dir is not in the namespace at all.
    with tempfile.TemporaryDirectory(prefix="quarry-jxscout-") as _scratch:
        out, err = Path(_scratch) / "out.txt", Path(_scratch) / "err.txt"
        cmd = _jxscout_sandbox([JXSCOUT_SHIM, str(artifact), str(max(0, limit))], out, err)
        if not cmd:
            return [], "no-sandbox", skipped(JXSCOUT_SHIM,
                                             "no bwrap: the analyzer EVALUATES target code, so it does "
                                             "not run uncontained")
        # THROUGH the registered source (`crawl.jxscout_chunks`), like every other tool in this phase:
        # the contract emits the source-level events and the ledger, and a direct runner call would
        # bypass both. The work unit is the ARTIFACT's content plus the guess limit — re-analysing the
        # same bytes under the same policy is the same work, and changing the limit is not.
        wu = events.work_unit("crawl.jxscout_chunks", inputs={"bundle": str(artifact)},
                              config={"brute_limit": max(0, limit)})
        res = run_contract("crawl.jxscout_chunks", cmd, work_unit=wu, timeout=timeout)
        lines: list = []
        ceiling = _JXSCOUT_OUTPUT_MB * 1024 * 1024
        at_ceiling = False
        try:
            # BOTH files: node swallows an EFBIG write and exits 0 (measured for stdout on the probe), so
            # a bundle that fills either stream would otherwise be classified success or empty. What
            # stdout did manage to write is kept as partial evidence — the ANSWER is what is incomplete.
            for f in (out, err):
                if f.exists() and f.stat().st_size >= ceiling:
                    at_ceiling = True
            raw_out = out.read_bytes() if out.exists() else b""
            lines = [l.strip() for l in raw_out.decode("utf-8", "replace").splitlines() if l.strip()]
        except OSError:
            return [], "unreadable", res
        blob = b""
        if err.exists():
            try:                                    # a TAIL only: the file is bounded, our memory is not
                with err.open("rb") as fh:
                    fh.seek(max(0, err.stat().st_size - _JXSCOUT_STDERR_TAIL))
                    blob = fh.read(_JXSCOUT_STDERR_TAIL)   # READ the tail; never the whole file
            except OSError:
                blob = b""
        # PUBLISH out of the private scratch into the run's evidence tree, atomically and content-bound.
        # The scratch dies with this call, so nothing the next bundle runs can reach what this one wrote.
        published = ctx.run.raw_path("crawl", "jxscout", f"{stem}.txt")
        kept = budget.publish_bytes(published, raw_out, digest=hashlib.sha256(raw_out).hexdigest())
        if blob:
            kept = budget.publish_bytes(ctx.run.raw_path("crawl", "jxscout", f"{stem}.stderr.txt"), blob,
                                        digest=hashlib.sha256(blob).hexdigest()) and kept
        res.raw_path = published if kept else None      # never NAME an artifact we could not prove landed
    if blob:
        # the note SAYS how much was read, so "we only ever read the tail" is a checkable claim rather
        # than a comment — the display slice would hide a full-file read otherwise.
        res.note = (res.note or "") + f" [stderr {len(blob)}B tail] " + secrets.redact(
            blob.decode("utf-8", "replace").strip()[-400:])
    if res.status is Status.TIMED_OUT:
        return [], "timeout", res
    if at_ceiling:
        # NOT success with fewer rows: the write was cut at the ceiling, so what else the bundle named is
        # UNKNOWN. Certifying the truncated set would report a coverage number nobody measured.
        return lines, "truncated", res
    if not kept:
        # AFTER the content verdicts on purpose: a timeout or a ceiling hit is what the bundle DOES, and
        # repeating it gives the same answer, so a failed evidence copy must not relabel a deterministic
        # verdict as retriable work. Below them it is the honest one — the ANSWER survived (these candidates are real, and suppressing them would lose discovery over a
        # disk fault), but its evidence did not. So it is never counted analysed: the bundle stays owed,
        # retriable, and a later child re-runs it into a tree that can hold the artifact.
        return lines, "unpublished", res
    if res.exit_code == 0:
        return lines, ("success" if lines else "empty"), res
    if res.exit_code == 1:
        return [], "engine-error", res
    return [], "killed", res                        # signal / OOM — a GAP, never "no chunks"


def _jxscout_coverage(stats: dict) -> None:
    """What this lane has READ, cumulatively. `tested` is what produced a clean answer — never "eligible
    minus the failures we happened to count" — and the dispositions accumulate across rounds, because
    folding keeps the latest record per (lane, unit, measure)."""
    events.coverage_partial("crawl.jxscout_chunks", kind=events.COVERAGE_TIMEOUT, measure="bundles",
                            unit="bundles", eligible=stats["eligible"], tested=stats["analysed"],
                            omitted=max(0, stats["eligible"] - stats["analysed"]),
                            reason="; ".join(f"{d}={n}" for d, n in sorted(stats["dispositions"].items()))
                                   or "no bundles analysed")


def _jxscout_chunks(ctx, ledger) -> int:
    """ONE round of lazy-chunk discovery over the JS already downloaded. Returns how many NEW `js_url`
    entities it added; the caller re-runs the fetch lane so the next round sees the new bundles.

    Quarry owns everything the upstream tool would have done for us: resolution (with the port and the
    query the tool's own resolver drops), scope, rate, fetching, evidence and resume. The analyzer is a
    CANDIDATE PRODUCER and nothing else."""
    stats = getattr(ctx, "_jxscout_stats", None)
    if stats is None:
        stats = ctx._jxscout_stats = {"dispositions": {}, "eligible": 0, "attempted": 0, "analysed": 0}
    seen_art = getattr(ctx, "_jxscout_seen", None)
    if seen_art is None:
        seen_art = ctx._jxscout_seen = set()
    dispositions = stats["dispositions"]

    # WORK FIRST, capability second. Asking `have()` before establishing eligibility made an absent
    # OPTIONAL tool a dependency failure on every run with no JS at all — a passive run would have owed
    # work it never had. An empty eligible set is a clean zero; a missing capability only matters when
    # there are bundles it would have read.
    eligible = [(u, art) for u, art in ledger.items() if art and art.suffix == ".js"]
    fresh = [(u, art) for u, art in eligible if str(art) not in seen_art]
    if not fresh:
        return 0
    stats["eligible"] += len(fresh)
    if not have(JXSCOUT_SHIM):
        # NOT the numeric zero of a clean convergence: these bundles went unread, and a supervisor
        # reading only "0 added" would call that a fixed point over a lane that never ran. The count is
        # in BUNDLES, the unit this remainder is measured in — one missing binary leaves N bundles owed.
        ctx.run.record("crawl", skipped(JXSCOUT_SHIM, "not installed (optional)"))
        dispositions["missing-tool"] = dispositions.get("missing-tool", 0) + len(fresh)
        seen_art.update(str(a) for _u, a in fresh)
        _jxscout_coverage(stats)
        return 0
    # the ENGAGEMENT knob, straight from target.yaml — not a flag, not machine config. It was read
    # through a `settings` helper that does not exist, so the fallback silently pinned it to 0 and
    # MODES.JS_CHUNK_BRUTE did nothing at all.
    limit = int(getattr(ctx.profile, "js_chunk_brute", JXSCOUT_BRUTE_LIMIT) or 0)
    added, produced = 0, 0
    for url, art in fresh:
        seen_art.add(str(art))
        try:
            text = art.read_text("utf-8", "replace")
        except OSError:
            dispositions["unreadable"] = dispositions.get("unreadable", 0) + 1
            continue
        stats["attempted"] += 1
        cands, disp, res = _jxscout_analyze(ctx, art, limit)
        dispositions[disp] = dispositions.get(disp, 0) + 1
        if disp in ("success", "empty"):
            stats["analysed"] += 1
        if res is not None:
            ctx.run.record("crawl", res)                 # every invocation is observable in the manifest
        if disp in ("no-sandbox", "unreadable"):
            # the same fault stops every remaining bundle, so it is THEIR disposition too. Counting only
            # the one we tried would report nine of ten bundles as covered when none was analysed.
            rest = len(fresh) - (fresh.index((url, art)) + 1)
            if rest:
                dispositions[disp] = dispositions.get(disp, 0) + rest
                seen_art.update(str(a) for _u, a in fresh[-rest:])
            break
        public = _jxscout_public_path(text)
        for cand in cands:
            produced += 1
            resolved = _jxscout_resolve(url, cand, public)
            if not resolved:
                continue
            host = normalize.host_of_url(resolved)
            if not host or not ctx.scope.in_scope(host):
                continue                                # OOS chunk references stay observed, never fetched
            # PROVENANCE is the bundle that named it: a chunk nothing links to is only explicable by the
            # loader it came from, and `raw_ref` points at that artifact.
            entity = {"url": resolved, "sources": ["jxscout-chunks"], "raw_ref": str(art),
                      "discovered_from": url}
            if ctx.run.add("js_url", entity):
                added += 1
                ctx.run.add("url", dict(entity))
                if host:
                    ctx.run.add("subdomain", {"host": host, "sources": ["jxscout-chunks"]})
    # coverage is per DISPOSITION, because "no candidates" is not one fact: a clean empty answer, a
    # silent kill and an unreadable bundle look identical in a count.
    _jxscout_coverage(stats)
    # the console shows the LIFECYCLE delta, the same number the manifest carries: a shared refusal
    # leaves untouched bundles unanalysed too, and `attempted - analysed` counted only the one we tried.
    _short = stats["eligible"] - stats["analysed"]
    ctx.echo(f"  jxscout chunks: {added} new JS URL(s) from {produced} candidate(s) "
             f"over {len(fresh)} bundle(s)" + (f" — {_short} not analysed" if _short else ""))
    return added


# ── AST analysis: COLLECT ONCE, INTERPRET LATER ─────────────────────────────────────────────────────
#: the OTHER half of the same pinned tree, and a different runtime: MEASURED, it runs under bun and fails
#: under node. The shim carries the napi variable; see tools.yaml.
AST_SHIM = "jxscout-ast"
AST_ENGINE = Path.home() / ".local" / "share" / "quarry" / "jxscout" / "internal" / "modules" / \
    "ast-analyzer" / "ast-analyzer.js"
AST_NATIVE = AST_ENGINE.parent / "parser.linux-x64-gnu.node"
#: MEASURED on 148 real bundles: 27-30 MB bundles take 93-102 s. A 60 s wall silently dropped 23,186
#: matches — from exactly the files jsluice gives up on, which is where this analyzer earns its place.
_AST_WALL_S = 300
#: MEASURED physical peak / bundle size: 165x, 166x, 175x, 176x, 201x, 211x, 225x. A first run at 250x
#: left only 11% margin over the worst case (a 12.8 MB bundle asked 3055 MB and used 2577), and an
#: under-request is not a smaller answer — the cgroup kills the analysis and the whole 100 s is wasted.
#: 300x keeps a third in hand. PROVISIONAL, from one corpus: the lane records what it asked for AND what
#: was used, so this number is revised from data rather than intuition.
_AST_MEM_PER_MB = 300
_AST_MEM_FLOOR_MB = 1024
#: the configured maximum for ONE invocation. A bundle needing more is a structured GAP, never a silent
#: skip: at 300x this is a ~40 MB bundle.
_AST_MEM_CEILING_MB = 12288
_AST_OUTPUT_MB = 64
_AST_ADDRESS_SPACE_MB = 65536              # a SECONDARY guard: address space is not the production cap


def _ast_engine_digest() -> str:
    """The EXECUTABLE's identity — analyzer bundle AND native parser.

    Both can change the answer, so both are in it, and it is computed when the lane runs rather than at
    import: a module-level constant would pin whatever was on disk when the process started and survive
    an install that replaced the engine underneath it.
    """
    h = hashlib.sha256()
    for f in (AST_ENGINE, AST_NATIVE):
        try:
            h.update(f.read_bytes())
        except OSError:
            h.update(b"absent:" + str(f).encode())
    return h.hexdigest()


def _ast_identity(bundle_digest: str, engine: str, mem_mb: int) -> dict:
    """Everything that can change what the analysis says. A policy input left out here is a policy change
    that silently resumes as already done."""
    return {"bundle": bundle_digest, "engine": engine, "wall_s": _AST_WALL_S,
            "mem_request_mb": mem_mb, "output_ceiling_mb": _AST_OUTPUT_MB,
            "address_space_mb": _AST_ADDRESS_SPACE_MB}


def _ast_mem_request_mb(size_bytes: int) -> int:
    """What this bundle is allowed to use, in physical memory."""
    return max(_AST_MEM_FLOOR_MB, int(_AST_MEM_PER_MB * (size_bytes / (1 << 20))))


def _ast_headroom_mb() -> int:
    """MemAvailable, for ADMISSION only. It does not guarantee the memory will still be free a moment
    later — another process can take it — so the cgroup remains the enforcement boundary and this only
    avoids launches that are obviously doomed."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _ast_command(bundle: Path, out: Path, err: Path, peak: Path, mem_mb: int, scratch: Path,
                 unit: str) -> list:
    """The full containment, or nothing: a per-invocation cgroup OUTSIDE, an allow-list bwrap INSIDE.

        cgroup      MemoryMax + MemorySwapMax=0 — the enforcement boundary. `RLIMIT_AS` is an
                    ADDRESS-SPACE measure (this analyzer needs 32 GB of it to use 5 GB of memory), so it
                    is kept high as a secondary guard and is not the cap.
        bwrap       an allow-list: the runtime, the engine, the native parser, the one bundle, and this
                    invocation's scratch. No network, no operator files, cleared environment.
        output      to FILES the child cannot overrun; the runner would otherwise capture
                    attacker-controlled bytes into Quarry's own memory.
        peak        the unit's own `memory.peak`, read by the shell INSIDE the cgroup but OUTSIDE bwrap,
                    where /sys/fs/cgroup is readable. systemd garbage-collects a successful transient
                    unit before its MemoryPeak can be queried, so the number is taken while it exists.
    """
    if not (shutil.which("bwrap") and cgroup.available()):
        return []
    exe = shutil.which(AST_SHIM)
    bun = shutil.which("bun")
    if not exe or not bun or not AST_ENGINE.is_file() or not AST_NATIVE.is_file():
        return []
    args = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv", "--chdir", "/",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in _JXSCOUT_RUNTIME_PATHS:
        args += ["--ro-bind-try", path, path]
    args += ["--ro-bind", str(Path(bun).resolve()), str(Path(bun).resolve()),
             "--ro-bind", str(AST_ENGINE), str(AST_ENGINE),
             "--ro-bind", str(AST_NATIVE), str(AST_NATIVE),
             "--ro-bind", str(bundle), str(bundle),
             "--bind", str(scratch), str(scratch),
             "--setenv", "NAPI_RS_NATIVE_LIBRARY_PATH", str(AST_NATIVE),
             "--setenv", "PATH", "/usr/bin:/bin",
             "--setenv", "HOME", str(scratch),
             "--setenv", "TMPDIR", str(scratch),
             str(Path(bun).resolve()), "run", str(AST_ENGINE), str(bundle)]
    inner = (f"ulimit -v {_AST_ADDRESS_SPACE_MB * 1024}; ulimit -f {_AST_OUTPUT_MB * 2048}; "
             + " ".join(shlex.quote(c) for c in args)
             + f" > {shlex.quote(str(out))} 2> {shlex.quote(str(err))}; rc=$?; "
             + "cg=$(awk -F: '/^0::/{print $3}' /proc/self/cgroup); "
             + f"cat /sys/fs/cgroup$cg/memory.peak > {shlex.quote(str(peak))} 2>/dev/null; exit $rc")
    return cgroup.wrap(unit, ["/bin/sh", "-c", inner], memory_max_mb=mem_mb)


def _ast_analyze(ctx, artifact: Path, digest: str, engine: str, ledger=None) -> tuple:
    """Analyse ONE bundle and publish its complete artifact. `(disposition, result, meta)`.

    The artifact is the product: everything the analyzer emitted, immutable and content-bound. Nothing is
    normalised here and nothing is named as a finding — that is a later step, deliberately, so the
    expensive part is paid once and interpreted many times.
    """
    size = artifact.stat().st_size
    want_mb = _ast_mem_request_mb(size)
    ident = _ast_identity(digest, engine, want_mb)
    key = hashlib.sha256(json.dumps(ident, sort_keys=True).encode()).hexdigest()
    meta = {"bundle_bytes": size, "mem_request_mb": want_mb, "mem_peak_mb": None,
            "wall_s": None, "engine": engine[:16], "work_key": key[:16]}
    # RESUME. `run_contract` emits the work unit as evidence; it does not skip anything, so the lane keeps
    # its own completion ledger. The item is the FULL identity, so a new engine or a changed policy is new
    # work rather than a silent reuse of an artifact produced under different rules.
    if ledger is not None and ledger.has(key):
        prior = ledger.artifact(key)
        if prior and prior.exists():
            meta["artifact"] = str(prior)
            return "resumed", None, meta
    if want_mb > _AST_MEM_CEILING_MB:
        # a GAP with a number attached, not a silent skip: at this ratio, the bundle needs more than the
        # configured maximum for one invocation.
        return "over-memory-policy", None, meta
    head = _ast_headroom_mb()
    if head and head < want_mb:
        return "insufficient-headroom", None, dict(meta, headroom_mb=head)
    unit = f"quarry-ast-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    cgroup.clear(unit)                       # a stale unit of this name would make systemd-run refuse
    with tempfile.TemporaryDirectory(prefix="quarry-ast-") as tmp:
        scratch = Path(tmp)
        out, err, peak = scratch / "out.json", scratch / "err.txt", scratch / "peak"
        cmd = _ast_command(artifact, out, err, peak, want_mb, scratch, unit)
        if not cmd:
            return "no-containment", skipped(AST_SHIM, "needs bwrap AND a user cgroup (systemd-run): "
                                                       "this parses hostile bytes and can take "
                                                       "gigabytes doing it"), meta
        wu = events.work_unit("crawl.jxscout_ast", inputs={"bundle": digest}, config=ident)
        try:
            res = run_contract("crawl.jxscout_ast", cmd, work_unit=wu, timeout=_AST_WALL_S + 30)
        finally:
            # ALWAYS: a timeout kills the systemd-run client, never the service it started.
            meta["unit_settled"] = cgroup.stop(unit)
        meta["wall_s"] = round(getattr(res, "duration", 0.0), 1)
        with contextlib.suppress(OSError, ValueError):
            meta["mem_peak_mb"] = int(peak.read_text().strip()) // (1 << 20)
        ceiling = _AST_OUTPUT_MB * 1024 * 1024
        try:
            out_bytes = out.stat().st_size if out.exists() else 0
            err_bytes = err.stat().st_size if err.exists() else 0
            raw = out.read_bytes() if 0 < out_bytes < ceiling else b""
        except OSError:
            return "unreadable", res, meta
        if err_bytes:
            with contextlib.suppress(OSError), err.open("rb") as fh:
                fh.seek(max(0, err_bytes - 4096))
                res.note = (res.note or "") + " " + secrets.redact(
                    fh.read(4096).decode("utf-8", "replace").strip()[-400:])
        if not meta["unit_settled"]:
            # the analysis may still be running and still holding its cap: nothing here is a result
            return "unit-unsettled", res, meta
        if res.status is Status.TIMED_OUT:
            return "timeout", res, meta
        if out_bytes >= ceiling or err_bytes >= ceiling:
            # ONE JSON document: a cut is not a shorter answer, it is an unparseable one, so there is no
            # partial evidence to keep and the bundle stays owed.
            return "truncated", res, meta
        if res.exit_code != 0:
            # 137/-9 is the cgroup killing it; the analyzer also catches its own allocation failure and
            # exits 1. Neither is "this bundle contains nothing".
            return ("oom-killed" if res.exit_code in (137, -9, 134) else "analyzer-error"), res, meta
        try:
            doc = json.loads(raw.decode("utf-8", "replace")) if raw else []
        except ValueError:
            return "unparseable", res, meta
        if not isinstance(doc, list):
            return "unparseable", res, meta
        meta["matches"] = len(doc)
        # the path carries the WORK identity, not just the bundle: two runs under different engines or
        # policies are different work and must not overwrite each other's evidence.
        dest = ctx.run.raw_path("crawl", "ast", f"{digest[:32]}.{key[:16]}.json")
        art_digest = hashlib.sha256(raw).hexdigest()
        if not budget.publish_bytes(dest, raw, digest=art_digest):
            return "unpublished", res, meta
        res.raw_path = dest
        meta["artifact"] = str(dest)
        if ledger is not None:
            ledger.record(key, dest, digest=art_digest)
        return ("success" if doc else "empty"), res, meta


def _ast_bundles(ctx, ledger) -> int:
    """Analyse every eligible bundle ONCE and publish its artifact. Returns the number published.

    Bundle-level work unit — `(bundle content digest, engine digest, policy)` — so a re-run skips what
    already landed and resumes the rest. One at a time on purpose: two 30 MB bundles want 10.6 GB of real
    memory between them (measured), and this lane's job is collection, not speed.
    """
    stats = getattr(ctx, "_ast_stats", None)
    if stats is None:
        stats = ctx._ast_stats = {"eligible": 0, "published": 0, "dispositions": {}, "peaks": []}
    engine = _ast_engine_digest()
    disp = stats["dispositions"]
    seen = getattr(ctx, "_ast_seen", None)
    if seen is None:
        seen = ctx._ast_seen = set()

    # WORK FIRST, capability second: an absent optional tool with no JS to read is a clean zero, not a
    # dependency failure.
    eligible = [(u, a) for u, a in ledger.items() if a and a.suffix == ".js" and str(a) not in seen]
    if not eligible:
        return 0
    stats["eligible"] += len(eligible)
    if not have(AST_SHIM):
        ctx.run.record("crawl", skipped(AST_SHIM, "not installed (optional)"))
        disp["missing-tool"] = disp.get("missing-tool", 0) + len(eligible)
        seen.update(str(a) for _u, a in eligible)
        _ast_coverage(ctx, stats)
        return 0
    # the completion ledger lives beside the artifacts but NOT inside the directory a later miner walks
    state = ctx.run.raw_path("crawl", "ast", "x.json").parent.parent / "ast.state.json"
    led = budget.Ledger(state, lane="crawl.jxscout_ast")
    published = 0
    for _url, art in eligible:
        seen.add(str(art))
        try:
            digest = hashlib.sha256(art.read_bytes()).hexdigest()
        except OSError:
            disp["unreadable"] = disp.get("unreadable", 0) + 1
            continue
        d, res, meta = _ast_analyze(ctx, art, digest, engine, ledger=led)
        disp[d] = disp.get(d, 0) + 1
        if res is not None:
            ctx.run.record("crawl", res)
        if meta.get("mem_peak_mb"):
            # requested AND actual, per bundle: the ratio is PROVISIONAL and this is what revises it
            stats["peaks"].append({"bytes": meta["bundle_bytes"], "request_mb": meta["mem_request_mb"],
                                   "peak_mb": meta["mem_peak_mb"], "wall_s": meta.get("wall_s")})
        if d == "success":
            published += 1
            stats["published"] += 1
        elif d in ("empty", "resumed"):
            # a resumed bundle is COVERED — its artifact is on disk and content-verified; re-analysing it
            # would pay 100 s to produce the same bytes
            stats["published"] += 1
        if d == "no-containment":
            # the same refusal stops every remaining bundle, so it is THEIR disposition too
            rest = len(eligible) - (eligible.index((_url, art)) + 1)
            if rest:
                disp[d] = disp.get(d, 0) + rest
                seen.update(str(a) for _u, a in eligible[-rest:])
            break
    # DURABILITY is part of the claim. A suppressed save let coverage report every artifact as covered
    # while the next run re-analysed all of it — 100 s a bundle on the big ones — with nothing saying so.
    saved = False
    try:
        saved = bool(led.save())
    except OSError:
        saved = False
    if not saved and stats["published"]:
        events.coverage_partial("crawl.jxscout_ast", kind=events.COVERAGE_UNKNOWN, measure="resume",
                                unit="ledger",
                                reason=f"completion ledger did NOT persist ({state}): the artifacts "
                                       f"landed, but the next run cannot know that and will re-analyse "
                                       f"all {stats['published']} of them")
        disp["ledger-unsaved"] = disp.get("ledger-unsaved", 0) + 1
    _ast_coverage(ctx, stats)
    ctx.echo(f"  ast analysis: {published} artifact(s) from {len(eligible)} bundle(s)"
             + (f" — {stats['eligible'] - stats['published']} not analysed" if
                stats["eligible"] - stats["published"] else ""))
    return published


def _ast_coverage(ctx, stats: dict) -> None:
    """What was READ, cumulatively, and why the rest was not. `tested` counts bundles whose artifact
    landed — an analysis nobody can read afterwards is not coverage."""
    events.coverage_partial("crawl.jxscout_ast", kind=events.COVERAGE_TIMEOUT, measure="bundles",
                            unit="bundles", eligible=stats["eligible"], tested=stats["published"],
                            omitted=max(0, stats["eligible"] - stats["published"]),
                            reason="; ".join(f"{d}={n}" for d, n in sorted(stats["dispositions"].items()))
                                   or "no bundles analysed")
    if stats["peaks"]:
        hi = max(stats["peaks"], key=lambda p: p["peak_mb"])
        # a DISTINCT unit: reconciliation keeps only the latest record per (source, unit), so sharing
        # "bundles" here silently replaced the eligible/tested row this lane exists to publish.
        events.coverage_partial("crawl.jxscout_ast", kind=events.COVERAGE_UNKNOWN, measure="memory",
                                unit="memory",
                                reason=f"memory policy is PROVISIONAL: requested "
                                       f"{_AST_MEM_PER_MB}x bundle size, peak observed "
                                       f"{hi['peak_mb']} MB on {hi['bytes']} B "
                                       f"({round(hi['peak_mb'] / max(1, hi['bytes'] / (1 << 20)))}x) "
                                       f"over {len(stats['peaks'])} bundle(s)")


def _jxscout_traverse(ctx, ledger, raw_dir):
    """Analyse, queue, re-fetch, repeat — until a round adds nothing (the fixed point) or the bound stops
    us. Returns the ledger/dir the later lanes read, so a chunk fetched in the last round is mined like
    any other bundle."""
    rounds = policy.limit("JXSCOUT_ROUNDS")
    rnd, owed = 0, 0
    while rounds <= 0 or rnd < rounds:
        rnd += 1
        owed = _jxscout_chunks(ctx, ledger)
        if not owed:
            break                                    # a round that adds nothing IS the fixed point
        ledger, raw_dir = _js_download(ctx)
    # what this lane still OWES, in the supervisor's vocabulary — on EVERY exit, so a converged traversal
    # CLEARS the remainder a bounded one left. A lane that only reports when it fails reads as unknown
    # for ever (settle prerequisite B). Best effort: a report is never a stop.
    #
    # TWO units, because a round count cannot express a bundle nobody analysed. `owed == 0` means only
    # that the last round added no URL — a timeout, a kill, a missing sandbox or a truncated answer all
    # add none either, so reporting rounds ALONE would tell the supervisor this lane owes nothing while
    # the coverage record beside it says a bundle was never read. That contradiction is how a campaign
    # reaches a fixed point over work it never did.
    _stats = getattr(ctx, "_jxscout_stats", {}) or {}
    _disp = _stats.get("dispositions", {})
    try:
        remainder.emit(remainder.for_rounds("crawl.jxscout_chunks",
                                            stop="bound" if owed else "converged",
                                            rounds=rounds, ran=rnd, made=bool(owed)))
        # a bundle we could not analyse splits in two, because the two halves have different repeat
        # behaviour and calling both terminal forbade a recovery that genuinely works:
        #   RETRIABLE   a timeout, a kill, an unreadable artifact — another child re-fetches that bundle
        #               and attempts it again, and it may simply succeed. The campaign's no-progress
        #               limit is what stops an endless retry, not a permanent verdict from us.
        #   TERMINAL    a missing tool or sandbox (`dependency` — fixable, but never by repetition), and
        #               a deterministic refusal or overflow (`unschedulable` — the same bytes under the
        #               same policy give the same answer every time).
        _terminal: dict = {}
        _retriable = 0
        for _d, _n in _disp.items():
            if _d in ("missing-tool", "no-sandbox"):
                _terminal["dependency"] = _terminal.get("dependency", 0) + _n
            elif _d in ("engine-error", "truncated"):
                _terminal["unschedulable"] = _terminal.get("unschedulable", 0) + _n
            elif _d in ("timeout", "killed", "unreadable", "unpublished"):
                _retriable += _n
        remainder.emit(remainder.Remainder(
            lane="crawl.jxscout_chunks", unit="crawl.jxscout_chunks:bundles", measure="bundles",
            model=remainder.UNIT_MODEL[("crawl.jxscout_chunks", "crawl.jxscout_chunks:bundles")],
            now=_retriable, cooldown=0, terminal=_terminal,
            detail={"eligible": _stats.get("eligible", 0), "attempted": _stats.get("attempted", 0),
                    "analysed": _stats.get("analysed", 0),
                    "dispositions": {k: v for k, v in sorted(_disp.items())}}))
    except Exception:                                            # noqa: BLE001
        pass
    if owed:
        # UNKNOWN, with no counters. A round still producing proves another round is REACHABLE and
        # nothing about how many remain: a chain needing a hundred more looks exactly like one needing
        # one, so an exact denominator would certify a depth nobody measured (the same correction the
        # permutation loop carries). And it does NOT resume: entities are run-scoped, so a later run
        # rediscovers the root and repeats rounds 1..N.
        events.coverage_partial("crawl.jxscout_chunks", kind=events.COVERAGE_UNKNOWN, measure="rounds",
                                unit="rounds",
                                reason=f"chunk traversal stopped by JXSCOUT_ROUNDS={rounds} while still "
                                       f"producing ({owed} newly-queued bundle(s) never analysed) — the "
                                       f"remaining depth is UNKNOWN, and a later run repeats rounds "
                                       f"1..{rounds} rather than continuing (raise it, or --unbound, to "
                                       f"reach the fixed point)")
    return ledger, raw_dir


def _js_publish_derived(ctx, ledger, raw_dir):
    """Build the DERIVED JS tree — the one the miners and secret scanners read — as a fresh generation and
    swap it in. Returns the published directory, or None when it could not be published exactly.

    Four review rounds tried to keep an in-place tree correct: prune what is unwanted, publish copies
    atomically, track provenance so beautification is not undone. Each round left another way for an
    unverified file to remain live — a failed replacement kept the old destination and then got SEALED as
    good, a leftover `.part-` temp survived, an undeletable stale file stayed mineable while coverage read
    clean. The tree is now EXACT BY CONSTRUCTION: staged from validated evidence only, beautified while still
    staged, and published atomically. Nothing partially-built is ever mineable, so there is no provenance
    state to get wrong.

    Beautification therefore re-runs each time rather than being preserved across runs. That is the right
    trade: it is derived data, and correctness of what the scanners read matters more than repeating a
    local reformat."""
    active = raw_dir.parent / "js_derived"
    for old in raw_dir.parent.glob("js_derived.gen-*"):           # abandoned staging from a killed run
        shutil.rmtree(old, ignore_errors=True)
    (raw_dir.parent / "js_derived.state.json").unlink(missing_ok=True)   # provenance state is obsolete
    wanted = ledger.artifacts()
    staging = _stage_dir(active)
    if staging is None:
        ctx.echo("    js_derived: could not create a clean staging directory — mining skipped")
        _js_mineable(ctx, eligible=len(wanted), tested=0)
        return None
    staged, failed = [], 0
    for src in sorted(wanted, key=lambda q: q.name):
        dst = staging / src.name
        try:
            data = src.read_bytes()
            dst.write_bytes(data)
            if dst.stat().st_size != len(data):
                raise OSError("short write")
            staged.append(dst)
        except OSError:
            failed += 1
            dst.unlink(missing_ok=True)                            # never leave a partial in the generation
    if failed:
        # an incomplete generation must not become the mineable tree — the scanners would silently see less
        ctx.echo(f"    js_derived: {failed} artifact(s) could not be staged — mining skipped")
        shutil.rmtree(staging, ignore_errors=True)
        _js_mineable(ctx, eligible=len(wanted), tested=0)
        return None
    if staged and have("js-beautify"):
        # beautify while STAGED: the published tree is then already in its final form, so there is no window
        # in which the mineable tree is mid-mutation and no digest to re-seal afterwards.
        try:
            ok, degraded, bstatus = _beautify_run(ctx, staged)
            events.ledger("crawl.js_beautify", beautified=ok, degraded=degraded,
                          input_total=len(staged), status=bstatus.value)
        except Exception as ex:
            ctx.echo(f"    js-beautify: {ex}")
    for stray in list(staging.glob("*.beauty")) + list(staging.glob("*.part-*")):
        stray.unlink(missing_ok=True)                              # tool temps never ship
    if not _publish_tree(ctx, active, staging):
        _js_mineable(ctx, eligible=len(wanted), tested=0)
        return None
    _js_mineable(ctx, eligible=len(wanted), tested=len(staged))
    return active


def _js_mineable(ctx, *, eligible: int, tested: int) -> None:
    """Coverage for "is every validated JS artifact actually available to the miners?". A tree we could not
    publish exactly means NONE of it is mineable — reported as such rather than as a warning beside a clean
    number."""
    omitted = max(0, eligible - tested)
    events.coverage_partial("crawl.js_fetch", kind=events.COVERAGE_TIMEOUT, measure="js_mineable",
                            unit="js_mineable", eligible=eligible, tested=tested, omitted=omitted,
                            reason=(f"{omitted} validated artifact(s) not available for mining"
                                    if omitted else
                                    f"all {tested} validated artifact(s) available for mining"))


def _publish_tree(ctx, active, staging) -> bool:
    """Swap a freshly built generation into place as the ACTIVE derived tree. Returns True only when the
    active tree is the new generation.

    review#1 (r3): the active tree must equal exactly what this run validated, and a swap makes that true by
    construction where an in-place prune cannot.

    review#1 (r4): the previous version could DESTROY THE LAST GOOD GENERATION. `os.replace` cannot overwrite
    a non-empty directory, so the outgoing tree is moved aside first; if publishing then failed AND rollback
    also failed, a `finally` deleted the retired copy anyway — leaving no tree at all. The retired copy is now
    removed ONLY after publication or rollback is confirmed, and the caller gets a status so a failure can be
    reported as a gap instead of passing silently."""
    # review#2 (r6): NEVER create the stage here. `mkdir(exist_ok=True)` recreated a MISSING generation and
    # published it as an empty success — reproduced: a missing stage returned True and replaced a populated
    # active tree with an empty directory. Publication requires a stage that the caller built exclusively.
    if staging is None or not staging.is_dir():
        ctx.echo(f"    refusing to publish {active.name}: staging generation is missing")
        return False
    retired = active.with_name(active.name + f".retired-{os.getpid()}")
    moved_aside = False
    try:
        if active.exists():
            os.replace(active, retired)
            moved_aside = True
        os.replace(staging, active)
    except OSError as ex:
        ctx.echo(f"    could not publish {active.name}: {ex}")
        shutil.rmtree(staging, ignore_errors=True)
        if moved_aside and not active.exists():
            try:
                os.replace(retired, active)          # put the previous generation back...
                moved_aside = False
            except OSError as ex2:
                # ...and if even that fails, KEEP it. A stale generation an operator can find beats no
                # evidence at all, so `retired` survives on disk and the failure is reported.
                ctx.echo(f"    WARNING: previous {active.name} left at {retired.name}: {ex2}")
        return False
    # publication confirmed — only now is the retired copy safe to drop
    if moved_aside:
        shutil.rmtree(retired, ignore_errors=True)
    return True


_SOURCEMAP_VERSION = 3          # the only source-map revision whose sourcesContent layout we extract


def _payload_key(label: str, ref_index: int, payload: bytes) -> str:
    """A stable, collision-resistant identity for one sourcemap payload.

    review#5: the extraction subdir was `md5(label)[:10]` — 40 bits, and worse, TWO INLINE MAPS IN ONE JS FILE
    share the same label, so extracting the second deleted the first's recovered sources while both counted as
    recovered. Identity is (origin url, reference index, payload digest), domain-separated."""
    h = hashlib.sha256()
    for part in (label.encode(), str(ref_index).encode(), payload):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()


def _sourcemap_schema(obj):
    """Validate an UNTRUSTED sourcemap and return (sources, contents) or None when it is not one.

    review#2: checking only the OUTER list types was fail-open — `{}`, `{"message":"not found"}`, and
    `sourcesContent: [3, {"x":1}]` all counted as VALID maps while their non-string members were silently
    skipped, and non-string `sources` turned into synthetic filenames. A map must declare `version: 3` and
    carry string-or-null members. An INDEX map (`sections`) is a real sourcemap we do not extract — it is
    attributed as unsupported, never accepted as if we had handled it."""
    if not isinstance(obj, dict):
        return None
    version = obj.get("version")
    # `type(...) is int`, not ==: bool is an int subclass and 3.0 == 3 is True, so `{"version": 3.0}` and
    # `{"version": True}` both slipped through an equality check (review#3 r4).
    if type(version) is not int or version != _SOURCEMAP_VERSION:
        return None
    if "sections" in obj:                             # index map: valid spec, unsupported here
        return "index_map"
    sources, contents = obj.get("sources"), obj.get("sourcesContent")
    # `sources` is REQUIRED by the spec. Treating it as optional made `{"version": 3}` and
    # `{"version": 3, "message": "not found"}` count as valid maps (review#3 r4).
    if not isinstance(sources, list):
        return None
    if contents is not None and not isinstance(contents, list):
        return None
    # review#4 (r5): `sourcesContent` must line up with `sources`. One source plus two contents used to be
    # accepted, with the extra content handed a synthetic filename.
    if contents is not None and len(contents) != len(sources):
        return None
    for member in (sources, contents or []):
        for x in member:
            if x is not None and not isinstance(x, str):
                return None                           # a non-string member makes the whole map untrusted
    return (sources, contents or [])


def _path_fingerprint(rels) -> str:
    """A stable fingerprint of an exact relative-path SET. Domain-separated and length-prefixed so no
    concatenation of two paths can ever equal a third."""
    h = hashlib.sha256()
    for r in sorted(rels):
        b = r.encode()
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)
    return h.hexdigest()


def _extract_payload(text, key, staging, tally, workroot=None):
    """Validate ONE sourcemap payload and extract its embedded sources into `staging`. Updates `tally`
    in place and returns the staging subdir name when extraction succeeded, else None.

    review#1 (r6): extraction is per-payload and STREAMED precisely so the caller never has to hold more
    than one map body in memory.

    review#3 (r2): a sourcemap is UNTRUSTED input — validate shapes and isolate extraction here, or one
    hostile map raises and aborts the phase before any coverage observation is emitted, discarding every
    valid sibling too."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        tally["parse_fail"]["not_json"] = tally["parse_fail"].get("not_json", 0) + 1
        return None                                              # e.g. a WAF HTML page served with 200
    shape = _sourcemap_schema(obj)
    if shape is None:
        tally["parse_fail"]["invalid_schema"] = tally["parse_fail"].get("invalid_schema", 0) + 1
        return None
    if shape == "index_map":
        tally["parse_fail"]["index_map_unsupported"] = tally["parse_fail"].get("index_map_unsupported", 0) + 1
        return None
    sources, contents = shape
    # review#4 (r2): `sourcesContent` is OPTIONAL in a valid source map. Its absence means "valid map, no
    # embedded source" — NOT failed recovery. Validity is one measure; EXTRACTION is another.
    tally["valid_maps"] += 1
    if not any(isinstance(c, str) and c for c in contents):
        return None
    tally["with_content"] += 1
    # review#1 (r7): extract into a WORK directory outside the publishable generation and move it in only on
    # success. Writing straight into staging meant a failed extraction whose `rmtree` cleanup ALSO failed left
    # a partial subdir inside the generation — published, and ingested by the scanners as evidence that
    # appears in no counter at all.
    sub = staging / key[:32]                                     # keyed by full payload identity (review#5 r3)
    work = (workroot or staging.parent) / f"{staging.name}.work-{key[:32]}"
    shutil.rmtree(work, ignore_errors=True)
    local = 0
    rels: list = []                              # exact relative paths written for this payload
    try:
        for i, content in enumerate(contents):
            if not isinstance(content, str) or not content:
                continue                                         # null entries are normal and legal
            name = sources[i] if i < len(sources) else None
            # review#4 (r5): sanitizing ALONE collides — `../a.js`, `./a.js`, `/a.js`, `webpack:///./a.js`
            # and `a.js` all reduce to `a.js`, so later sources silently overwrote earlier ones while both
            # were counted as recovered. The source INDEX makes every output path unique.
            safe = _safe_srcpath(name if isinstance(name, str) and name else f"src{i}.js")
            out = work / f"{i:04d}" / safe
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content)
            rels.append(f"{i:04d}/{safe}")
            local += 1
        # complete: move the finished payload INTO the generation. Only now can a scanner ever see it.
        os.replace(work, sub)
    except (OSError, ValueError, TypeError):
        # review#3 (r3): valid_maps was already incremented, so without a separate extraction measure the
        # outcome report saw obtained == attempted and DROPPED the class from its reason.
        tally["extract_fail"]["extract_error"] = tally["extract_fail"].get("extract_error", 0) + 1
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(sub, ignore_errors=True)
        return None
    # review#5 (r4): commit the count only once the payload finished — per-file increments stayed on the
    # books when a later error deleted the whole payload directory.
    tally["recovered"] += local
    tally["extracted"] += 1
    # review#1 (r10): a COUNT was not containment. Counting only regular non-symlink files meant a planted
    # `payload/extra.js -> outside/file` left the expected count unchanged, published, and was then followed
    # by the downstream `is_file()` straight to the miners. The manifest is now the exact set of relative
    # paths (fingerprinted, so memory stays O(1) per payload) and verification additionally refuses ANY
    # symlink anywhere inside a payload.
    tally["manifest"][key[:32]] = (local, _path_fingerprint(rels))
    return key[:32]


def _sourcemap_recover(ctx, js_ledger):
    """The crawl SOURCEMAP lane: find .map references in the fetched JS, fetch every in-scope one host-fair
    under a throughput budget, and recover `sourcesContent` to disk. Returns the published recovered-source
    directory, or None when it could not be published exactly — in which case NOTHING may be mined from it.

    review#3: reference resolution is driven by the LEDGER's url->artifact map, once per ORIGINAL URL. It used
    to recompute md5(url) and skip any URL whose file was absent — which silently excluded every URL whose
    body had been content-deduplicated away.

    review#1 (r6): payload bodies are STREAMED — decoded, extracted, released. Collecting them first meant the
    unbounded lane held every inline map plus every resumed and fetched body in memory at once (20 MiB allowed
    each), so a large target OOM'd and every resume rebuilt the same list and OOM'd again. Peak is now roughly
    one map."""
    recov_dir = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered"
    MAX_MAP = 20 * 1024 * 1024     # 20 MB PER-ITEM guard
    live_subdirs: set = set()      # map subdirs backed by a payload THIS run; everything else is pruned
    tally = {"valid_maps": 0, "with_content": 0, "extracted": 0, "recovered": 0,
             "parse_fail": {}, "extract_fail": {}, "manifest": {}}
    for _old in list(recov_dir.parent.glob(f"{recov_dir.name}.gen-*")) + \
                list(recov_dir.parent.glob(f"{recov_dir.name}.gen-*.work-*")):
        shutil.rmtree(_old, ignore_errors=True)                  # abandoned staging/work from a killed run
    staging = _stage_dir(recov_dir)                              # unique + provably empty (review#5 r5)
    obtained_js = list(js_ledger.items())
    map_urls: set = set()          # in-scope http(s) .map candidates (for the review queue)
    inline_n, inline_fail = 0, {}  # data: URIs are candidates too, and must be accounted for
    payload_n = 0                  # every payload we actually looked at (inline + resumed + fetched)
    m_att = m_got = 0
    m_fail: dict = {}
    map_budget = budget.Budget(budget.budget_seconds("SOURCEMAP_BUDGET_S"))
    map_persisted = True
    published = False
    if staging is None:
        # review#2 (r6): the exclusive-stage contract is end-to-end. No stage -> no extraction, no publication.
        ctx.echo("    sourcemaps: could not create a clean staging directory — extraction skipped")
    elif obtained_js:
        import base64
        from urllib.parse import urljoin
        js_read_ok, js_read_fail = 0, 0
        for u, art in obtained_js:
            try:
                text = art.read_text(errors="replace")
            except OSError:
                # review#1 (r9): mirrors the cached-map fix. Skipping silently meant that if the ONLY JS
                # artifact became unreadable after ledger validation, every sourcemap measure reported a
                # clean 0/0 and an empty generation was published — indistinguishable from "this target has
                # no sourcemaps". This lane cannot refetch JS, so it reports the inspection gap instead.
                js_read_fail += 1
                continue
            js_read_ok += 1
            refs = [line.split("sourceMappingURL=", 1)[1].strip()
                    for line in text.splitlines() if "sourceMappingURL=" in line]
            refs.append(u.split("?")[0] + ".map")               # conventional fallback
            for ref_i, ref in enumerate(refs):
                if ref.startswith("data:"):                     # inline base64 sourcemap
                    # review#6 (r2): an inline map that fails to decode or busts the size guard used to be
                    # dropped before any measure saw it.
                    inline_n += 1
                    try:
                        raw = base64.b64decode(ref.split(",", 1)[1])
                    except Exception:
                        inline_fail["decode_error"] = inline_fail.get("decode_error", 0) + 1
                        continue
                    if len(raw) > MAX_MAP:
                        inline_fail["size_guard"] = inline_fail.get("size_guard", 0) + 1
                        continue
                    payload_n += 1                               # extract NOW; never accumulate the body
                    got = _extract_payload(raw.decode("utf-8", "replace"),
                                           _payload_key(u, ref_i, raw), staging, tally)
                    if got:
                        live_subdirs.add(got)
                    del raw
                else:
                    # resolved against THIS url, which is why the per-url loop must cover deduplicated bodies
                    m = urljoin(u, ref)
                    # fetching is ACTIVE — a malicious sourceMappingURL can point off-scope.
                    if ctx.scope.active_allowed(normalize.host_of_url(m)):
                        map_urls.add(m)
            del text
        # No MAP_CAP. `sorted(map_urls)[:100]` was the cap lottery at its worst: sorting CLUSTERS by host, so
        # one alphabetically-early host consumed the entire 100-fetch budget. Measured on two OTC runs of the
        # same target — the first window landed on `influx1` (85 of 100 slots) and recovered 46 maps; the second
        # landed on `dependencytrack` (74 slots) and recovered 5, and `report-sourcemap.json` came back `[]`
        # because the map holding the secret was never fetched. Host-fair order + a budget + a ledger instead.
        map_dir = ctx.run.dir / "raw" / "crawl" / "sourcemaps"
        map_dir.mkdir(parents=True, exist_ok=True)
        # same reasoning as js_fetch: keep state out of any directory a scanner or miner walks
        map_ledger = budget.Ledger(map_dir.parent / "sourcemap_fetch.state.json", lane="crawl.sourcemaps")
        cache_dir = map_dir / "fetched"                          # the raw .map bodies: the ledger's artifacts
        cache_dir.mkdir(parents=True, exist_ok=True)
        # resumed maps: read ONE body at a time from its cached artifact, extract, release.
        # review#2 (r7): a resumed entry whose artifact is gone or unreadable used to be `continue`d — then
        # counted in `m_got` as successfully fetched while `payload_n` excluded it, so it vanished from every
        # denominator. It is REQUEUED for fetching instead (coverage-first); only if the re-fetch also fails
        # does it surface, as a named failure.
        requeue = []
        resumed_ok = 0
        for m in [m for m in map_urls if map_ledger.has(m)]:
            art = map_ledger.artifact(m)
            body = None
            if art is not None:
                try:
                    body = art.read_bytes()
                except OSError:
                    body = None
            if body is None:
                requeue.append(m)                                # cached artifact unusable -> fetch it again
                continue
            resumed_ok += 1
            payload_n += 1
            got = _extract_payload(body.decode("utf-8", "replace"), _payload_key(m, 0, body), staging, tally)
            if got:
                live_subdirs.add(got)
            del body
        # review#5 (r2): order only PENDING work, so a host's already-fetched history cannot push its new
        # remainder behind other hosts in a bounded run.
        pending = budget.order_fairly(sorted([m for m in map_urls if not map_ledger.has(m)] + requeue),
                                      lambda m: normalize.host_of_url(m))
        m_att = m_got = resumed_ok
        try:
            for m in pending:
                if map_budget.exhausted():
                    break                                        # between items only
                m_att += 1
                try:
                    # shared choke point: rate pace + bounded read + off-scope-redirect guard.
                    data, _final, status = fetch.scoped_get(ctx, m, max_body=MAX_MAP)
                    if data is None:
                        m_fail["not_contacted"] = m_fail.get("not_contacted", 0) + 1
                        continue
                    if status != 200:
                        m_fail[f"http_{status}"] = m_fail.get(f"http_{status}", 0) + 1
                        continue
                    if len(data) > MAX_MAP:
                        m_fail["size_guard"] = m_fail.get("size_guard", 0) + 1
                        continue
                    m_digest = hashlib.sha256(data).hexdigest()
                    cached = cache_dir / (m_digest + ".map")
                    if not budget.publish_bytes(cached, data, digest=m_digest):
                        m_fail["write_failed"] = m_fail.get("write_failed", 0) + 1
                        continue                                 # a truncated cache file must never be evidence
                    map_ledger.record(m, cached, digest=m_digest)
                    m_got += 1
                    payload_n += 1
                    got = _extract_payload(data.decode("utf-8", "replace"),
                                           _payload_key(m, 0, data), staging, tally)
                    if got:
                        live_subdirs.add(got)
                    del data
                except Exception:
                    m_fail["error"] = m_fail.get("error", 0) + 1
                    continue
        finally:
            map_persisted = map_ledger.save()                    # review#3 (r6): persistence CAN fail
            if not map_persisted:
                _persistence_gap(ctx, "crawl.sourcemaps", map_ledger, len(map_urls))
            else:                                                # emit BOTH ways, or a prior gap lingers
                events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT,
                                        measure="state_persisted", unit="state_persisted",
                                        eligible=1, tested=1, omitted=0,
                                        reason="completion state persisted")
        sm_raw = ctx.run.raw_path("crawl", "sourcemaps", "candidates.txt")
        sm_raw.write_text("\n".join(sorted(map_urls)) + "\n")
        for smap in sorted(map_urls):
            ctx.run.add("review", {"id": f"sourcemap:{smap}", "klass": "sourcemap", "value": smap,
                                   "sources": ["sourcemap-scan"]})
        budget.report_outcome("crawl.sourcemaps", measure="js_inspected", attempted=len(obtained_js),
                              obtained=js_read_ok,
                              classes={"unreadable_artifact": js_read_fail} if js_read_fail else {},
                              noun="JS artifact")
        budget.report_selection("crawl.sourcemaps", measure="sourcemaps", eligible=len(map_urls),
                                attempted=m_att, budget=map_budget, noun="sourcemap", durable=map_persisted)
        budget.report_outcome("crawl.sourcemaps", measure="sourcemaps_fetched", attempted=m_att,
                              obtained=m_got, classes=m_fail, noun="sourcemap")
    if staging is not None and (obtained_js or True):
        # review#6 (r2)/#3 (r3): VALIDITY and EXTRACTION are separate outcomes, and inline candidates that
        # never became payloads are still counted.
        budget.report_outcome("crawl.sourcemaps", measure="sourcemaps_valid",
                              attempted=payload_n + sum(inline_fail.values()),
                              obtained=tally["valid_maps"],
                              classes={**tally["parse_fail"], **inline_fail}, noun="sourcemap payload")
        budget.report_outcome("crawl.sourcemaps", measure="sourcemaps_extracted",
                              attempted=tally["with_content"], obtained=tally["extracted"],
                              classes=tally["extract_fail"], noun="sourcemap with embedded source")
    else:
        # review#2 (r8): with JS evidence present but no staging, candidate discovery never ran — so these
        # measures are UNMEASURED, not zero. Clean 0/0 records would imply there was nothing to inspect.
        # COVERAGE_UNKNOWN reaches the verdict as a gap and keeps the input count as attribution.
        for _m in ("sourcemaps", "sourcemaps_fetched", "sourcemaps_valid", "sourcemaps_extracted",
                   "js_inspected"):
            events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_UNKNOWN, measure=_m, unit=_m,
                                    reason=f"no staging directory — {len(obtained_js)} JS artifact(s) were "
                                           f"never inspected for sourcemaps; coverage UNMEASURED")
    if not obtained_js and staging is not None:
        # no JS -> zero eligible sourcemaps. Emit zero observations anyway so the structured auto-reset opens a
        # fresh generation and a PRIOR gap doesn't linger as stale.
        events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_CAP, measure="sourcemaps",
                                eligible=0, tested=0, omitted=0, reason="no JS files this run -> 0 sourcemaps")
        events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT, measure="sourcemaps_fetched",
                                eligible=0, tested=0, omitted=0, reason="no JS files this run -> 0 fetches")
        events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT, measure="js_inspected",
                                eligible=0, tested=0, omitted=0, reason="no JS files this run -> 0 inspected")
    # review#1 (r5): publication is ONE operation, measured 1/0. Sizing it by subdir count meant an EMPTY
    # generation that failed to publish reported eligible=0/omitted=0 — no gap at all — while the rolled-back
    # previous tree stayed on disk. And returning the directory regardless let jsluice / xnLinkFinder /
    # gitleaks / trufflehog mine that stale tree as if it were this run's output.
    # review#1 (r7/r8/r9): the generation must contain EXACTLY what we counted — checked in BOTH directions
    # and down to the FILE level. Removing only the EXTRAS was one-sided (a counted payload that vanished
    # shipped an incomplete tree while the counters still claimed it); comparing only top-level DIRECTORY
    # names was still too coarse (a recovered file disappearing inside a counted directory published fine
    # while `recovered_sources` overstated disk evidence).
    #
    # review#3 (r9): the whole check runs inside a guard. iterdir()/unlink() can raise, and an escaping
    # exception aborted before `sourcemaps_published` recorded the gap — so a failure to verify became a
    # failure to report.
    if staging is not None and staging.is_dir():
        try:
            for entry in list(staging.iterdir()):                # drop what no counter claims
                ok = (entry.name in live_subdirs and entry.is_dir() and not entry.is_symlink())
                if ok:
                    continue
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)                # a symlink is unlinked, never followed
                if entry.exists():
                    raise OSError(f"uncounted entry {entry.name} could not be removed")
            manifest = {e.name for e in staging.iterdir() if e.is_dir() and not e.is_symlink()}
            if manifest != live_subdirs:
                raise OSError(f"{len(live_subdirs - manifest)} counted payload(s) missing from the generation")
            for key, (exp_n, exp_fp) in tally["manifest"].items():   # ...and the FILES inside each payload
                sub = staging / key
                seen = []
                for q in sub.rglob("*"):
                    if q.is_symlink():
                        # review#1 (r10): no symlink may exist anywhere inside a payload. Rejecting is the
                        # only real containment — the scanners walk this tree themselves and we cannot make
                        # gitleaks or xnLinkFinder stop following links.
                        raise OSError(f"payload {key} contains a symlink ({q.name})")
                    if q.is_file():
                        seen.append(str(q.relative_to(sub)))
                if len(seen) != exp_n or _path_fingerprint(seen) != exp_fp:
                    raise OSError(f"payload {key} has {len(seen)} recovered file(s), counted {exp_n} "
                                  f"(or the paths differ)")
        except OSError as ex:
            ctx.echo(f"    sourcemaps: generation disagrees with its counters ({ex}) — not publishing")
            shutil.rmtree(staging, ignore_errors=True)
            staging = None
    published = _publish_tree(ctx, recov_dir, staging)
    events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT, measure="sourcemaps_published",
                            unit="sourcemaps_published", eligible=1, tested=1 if published else 0,
                            omitted=0 if published else 1,
                            reason=(f"recovered-source tree published ({len(live_subdirs)} map(s))"
                                    if published else
                                    "recovered-source tree could NOT be published; extraction unavailable "
                                    "and the directory on disk is a stale generation"))
    # review#4 (r6): emit a ledger EVERY lifecycle. Event folding carries the latest ledger forward, so
    # omitting it on failure/empty left the PREVIOUS generation's recovered_sources on display as current —
    # confirmed: an old count of nine survived a newer publication-failure event.
    events.ledger("crawl.sourcemaps",
                  produced={"recovered_sources": tally["recovered"] if published else 0,
                            "valid_maps": tally["valid_maps"] if published else 0,
                            "published": 1 if published else 0},
                  consumed={"map_candidates": len(map_urls), "inline_candidates": inline_n,
                            "payloads": payload_n})
    if not published:
        return None
    m_left = len(map_urls) - m_att
    ctx.echo(f"  sourcemaps: {len(map_urls)} .map candidate(s), {m_got}/{m_att} fetched"
             + (f", {m_left} left by budget — {'resumable' if map_persisted else 'NOT saved, will restart'}"
                if m_left else "")
             + f", {tally['valid_maps']}/{payload_n} valid, recovered {tally['recovered']} source file(s)")
    return recov_dir


def run(ctx) -> None:
    # every xnLinkFinder input, mined together at the end of the phase under ONE source lifecycle.
    xnl_units: list = []
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
        # C10b resume: work_unit = the target-list digest + crawl config (depth, form-fill, scope). A changed
        # target set or crawl depth is a new unit.
        kat_wu = events.work_unit("crawl.katana_standard",
                                  file_digests={"targets": events.file_digest(targets)},
                                  config={"depth": 2, "jc": True, "kf": "all"})
        r = run_contract("crawl.katana_standard", cmd, work_unit=kat_wu, raw_path=kat, timeout=ctx.http_timeout)
        ctx.run.record("crawl", r)
        if r.raw_path:
            ctx.echo(f"  katana: +{_collect_url(ctx, r.raw_path.read_text(), 'katana', str(kat))} urls")

        # headless SPA pass on JS-heavy / app hosts (RAM-heavy; opt-in via MODES.HEADLESS)
        if prof.headless:
            _cap = policy.limit("SPA_CAP")
            _spa_all = sorted({u for u in targets.read_text().splitlines()
                               if any(k in u.lower() for k in
                               ("app", "portal", "dashboard", "account", "my-", "/app"))})
            spa = _spa_all if not _cap else _spa_all[:_cap]
            # MODES.HEADLESS enables headless crawling; it does NOT request "first 10 only" — so the 10-cap is a
            # HIDDEN CAP (gates when it drops hosts), not an operator-chosen sample. Emit every run (clears prior).
            _n_spa = len(_spa_all)
            events.coverage_partial("crawl.katana_headless", kind=events.COVERAGE_CAP, measure="spa_hosts",
                                    eligible=_n_spa, tested=len(spa), omitted=_n_spa - len(spa),
                                    reason=f"headless SPA {len(spa)}/{_n_spa} app-like hosts "
                                           f"(cap {_cap or 'none'})")
            if spa:
                spa_f = ctx.write_list("spa_targets.txt", spa)
                kh = ctx.run.raw_path("crawl", "katana", "headless.txt")
                # C10b resume: the headless pass is its own unit — the SPA host set + headless crawl config.
                kh_wu = events.work_unit("crawl.katana_headless", inputs={"spa_hosts": spa},
                                         config={"depth": 2, "headless": True, "jc": True})
                r = run_contract("crawl.katana_headless",
                              ["katana", "-list", str(spa_f), "-headless",
                                         "-system-chrome", "-jc", "-d", "2", "-c", "2", "-p", "1",
                                         "-timeout", "20", "-silent"] +
                                        _katana_scope_flags(scope) +   # same OOS exclusion on the headless pass
                                        (["-rl", str(prof.http_rl)] if prof.http_rl else []),
                              work_unit=kh_wu, raw_path=kh, timeout=ctx.http_timeout)
                ctx.run.record("crawl", r)
                if r.raw_path:
                    ctx.echo(f"  katana headless SPA: +{_collect_url(ctx, r.raw_path.read_text(), 'katana-headless', str(kh))} urls")
    else:
        ctx.run.record("crawl", skipped("katana", "passive-only or no live targets"))

    # ── passive urls (gau) ──
    gau_raw = ctx.run.raw_path("crawl", "gau", "gau.txt")
    # gau reads domains from POSITIONAL ARGS or stdin, never both — args take precedence and stdin is
    # ignored when args are present (verified upstream cmd/gau/main.go: `if len(domains)>0 {...} else
    # {read stdin}`). We pass the apexes as args, so the old stdin_data was DEAD input (not a duplicate
    # request — gau never read it — just misleading); dropped (T1.4). Coverage unchanged.
    # C10b resume: work_unit = apex set + gau config (--subs). A changed apex set is a new unit.
    gau_wu = events.work_unit("crawl.gau", inputs={"apexes": sorted(prof.apex_domains)}, config={"subs": True})
    r = run_contract("crawl.gau", ["gau", "--subs", "--threads", "5"] + prof.apex_domains,
                     work_unit=gau_wu, raw_path=gau_raw, timeout=ctx.http_timeout)
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
        # C07 inc3: per-apex work_unit; source_id reflects the mode (URLs vs responses). config binds the
        # coverage-affecting mode + response limit so a wider-limit re-run is a new unit.
        sid = "crawl.waymore_responses" if mode == "B" else "crawl.waymore_urls"
        wu = events.work_unit(sid, inputs={"apex": d, "mode": mode},
                              config={"limit": prof.waymore_limit if mode == "B" else None, "ci": "d"})
        r = run_contract(sid, cmd, work_unit=wu, timeout=ctx.http_timeout)
        ctx.run.record("crawl", r)
        if wm.exists():
            _collect_url(ctx, wm.read_text(), "waymore", str(wm))
        # mine the response dir (only if responses were actually downloaded)
        if mode == "B" and len([p for p in wdir.iterdir() if p.name != "waymore.txt"]) > 1:
            # OFFLINE mining of the archived bodies only — see `_xnl_unit` for why depth-3 crawling is
            # gone. Collected, not run: all four inputs are mined under ONE source lifecycle at the end of
            # the phase (step 3), so `crawl.xnlinkfinder` has one terminal instead of four competing ones.
            xnl_units.append((str(wdir), f"waymore-{d}", True))

    # ── download JS, dedup, beautify ──
    js_ledger, js_raw_dir = _js_download(ctx)

    # ── LAZY CHUNKS: bundles name JS that nothing links to, so nothing else in the crawl can reach it.
    # Analyse what we just downloaded, resolve the candidates ourselves, then re-run the fetch lane —
    # which RESUMES, so it only pays for the new URLs. A chunk can name another chunk, hence rounds; the
    # loop ends when a round adds nothing, and `JXSCOUT_ROUNDS` bounds the depth (0 = to the fixed point).
    js_ledger, js_raw_dir = _jxscout_traverse(ctx, js_ledger, js_raw_dir)

    # ── AST ANALYSIS (MODES.JS_AST, default off): collect once, interpret later. Runs AFTER the chunk
    # traversal so the bundles it discovered are analysed too. Publishes artifacts and nothing else — no
    # entity, no request — because the observation layer is a later step.
    if getattr(ctx.profile, "js_ast", False):
        _ast_bundles(ctx, js_ledger)

    # review#1/#2: the mineable tree is a STAGED generation, beautified before publication and swapped in
    # atomically — so what the miners and secret scanners read is exactly this run's validated evidence, or
    # nothing at all. `None` means it could not be published exactly, and NOTHING is mined from it.
    js_derived_dir = _js_publish_derived(ctx, js_ledger, js_raw_dir)
    js_files = sorted(js_derived_dir.glob("*.js")) if js_derived_dir else []

    # the sourcemap lane reads the RAW bodies (immutable, and a reformat could disturb the trailing
    # sourceMappingURL comment) and takes its URL->artifact truth from the ledger.
    recov_dir = _sourcemap_recover(ctx, js_ledger)

    # ── re-mine recovered source (jsluice + xnLinkFinder), provenance = sourcemap ──
    # review#1 (r5): None means publication failed, so the directory on disk is a ROLLED-BACK previous
    # generation. Mining it would present stale extraction as this run's output.
    # `is_file()` FOLLOWS symlinks, so filter them explicitly — publication already refuses a tree
    # containing any, and this keeps the invariant local to where the files are consumed.
    recov_files = ([p for p in recov_dir.rglob("*") if p.is_file() and not p.is_symlink()]
                   if (recov_dir and recov_dir.exists()) else [])
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
    if recov_files:
        if recov_dir:
            xnl_units.append((str(recov_dir), "sourcemap", False))

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
    if js_files:
        xnl_units.append((str(js_derived_dir), "js", False))

    # ── xnLinkFinder over katana's stored responses (flags.md: crawl-then-mine) ──
    if kat_resp.exists() and any(kat_resp.iterdir()):
        xnl_units.append((str(kat_resp), "katana-resp", False))

    # (waymore response mining happens per-apex above via -mode B + xnLinkFinder)

    # ── secret scanners on JS dir + sourcemap-recovered sources ──
    # BOTH dirs must be scanned: a canary planted only in a recovered source (e.g. a stripe key in
    # app.js.map's sourcesContent) is missed if we scan js_files/ alone (Test-5). js_files gate
    # holds — no JS means no sourcemaps, nothing to scan.
    # the DERIVED tree, not raw_dir: scanning both would double-report every secret, and raw is kept as
    # immutable evidence (review#1) rather than as scanner input.
    scan_dirs = [d for d in (js_derived_dir, recov_dir)
                 if d and d.exists() and any(p.is_file() for p in d.rglob("*"))]
    if scan_dirs and have("gitleaks"):
        # `gitleaks dir <path>` (T1.3 drift fix): the old `detect --no-git -s <path>` is deprecated —
        # current gitleaks uses the `dir` subcommand with a POSITIONAL path (filesystem scan, no-git is
        # implicit; verified `gitleaks dir --help`: usage `gitleaks dir [flags] [path]`, no -s/--no-git).
        # It writes its JSON report to the -r FILE and exits 1 when it FINDS leaks (success, not error);
        # write a REAL file and classify on its contents — `-r /dev/stdout` is non-portable (0 bytes on
        # some builds). One path per invocation, so scan each dir in turn (per-dir report = audit trail).
        # (Report redaction + version pinning are separate items — C15 secret-hygiene / C08 install-lock.)
        for sd in scan_dirs:
            rep = ctx.run.raw_path("crawl", "gitleaks",
                                   "report.json" if sd == js_derived_dir else "report-sourcemap.json")
            rep.unlink(missing_ok=True)                    # stale report must not fabricate findings/success
            # review#4/#6: gitleaks runs TWICE under one source_id (js_derived + sourcemap dir). Each invocation
            # needs its OWN work_unit so C10b tracks them separately AND re-scans a dir whose CONTENT changed.
            # Keyed on the dir name + a per-file CONTENT digest (not path+size — a same-size edit MUST re-scan;
            # a size-only key would skip a canary swapped into an equal-length secret).
            digests = {}
            for p in sorted(sd.rglob("*")):
                try:
                    if p.is_file():
                        digests[str(p.relative_to(sd))] = events.file_digest(p)
                except OSError:
                    continue
            gl_wu = events.work_unit("crawl.gitleaks", inputs={"dir": sd.name}, file_digests=digests)
            # C07: run under the authoritative contract; reclassify (status-only) inside it so the terminal
            # event carries the FINAL file-output status. Ingest below re-reads the report (fail-closed).
            r = run_contract("crawl.gitleaks", ["gitleaks", "dir", str(sd), "-r", str(rep), "-f", "json"],
                             work_unit=gl_wu,
                             reclassify=lambda res: (_gitleaks_status(res, rep), res)[1],
                             ok_codes=(0, 1), timeout=ctx.http_timeout)
            items = _gitleaks_report(rep)                  # validated findings for ingest (status already set)
            for item in (items or []):
                sec = item.get("Secret", "")
                # fingerprint from the secret; fall back to rule+file+line so an empty Secret
                # can't collapse distinct findings to fingerprint("").
                basis = sec or f"{item.get('RuleID')}|{item.get('File')}|{item.get('StartLine')}"
                ctx.run.add("secret", {"id": f"gitleaks:{item.get('RuleID')}:{secrets.fingerprint(basis)}",
                                       "kind": item.get("RuleID"), "preview": secrets.mask(sec),
                                       "file": item.get("File"), "sources": ["gitleaks"]})
            ctx.run.record("crawl", r)

    if scan_dirs and have("trufflehog"):
        # `filesystem` accepts multiple paths — hand it both dirs in one pass.
        th = ctx.run.raw_path("crawl", "trufflehog", "out.jsonl")
        # SAFETY: trufflehog VERIFIES by default — it sends discovered TARGET credentials to their
        # THIRD-PARTY provider APIs, turning offline secret mining into active credential use against a
        # third party (RoE/legal concern). Default `--no-verification`; verification is an explicit
        # authorized lane (MODES.SECRET_VERIFICATION). Discovery is UNAFFECTED — every secret is still
        # found and reported (as unverified) either way; only the active provider round-trip is gated.
        th_cmd = ["trufflehog", "filesystem", *[str(d) for d in scan_dirs], "--json", "--no-update"]
        if not prof.verify_secrets:
            th_cmd.append("--no-verification")
        r = exec_tool("trufflehog", th_cmd, raw_path=th, timeout=ctx.http_timeout)
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
                # verification is TRI-state. `verified`: True/False mean attempted (valid/invalid);
                # None means NOT attempted (lane off) — so a not-checked secret never reads as
                # "checked and invalid" (False). `verification` carries the same truth as a string.
                if prof.verify_secrets:
                    verified = bool(o.get("Verified", False))
                    verification = "verified" if verified else "unverified"
                else:
                    verified = None
                    verification = "not_checked"
                ctx.run.add("secret", {"id": f"trufflehog:{det}:{secrets.fingerprint(basis)}",
                                       "kind": det, "preview": red or secrets.mask(raw_s),
                                       "verified": verified, "verification": verification,
                                       "sources": ["trufflehog"]})

    # ── xnLinkFinder: ONE lifecycle over every collected input, LAST so each input is complete ──
    _xnl_lane(ctx, xnl_units)

    ctx.echo(f"  urls: {ctx.run.count('url')}  js: {ctx.run.count('js_url')}  "
             f"endpoints: {ctx.run.count('endpoint')}  params: {ctx.run.count('parameter')}  "
             f"secrets: {ctx.run.count('secret')}")


#: bump when CLASSIFICATION or INGEST meaning changes — it is part of a unit's identity, because the same
#: bytes parsed under different rules are a different result.
#: v2 (step 4.1): RETENTION is complete. The per-call param cap and the derived-wordlist cap are gone, so a
#: v1 bundle holds a TRUNCATED corpus and must not be replayed as if it answered today's question.
XNL_PARSER_SCHEMA = 2
#: app-like hosts the headless SPA pass may take. A HIDDEN cut on hosts already retained (it gates when it
#: drops any), so `--unbound` lifts it: 0 = every app-like host (flag-axis step 4).
SPA_CAP = 10
XNL_MAX_INPUT = 200 * 1024 * 1024      # cap the stdin blob so a huge dir can't blow RAM
XNL_WORDLIST_LIMIT = 10 * 1024 * 1024  # -owl/-os are permutation timekillers on big input -> small only
#
# step 4.1 — RETENTION vs ACTIVE SELECTION. `XNL_PARAM_CAP = 2000` and `XNL_WORDLIST_DERIVE_CAP = 5000`
# used to live here. They were RETENTION caps, and they bought no request safety at all: the `parameter`
# entity has exactly one consumer, `exports.parameters.txt`; nothing turns a stored candidate into a
# request. What DOES spend — the A1d brute vocabulary and the wildcard candidate set — is selected
# downstream and stays bounded there, unchanged by this commit.
#
# MEASURED on OTC 20260725: 111,313 distinct candidates produced, 6,086 stored — 94.5% destroyed. The cap
# sorted and then kept the first N, which is deterministic for identical input but LEXICOGRAPHIC, so it
# favoured punctuation and digits: on the `js` unit the 2,000 survivors ran from `-` to `34498` with ZERO
# entries beginning with a letter, and the same for `katana-resp`; only `sourcemap` reached letters at all
# (1,551 of its 2,000). Most named candidates were the part thrown away.
#
# The corpus is now kept whole (~20 MB/run at 190 B/row). Bounding what we SPEND is step 4.2/4.3, after a
# measured run: an active lane does not get an unbounded default on my say-so.


#: what one line of xnLinkFinder output can be. The tool's OWN scope filter is not a boundary Quarry may
#: rely on: its `-sf` regex is unanchored at the end of the host, so for apex `acme.com` it admits
#: `acme.com.evil.net`, `notacme.com` and `xacme.common.io` (measured, xnLinkFinder 8.2 ~line 1053). Output
#: is therefore UNTRUSTED input, re-validated here against Quarry's own scope before anything is stored.
XNL_ENDPOINT = "endpoint"        # an absolute URL, IN Quarry's scope
XNL_PATH = "path"                # a relative path — no host, so not contactable and not scope-checkable
XNL_SCHEMELESS = "schemeless"    # `//host/path` — a host, but its SCHEME is the source document's, and the
                                 # blob destroyed which document that was. Evidence, never a contact target.
XNL_OOS = "oos"                  # an absolute URL OUTSIDE scope: retained as review evidence, never endpoint
XNL_CREDENTIAL = "credential"    # a URL carrying USERINFO: unsafe to contact, but possibly a real finding
XNL_MALFORMED = "malformed"      # not usable as a reference at all — counted, never stored as surface
XNL_IGNORED = "ignored"          # blank lines and the tool's own `<stdin>` token: not a finding, not an error

#: a potential parameter NAME. xnLinkFinder mines path words, JSON keys, JS variables, input names and meta
#: fields, so the file also picks up sentences, code fragments and binary noise from minified sources.
_XNL_PARAM_RX = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\-\[\]]{0,63}$")
#: an absolute reference: a scheme, or a scheme-relative `//host/...`
_XNL_ABSOLUTE_RX = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:)?//", re.IGNORECASE)


def _safe_netloc(raw: str) -> bool:
    """Whether `urlsplit` can even read this reference's authority. Never raises."""
    try:
        _urlsplit(raw)
        return True
    except ValueError:
        return False


def _xnl_safe_url(raw: str):
    """`(canonical_url, canonical_host)` for an absolute reference, or None.

    review-B-audit-2#1: scope was decided on a host extracted by regex while a consumer would later re-parse
    the RAW string — so `https://acme.com:443@evil.net/graphql` passed as `acme.com` and would have been
    fetched from `evil.net`. The authority is parsed STRUCTURALLY here, the dangerous shapes are refused
    outright, and what gets STORED is rebuilt from the parsed parts: a downstream re-parse cannot then
    disagree with the scope decision that admitted it.

    Refused: any scheme but http/https, userinfo (`user@host` — the confusion itself, and nothing in recon
    input needs it), an unparseable authority, a host that is not a canonical hostname."""
    v = raw.strip()
    # NB no scheme is invented here: a `//host/path` reference never reaches this function (see
    # `_xnl_classify_link`), because its scheme belongs to a source document the blob destroyed.
    # ONE authority decision, in ONE place. `normalize.host_of_url` is what every scope check in the repo
    # runs through — including `fetch.scoped_get`, which makes the request — and it is fail-closed: a
    # non-http scheme, any userinfo, an unparseable port or IPv6 literal all answer "". Re-checking those
    # here would be a second copy that cannot be falsified while the first one holds, and two copies of a
    # security decision are how they drift apart.
    host = normalize.host_of_url(v)
    if not host:
        return None
    canon = normalize.canon_host_strict(host)
    if not canon:
        return None
    try:
        parts = _urlsplit(v)
        port = parts.port
    except ValueError:
        return None
    authority = canon if port is None else f"{canon}:{port}"
    rebuilt = _urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, parts.fragment))
    return rebuilt, canon


def _xnl_classify_link(raw: str, scope) -> tuple:
    """`(kind, value)` for one line of xnLinkFinder link output. NEVER raises.

    Absolute URLs are scoped by QUARRY (`in_scope` and not `is_oos`) on a CANONICAL host, not by the tool's
    substring regex. An off-scope URL is real evidence — the archive really did link there — so it is kept
    as review, but it is not surface: `endpoint` is consumed by lanes that go on to contact things."""
    v = (raw or "").strip()
    if not v or v == "<stdin>":
        # review-B-audit-3#4: this said "not an error" and was then counted as malformed. Ignored noise has
        # its own disposition, so the rejected count means what it says.
        return XNL_IGNORED, ""
    if any(ch in v for ch in "\t \x00") or len(v) > 4096:
        return XNL_MALFORMED, v               # a link with whitespace/NUL, or an absurd length, is not a link
    schemeless = v.startswith("//")
    if schemeless or _XNL_ABSOLUTE_RX.match(v):
        # review-B-audit-4#1: the schemeless branch used to return BEFORE the authority was parsed, so
        # `//acme.com.attacker.io/y` was stored as an endpoint (D12's inventory poisoning, reopened) and
        # `//user:pass@evil.net/g` missed the credential classification entirely.
        #
        # A protocol-relative reference still inherits its SOURCE DOCUMENT's scheme, and the blob destroyed
        # which document that was — so `https:` here is a PARSING DEVICE ONLY. It decides nothing about
        # what is stored: an in-scope schemeless link keeps its verbatim `//host/...` form with the scheme
        # unbound. Every other authority rule applies identically.
        probe = ("https:" + v) if schemeless else v
        if _safe_netloc(probe) and "@" in _urlsplit(probe).netloc:
            # review-B-audit-3#2: unsafe to CONTACT is not the same as worthless. `user:pass@host` carries
            # credentials someone published — a finding in its own right — so it is retained VERBATIM as
            # review evidence and never as surface. (Quarry's own configured credentials are the only thing
            # redacted from telemetry; discovered ones are the point.)
            return XNL_CREDENTIAL, v
        safe = _xnl_safe_url(probe)
        if safe is None:
            return XNL_MALFORMED, v           # not a URL an HTTP client could act on, so not surface
        canon_url, canon_host = safe
        if not (scope.in_scope(canon_host) and not scope.is_oos(canon_host)):
            # off scope either way — and a schemeless one keeps its own form, because we still do not know
            # what scheme it was written under.
            return XNL_OOS, (v if schemeless else canon_url)
        return (XNL_SCHEMELESS, v) if schemeless else (XNL_ENDPOINT, canon_url)
    if v.startswith("/") or v.startswith("./") or v.startswith("../"):
        return XNL_PATH, v
    # anything else — a bare word, a code fragment, a mangled token — is not a reference at all
    return XNL_MALFORMED, v


def _xnl_classify_param(raw: str) -> tuple:
    """`(ok, value)` for one line of xnLinkFinder param output. NEVER raises."""
    v = (raw or "").strip()
    if not v or v == "<stdin>":
        return False, ""
    return bool(_XNL_PARAM_RX.match(v)), v


def _xnl_wants_secrets(written: int) -> bool:
    """Whether `-os` was asked for at this input size. ONE authority: `_xnl_run` decides with it and the
    parser boundary asks it again, so "the tool wrote no secrets file" can be told apart from "we never
    asked" — on the fresh path and on replay alike."""
    return written < XNL_WORDLIST_LIMIT


def _xnl_secret_row(item) -> bool:
    """Whether a row matches the MEASURED `-os` row exactly. review-B-audit-7#4: only `value` was checked,
    so a row with a malformed `type`/`sources`/`count` was ingested and the unit owned — the contract names
    four fields, and a document that disagrees with it is not one we have measured."""
    src = item.get("sources") if isinstance(item, dict) else None
    return bool(isinstance(item, dict)
                and isinstance(item.get("type"), str) and item["type"].strip()
                and isinstance(item.get("value"), str) and item["value"].strip()
                # MEASURED provenance: this lane always streams the concatenated blob on stdin, so every
                # row the tool writes carries `["<stdin>"]`. A different source list is a document from a
                # mode we have not measured — including an EMPTY one, which claims no origin at all.
                and isinstance(src, list) and src and all(s == "<stdin>" for s in src)
                # a real occurrence count: a positive int, and `bool` is not an int here.
                and isinstance(item.get("count"), int) and not isinstance(item.get("count"), bool)
                and item["count"] >= 1)


def _xnl_secrets(ctx, tag: str, shot: tuple, *, requested: bool, carrier: dict | None = None) -> tuple:
    """Ingest xnLinkFinder's `-os` output. Returns (stored, unusable, parse_gap).

    MEASURED schema (xnLinkFinder 8.2, this machine, offline stdin fixtures): a JSON ARRAY of
        {"type": str, "value": str, "sources": [str], "count": int}
    and a run that finds NOTHING writes the array `[]` — measured separately, because "the tool found no
    secrets" and "the artifact we asked for is missing" are different facts and only one of them is clean.
    `sources` is always `["<stdin>"]` in the offline mode this lane runs in: the concatenated blob has no
    per-file provenance to give, so it is not stored as if it did.

    A discovered secret is BOUNTY EVIDENCE. It is stored VERBATIM: not masked, not truncated, not
    rewritten. (Only QUARRY's own configured credentials are ever redacted, and none of them appear here.)
    The counted result used to be `len(json)` with a bare `except: 0` — so a malformed or unexpected
    document produced a confident `secrets=0` AND an ownable unit, freezing that silence forever. Anything
    the measured schema does not explain is a PARSE GAP that keeps the unit retryable."""
    res = carrier if carrier is not None else _xnl_result(tag)
    state, raw = shot
    if state == "absent":
        if requested:
            # review-B-audit-7#5: `-os` was passed and the tool wrote no file. The measured no-find shape
            # is `[]`, so this is UNMEASURED — fail closed rather than call our own blind spot a zero.
            return 0, 0, (f"{tag}: -os was requested and no artifact was written (the measured no-find "
                          f"shape is `[]`) — unit retryable")
        return 0, 0, ""                        # the tool was never asked for secrets
    if state == "unreadable":
        res["unreadable"] = True
        return 0, 0, f"{tag}: -os artifact exists and could not be read"
    if not raw.strip():
        return 0, 0, (f"{tag}: -os artifact is empty (the measured no-find shape is `[]`) — artifact "
                      f"RETAINED, unit retryable")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return 0, 0, f"{tag}: -os output is not the measured JSON document — artifact RETAINED, unit retryable"
    if not isinstance(doc, list):
        return 0, 0, (f"{tag}: -os output is a {type(doc).__name__}, not the measured array — artifact "
                      f"RETAINED, unit retryable")
    stored = bad = 0
    for item in doc:
        if not _xnl_secret_row(item):
            bad += 1
            res["unusable"] += 1
            continue
        value, kind = item["value"], item["type"]
        # id from the VERBATIM value, so the same secret from two inputs is one row; `secrets.fingerprint`
        # is a digest, not a redaction — the value itself is stored beside it.
        ctx.run.add("secret", {"id": f"xnLinkFinder:{kind}:{secrets.fingerprint(value)}",
                               "kind": kind, "value": value, "preview": value,
                               "verified": None, "verification": "not_checked",
                               "sources": ["xnLinkFinder"], "context": f"xnLinkFinder-{tag}"})
        # review-B-audit-9#2: counted into the CARRIER the moment the write returns — the local total only
        # reached the caller if the whole document parsed, so a sink dying on the second secret reported
        # zero while the first one sat in the store.
        stored += 1
        res["secrets"] += 1
    gap = (f"{tag}: {bad}/{len(doc)} -os entries do not match the measured schema — artifact RETAINED, "
           f"unit retryable") if bad else ""
    return stored, bad, gap


def _xnl_decode(shot: tuple) -> tuple:
    """`(lines, undecodable, unreadable)` from a snapshot entry `(state, bytes)` — decode per line, never
    whole-file: a `errors="replace"` decode turns invalid UTF-8 into replacement characters that then look
    like perfectly good values, and mined minified/binary sources produce exactly that."""
    state, data = shot
    if state == "unreadable":
        return [], 0, True                    # it is there and we cannot read it: our machinery failing
    if state == "absent":
        return [], 0, False                   # no output file: a legitimate zero
    out, bad = [], 0
    for chunk in data.splitlines():
        try:
            out.append(chunk.decode("utf-8"))
        except UnicodeDecodeError:
            bad += 1
    return out, bad, False


def _xnl_snapshot(outs: dict) -> dict:
    """Read a unit's four artifacts ONCE: `{key: (state, bytes)}`.

    review-B-audit-10#1: parsing, the presence check, publication and (on replay) digest verification each
    re-read the files, so the bytes that produced the ENTITIES were not provably the bytes bound into the
    ledger. A sink callback rewriting an artifact between two of those reads could make a run store URL A
    and own URL B, which every later replay would then ingest. One snapshot, carried through all four."""
    return {k: _xnl_read(outs[k]) for k in ("links", "params", "secrets", "wordlist")}


def _xnl_lines(path) -> tuple:
    """`(lines, undecodable, unreadable)` — read tool output as BYTES and decode per line, strictly.

    A whole-file `errors="replace"` decode turns invalid UTF-8 into replacement characters that then look
    like perfectly good values; mined minified/binary sources produce exactly that. A line we cannot decode
    is counted, not guessed at.

    review-B-audit-2#3: every `OSError` used to become `([], 0)`, so a file that EXISTS and cannot be read
    was indistinguishable from a tool that found nothing. Absence is a legitimate zero; an unreadable
    artifact is our own machinery failing, and `unreadable` says which happened."""
    # review-B-audit-3#3: an `exists()` pre-check collapses a stat/permission failure to "absent" and adds a
    # check/read race. Read, then let the ERROR say which happened.
    return _xnl_decode(_xnl_read(path))


def _xnl_read(path):
    """Read an artifact ONCE and say what it is: `("absent"|"ok"|"unreadable", bytes)`.

    review-B-audit-9#3: `exists()` followed by a read is the check/read split `_xnl_lines` was fixed for
    and it kept coming back — a permission or stat failure was reported as "the tool wrote no artifact",
    and between the two calls the answer could change. One read, one verdict, used by everything that
    needs to know whether an artifact is there."""
    try:
        return "ok", Path(path).read_bytes()
    except FileNotFoundError:
        return "absent", b""
    except OSError:
        return "unreadable", b""


def _xnl_state_dir(ctx):
    """PROJECT-owned state for the lane: `<project>/recon/state/xnlinkfinder/v<schema>/`.

    review-B-audit-5#1: this lived under `ctx.run.dir`, which `Run.create()` mints fresh for every run —
    so the "resume" ledger was empty on every production invocation and only a test reusing one tmp_path
    could see it work. The same single-run fixture blindness that hid the Whoxy cross-run defect."""
    d = (Path(ctx.run.project_dir) / "recon" / "state" / "xnlinkfinder"
         / f"v{XNL_PARSER_SCHEMA}")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _xnl_engine() -> str:
    """The INSTALLED xnLinkFinder's proven identity (pipx metadata for the executable that resolves on
    PATH), or "" when it cannot be proven.

    review-B-audit-6#7: `have()` only asks whether the name resolves, and `pipx upgrade xnLinkFinder` is an
    allowed operation — so a unit mined by 8.2 was replayed forever under a newer extractor that would have
    found more. The engine is part of what produced the output, so it is part of the unit's identity."""
    try:
        tool = next((x for x in registry.load_tools() if x.bin == "xnLinkFinder"), None)
        return registry.installed_identity(tool) if tool is not None else ""
    except Exception:
        return ""                       # an unprovable engine is handled by the caller, never guessed


def _xnl_unit_identity(ctx, tag: str, spo: bool, blob_digest: str, engine: str) -> str:
    """The unit's work identity: the exact BOUNDED INPUT ARTIFACT plus everything that changes the output.

    review-B-audit-5#7: a per-file digest map keyed on RELATIVE FILENAMES made a rename a new unit (so the
    old "a renamed identical file does not re-mine" claim was simply false), while omitting the scope roots,
    `spo`, the caps and the parser schema — all of which change what is extracted or stored. The blob digest
    covers the bytes AND the path order and byte cap that selected them."""
    if not blob_digest:
        # review-B-audit-6#7: an unreadable input digested to "", and every such unit collapsed onto ONE
        # identity — mine one, own them all. A unit we cannot identify is a unit we must not own.
        raise ValueError(f"{tag}: input artifact could not be digested — unit has no identity")
    return events.work_unit("crawl.xnlinkfinder",
                            inputs={"tag": tag, "apexes": sorted(ctx.profile.apex_domains)},
                            file_digests={"input_blob": blob_digest},
                            config={"engine": engine, "spo": bool(spo),
                                    "input_cap": XNL_MAX_INPUT, "wordlist_limit": XNL_WORDLIST_LIMIT},
                            schema_version=XNL_PARSER_SCHEMA)


def _xnl_bundle(state_dir, wu: str) -> dict:
    """Where a unit's OUTPUTS are kept so a LATER RUN can re-ingest them."""
    return {"links": state_dir / f"{wu}_links.txt", "params": state_dir / f"{wu}_params.txt",
            "secrets": state_dir / f"{wu}_secrets.json", "wordlist": state_dir / f"{wu}_wordlist.txt"}


def _xnl_publish_bundle(ledger, state_dir, wu: str, snap: dict) -> dict:
    """Copy a unit's outputs into project state, DIGEST-BOUND, and record the unit.

    review-B-audit-5#1: the ledger bound only the INPUT blob, so `has()` meant "we mined this once" and the
    lane then skipped — storing nothing in the new run. Evidence has to travel with the completion, or a
    resumed run silently loses every entity the earlier run found.

    review-B-audit-5#3: `record()`'s boolean is the durability handshake and it was discarded. It is
    returned here so the caller can tell "journaled" from "in memory only"."""
    bundle = _xnl_bundle(state_dir, wu)
    manifest = {}
    for key, dst in bundle.items():
        # review-B-audit-10#1: the bytes come from the SNAPSHOT the parser used, never a fresh read — a
        # second read is a second answer, and the ledger must bind exactly what produced the entities.
        # Absence is one measured answer; an unreadable artifact fails publication (review-B-audit-6#6).
        state, data = snap[key]
        if state == "unreadable":
            return {"stored": False, "journaled": False}
        present = state == "ok"
        dig = hashlib.sha256(data).hexdigest()
        if present and not budget.publish_bytes(dst, data, digest=dig):
            return {"stored": False, "journaled": False}
        if not present:
            dst.unlink(missing_ok=True)          # a file the tool never wrote must not exist in state
        manifest[key] = {"file": dst.name, "present": present, "digest": dig, "bytes": len(data)}
    man_path = state_dir / f"{wu}_bundle.json"
    raw = json.dumps({"schema": XNL_PARSER_SCHEMA, "unit": wu, "outputs": manifest},
                     sort_keys=True).encode()
    if not budget.publish_bytes(man_path, raw, digest=hashlib.sha256(raw).hexdigest()):
        return {"stored": False, "journaled": False}
    # review-B-audit-6#5: every one of these is a durability answer and all four were discarded. Evaluated
    # eagerly (never short-circuited) so each artifact is actually bound before the verdict is taken.
    bound = [ledger.add_evidence(wu, dst, digest=manifest[key]["digest"])
             for key, dst in bundle.items() if manifest[key]["present"]]
    recorded = bool(ledger.record(wu, man_path, digest=hashlib.sha256(raw).hexdigest()))
    return {"stored": True, "journaled": recorded and all(bound)}


def _xnl_replay_bundle(ledger, state_dir, wu: str) -> dict | None:
    """The stored outputs for an owned unit as a verified SNAPSHOT, or None when they no longer validate."""
    man_path = ledger.artifact(wu)
    if man_path is None:
        return None
    try:
        man = json.loads(man_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    if man.get("schema") != XNL_PARSER_SCHEMA or man.get("unit") != wu:
        return None
    bundle = _xnl_bundle(state_dir, wu)
    declared = man.get("outputs") or {}
    snap = {}
    for key, path in bundle.items():
        decl = declared.get(key) or {}
        want = decl.get("digest")
        state, data = _xnl_read(path)          # ONE read: the bytes that are verified ARE the bytes used
        if decl.get("present") is False:
            # the tool wrote no such artifact. A file appearing there later is not our evidence.
            if state != "absent":
                return None
            snap[key] = ("absent", b"")
            continue
        if state != "ok":
            return None
        if not want or want != hashlib.sha256(data).hexdigest():
            return None                # the bundle no longer says what it said: re-mine rather than trust
        snap[key] = ("ok", data)
    return snap


def _xnl_materialize(ctx, tag: str, snap: dict) -> None:
    """Write an owned unit's VERIFIED bytes into this run's raw tree, for the operator to inspect.

    review-B-audit-6#2: replay handed the project-state files straight to `_xnl_ingest`, which REWRITES the
    derived wordlist for large inputs — mutating digest-bound evidence after verifying it, and failing
    outright on read-only state. Verified evidence is immutable; a run works on its own copy.

    review-B-audit-10#1: it no longer RE-READS state to make that copy. The snapshot returned by
    verification is what is written here and what is ingested — one set of bytes, one meaning."""
    outs = _xnl_outputs(ctx, tag)
    for key, dst in outs.items():
        state, data = snap[key]
        if state != "ok":
            dst.unlink(missing_ok=True)      # the mining run produced no such artifact; neither do we
            continue
        dst.write_bytes(data)


def _xnl_lane(ctx, units: list) -> None:
    """Mine every collected input under ONE `crawl.xnlinkfinder` lifecycle.

    review-B-audit#D3: `_xnl` ran up to four times per phase via bare `exec_tool`, so the source emitted
    coverage and ledger events but NEVER a terminal, and its registry entry was never consulted. Wrapping
    each call independently would have been worse — four competing terminals under one source id.

    So: one `tool_start`, one `tool_finish`, and INDEPENDENTLY IDENTIFIED units in between, whose state is
    PROJECT-owned, LOCKED for the whole lifecycle, and re-ingested on every run."""
    if not units:
        return
    sid = "crawl.xnlinkfinder"
    if not registered(sid):
        # the registry is authoritative for execution, and that authority lives in `contract` — a phase
        # asking `sources` directly would be a second copy of the same gate.
        return
    fp = events.work_unit(sid, inputs={}, config={"input_cap": XNL_MAX_INPUT},
                          schema_version=XNL_PARSER_SCHEMA)
    events.tool_start(sid, cmd=["xnLinkFinder", "(stdin)"], input_total=len(units), work_unit=fp)

    # review-B-audit-5#6: the tool check lived at every COLLECTION site, so an uninstalled tool meant no
    # units, no lane, and total silence from a `tier: core` source. The units are eligible either way; only
    # the mining depends on the binary.
    if not have("xnLinkFinder"):
        events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, unit="install", measure="units",
                                eligible=len(units), tested=0, omitted=len(units),
                                reason=f"xnLinkFinder is not installed — {len(units)} input(s) unmined")
        ctx.run.record("crawl", skipped("xnLinkFinder", "not installed"))
        events.tool_finish(sid, status=Status.SKIPPED.value, work_unit=fp,
                           reason=f"xnLinkFinder not installed — {len(units)} input(s) eligible")
        return

    st = {"done": 0, "incomplete": 0, "replayed": 0, "machinery": [], "results": [],
          "pending": [], "persisted": False, "busy": False, "cancelled": False,
          "persist_note": "unit state was NOT persisted — every input re-mines"}
    try:
        # review-B-audit-6#1: state creation, pruning and ledger load were OUTSIDE every boundary — an
        # ordinary IO error there aborted the whole crawl phase with no terminal at all. And nothing
        # serialised two runs of one project: both pruned the same directory, mined the same units, raced
        # on the shared `.tmp` and unlinked each other's journal. ONE lock, taken before prune/load and
        # held through replay, publication and save.
        with contextlib.ExitStack() as stack:
            state_dir = _xnl_state_dir(ctx)
            stack.enter_context(budget.state_lock(state_dir / ".lock"))
            budget.prune_state(state_dir, sid, fp)
            ledger = budget.Ledger(budget.state_path(state_dir, sid, fp), lane=sid)
            try:
                _xnl_mine(ctx, sid, units, state_dir, ledger, st)
            finally:
                _xnl_settle(sid, ledger, st)
    except budget.StateBusy as e:
        st["busy"] = True
        st["machinery"].append(f"another lifecycle holds this project's xnLinkFinder state ({e})")
        events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, unit="lock", measure="units",
                                eligible=len(units), tested=0, omitted=len(units),
                                reason=f"another lifecycle holds the lane state — {len(units)} input(s) "
                                       f"unmined in THIS run")
    except (KeyboardInterrupt, SystemExit):
        # review-B-audit-6#3: cancellation re-raised, but the terminal was computed in a `finally` that had
        # no idea the run had been cancelled — so an interrupted lane signed off SUCCESS or EMPTY. The
        # terminal is emitted HERE, saying what actually happened, before the signal continues upward.
        st["cancelled"] = True
        _xnl_terminal(ctx, sid, fp, units, st)
        raise
    except Exception as e:
        st["machinery"].append(f"lane state unavailable ({type(e).__name__}: {e})")
    _xnl_terminal(ctx, sid, fp, units, st)


def _xnl_mine(ctx, sid: str, units: list, state_dir, ledger, st: dict) -> None:
    """Replay or mine every unit, under the lane's lock. Accumulates into `st`; raises only cancellation."""
    engine = _xnl_engine()
    for i, (indir, tag, spo) in enumerate(units, 1):
        events.tool_progress(sid, input_total=len(units), current_index=i)
        try:
            prep = _xnl_blob(ctx, indir, tag)
            if not prep["digest"]:
                # review-B-audit-6#7: without a digest there is no identity, and every such unit collapsed
                # onto the same one. Named as the input problem it is, not as a machinery failure.
                st["incomplete"] += 1
                events.coverage_partial(
                    sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit", measure="units",
                    eligible=1, tested=0, omitted=1,
                    reason=f"{tag}: the bounded input artifact could not be digested — unit has no "
                           f"identity, nothing mined, next run retries it")
                continue
            wu = _xnl_unit_identity(ctx, tag, spo, prep["digest"], engine)
            bundle = _xnl_replay_bundle(ledger, state_dir, wu) if ledger.has(wu) else None
            if bundle is not None:
                # REPLAY, not skip: the stored outputs are re-ingested so this run's store holds the same
                # entities the run that mined them did. Read-only: we ingest our own copies.
                st["replayed"] += 1
                _xnl_materialize(ctx, tag, bundle)     # the verified bytes, copied for the operator
                res = _xnl_result(tag)
                st["results"].append(res)          # registered BEFORE the writes, not after them
                _xnl_ingest(ctx, tag, bundle, blob=prep["blob"], written=prep["written"],
                            replay=True, carrier=res)
                events.coverage_partial(sid, kind=events.COVERAGE_CAP, unit=f"{tag}:unit",
                                        measure="units", eligible=1, tested=1, omitted=0,
                                        reason=f"{tag}: replayed from owned evidence (same bytes)")
                continue
            run = _xnl_run(ctx, tag, prep["blob"], prep["written"], spo=spo)
            # ONE read of each artifact; these exact bytes parse, publish and are digest-bound.
            snap = _xnl_snapshot(run["outs"])
            # review-B-audit-8#1: the carrier joins the accounting BEFORE any entity is written, so a sink
            # that raises — or a cancellation — half-way through cannot leave the terminal claiming
            # "nothing extracted" while the store holds what was already saved.
            res = _xnl_result(tag)
            st["results"].append(res)
            _xnl_ingest(ctx, tag, snap, blob=prep["blob"], written=prep["written"], carrier=res)
            # review-B-audit-5#2: a unit whose INPUT was truncated by the byte cap, or whose files could
            # not all be read, has not mined everything it was given — recording it would freeze that
            # omitted suffix forever. Completion needs the tool AND the whole input AND readable output.
            whole_input = (prep["files_completed"] == prep["files"] and not prep["capped"]
                           and not prep["partial_files"] and not prep["unreadable_files"])
            if not engine:
                # review-B-audit-6#7: an unprovable engine cannot be bound into the identity, so a later
                # upgrade could not invalidate this unit. Mine it, keep the evidence, own nothing.
                st["incomplete"] += 1
                events.coverage_partial(
                    sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit", measure="units",
                    eligible=1, tested=0, omitted=1,
                    reason=f"{tag}: the installed xnLinkFinder's identity is unproven — evidence KEPT, "
                           f"unit not recorded (an upgrade must not replay old output)")
            elif run["complete"] and not res["unreadable"] and not res["parse_gap"] and whole_input:
                pub = _xnl_publish_bundle(ledger, state_dir, wu, snap)
                if not pub["stored"]:
                    st["incomplete"] += 1
                    events.coverage_partial(
                        sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit", measure="units",
                        eligible=1, tested=0, omitted=1,
                        reason=f"{tag}: evidence could not be stored durably — unit not recorded")
                elif pub["journaled"]:
                    st["done"] += 1
                else:
                    # review-B-audit-6#5: a failed APPEND still leaves the completion in memory, and a
                    # later successful snapshot persists it — so the unit IS owned next run. Counting it
                    # incomplete now and never revisiting produced a gap for work that was in fact kept.
                    # It is PENDING until `save()` answers.
                    st["pending"].append(tag)
            else:
                st["incomplete"] += 1
                why = ("tool status " + run["status"].value if not run["complete"] else
                       "output unreadable" if res["unreadable"] else
                       res["parse_gap"] if res["parse_gap"] else
                       f"input incomplete ({prep['files_completed']}/{prep['files']} files"
                       f"{', byte cap hit' if prep['capped'] else ''})")
                events.coverage_partial(
                    sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit", measure="units",
                    eligible=1, tested=0, omitted=1,
                    reason=(f"{tag}: extraction did NOT complete ({why}) — evidence KEPT, unit not "
                            f"recorded, next run re-mines it"))
        except (KeyboardInterrupt, SystemExit):
            raise                                  # cancellation ends the run; it is not a unit outcome
        except Exception as e:
            # review-B-audit-5#5: an ordinary failure in one unit used to abort the whole crawl phase and
            # leave the lane's terminal claiming success. Contain it, keep what the other units found.
            st["incomplete"] += 1
            st["machinery"].append(f"{tag}: {type(e).__name__}: {e}")
            events.coverage_partial(
                sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit", measure="units",
                eligible=1, tested=0, omitted=1,
                reason=f"{tag}: our own machinery failed ({type(e).__name__}: {e})")


def _xnl_settle(sid: str, ledger, st: dict) -> None:
    """Compact the ledger and RESOLVE every pending completion — still under the lane's lock."""
    try:
        saved = bool(ledger.save())
    except Exception as e:                          # `save()` promises a bool; a broken promise is ours
        saved = False
        st["machinery"].append(f"ledger save failed ({type(e).__name__}: {e})")
    # review-B-audit-7#3: the durability fallback is a FALLBACK. A successful snapshot has already answered
    # the question, and reading `durable` anyway let a raising property fabricate machinery on a clean run
    # (the same short-circuit Whoxy needed).
    durable = True
    if not saved:
        try:
            durable = bool(getattr(ledger, "durable", False))
        except Exception as e:
            durable = False
            st["machinery"].append(f"ledger durability unreadable ({type(e).__name__}: {e})")
    # review-B-audit-5#3: `durable` alone says the JOURNAL is readable, not that every completion reached
    # it. A record that failed to append leaves an older journal perfectly intact.
    st["persisted"] = saved or (durable and not st["pending"])
    # review-B-audit-7#6 / 8#4: "every input re-mines" was printed even when the journal held some of
    # them, and the fraction was taken over every RESULT — replayed and gapped units included — rather
    # than over the units that actually attempted a completion. What is lost is exactly the completions
    # that reached NEITHER the journal nor a snapshot; what survives (an earlier snapshot's units, and
    # anything journaled) is not this run's to disown.
    pending, attempted = len(st["pending"]), st["done"] + len(st["pending"])
    if not st["persisted"]:
        st["persist_note"] = (f"{pending}/{attempted} completion(s) reached neither the journal nor a "
                              f"snapshot — those re-mine" if durable else
                              f"the journal is unusable and the snapshot failed — {attempted} "
                              f"completion(s) from this run re-mine; units owned by an earlier snapshot "
                              f"still replay")
    for tag in st["pending"]:
        if saved:
            # the snapshot carries it: the unit IS owned, and the earlier "not recorded" reading was wrong.
            # Coverage is LATEST per (source, unit), so this REPLACES the gap rather than adding a fact.
            st["done"] += 1
            events.coverage_partial(sid, kind=events.COVERAGE_CAP, unit=f"{tag}:unit", measure="units",
                                    eligible=1, tested=1, omitted=0,
                                    reason=f"{tag}: journal append failed but the snapshot compacted — "
                                           f"unit owned")
        else:
            st["incomplete"] += 1
            events.coverage_partial(sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit",
                                    measure="units", eligible=1, tested=0, omitted=1,
                                    reason=f"{tag}: completion reached neither the journal nor a snapshot "
                                           f"— evidence KEPT, next run re-mines it")
    st["pending"] = []


def _xnl_terminal(ctx, sid: str, fp: str, units: list, st: dict) -> None:
    """The lane's ONE terminal, computed from what actually happened."""
    results, machinery = st["results"], st["machinery"]
    # review-B-audit-5#4: production is EVERY evidence category, replayed evidence included — a
    # parameter-only extraction is not an empty one.
    # ...and it counts what the PARSER ACCEPTED, not what the store found NEW (review-B-audit-2#2):
    # a parameter jsluice already stored is still this lane's output, and an EMPTY terminal would be a
    # lie about extraction.
    got = sum(r["endpoints"] + r["paths"] + r["schemeless"] + r["oos"] + r["credentials"]
              + r["params"] + r["wordlist"] + r["secrets"] for r in results)
    produced = {"references": sum(r["endpoints"] + r["paths"] + r["schemeless"] + r["oos"]
                                  + r["credentials"] for r in results),
                "params": sum(r["params"] for r in results),
                "wordlist": sum(r["wordlist"] for r in results),
                "secrets": sum(r["secrets"] for r in results)}
    incomplete = st["incomplete"]
    if st["cancelled"]:
        # an interrupted lane has NOT covered its input, whatever it managed to extract first.
        # review-B-audit-7#2: PARTIAL asserts something was produced. A cancellation before any ingestion
        # produced nothing, and that is a FAILED lifecycle with a cancellation reason — not a partial one.
        status = Status.PARTIAL.value if got else Status.FAILED.value
        reason = (f"CANCELLED after {st['done'] + st['replayed']}/{len(units)} input(s)"
                  + (" — evidence KEPT" if got else " — nothing extracted")
                  + ("; " + "; ".join(machinery) if machinery else ""))
    elif st["busy"]:
        # review-B-audit-7#1: SKIPPED claims we CHOSE not to run. Losing the lock is not a choice, and this
        # run holds none of the holder's evidence — its own store is empty. Same rule as everywhere else:
        # zero evidence is FAILED, and the `lock` coverage gap says who bounded us.
        status = Status.PARTIAL.value if got else Status.FAILED.value
        reason = "; ".join(machinery)
    elif machinery:
        status = Status.PARTIAL.value if got else Status.FAILED.value
        reason = "; ".join(machinery)
    elif incomplete and got:
        status, reason = Status.PARTIAL.value, (f"{incomplete}/{len(units)} input(s) did not finish "
                                                f"extracting — evidence KEPT")
    elif incomplete:
        status, reason = Status.FAILED.value, f"{incomplete}/{len(units)} input(s) failed to extract"
    else:
        status = Status.SUCCESS.value if got else Status.EMPTY.value
        reason = None
    if not (st["persisted"] or st["busy"]):
        # the note always rides along; it may only make the verdict WORSE. Turning a FAILED lane into a
        # PARTIAL one because its state also failed to persist would hide the first, larger fact.
        if status in (Status.SUCCESS.value, Status.EMPTY.value):
            status = Status.PARTIAL.value
        reason = ((reason + "; ") if reason else "") + st.get(
            "persist_note", "unit state was NOT persisted — every input re-mines")
    events.tool_finish(sid, status=status, reason=reason, work_unit=fp, produced=produced)
    ctx.echo(f"  xnLinkFinder: {len(units)} input(s) · {st['done']} mined · {st['replayed']} replayed · "
             f"{incomplete} incomplete")


def _xnl_outputs(ctx, tag: str) -> dict:
    """The four artifacts one unit writes, under this run's raw tree."""
    safe = tag.replace("/", "_").replace(".", "_")
    return {"links": ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe}_links.txt"),
            "params": ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe}_params.txt"),
            "secrets": ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe}_secrets.json"),
            "wordlist": ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe}_wordlist.txt")}


def _xnl_blob(ctx, indir: str, tag: str) -> dict:
    """Build the BOUNDED INPUT ARTIFACT for one unit — the exact bytes that will be mined.

    This artifact IS the unit's identity (review-B-audit-5#7): it already reflects the byte cap and the
    path order that decided WHICH bytes made it in, which a per-file digest map does not."""
    safe_tag = tag.replace("/", "_").replace(".", "_")
    # xnLinkFinder v8.2: `-i <dir>` silently yields NOTHING (exit 0) and `-i <file>` is treated as a file
    # of DOMAINS to crawl — only STDIN parses file CONTENT offline (this silently produced 0 links/params
    # on every run). Concatenate the dir's files into a bounded blob and stream it via stdin (no -i).
    # Build the stdin blob with BYTE-ACCURATE bounding: chunked binary copy that stops EXACTLY at the cap
    # (a single 600 MB file can't blow it), and `capped` is set whenever any bytes/files were omitted.
    blob = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_input.txt")
    written = 0
    capped = False
    files_completed = 0                              # files read to EOF (honest `tested`)
    partial_files = 0                                # files cut off mid-body by the byte cap (NOT counted tested)
    unreadable = 0                                   # files that raised on open/read (NOT counted tested)
    files = [f for f in sorted(Path(indir).rglob("*")) if f.is_file()]
    with blob.open("wb") as bf:
        # FORCE offline-content mode. xnLinkFinder classifies stdin by its FIRST line: one starting with
        # "http" or "//" makes stdin a URL LIST and the tool CRAWLS those URLs (network contact + timing-
        # dependent, NON-deterministic output) instead of extracting links from the file bytes. A single
        # leading blank line makes firstLine == "" -> fileContent mode: offline, deterministic, -p irrelevant.
        # Verified on a sourcemap blob: URL-mode = 138s / 0 endpoints WITH target contact; content-mode =
        # 10s / 1071 endpoints offline, byte-identical across -p 1/4/8/25 and across repeats.
        bf.write(b"\n")
        written += 1
        for i, f in enumerate(files):
            if written >= XNL_MAX_INPUT:
                capped = True                            # remaining files omitted
                break
            eof = False
            try:
                with f.open("rb") as src:
                    while written < XNL_MAX_INPUT:
                        chunk = src.read(min(1 << 20, XNL_MAX_INPUT - written))
                        if not chunk:
                            eof = True                   # read the whole file
                            break
                        bf.write(chunk)
                        written += len(chunk)
                    else:
                        if src.read(1):                  # hit the cap mid-file -> more remained
                            capped = True
                            partial_files += 1           # NOT fully tested — this file is (partly) omitted
                        else:
                            eof = True                   # ended exactly at the cap boundary
            except Exception:
                unreadable += 1                          # NOT tested (and not a silent success)
                continue
            if eof:
                files_completed += 1                     # only a fully-read file counts as tested
            if written < XNL_MAX_INPUT:
                bf.write(b"\n")
                written += 1
    # -orig ("LINK [ORIGIN]") is OMITTED entirely: in stdin mode the origin is always "<stdin>", so the flag
    # buys nothing and would CORRUPT the endpoint value. (We do NOT post-strip a trailing "[..]": with -orig
    # never passed xnLinkFinder appends none, and a strip would mangle route templates like /users/[id].)
    # review-B-audit: `extra: list` was an UNRESTRICTED flag injection point — a caller could pass `-d 3`,
    # `-i <url>` or any other crawl flag straight into the command line of a lane whose whole contract is
    # "never requests anything". The only flag any call site actually needed is `-spo`, so that is the only
    # one that exists now: an option cannot smuggle a flag the way a list can.
    # `-orig` used to be passed and then filtered out here — in stdin mode the origin is always `<stdin>`,
    # so it is simply gone rather than accepted-and-dropped.
    # STRUCTURED input coverage per tag (emit every run so an uncapped rerun clears). tested = files read to
    # EOF ONLY; a file cut off by the 200MB cap (partial) or that raised (unreadable) is NOT counted tested —
    # it is honestly part of `omitted`. measure=files so this is never summed with the param-candidate measure.
    _n_files = len(files)
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_CAP, unit=f"{tag}:input",
                            measure="files", eligible=_n_files, tested=files_completed,
                            omitted=max(0, _n_files - files_completed),
                            reason=f"{tag}: {files_completed}/{_n_files} files fully read "
                                   f"({partial_files} partial, {unreadable} unreadable; input cap "
                                   f"{XNL_MAX_INPUT // (1024*1024)}MB)")
    return {"blob": blob, "written": written, "capped": capped, "files": _n_files,
            "files_completed": files_completed, "partial_files": partial_files,
            "unreadable_files": unreadable,
            "digest": events.file_digest(blob) if blob.exists() else ""}


def _xnl_run(ctx, tag: str, blob, written: int, *, spo: bool = False) -> dict:
    """Run the tool over one prepared blob. Returns the tool's own status and its four artifacts."""
    roots = ctx.write_list("roots.txt", ctx.profile.apex_domains)
    outs = _xnl_outputs(ctx, tag)
    out_links, out_params, out_secrets, out_wl = (outs["links"], outs["params"], outs["secrets"],
                                                  outs["wordlist"])
    # xnLinkFinder APPENDS to existing output files (dedup) unless -ow — clear the per-tag outputs and pass
    # -ow so a re-run is DETERMINISTIC (a stale artifact from an earlier invocation can't inflate the count).
    for _o in (out_links, out_params, out_secrets, out_wl):
        _o.unlink(missing_ok=True)
    cmd = ["xnLinkFinder", "-sp", str(roots), "-sf", str(roots), "-ow",
           "-o", str(out_links), "-op", str(out_params), "-all", "-mfs", "0"]
    if spo:
        # -spo (scope-prefix-original) is meaningful because `-sp` is always supplied above.
        cmd.append("-spo")
    # -owl (wordlist permutations) + -os (secrets regex) are TIMEKILLERS on large input (a 74 MB blob hangs
    # xnLinkFinder for minutes after links are written). Request them only for SMALL input; a large dir gets
    # links+params fast, a DERIVED wordlist (below) so A1d still has vocabulary, and -os skipped (secrets are
    # covered by trufflehog/gitleaks/jsluice).
    small = _xnl_wants_secrets(written)
    if small:
        cmd += ["-owl", str(out_wl), "-os", str(out_secrets)]
    # ALWAYS -d 0. This lane EXTRACTS from bytes we already hold; it never requests anything.
    #
    # It used to run the waymore-response mining at depth 3, which makes xnLinkFinder REQUEST every link it
    # extracts — and the only scope gate on those requests is the tool's own `-sf` regex
    # (xnLinkFinder 8.2, line ~1053):
    #     ^([A-Za-z]*)?(://|//|^)[^\/|?|#]*<apex>
    # which is not anchored at the END of the host. Measured against apex `acme.com`, all of these are IN
    # scope for it: `acme.com.evil.net`, `notacme.com`, `//acme.com.attacker.io`, `xacme.common.io`.
    # Quarry's own scope requires `host == apex or host.endswith("." + apex)`, so the lane was contacting
    # hosts Quarry itself refuses — from ARCHIVED THIRD-PARTY RESPONSE BODIES, i.e. content anyone can plant
    # a link in. The same crawl followed redirects (`allow_redirects=True`, xnLinkFinder 8.2:709/2519) and
    # ran with `-insecure`, so an off-scope hop was both unverified and unbounded.
    #
    # The depth parameter is GONE rather than defaulted: a parameter can be passed again by a future call
    # site, a missing one cannot. Crawling archived links is a real technique, but it needs Quarry's scope
    # and Quarry's transport — not a tool flag we cannot constrain.
    cmd += ["-d", "0"]
    # PYTHONHASHSEED=0: xnLinkFinder dedups via list(set(...)) whose iteration order is hash-seed-randomized;
    # on large/link-dense input that randomness makes the extracted SET vary run-to-run (verified: waymore
    # swung 2693..9858 endpoints at a FIXED -p, offline, no timeout — pinning the seed gives a stable 7259,
    # byte-identical across -p 1/25 and repeats). Deterministic recon needs a fixed seed.
    r = exec_tool("xnLinkFinder", cmd, timeout=ctx.http_timeout, input_file=blob,
                  env={"PYTHONHASHSEED": "0"})
    ctx.run.record("crawl", r)
    # review-B-audit#D5: the tool's OWN status was recorded and then ignored when interpreting output.
    # `-ow` truncates the four artifacts at start, so a killed run leaves whatever was flushed — real
    # evidence, and NOT a completed extraction. Both facts travel out of here.
    extraction_complete = r.status in (Status.SUCCESS, Status.EMPTY)
    return {"status": r.status, "complete": extraction_complete, "outs": outs, "small": small}


def _xnl_result(tag: str) -> dict:
    """A unit's OUTCOME CARRIER, zeroed. Created by the lane BEFORE ingestion and updated as each entity
    lands (review-B-audit-8#1): the counts used to exist only in `_xnl_ingest`'s return value, so a sink
    that raised — or a cancellation — after real writes left the store holding evidence while the terminal
    reported `FAILED / nothing extracted`."""
    return {"tag": tag, "endpoints": 0, "paths": 0, "schemeless": 0, "oos": 0, "credentials": 0,
            "params": 0, "params_seen": 0, "params_kept": 0, "wordlist": 0, "secrets": 0,
            "unusable": 0, "undecodable": 0, "unreadable": False, "parse_gap": ""}


def _xnl_ingest(ctx, tag: str, snap: dict, *, blob=None, written: int = 0, replay: bool = False,
                carrier: dict | None = None) -> dict:
    """The PARSER BOUNDARY and the entity writes, over one unit's four artifacts.

    Used by the fresh path AND by replay: fresh and replayed evidence owe the same contract, and a second
    implementation is how the two drift apart. Counts land in `carrier` AS THEY HAPPEN, so an interruption
    part-way through leaves the terminal agreeing with the store."""
    res = carrier if carrier is not None else _xnl_result(tag)
    # ── links: UNTRUSTED output, re-validated against QUARRY's scope before anything is stored ──
    # It used to be ingested as-is, "scope already applied by xnLinkFinder" — but that filter admits
    # `acme.com.evil.net` and `notacme.com` for apex `acme.com`, so the inventory was inheriting the same
    # defect the depth-3 crawl was contained for.
    src_tag = f"xnLinkFinder-{tag}"
    lines, undecodable, links_unreadable = _xnl_decode(snap["links"])
    # review-B-audit-2#2: these used to count only what `add()` reported as NEW, so an endpoint jsluice had
    # already stored made the parser look like it had rejected it (`tested=0` for a line it accepted).
    # ACCEPTANCE is a parser fact; NOVELTY is a store fact. Both are counted, separately.
    n_ignored = n_bad_links = 0                            # local aliases for the telemetry lines below
    # review-B-audit-10#2: the DERIVED wordlist used to be built by re-decoding the raw artifacts with
    # `errors="replace"`, so a line the strict reader REJECTED as undecodable still contributed words —
    # and those words drive an ACTIVE puredns brute in A1d. Derivation now consumes only values this
    # boundary accepted.
    accepted: list = []
    res["undecodable"] += undecodable
    res["unreadable"] = res["unreadable"] or links_unreadable
    # ...and new to the store. review-B-audit-4 (note): `xnl_stored` reported novelty for surface only,
    # because the other `add()` results were discarded — so a re-run looked like it had stored nothing new
    # even when it had recorded a fresh off-scope link or credential.
    new_endpoints = new_paths = new_schemeless = new_oos = new_credential = 0
    for line in lines:
        kind, v = _xnl_classify_link(line, ctx.scope)
        if kind == XNL_ENDPOINT:
            # counted AFTER the write returns: a line the parser accepted and the store REFUSED (already
            # present) is still production, but a write that RAISED never happened (review-B-audit-8#1).
            stored = ctx.run.add("endpoint", {"value": v, "sources": [src_tag]})
            res["endpoints"] += 1
            accepted.append(v)
            new_endpoints += 1 if stored else 0
        elif kind == XNL_PATH:
            # a relative path has no host, so it is not contactable on its own — and the concatenated stdin
            # blob has already destroyed which file it came from. `origin: unbound` says that plainly rather
            # than letting a consumer assume the path belongs to some particular site.
            stored = ctx.run.add("endpoint", {"value": v, "kind": "path", "origin": "unbound",
                                              "sources": [src_tag]})
            res["paths"] += 1
            accepted.append(v)
            new_paths += 1 if stored else 0
        elif kind == XNL_SCHEMELESS:
            # a host we may well own, but with NO scheme we were told — kept verbatim and marked unbound on
            # both axes, so nothing downstream can turn it into a request.
            stored = ctx.run.add("endpoint", {"value": v, "kind": "scheme-relative", "scheme": "unbound",
                                              "origin": "unbound", "sources": [src_tag]})
            res["schemeless"] += 1
            accepted.append(v)
            new_schemeless += 1 if stored else 0
        elif kind == XNL_CREDENTIAL:
            # DISCOVERED credentials are a finding, not noise. Verbatim — masking a discovered secret would
            # destroy the evidence; only Quarry's OWN configured credentials are redacted from telemetry.
            stored = ctx.run.add("review", {"id": f"{src_tag}:cred:{v}", "klass": "credential-in-url",
                                            "value": v,
                                            "note": f"{src_tag} extracted a URL carrying USERINFO — never "
                                                    f"contacted (the authority is ambiguous), retained "
                                                    f"verbatim as evidence",
                                            "sources": [src_tag]})
            res["credentials"] += 1
            new_credential += 1 if stored else 0
        elif kind == XNL_IGNORED:
            n_ignored += 1                     # blank lines and the tool's own token: neither finding nor error
        elif kind == XNL_OOS:
            # the archive really did link there: real evidence, and NOT surface. `endpoint` feeds lanes that
            # go on to contact things, so an off-scope URL is retained where nothing active consumes it.
            stored = ctx.run.add("review", {"id": f"{src_tag}:oos:{v}", "klass": "oos-link", "value": v,
                                            "note": f"{src_tag} extracted an OFF-SCOPE link — retained as "
                                                    f"evidence, never probed (Quarry scope, not the "
                                                    f"tool's filter)",
                                            "sources": [src_tag]})
            res["oos"] += 1
            new_oos += 1 if stored else 0
        else:
            res["unusable"] += 1
            n_bad_links += 1                   # local alias for the telemetry line below
    n_endpoints, n_paths, n_schemeless = res["endpoints"], res["paths"], res["schemeless"]
    n_credential, n_oos = res["credentials"], res["oos"]
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:links",
                            # IGNORED noise is neither eligible nor omitted: it was never a candidate.
                            measure="links", eligible=len(lines) - n_ignored + undecodable,
                            tested=n_endpoints + n_paths + n_schemeless + n_oos + n_credential,
                            omitted=n_bad_links + undecodable,
                            reason=(f"{tag}: {n_endpoints} in-scope, {n_paths} relative, {n_schemeless} "
                                    f"scheme-relative, {n_oos} off-scope, {n_credential} credential-bearing "
                                    f"(evidence only); {n_bad_links} unusable, {undecodable} undecodable"
                                    + ("; LINK OUTPUT UNREADABLE" if links_unreadable else "")))

    # ── params: xnLinkFinder emits POTENTIAL params (path words / JSON keys / JS vars / input names / meta)
    #    — NOT confirmed request params. Store as CANDIDATES (kind=potential), ALL of them: the inventory
    #    is retention, and nothing turns a stored candidate into a request (step 4.1). Drop <stdin>. ──
    n_params_added = 0
    param_lines, param_undecodable, params_unreadable = _xnl_decode(snap["params"])
    res["undecodable"] += param_undecodable
    res["unreadable"] = res["unreadable"] or params_unreadable
    cand_set, n_bad_params = set(), param_undecodable
    for line in param_lines:
        ok, v = _xnl_classify_param(line)
        if ok:
            cand_set.add(v)
        elif v:
            n_bad_params += 1                 # a sentence, a code fragment, binary noise — not a param name
    cand = sorted(cand_set)
    n_params_seen = len(cand)
    # review-B-audit-9#1: `params` was the PARSER-SEEN count, assigned before the first write — so a store
    # that raised on the first parameter still reported every candidate as produced. Production is what was
    # DELIVERED; parser-seen and novelty are their own counters.
    res["params_seen"] = n_params_seen
    res["unusable"] += n_bad_params
    # step 4.1: EVERY accepted candidate is stored. Sorted so a re-run writes them in the same order (the
    # tool's -op order is set-derived and unstable); nothing is dropped.
    for v in cand:
        stored = ctx.run.add("parameter", {"value": v, "kind": "potential",
                                           "sources": [f"xnLinkFinder-{tag}"]})
        res["params"] += 1                     # delivered: the write returned (novel or already present)
        if stored:
            n_params_added += 1
            res["params_kept"] = n_params_added
    # STRUCTURED param coverage per tag (emit every run): eligible = distinct POTENTIAL params xnLinkFinder
    # produced, tested = stored. Since step 4.1 nothing is dropped by policy, so `omitted` is 0 and this
    # record CLEARS the cap gap a v1 run left behind; only unusable lines are still counted as rejected.
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_CAP, unit=f"{tag}:params",
                            measure="potential_params",
                            eligible=n_params_seen, tested=n_params_seen, omitted=0,
                            reason=f"{tag}: {n_params_seen}/{n_params_seen} potential params retained "
                                   f"(no cap); {n_bad_params} rejected as unusable")

    # ── A1d vocabulary: if -owl was skipped (large), DERIVE a target wordlist from the mined links+params
    #    (path segments + param names are exactly the useful brute words) so A1d isn't starved; record the
    #    -owl/-os skip. The artifact is the RETAINED corpus — how much of it is ever brute-forced is
    #    `vertical._target_wordlist`'s decision, and that bound lives there (step 4.1). ──
    # `-owl`/`-os` are requested only for SMALL input (see `_xnl_run`); the same threshold decides here
    # whether a wordlist must be DERIVED instead. Computed from the blob size the caller passed, so the
    # replay path reaches the same conclusion the fresh path did.
    # review-B-audit-8#2: computed HERE, before the derived wordlist is written, so it asks what the TOOL
    # produced. `-o`/`-op` are always requested; `-owl` only on small input.
    # ABSENCE only. An artifact that is there and UNREADABLE is our machinery failing, and each reader
    # (`_xnl_lines`, `_lines`, `_xnl_secrets`) already says so from its own read — a second verdict here
    # would be a duplicate no test could distinguish.
    asked_for = {"-o": True, "-op": True, "-owl": _xnl_wants_secrets(written)}
    tool_missing = [name for name in ("-o", "-op", "-owl")
                    if asked_for[name] and snap[{"-o": "links", "-op": "params",
                                                 "-owl": "wordlist"}[name]][0] == "absent"]
    if written >= XNL_WORDLIST_LIMIT and not replay:
        # (on REPLAY the owned bundle already carries the derived wordlist — deriving it again would be a
        # second answer to a question the mining run already answered and bound by digest.)
        words = set()
        for value in accepted + cand:
            for w in re.split(r"[^A-Za-z0-9]+", value.lower()):
                if 3 <= len(w) <= 30 and not w.isdigit():
                    words.add(w)
        # step 4.1: the derived vocabulary is RETAINED whole. How much of it is ever brute-forced is the
        # A1d selection's decision (`vertical._target_wordlist`), and that bound is unchanged here.
        derived = ("\n".join(sorted(words)) + "\n").encode()
        out_wl = _xnl_outputs(ctx, tag)["wordlist"]
        out_wl.write_bytes(derived)
        snap["wordlist"] = ("ok", derived)     # OUR artifact now, and the bytes that will be published
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: -owl skipped ({written // (1024*1024)}MB input, timekiller) — "
                                       f"wordlist DERIVED from links/params ({len(words)}); -os skipped "
                                       f"(secrets covered by trufflehog/gitleaks/jsluice)")

    # ── ledger over all four artifacts + suspicious-empty (real input, none produced) ──
    # the wordlist is counted the same STRICT way as every other artifact: an undecodable line is not a
    # word, it is a rejected line (review-B-audit-10#2).
    wl_lines, wl_undecodable, wl_unreadable = _xnl_decode(snap["wordlist"])
    res["unreadable"] = res["unreadable"] or wl_unreadable
    res["undecodable"] += wl_undecodable
    n_words = len([ln for ln in wl_lines if ln.strip()])
    res["wordlist"] = n_words
    # review-B-audit-11#1: a REASON-ONLY coverage event never reaches the verdict — the reconciler admits
    # structured counters (or COVERAGE_UNKNOWN) only. These words arm an ACTIVE brute in A1d, so a line we
    # dropped is un-mined vocabulary and must gate the run. Emitted EVERY run so a clean rerun clears it.
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:wordlist",
                            measure="wordlist_lines", eligible=n_words + wl_undecodable,
                            tested=n_words, omitted=wl_undecodable,
                            reason=(f"{tag}: {n_words} wordlist line(s) usable, {wl_undecodable} not valid "
                                    f"UTF-8 and DROPPED (this vocabulary drives the A1d brute)"
                                    + ("; WORDLIST OUTPUT UNREADABLE" if wl_unreadable else "")))
    n_secrets, n_secret_bad, secret_gap = _xnl_secrets(ctx, tag, snap["secrets"],
                                                       requested=_xnl_wants_secrets(written), carrier=res)
    # `-o`, `-op` and (on small input) `-owl` are requested EXPLICITLY, and the MEASURED no-find shape of
    # each is an EMPTY FILE, not an absent one (xnLinkFinder 8.2, empty stdin blob: links/params/wordlist
    # all created at 0 bytes, secrets `[]`). A requested artifact that is missing is our blind spot, and
    # the unit stays retryable.
    missing = tool_missing
    gaps = [g for g in (secret_gap,
                        (f"{tag}: {', '.join(missing)} requested and no artifact written (the measured "
                         f"no-find shape is an EMPTY FILE) — unit retryable") if missing else "") if g]
    res["parse_gap"] = "; ".join(gaps)
    events.ledger("crawl.xnlinkfinder", unit=tag, replay=replay,
                  produced={"endpoints": n_endpoints, "paths": n_paths, "oos_links": n_oos,
                            "scheme_relative": n_schemeless, "credential_urls": n_credential,
                            "potential_params": n_params_seen, "params_kept": n_params_added,
                            "wordlist": n_words, "secrets": n_secrets},
                  # what the tool emitted that Quarry REFUSED to treat as surface. A parser boundary that
                  # reports nothing is indistinguishable from a tool that emitted nothing.
                  xnl_rejected={"links_unusable": n_bad_links, "links_undecodable": undecodable,
                                "params_unusable": n_bad_params, "off_scope_links": n_oos,
                                "links_ignored": n_ignored, "secrets_unusable": n_secret_bad,
                                "wordlist_undecodable": wl_undecodable},
                  # ACCEPTED vs NEW: a line the parser took that the store already had is not a rejection.
                  xnl_stored={"endpoints_new": new_endpoints, "paths_new": new_paths,
                              "scheme_relative_new": new_schemeless, "oos_links_new": new_oos,
                              "credential_urls_new": new_credential, "params_new": n_params_added},
                  # an artifact that EXISTS and cannot be read is our machinery failing, not a zero result.
                  # Step 3 turns these into a gap; recorded now so the fact is not invented later.
                  xnl_unreadable={"links": links_unreadable, "params": params_unreadable,
                                  "wordlist": wl_unreadable})
    # a run that produced NOTHING usable is suspicious; one that produced only off-scope links is a
    # different fact, so both are named.
    if written > 512 and not (n_endpoints or n_paths or n_params_seen or n_words or n_secrets or n_oos
                              or n_schemeless or n_credential):
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: {written}B input -> 0 links/params/words/secrets "
                                       f"(capability drift? input kept: "
                                       f"{blob.name if blob is not None else '?'})")
    # the carrier IS the result: everything above wrote into it as it happened. (A PARSE GAP is neither an
    # unreadable file nor a zero result: the artifact is retained evidence we could not fully account for,
    # so the unit stays retryable — review-B-audit-6#4.)
    return res
