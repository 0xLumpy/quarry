"""Phase 5: Crawl + URL/archive + JS mining (deepened).

katana (batched, RAM-safe) + gau + waymore (-mode U) -> url corpus; download JS,
beautify, dedup; jsluice urls+secrets; xnLinkFinder over the JS dir AND over waymore
RESPONSE dirs (-mode R + xnLinkFinder -orig = the "killer combo"); source-map recovery;
gitleaks + trufflehog secret scans.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

from .. import budget, events, fetch, normalize, secrets, settings
from ..contract import run_contract
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
            SPA_CAP = 10
            _spa_all = sorted({u for u in targets.read_text().splitlines()
                               if any(k in u.lower() for k in
                               ("app", "portal", "dashboard", "account", "my-", "/app"))})
            spa = _spa_all[:SPA_CAP]
            # MODES.HEADLESS enables headless crawling; it does NOT request "first 10 only" — so the 10-cap is a
            # HIDDEN CAP (gates when it drops hosts), not an operator-chosen sample. Emit every run (clears prior).
            _n_spa = len(_spa_all)
            events.coverage_partial("crawl.katana_headless", kind=events.COVERAGE_CAP, measure="spa_hosts",
                                    eligible=_n_spa, tested=min(_n_spa, SPA_CAP), omitted=max(0, _n_spa - SPA_CAP),
                                    reason=f"headless SPA {min(_n_spa, SPA_CAP)}/{_n_spa} app-like hosts (cap {SPA_CAP})")
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
        if mode == "B" and have("xnLinkFinder") and len([p for p in wdir.iterdir() if p.name != "waymore.txt"]) > 1:
            # OFFLINE mining of the archived bodies only — see `_xnl` for why depth-3 crawling is gone.
            _xnl(ctx, str(wdir), f"waymore-{d}", spo=True)

    # ── download JS, dedup, beautify ──
    js_ledger, js_raw_dir = _js_download(ctx)

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
    if recov_files and have("xnLinkFinder"):
        if recov_dir:
            _xnl(ctx, str(recov_dir), "sourcemap")

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
        _xnl(ctx, str(js_derived_dir), "js")

    # ── xnLinkFinder over katana's stored responses (flags.md: crawl-then-mine) ──
    if have("xnLinkFinder") and kat_resp.exists() and any(kat_resp.iterdir()):
        _xnl(ctx, str(kat_resp), "katana-resp")

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

    ctx.echo(f"  urls: {ctx.run.count('url')}  js: {ctx.run.count('js_url')}  "
             f"endpoints: {ctx.run.count('endpoint')}  params: {ctx.run.count('parameter')}  "
             f"secrets: {ctx.run.count('secret')}")


XNL_MAX_INPUT = 200 * 1024 * 1024      # cap the stdin blob so a huge dir can't blow RAM
XNL_WORDLIST_LIMIT = 10 * 1024 * 1024  # -owl/-os are permutation timekillers on big input -> small only
XNL_PARAM_CAP = 2000                   # xnLinkFinder emits POTENTIAL params (noisy) -> cap per call
XNL_WORDLIST_DERIVE_CAP = 5000         # bounded vocabulary derived from links/params when -owl is skipped


def _xnl(ctx, indir: str, tag: str, *, spo: bool = False) -> None:
    roots = ctx.write_list("roots.txt", ctx.profile.apex_domains)
    safe_tag = tag.replace("/", "_").replace(".", "_")
    out_links = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_links.txt")
    out_params = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_params.txt")
    out_secrets = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_secrets.json")
    out_wl = ctx.run.raw_path("crawl", "xnLinkFinder", f"{safe_tag}_wordlist.txt")
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
    # xnLinkFinder APPENDS to existing output files (dedup) unless -ow — clear the per-tag outputs and pass
    # -ow so a re-run is DETERMINISTIC (a stale artifact from an earlier invocation can't inflate the count).
    for _o in (out_links, out_params, out_secrets, out_wl):
        _o.unlink(missing_ok=True)
    # -orig ("LINK [ORIGIN]") is useless in stdin mode — origin is always "<stdin>" and would CORRUPT the
    # endpoint value — so strip it from the flags. (We do NOT post-strip a trailing "[..]": with -orig gone
    # xnLinkFinder never appends one, and a strip would mangle legitimate route templates like /users/[id].)
    # review-B-audit: `extra: list` was an UNRESTRICTED flag injection point — a caller could pass `-d 3`,
    # `-i <url>` or any other crawl flag straight into the command line of a lane whose whole contract is
    # "never requests anything". The only flag any call site actually needed is `-spo`, so that is the only
    # one that exists now: an option cannot smuggle a flag the way a list can.
    # `-orig` used to be passed and then filtered out here — in stdin mode the origin is always `<stdin>`,
    # so it is simply gone rather than accepted-and-dropped.
    cmd = ["xnLinkFinder", "-sp", str(roots), "-sf", str(roots), "-ow",
           "-o", str(out_links), "-op", str(out_params), "-all", "-mfs", "0"]
    if spo:
        # -spo (scope-prefix-original) is meaningful because `-sp` is always supplied above.
        cmd.append("-spo")
    # -owl (wordlist permutations) + -os (secrets regex) are TIMEKILLERS on large input (a 74 MB blob hangs
    # xnLinkFinder for minutes after links are written). Request them only for SMALL input; a large dir gets
    # links+params fast, a DERIVED wordlist (below) so A1d still has vocabulary, and -os skipped (secrets are
    # covered by trufflehog/gitleaks/jsluice).
    small = written < XNL_WORDLIST_LIMIT
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

    # ── endpoints: ingest as-is (scope already applied by xnLinkFinder; no -orig -> no origin suffix) ──
    n_endpoints = 0
    if out_links.exists():
        for line in out_links.read_text(errors="replace").splitlines():
            v = line.strip()
            if v and ctx.run.add("endpoint", {"value": v, "sources": [f"xnLinkFinder-{tag}"]}):
                n_endpoints += 1

    # ── params: xnLinkFinder emits POTENTIAL params (path words / JSON keys / JS vars / input names / meta)
    #    — NOT confirmed request params. Store as CANDIDATES (kind=potential) with a per-call CAP so a 52k
    #    dump can't flood the inventory / downstream arjun. Drop the <stdin> noise token. ──
    n_params_added = 0
    cand = sorted({ln.strip() for ln in out_params.read_text(errors="replace").splitlines()
                   if ln.strip() and ln.strip() != "<stdin>"}) if out_params.exists() else []
    n_params_seen = len(cand)
    # cap a DETERMINISTIC subset: sort first, then keep the first N — so a re-run keeps the SAME candidates
    # (xnLinkFinder's -op file order is set-derived / unstable; capping the raw order was non-idempotent).
    for v in cand[:XNL_PARAM_CAP]:
        if ctx.run.add("parameter", {"value": v, "kind": "potential", "sources": [f"xnLinkFinder-{tag}"]}):
            n_params_added += 1
    # STRUCTURED param coverage per tag (emit every run): eligible = distinct POTENTIAL params xnLinkFinder
    # produced, tested = kept under the cap, omitted = dropped. These are candidates (path words/JSON keys/JS
    # vars — not all request params) but a dropped candidate is still un-mined surface, so this is honestly a
    # gap; priority follows the generic 10%/100 rule (a large omission is `major`, like any other cap).
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_CAP, unit=f"{tag}:params",
                            measure="potential_params",
                            eligible=n_params_seen, tested=min(n_params_seen, XNL_PARAM_CAP),
                            omitted=max(0, n_params_seen - XNL_PARAM_CAP),
                            reason=f"{tag}: {min(n_params_seen, XNL_PARAM_CAP)}/{n_params_seen} potential params "
                                   f"(cap {XNL_PARAM_CAP})")

    # ── A1d vocabulary: if -owl was skipped (large), DERIVE a bounded target wordlist from the mined
    #    links+params (path segments + param names are exactly the useful brute words) so A1d isn't starved;
    #    record the -owl/-os skip. ──
    if not small:
        words = set()
        for p in (out_links, out_params):
            if not (p.exists() and len(words) < XNL_WORDLIST_DERIVE_CAP):
                continue
            for ln in p.read_text(errors="replace").splitlines():
                for w in re.split(r"[^A-Za-z0-9]+", ln.lower()):
                    if 3 <= len(w) <= 30 and not w.isdigit():
                        words.add(w)
                if len(words) >= XNL_WORDLIST_DERIVE_CAP:
                    break
        out_wl.write_text("\n".join(sorted(words)[:XNL_WORDLIST_DERIVE_CAP]) + "\n")
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: -owl skipped ({written // (1024*1024)}MB input, timekiller) — "
                                       f"wordlist DERIVED from links/params ({len(words)}); -os skipped "
                                       f"(secrets covered by trufflehog/gitleaks/jsluice)")

    # ── ledger over all four artifacts + suspicious-empty (real input, none produced) ──
    def _lines(p):
        return len([ln for ln in p.read_text(errors="replace").splitlines() if ln.strip()]) if p.exists() else 0
    n_words = _lines(out_wl)
    n_secrets = 0
    if out_secrets.exists():
        try:
            sd = json.loads(out_secrets.read_text() or "[]")
            n_secrets = len(sd) if isinstance(sd, (list, dict)) else 0
        except Exception:
            n_secrets = 0
    events.ledger("crawl.xnlinkfinder",
                  produced={"endpoints": n_endpoints, "potential_params": n_params_seen,
                            "params_kept": n_params_added, "wordlist": n_words, "secrets": n_secrets})
    if written > 512 and not (n_endpoints or n_params_seen or n_words or n_secrets):
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: {written}B input -> 0 links/params/words/secrets "
                                       f"(capability drift? input kept: {blob.name})")
