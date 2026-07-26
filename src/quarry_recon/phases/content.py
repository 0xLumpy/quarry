"""Content discovery (Phase 11) — candidate-driven, scope-safe ffuf. Default OFF.

Intensity via MODES.CONTENT_DISCOVERY: off | light | balanced | deep (11.1 = off/light/balanced,
flat). Recursion (MODES.CONTENT_RECURSION) is 11.2. Guardrails: skipped in passive mode and when
off; only live, in-scope, active-allowed hosts (origin-first ORDER, never capped); ffuf -ac autocalibration
always (kills wildcard/catch-all floods); http_rl -> ffuf -rate. Map-don't-exploit: results are
url + review candidates, never actions.
"""
from __future__ import annotations

import hashlib
from importlib import resources
from pathlib import Path

from .. import budget, events, normalize, settings
from ..contract import run_contract
from ..runner import (Status, ffuf_http_row, ffuf_results, ffuf_usable_rows,
                      fresh_artifact_dir as runner_fresh,
                      have, reclassify_ffuf, run as exec_tool, scaled_timeout, skipped)

# No MAX_HOSTS / MAX_RESULTS_PER_HOST. Both were MEMBERSHIP caps: the first silently excluded 473 of 498
# eligible hosts on the OTC run, the second discarded discovered URLs. Bound THROUGHPUT and ORDER, never
# membership — full eligible set, ranked-then-fair order, a wall-clock budget that defaults to UNBOUNDED,
# and a per-target resumable ledger for whatever a bounded run did not reach.
# review#3 (A1): there is NO row budget. A configurable first-N is still a MEMBERSHIP cap — it permanently
# discarded already-discovered URLs, and raising the setting later could not recover them because the
# service resumes instead of re-parsing. The expensive network work has already happened; store ingestion
# needs no breadth bound. A flood is FLAGGED, never discarded.
_CONTENT_SCHEMA = 2      # review#4 (A1 r2): the row parser got STRICTER (typed url/status). Bumping the
                         # adapter schema invalidates work units whose artifacts an older, looser parser
                         # accepted — otherwise those stay resumable under the new contract.
_NOTABLE = {200, 401, 403}         # statuses worth a review-queue entry


def _wordlist(ctx, tier: str) -> Path | None:
    """Resolve the wordlist for a tier. `light` ships with the package (always available);
    `balanced`/`deep` come from framework-managed lists (install/user-provided)."""
    home = Path.home()
    override = home / ".config" / "quarry" / "wordlists" / "content" / f"{tier}.txt"
    if override.exists():
        return override
    if tier == "light":            # shipped curated list -> materialize to the run workdir
        try:
            data = resources.files("quarry_recon.data").joinpath("content-light.txt").read_text()
        except Exception:
            return None
        p = ctx.tmp("content-light.txt")
        p.write_text(data)
        return p
    for c in (home / "wordlists" / f"{tier}.txt",
              home / "wordlists" / "seclists" / "Discovery" / "Web-Content" /
              ("raft-medium-directories.txt" if tier == "balanced" else "raft-large-directories.txt")):
        if c.exists():
            return c
    return None


def _configleak_words() -> list[str]:
    """Shipped curated high-signal config/secret/VCS/dangerous-endpoint paths (bare, ffuf FUZZ)."""
    try:
        data = resources.files("quarry_recon.data").joinpath("content-configleak.txt").read_text()
    except Exception:
        return []
    return [w.strip() for w in data.splitlines() if w.strip() and not w.startswith("#")]


def _merged_wordlist(ctx, wl: Path) -> Path:
    """Union the tier wordlist with the always-on config-leak list (dedup, order-preserving), so the
    high-signal secret/config paths are checked on EVERY content run regardless of tier."""
    extra = _configleak_words()
    if not extra:
        return wl
    seen: set[str] = set()
    words: list[str] = []
    for w in extra + wl.read_text().splitlines():        # config-leak first (highest-signal paths)
        w = w.strip()
        if w and not w.startswith("#") and w not in seen:
            seen.add(w)
            words.append(w)
    merged = ctx.tmp("content-fuzz.txt")
    merged.write_text("\n".join(words) + "\n")
    return merged


def _run_one(ctx, url, wl, wl_digest, mc, recurse, ct_to, out, prof):
    """One ffuf content sweep against one service, under the contract.

    Redirect policy (DELIBERATE exception to the follow-redirects rule the classify-probes obey): content
    discovery RECORDS what exists at a path — a path returning 301/302/307/308 IS a finding (`/admin`->
    `/login`, `/.git`->redirect: the path exists + where it goes is intel). So we MATCH 3xx (-mc) instead of
    following (-r): following would classify many distinct paths onto one login/home page, -ac/dedup would
    then drop them, and the "this path exists" signal is lost. -ac already neutralises the
    redirect-everything catch-all. (ISC-16, v0.3.)

    -maxtime is the GRACEFUL whole-run ceiling (bounds the call incl. recursion sub-jobs) so a slow origin
    writes its partial -o instead of a hard SIGKILL-empty; exec_tool's timeout is the hard backstop.
    -noninteractive: batch hygiene (no keybinding console). (T2.2)"""
    cmd = ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", str(wl), "-ac", "-timeout", "7",
           "-noninteractive",
           "-t", str(settings.workers("ffuf", 40)),   # H2: core-scaled concurrency
           "-mc", mc, "-of", "json", "-o", str(out), "-s"]
    if ct_to:                                    # 0 = fully unbounded (RoE no-cut) -> no ceiling at all
        cmd += ["-maxtime", str(ct_to)]
    if prof.http_rl:
        cmd += ["-rate", str(prof.http_rl)]
    if recurse:                                  # 11.2: balanced/deep only (gated by the caller)
        cmd += ["-recursion", "-recursion-depth", str(recurse)]
    hard = ct_to + 60 if ct_to else 0            # backstop when bounded; stays UNBOUNDED (0) when ct_to==0
    # C07 inc3: per-TARGET work_unit (content.ffuf is per-target, NOT single-shot) binds the target URL +
    # coverage config (match codes, recursion depth, wordlist) + wordlist digest -> re-run on any change.
    wu = events.work_unit("content.ffuf", inputs={"url": url},
                          config={"mc": mc, "recursion": recurse, "wordlist": wl.name},
                          file_digests={"wordlist": wl_digest}, schema_version=_CONTENT_SCHEMA)
    errf = out.with_suffix(".stderr.log")        # FULL stderr: the -maxtime marker must not be evictable
    return run_contract("content.ffuf", cmd, work_unit=wu, timeout=hard, stderr_path=errf,
                        reclassify=lambda res, o=out, e=errf: reclassify_ffuf(res, o, e, ct_to or None))


def _ingest_status(out) -> tuple:
    """(trustworthy, clean_rows) for ONE artifact — the completion judgement for the CURRENT attempt only.

    review#1 (A1 r3): aggregating this across every retained attempt meant a dirty run-1 artifact blocked
    completion forever, even after a clean run-2. Completion is about the attempt just made."""
    rows = ffuf_results(out)
    if rows is None:
        return False, False
    _usable, dropped = ffuf_usable_rows(rows, ffuf_http_row)
    return True, dropped == 0


def _ingest(ctx, scope, host, svc, artifacts, current, seen_notable, launched) -> None:
    """Ingest EVERY retained artifact for one service, then report coverage for the CURRENT one.

    review#2 (A1 r2): completion and RETAINED EVIDENCE are separate. Reading only the current attempt left
    one killed mid-ingest on disk, absent from the ledger and never replayed.

    review#3 (A1 r2): coverage is emitted AFTER consumption and counts rows that actually reached the store.

    review#5 (A1 r3): the denominator is USABLE, IN-SCOPE rows. An out-of-scope row is a deliberate filter,
    not a coverage loss. Rows failing the TYPE contract are not a Quarry ceiling either, so they read as
    UNKNOWN rather than as a CAP gap.

    review#2 (A1 r4): HISTORY IS PROVENANCE ONLY. Aggregating schema trust across historical artifacts meant
    one dirty old artifact emitted COVERAGE_UNKNOWN forever — a clean rerun could never clear the gap even
    once it earned completion. This generation's coverage verdict is computed from `current` alone (the
    artifact this lifecycle stands behind); older ones are still replayed so their findings survive."""
    # review#2 (A1 r5): `notable` used to increment per ROW per ARTIFACT, so one unique notable path became
    # 10 or 20 in the console as retries and resumes replayed the same rows. Identities are collected in a
    # per-lifecycle SET; provenance replay no longer inflates the count.
    try:
        for out in artifacts:
            rows = ffuf_results(out)
            if rows is None:
                continue                                      # untrustworthy history: replay nothing from it
            usable, _dropped = ffuf_usable_rows(rows, ffuf_http_row)
            for res in usable:
                u, st = res["url"], res["status"]
                if not scope.in_scope(normalize.host_of_url(u)):
                    continue                                  # deliberately filtered
                ctx.run.add("url", {"url": u, "status": st, "sources": ["ffuf"], "raw_ref": str(out)})
                if st in _NOTABLE:
                    rid = f"content:{u}"
                    ctx.run.add("review", {"id": rid, "klass": "content",
                                           "value": f"[{st}] {u}", "host": host,
                                           "sources": ["ffuf"], "raw_ref": str(out)})
                    seen_notable.add(rid)
    except Exception:
        # review#3 (A1 r2): a store-write failure must never be reported as successful ingestion. (Dropped
        # while rewriting _ingest for r4 and caught by the existing regression — restored.)
        events.coverage_partial("content.ffuf", kind=events.COVERAGE_UNKNOWN, unit=f"results:{svc}",
                                measure="result_rows",
                                reason=f"{host}: ingestion failed mid-artifact — row coverage UNMEASURED")
        raise
    # ── coverage for THIS generation: the current artifact only ──
    if current is None:
        events.coverage_partial("content.ffuf", kind=events.COVERAGE_UNKNOWN, unit=f"results:{svc}",
                                measure="result_rows",
                                reason=(f"{host}: "
                                        + ("attempted but produced no ffuf artifact" if launched
                                           else "no current artifact this lifecycle (not launched)")
                                        + " — row coverage UNMEASURED"))
        return
    rows = ffuf_results(current)
    if rows is None:
        events.coverage_partial("content.ffuf", kind=events.COVERAGE_UNKNOWN, unit=f"results:{svc}",
                                measure="result_rows",
                                reason=f"{host}: current ffuf artifact missing/malformed — UNMEASURED")
        return
    usable, dropped = ffuf_usable_rows(rows, ffuf_http_row)
    if dropped:
        events.coverage_partial("content.ffuf", kind=events.COVERAGE_UNKNOWN, unit=f"results:{svc}",
                                measure="result_rows",
                                reason=f"{host}: {dropped} row(s) failed the url/status type contract "
                                       f"— row coverage UNMEASURED")
        return
    in_scope = [r for r in usable if scope.in_scope(normalize.host_of_url(r["url"]))]
    # unit = the SERVICE identity, same as the raw artifact — http/https/:port on one host are DISTINCT
    # services and must not share a coverage unit. measure=result_rows so it is never summed with hosts.
    events.coverage_partial("content.ffuf", kind=events.COVERAGE_TIMEOUT, unit=f"results:{svc}",
                            measure="result_rows",
                            eligible=len(in_scope), tested=len(in_scope), omitted=0,
                            reason=(f"{host}: {len(in_scope)} in-scope row(s) ingested"
                                    + (" (a large row count is likely a wildcard/-ac flood, flagged not "
                                       "discarded)" if len(in_scope) > 500 else "")))


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    tier = prof.content_discovery
    if tier == "off" or scope.passive_only:
        ctx.run.record("content", skipped("ffuf", f"content discovery: {tier} / passive — skipped"))
        return
    if not have("ffuf"):
        ctx.run.record("content", skipped("ffuf", "ffuf not installed"))
        return
    wl = _wordlist(ctx, tier)
    if not wl:
        ctx.run.record("content", skipped(
            "ffuf", f"no '{tier}' wordlist (~/.config/quarry/wordlists/content/{tier}.txt)"))
        return
    wl = _merged_wordlist(ctx, wl)                        # +config-leak quick-hunt (always merged)

    # eligible = every active-allowed live service with a url. NOT capped.
    cand = [l for l in ctx.run.read("live")
            if scope.active_allowed(normalize.host_of_url(l.get("url", "")))]
    eligible = [l for l in cand if l.get("url")]
    if not eligible:
        ctx.run.record("content", skipped("ffuf", "no active-allowed live hosts"))
        return
    # recursion is a separate knob, allowed on balanced/deep only (light stays a flat sweep)
    recurse = prof.content_recursion if tier in ("balanced", "deep") else 0
    rec = f", recursion depth {recurse}" if recurse else ""
    if recurse >= 4:
        ctx.echo(f"  ⚠️  recursion depth {recurse} is aggressive — expect a loud / slow scan")

    seen_notable: set = set()
    # review#4 (A1 r3): EXECUTION completion and ARTIFACT usability are separate counters — one
    # malformed clean run used to increment both ff_clean and ff_partial.
    ff_clean = ff_partial = ff_blocked = ff_errors = ff_resumed = ff_unusable = 0
    # workload-scaled ceiling per host: content brute is the balanced/deep+recursion path, so on a real
    # target it hits the same flat-1800s wall the vhost/probe ffuf did. Scale by wordlist size × recursion
    # depth (recursion multiplies the paths fuzzed). Merged wordlist counted once.
    wl_n = sum(1 for _ in wl.open())
    ct_to = scaled_timeout(wl_n * (recurse + 1), ctx.http_timeout, per_unit=0.4)
    wl_digest = events.file_digest(wl)                       # C07 inc3: wordlist change → new work_unit
    _mc = "200,204,301,302,307,308,401,403,405"
    # the ledger is namespaced by the COVERAGE CONFIG: an artifact produced under a different wordlist or
    # match-code set still validates by digest, and must NOT be treated as this generation's completed work.
    cfg_fp = events.work_unit("content.ffuf", inputs={}, config={"mc": _mc, "recursion": recurse,
                                                                "wordlist": wl.name, "tier": tier},
                              file_digests={"wordlist": wl_digest}, schema_version=_CONTENT_SCHEMA)
    state_base = ctx.run.dir / "raw" / "content"
    state_base.mkdir(parents=True, exist_ok=True)
    budget.prune_state(state_base, "content.ffuf", cfg_fp)
    ledger = budget.Ledger(budget.state_path(state_base, "content.ffuf", cfg_fp), lane="content.ffuf")
    ff_budget = budget.Budget(budget.budget_seconds("CONTENT_FFUF_BUDGET_S"))
    # review#2 (A1): evidence is IMMUTABLE. Reusing one fixed path meant a retry (or a config change)
    # unlinked an artifact the store already referenced by raw_ref. Each attempt writes into its own dir,
    # and a RESUMED target reads the artifact the LEDGER recorded — never a recomputed path.
    cfg_dir = state_base / "ffuf" / cfg_fp[:16]
    attempt_dir = runner_fresh(cfg_dir)
    # RANK decides order, never membership: origin (non-CDN) services first, then round-robin by host so one
    # host's several services cannot drain a bounded run before another host is reached.
    ordered = budget.order_ranked_fair(eligible, rank=lambda l: 1 if l.get("cdn") else 0,
                                       group=lambda l: normalize.host_of_url(l.get("url", "")))
    n_resumed = sum(1 for l in ordered if ledger.has(l["url"]))
    ctx.echo(f"  content discovery [{tier}]: {len(eligible)} service(s) eligible"
             + (f", {n_resumed} resumed" if n_resumed else "") + f", wordlist {wl.name}{rec}")
    attempted = 0
    for _l in ordered:
        url = _l["url"]
        host = normalize.host_of_url(url)
        # review#5 (A1 r2): FULL sha256 service identity. An 8-hex (32-bit) hash let two service URLs
        # collide, overwriting each other's artifact inside one attempt and sharing one coverage unit.
        svc = f"{host}-{hashlib.sha256(url.encode()).hexdigest()}"
        done = ledger.has(url)
        current, ran_clean, launched = None, False, False
        if not done:
            # review#3 (A1 r3): the budget gates LAUNCHING pending work only. Breaking out on the first
            # pending service left every already-completed service LATER in the fair order unreplayed and
            # uncounted — so a coverage generation silently lost those units.
            if ff_budget.exhausted():
                pass                                          # the SELECTION measure already accounts for it
            else:
                launched = True
                current = attempt_dir / f"{svc}.json"
                current.unlink(missing_ok=True)               # our OWN fresh attempt file, never a recorded one
                r = _run_one(ctx, url, wl, wl_digest, _mc, recurse, ct_to, current, prof)
                ctx.run.record("content", r)
                if r.status == Status.BLOCKED:
                    ff_blocked += 1
                    events.coverage_partial("content.ffuf", reason=f"{host}: blocked — {r.note}")
                elif r.status == Status.PARTIAL:
                    ff_partial += 1
                    events.coverage_partial("content.ffuf", reason=f"{host}: partial — {r.note}")
                elif r.status in (Status.SUCCESS, Status.EMPTY):
                    ff_clean += 1                            # EXECUTION completed (says nothing about rows)
                else:
                    ff_errors += 1                           # FAILED / TIMED_OUT / SKIPPED
                    events.coverage_partial("content.ffuf", reason=f"{host}: {r.status.value} — {r.note}")
                ran_clean = r.status in (Status.SUCCESS, Status.EMPTY)
                if not current.exists():
                    current = None
                elif ffuf_results(current) is not None:
                    # review#1 (A1 r4): retain EVERY trustworthy artifact regardless of execution status. A
                    # PARTIAL/BLOCKED run's rows are real evidence; gating retention on ran_clean threw them
                    # away. Retention is not a completion claim.
                    ledger.add_evidence(url, current)
                attempted += 1
        else:
            ff_resumed += 1
            attempted += 1
            current = ledger.artifact(url)                   # the completion artifact IS this generation's
        # review#2 (A1 r3): replay only DIGEST-MATCHING retained evidence. Globbing attempt-*/ trusted any
        # matching file, so a tampered, planted or symlinked artifact could inject fabricated findings.
        artifacts = ledger.evidence(url)
        if current is not None and current not in artifacts:
            artifacts = artifacts + [current]                # the just-run attempt (not yet re-validated)
        # review#1 (A1 r5): a service the budget never LAUNCHED, with no retained evidence, gets NO row unit.
        # It used to emit a bogus "no current artifact" UNKNOWN gap on top of the correct selection omission,
        # so every intentionally-unlaunched service on a bounded run was double-reported.
        if not launched and not artifacts:
            continue
        _ingest(ctx, scope, host, svc, artifacts, current, seen_notable, launched)
        if done or current is None:
            continue
        # review#1 (A1 r4): completion requires a CLEAN EXECUTION as well as a usable artifact. Judging the
        # artifact alone recorded a PARTIAL/BLOCKED run as done — skipped forever — whenever its JSON parsed.
        cur_ok, cur_clean = _ingest_status(current)
        if ran_clean and cur_ok and cur_clean:
            ledger.record(url, current)                      # the EXPLICIT current artifact, never sorted[-1]
        elif ran_clean:
            ff_unusable += 1                                 # execution completed, OUTPUT unusable
            events.coverage_partial("content.ffuf",
                                    reason=f"{host}: unusable/untrustworthy ffuf rows — not resumable")
    persisted = ledger.save()
    if not persisted:
        ctx.echo("    content.ffuf: completion state NOT persisted"
                 + (" (state file belongs to another lane)" if ledger.foreign else ""))
    events.coverage_partial("content.ffuf", kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit="state_persisted", eligible=1, tested=1 if persisted else 0,
                            omitted=0 if persisted else 1,
                            reason=("completion state persisted" if persisted else
                                    "completion state could not be persisted; a resume will redo this lane"))
    # SELECTION: of every eligible service, how many did we get to at all? (the old cap lived here)
    budget.report_selection("content.ffuf", measure="hosts", eligible=len(eligible),
                            attempted=attempted, budget=ff_budget, noun="service", durable=persisted)
    # OUTCOME: of those we attempted, how many produced a COMPLETED scan?
    budget.report_outcome("content.ffuf", measure="hosts_scanned", attempted=attempted,
                          obtained=ff_clean - ff_unusable + ff_resumed,
                          classes={k: v for k, v in (("partial", ff_partial), ("blocked", ff_blocked),
                                                     ("error", ff_errors), ("unusable_output", ff_unusable))
                                   if v},
                          noun="service")
    _left = len(eligible) - attempted
    ctx.echo(f"  content ffuf: {ff_clean}/{attempted} clean · {ff_partial} partial · "
             f"{ff_blocked} blocked · {ff_errors} error · {ff_unusable} unusable · "
             f"{ff_resumed} resumed · "
             f"{len(seen_notable)} notable path(s) (200/401/403)"
             + (f" · {_left} left by budget — {'resumable' if persisted else 'NOT saved, will restart'}"
                if _left else ""))
