"""Content discovery (Phase 11) — candidate-driven, scope-safe ffuf. Default off.

Intensity via MODES.CONTENT_DISCOVERY: off | light | balanced | deep; recursion via
MODES.CONTENT_RECURSION. Guardrails: skipped in passive mode and when off; only live, in-scope,
active-allowed hosts (origin-first order, never capped); ffuf -ac autocalibration always (kills
wildcard/catch-all floods); http_rl → ffuf -rate. Map-don't-exploit: results are url + review
candidates, never actions.
"""
from __future__ import annotations

import hashlib
from importlib import resources
from pathlib import Path

from .. import budget, events, normalize, settings
from ..contract import run_contract
from ..runner import (Status, ffuf_http_row, ffuf_results, ffuf_usable_rows,
                      fresh_artifact_dir as runner_fresh,
                      have, native_output_current, reclassify_ffuf, run as exec_tool,
                      scaled_timeout, skipped)
from ..runner_repository import RepositoryOutput
from ..runner_native import RepositoryNativeOutput

# No host or per-host row caps (those discard already-discovered URLs). Bound throughput and order:
# full eligible set, ranked-fair order, an unbounded-by-default wall-clock budget + resumable ledger.
_CONTENT_SCHEMA = 2      # bump invalidates work units whose artifacts an older, looser row parser
                         # accepted, forcing re-run under the current typed url/status parser.
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
    high-signal secret/config paths are checked on every content run regardless of tier."""
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

    Redirect policy (ISC-16, deliberate exception to the classify-probes' follow rule): a path 3xx is
    itself a finding (the path exists + where it goes), so we match 3xx (-mc) instead of following (-r) —
    following would collapse distinct paths onto one login/home page and -ac/dedup would drop them. -ac
    neutralises the redirect-everything catch-all.

    -maxtime is the graceful whole-run ceiling (incl. recursion sub-jobs) so a slow origin writes its
    partial -o instead of a hard kill; exec_tool's timeout is the hard backstop. -noninteractive: batch
    hygiene."""
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
    hard = ct_to + 60 if ct_to else 0            # backstop when bounded; unbounded (0) when ct_to==0
    # per-target work_unit binds the target URL + coverage config (match codes, recursion depth,
    # wordlist) + wordlist digest → re-run on any change.
    wu = events.work_unit("content.ffuf", inputs={"url": url},
                          config={"mc": mc, "recursion": recurse, "wordlist": wl.name},
                          file_digests={"wordlist": wl_digest}, schema_version=_CONTENT_SCHEMA)
    errf = out.with_suffix(".stderr.log")        # full stderr: the -maxtime marker must not be evictable
    return run_contract("content.ffuf", cmd,
        repository=ctx.run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.publish(*errf.relative_to(ctx.run.dir).parts),
        native_outputs=(RepositoryNativeOutput.file(
            16, *out.relative_to(ctx.run.dir).parts,
        ),),
        work_unit=wu, timeout=hard,
        reclassify=lambda res, o=out, e=errf: reclassify_ffuf(res, o, e, ct_to or None),
    )


def _ingest_status(out) -> tuple:
    """(trustworthy, clean_rows) for one artifact — the completion judgement for the current attempt only."""
    rows = ffuf_results(out)
    if rows is None:
        return False, False
    _usable, dropped = ffuf_usable_rows(rows, ffuf_http_row)
    return True, dropped == 0


def _ingest(ctx, scope, host, svc, artifacts, current, seen_notable, launched) -> None:
    """Ingest every retained artifact for one service, then report coverage for the current one only.

    Coverage counts rows that reached the store; its denominator is usable, in-scope rows (out-of-scope
    rows are a deliberate filter, type-contract failures read as unknown, not a cap gap). The verdict is
    computed from `current` alone — older artifacts are still replayed so their findings survive."""
    # notable identities are collected in a per-lifecycle set, so provenance replay does not inflate
    # the count.
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
        # a store-write failure must never be reported as successful ingestion.
        events.coverage_partial("content.ffuf", kind=events.COVERAGE_UNKNOWN, unit=f"results:{svc}",
                                measure="result_rows",
                                reason=f"{host}: ingestion failed mid-artifact — row coverage UNMEASURED")
        raise
    # ── coverage for this generation: the current artifact only ──
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
    # unit = the service identity (http/https/:port on one host are distinct services, never sharing a
    # coverage unit); measure=result_rows so it is never summed with hosts.
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

    # eligible = every active-allowed live service with a url. Not capped.
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
    # execution completion and artifact usability are separate counters.
    ff_clean = ff_partial = ff_blocked = ff_errors = ff_resumed = ff_unusable = 0
    # workload-scaled ceiling: scale by wordlist size × recursion depth (recursion multiplies the paths
    # fuzzed). Merged wordlist counted once.
    wl_n = sum(1 for _ in wl.open())
    ct_to = scaled_timeout(wl_n * (recurse + 1), ctx.http_timeout, per_unit=0.4)
    wl_digest = events.file_digest(wl)                       # wordlist change → new work_unit
    _mc = "200,204,301,302,307,308,401,403,405"
    # the ledger is namespaced by the coverage config: an artifact from a different wordlist or match-code
    # set validates by digest but is not this generation's completed work.
    cfg_fp = events.work_unit("content.ffuf", inputs={}, config={"mc": _mc, "recursion": recurse,
                                                                "wordlist": wl.name, "tier": tier},
                              file_digests={"wordlist": wl_digest}, schema_version=_CONTENT_SCHEMA)
    state_base = ctx.run.dir / "raw" / "content"
    budget.prune_state(state_base, "content.ffuf", cfg_fp)
    ledger = budget.Ledger(budget.state_path(state_base, "content.ffuf", cfg_fp), lane="content.ffuf")
    ff_budget = budget.Budget(budget.budget_seconds("CONTENT_FFUF_BUDGET_S"))
    # evidence is immutable: each attempt writes into its own dir, and a resumed target reads the
    # artifact the ledger recorded, never a recomputed path.
    cfg_dir = state_base / "ffuf" / cfg_fp[:16]
    attempt_dir = runner_fresh(cfg_dir)
    # rank decides order, never membership: origin (non-CDN) services first, then round-robin by host so
    # one host's services cannot drain a bounded run before another host is reached.
    ordered = budget.order_ranked_fair(eligible, rank=lambda l: 1 if l.get("cdn") else 0,
                                       group=lambda l: normalize.host_of_url(l.get("url", "")))
    n_resumed = sum(1 for l in ordered if ledger.has(l["url"]))
    ctx.echo(f"  content discovery [{tier}]: {len(eligible)} service(s) eligible"
             + (f", {n_resumed} resumed" if n_resumed else "") + f", wordlist {wl.name}{rec}")
    attempted = 0
    for _l in ordered:
        url = _l["url"]
        host = normalize.host_of_url(url)
        # full sha256 service identity: a short hash could collide two service URLs onto one artifact.
        svc = f"{host}-{hashlib.sha256(url.encode()).hexdigest()}"
        done = ledger.has(url)
        current, ran_clean, launched = None, False, False
        if not done:
            # the budget gates launching pending work only; already-completed services later in the fair
            # order are still replayed and counted.
            if ff_budget.exhausted():
                pass                                          # the selection measure already accounts for it
            else:
                launched = True
                current = attempt_dir / f"{svc}.json"
                r = _run_one(ctx, url, wl, wl_digest, _mc, recurse, ct_to, current, prof)
                ctx.run.record("content", r)
                if r.status == Status.BLOCKED:
                    ff_blocked += 1
                    events.coverage_partial("content.ffuf", reason=f"{host}: blocked — {r.note}")
                elif r.status == Status.PARTIAL:
                    ff_partial += 1
                    events.coverage_partial("content.ffuf", reason=f"{host}: partial — {r.note}")
                elif r.status in (Status.SUCCESS, Status.EMPTY):
                    ff_clean += 1                            # execution completed (says nothing about rows)
                else:
                    ff_errors += 1                           # failed / timed-out / skipped statuses
                    events.coverage_partial("content.ffuf", reason=f"{host}: {r.status.value} — {r.note}")
                ran_clean = r.status in (Status.SUCCESS, Status.EMPTY)
                if not native_output_current(r, current) or not current.exists():
                    current = None
                elif ffuf_results(current) is not None:
                    # retain every trustworthy artifact regardless of execution status — a partial/blocked
                    # run's rows are real evidence. Retention is not a completion claim.
                    ledger.add_evidence(url, current)
                attempted += 1
        else:
            ff_resumed += 1
            attempted += 1
            current = ledger.artifact(url)                   # the completion artifact is this generation's
        # replay only digest-matching retained evidence, so a tampered or planted artifact cannot inject
        # fabricated findings.
        artifacts = ledger.evidence(url)
        if current is not None and current not in artifacts:
            artifacts = artifacts + [current]                # the just-run attempt (not yet re-validated)
        # a service the budget never launched, with no retained evidence, gets no row unit (otherwise the
        # selection omission would be double-reported as an unknown gap).
        if not launched and not artifacts:
            continue
        _ingest(ctx, scope, host, svc, artifacts, current, seen_notable, launched)
        if done or current is None:
            continue
        # completion requires a clean execution as well as a usable artifact, not just parseable JSON.
        cur_ok, cur_clean = _ingest_status(current)
        if ran_clean and cur_ok and cur_clean:
            ledger.record(url, current)                      # the explicit current artifact, never sorted[-1]
        elif ran_clean:
            ff_unusable += 1                                 # execution completed, output unusable
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
    # selection: of every eligible service, how many did we reach at all?
    budget.report_selection("content.ffuf", measure="hosts", eligible=len(eligible),
                            attempted=attempted, budget=ff_budget, noun="service", durable=persisted)
    # outcome: of those attempted, how many produced a completed scan?
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
