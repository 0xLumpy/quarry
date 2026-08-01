"""Enrich phase — catch-up over hosts discovered AFTER vertical + probe.

CSP siblings (found in probe via httpx -irh) and link-only needles (found in crawl) become
known *after* the vertical resolve/CNAME pass and the probe pass have already run. Without a
catch-up they stay un-resolved, un-probed, and — critically — never get subdomain-takeover
analysis (a dangling-CNAME host first seen via a crawl link would otherwise be invisible to
the takeover check). This phase resolves them, runs the CNAME/takeover signal, and probes the
ones that resolve, so late-discovered hosts get the same treatment as vertical-discovered ones.
"""
from __future__ import annotations

from pathlib import Path

import json as _json

from .. import normalize
from .. import settings
from ..runner import (RunResult, Status, fresh_artifact_dir, have, nuclei_timeout, reclassify_from_files,
                      run as exec_tool, scaled_timeout, skipped)
from .. import budget, events, sweep
from ..contract import registered


#: how many mined labels A1d may actually brute-force per apex (puredns, DNS). A SPEND bound, unchanged
#: since before step 4 — what a measured, chunked, resumable selection should look like is 4.2's question.
A1D_WORD_CAP = 2000

#: how many mined labels A1d may hand to the WILDCARD HTTP differentiator, per zone. review-step4-remeasure
#: #3: this used to be the very same list `puredns` got, so widening the DNS selection in 4.2 would have
#: silently widened HTTP work in a lane 4.3 had not scheduled yet. Two lanes, two bounds — the value is
#: today's effective behaviour, so nothing widens now.
A1D_WILDCARD_WORD_CAP = 2000


def _a1d_subtract_base(ctx, words: list, wordlist_fn, loss: dict) -> list:
    """Drop mined words the BASE dictionary already covers, by STREAMING the base file.

    review-step4-measure#3: this used to build a `set()` of the whole base list — MEASURED at 9,544,235
    words, 1.5 GB RSS and 3.9 s on this box — purely to subtract a few thousand mined labels from. The
    membership test only needs OUR side in memory: stream the base file and drop the mined words it hits.

    review-B-audit-12#2: the read stays inside A1d's loss boundary. The base list exists only to avoid
    re-brute-forcing dictionary words, so failing to read it does not stop A1d; it means the mined words
    were NOT deduped against it, which is a loss worth reporting."""
    try:
        base_wl = wordlist_fn(ctx)
    except Exception as ex:
        loss["base_error"] = f"the base wordlist could not be located ({type(ex).__name__})"
        return list(words)
    if not base_wl:
        return list(words)
    mined = set(words)
    covered: set = set()
    dropped = 0
    try:
        with Path(base_wl).open("rb") as fh:
            for chunk in fh:
                try:
                    w = chunk.decode("utf-8")
                except UnicodeDecodeError:
                    dropped += 1               # a line we cannot decode cannot exclude anything
                    continue
                w = w.strip().lower()
                if w and not w.startswith("#") and w in mined:
                    covered.add(w)
    except OSError as ex:
        loss["base_error"] = f"the base wordlist could not be read ({type(ex).__name__})"
        return list(words)
    if dropped:
        loss["base_dropped_lines"] = dropped
    return [w for w in words if w not in covered]


def _a1d_loss_why(loss: dict, produced: int) -> str:
    """One accurate sentence for everything A1d lost, or "" when nothing was lost.

    review-B-audit-12#1: "every mined wordlist artifact was unreadable" was asserted whenever ANY file was
    unreadable, so one unreadable file beside a readable-but-empty one produced a false claim. What the
    readable files yielded is stated, not assumed."""
    files, unreadable = loss.get("files", 0), loss.get("unreadable_files", 0)
    parts = []
    if unreadable:
        parts.append(f"ALL {files} mined wordlist artifact(s) unreadable" if unreadable == files and files
                     else (f"{unreadable}/{files} mined wordlist artifact(s) unreadable — the readable "
                           f"{files - unreadable} yielded {produced} usable word(s)"))
    if loss.get("dropped_lines"):
        parts.append(f"{loss['dropped_lines']} mined line(s) not valid UTF-8 and dropped")
    if loss.get("base_error"):
        parts.append(f"{loss['base_error']} — mined words were NOT deduped against it")
    if loss.get("base_dropped_lines"):
        parts.append(f"{loss['base_dropped_lines']} base wordlist line(s) not valid UTF-8")
    if loss.get("wildcard_withheld"):
        parts.append(f"{loss['wildcard_withheld']}/{loss.get('after_base', 0)} mined word(s) withheld from "
                     f"the wildcard differ by its {A1D_WILDCARD_WORD_CAP}-word bound")
    if loss.get("unschedulable_pairs"):
        parts.append(f"{loss['unschedulable_pairs']} candidate(s) in {loss['unschedulable_slots']} "
                     f"slot(s) cannot be scheduled under the current bounds and will NOT be retried")
    if loss.get("sweep_stop"):
        parts.append(f"the scheduled brute stopped early ({loss['sweep_stop']})")
    if loss.get("sweep_machinery"):
        parts.append(loss["sweep_machinery"])
    if loss.get("withheld_by_word_cap"):
        # the SPEND bound is a fact, like every other cap. Counted in candidate-TARGET PAIRS, exactly as
        # the scheduler measures them, and taken from what it ACTUALLY submitted — whole buckets can
        # underfill the bound, so the arithmetic `corpus - cap` was wrong (review v17#4).
        parts.append(f"{loss['withheld_by_word_cap']}/{loss.get('sweep_eligible_pairs', 0)} candidate(s) "
                     f"withheld by the {A1D_WORD_CAP}-per-apex A1d spend bound")
    return "; ".join(parts)


def _a1d_sweep(ctx, prof, kept, origins, execute, *, dependency_ok):
    """The scheduled apex brute. Isolated so its caller can bracket it in ONE source lifecycle."""
    return sweep.run_sweep(
        lane="a1d_brute",
        # the SCHEMA is part of the path: changing `BUCKETS` bumps it, and a bumped schema must start a
        # fresh rotation rather than meeting a document `RotationProgress` will (correctly) refuse to
        # overwrite — which would leave the lane unable to reserve anything until an operator intervened
        # (review v17#2).
        state_dir=Path(ctx.run.project_dir) / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}",
        targets=list(prof.apex_domains), vocabulary=lambda _apex: list(kept), execute=execute,
        budget_s=budget.budget_seconds("A1D_BUDGET_S"), coverage_lane="enrich.a1d_brute",
        dependency_ok=dependency_ok, max_pairs_per_target=A1D_WORD_CAP,
        attribution=lambda w: sweep.owner_of(w, sorted(origins.get(w) or ["crawl"])))


def _a1d_fold_sweep(ctx, prof, swept, wl_loss) -> None:
    """Fold the sweep into the lane's reported facts. Fallible on purpose — the caller contains it."""
    # machinery is folded UNCHANGED: unschedulable slots are their own structured fact on the result and
    # are rendered once from the counters below, so there is nothing to filter out by wording (v38).
    if swept.machinery:
        wl_loss["sweep_machinery"] = "; ".join(swept.machinery)
    if swept.stop_kind not in (None, "bound"):
        wl_loss["sweep_stop"] = swept.stop
    if swept.stop_kind == "dependency" and not swept.slots_attempted:
        # review-B-audit-13#1: an eligible brute that never ran must SAY so — a missing REQUIRED tool is
        # already a manifest gap, and the note carries how much work went unsubmitted. The gate itself is
        # the sweep's (one authority), so this is the reporting half. A tool that vanished MID-sweep is a
        # different fact and is carried by the terminal, not by a second dependency record (v17#3).
        ctx.run.record("enrich", skipped("puredns", f"not installed — {len(prof.apex_domains)} A1d "
                                                    f"apex brute(s) unsubmitted"))
    # review v19#2: the SELECTION remainder is not automatically cap withholding — contention, a
    # dependency stop, machinery and the clock all leave `eligible - attempted` behind, and each already
    # has its own fact. Only a `bound` stop is the spend bound withholding work.
    if swept.stop_kind == "bound":
        wl_loss["withheld_by_word_cap"] = max(0, swept.eligible_pairs - swept.attempted_pairs)
        wl_loss["sweep_eligible_pairs"] = swept.eligible_pairs
    if swept.unselectable_pairs:
        # NOT a remainder any later run collects, and not the spend bound either: candidates in a slot no
        # bound can admit. The scheduler carries the slots structurally; the verdict carries the size.
        wl_loss["unschedulable_pairs"] = swept.unselectable_pairs
        wl_loss["unschedulable_slots"] = swept.unselectable_slots


def _a1d_terminal(swept, produced: int):
    """ONE terminal for the source, over the WHOLE multi-bucket sweep (v17#1).

    review v18#3: derived from what was PRODUCED and from the slot CLASSES, not from "the runner
    returned" — `slots_obtained` counts SUCCESS *and* EMPTY, so an all-empty sweep read SUCCESS and a
    failed one read EMPTY, while failed/timed-out/blocked slots never showed at all."""
    if swept.contended:
        _st, _why = Status.FAILED, swept.stop
    elif swept.stop_kind == "dependency" and not swept.slots_attempted:
        _st, _why = Status.SKIPPED, swept.stop          # nothing ran at all
    else:
        # every degrading fact is ORTHOGONAL and they ACCUMULATE (v39#1): a run can lose slots to a
        # machinery failure, get failures back from the ones it did submit, AND hold candidates no bound
        # can admit. Reporting only the first of those hid the class maps the terminal promises.
        facts = []
        if swept.machinery:
            facts.append("; ".join(swept.machinery))
        if swept.classes:
            # both currencies: with batching, 10 failed slots may be one failed call or ten of them, and
            # the slot-weighted map alone cannot say which (step 4.2, invocation classes).
            facts.append(f"slot outcomes {dict(sorted(swept.classes.items()))} in "
                         f"{swept.invocations} invocation(s) "
                         f"{dict(sorted(swept.invocation_classes.items()))}")
        if swept.unselectable_pairs:
            facts.append(f"{swept.unselectable_pairs} candidate(s) in {swept.unselectable_slots} slot(s) "
                         f"cannot be scheduled under the current bounds")
        if facts or swept.stop_kind == "dependency":
            # PARTIAL asserts something was PRODUCED — a slot answering "nothing here" is not production
            # (the audit-7#2 rule). A tool that vanished mid-sweep degrades the same way.
            _st = Status.PARTIAL if produced else Status.FAILED
            _why = "; ".join(p for p in ([swept.stop] if swept.stop else []) + facts)
        else:
            _st = Status.SUCCESS if produced else Status.EMPTY
            _why = swept.stop
    return _st, _why


def _a1d_recursive_brute(ctx) -> set[str]:
    """A1d — recursion: feed the target-specific wordlist mined during the crawl back into the brute.

    "Teach Quarry how the target functions." The crawl phase (which runs AFTER vertical) mines the
    target's own naming vocabulary via xnLinkFinder over waymore/JS. Here — the first phase after
    crawl — we harvest that vocabulary and re-brute with it: apexes (puredns) + any wildcard zones
    vertical discovered (the A1 HTTP-differentiator, with the target words folded in). Bounded: the
    target wordlist is capped and deduped against the base dictionary, so this can't explode the
    brute. Returns the set of hosts discovered so run() can force them into the enrich catch-up set."""
    prof, scope = ctx.profile, ctx.scope
    if scope.passive_only:
        return set()
    from .vertical import _target_wordlist, _wildcard_differentiate, _resolvers, _wordlist
    wl_loss: dict = {}
    # RETENTION: everything the crawl mined, in encounter order. SUBTRACTION: streamed against the base
    # dictionary. SELECTION: the spend bound, applied last and unchanged by step 4.1 — the set A1d
    # brute-forces is the same size it has always been.
    mined = _target_wordlist(ctx, loss=wl_loss)
    kept = _a1d_subtract_base(ctx, mined, _wordlist, wl_loss)
    wl_loss["mined_words"] = len(mined)
    wl_loss["after_base"] = len(kept)
    # `kept` is RETENTION: the whole mined corpus minus what the base dictionary already covers. Each
    # ACTIVE lane then selects from it under its OWN bound, so a change to one cannot widen the other.
    # SELECTION 1 -> puredns (DNS): the SWEEP picks which `A1D_WORD_CAP` candidates per apex, from the
    # whole retained corpus, in rotation. `twords` stays only as the "is there vocabulary at all" answer.
    twords = kept
    wc_words = sorted(kept[:A1D_WILDCARD_WORD_CAP])            # -> the wildcard differ (HTTP), per zone
    # the DNS withholding is the SWEEP's fact — it knows what it submitted and why it stopped (v19#2).
    # review-step4-remeasure2#1: the wildcard withholding is NOT a fact yet. Words are only withheld from
    # work that EXISTS, and whether any wildcard zone is eligible is something only the pass can say — a
    # puredns-only run with no in-scope zone was degrading itself over vocabulary nothing wanted.
    # review-B-audit-12#1: ONE attempt, ONE outcome. Two independent branches used to record a PARTIAL and
    # then a FAILED/SKIPPED for the same attempt, and the FAILED claimed "every artifact was unreadable"
    # even when a readable one had simply yielded nothing. The verdict is chosen once, from what was
    # PRODUCED and what was LOST.
    lost = _a1d_loss_why(wl_loss, len(twords))
    if not twords:
        # review-B-audit-13#2: the base list exists only to DEDUP mined words against. With nothing mined,
        # dedup had no work to do, so a base-only failure is not A1d damage — a genuine no-input SKIP must
        # survive it. Damage to the MINED input is a different fact and still fails.
        mined_damage = _a1d_loss_why({k: v for k, v in wl_loss.items() if not k.startswith("base_")}, 0)
        if mined_damage:
            why = (f"A1d has NO vocabulary and the mined input was DAMAGED ({mined_damage}) — not proof "
                   f"the target had none")
            ctx.run.record("enrich", RunResult("a1d", ["a1d"], Status.FAILED, None, 0.0, None, 0, note=why))
            ctx.echo(f"  A1d: {why}")
        else:
            ctx.run.record("enrich", skipped("a1d", "no target-specific words mined from crawl"))
        return set()
    ctx.echo(f"  A1d: {len(kept)} target-specific word(s) mined from crawl → scheduled re-brute "
             f"({A1D_WORD_CAP}/apex)")
    discovered: set[str] = set()

    # ── the apex brute is SCHEDULED (step 4.2): stable buckets, one sweeper per lane, a resumable
    #    rotation. The SPEND is unchanged — `A1D_WORD_CAP` candidates per apex, exactly as before — but
    #    WHICH candidates is no longer the lexicographic first N forever: a bounded run advances the
    #    rotation and the next one continues where it stopped. ──
    submitted_apexes = 0
    swept = None
    origins = wl_loss.get("origins") or {}
    apexes_run: set = set()
    resolvers = trusted = None
    # review v20#1: dependency detection and resolver preparation happen INSIDE the guarded interval
    # below — they used to run before the registry gate and before `tool_start`, so a raising
    # `_resolvers()` aborted the whole enrich phase with no A1d lifecycle at all (and silenced the
    # wildcard lane), and `have()` was observed TWICE: False here and True in the scheduler's gate ran
    # puredns with `--resolvers-trusted None`.
    sid = "enrich.a1d_brute"
    # the resume key covers everything that shapes the PARTITION, not just the spend: the root count, the
    # invocation maximum (slots are split against the smaller of it and the spend bound) and the slot-space
    # schema. A run under a different partition is a different question, and must not read as the same one.
    fp = events.work_unit(sid,
                          # the INPUT is the retained vocabulary, not only which apexes it is aimed at
                          # (v37#1): two entirely different corpora over the same apexes are not the same
                          # work, and they were emitting the same key. Per-INVOCATION identity is not
                          # needed here — the unit names the artifacts and the rotation owns the slots.
                          inputs={"apexes": sorted(prof.apex_domains),
                                  "vocabulary": sweep.content_digest(sorted(kept))},
                          config={"per_apex": A1D_WORD_CAP, "buckets": sweep.BUCKETS,
                                  "invocation_max": sweep.MAX_BATCH_WORDS},
                          schema_version=sweep.SCHEMA)

    def _brute(apex: str, unit: str, words):
        """ONE puredns invocation. `unit` names it — a lone slot keeps its own id, a batched one reads
        `<first>+<n>` — and `words` is the union of every slot it carries (step 4.2 batching)."""
        nonlocal submitted_apexes
        wl_file = ctx.write_list(f"a1d_words_{apex.replace('.', '_')}_{unit}.txt", sorted(words))
        cmd = ["puredns", "bruteforce", str(wl_file), apex, "--resolvers-trusted", str(trusted), "-q"]
        if resolvers:
            cmd += ["-r", str(resolvers)]
        if prof.dns_rate:
            cmd += ["--rate-limit", str(prof.dns_rate)]
        br = ctx.run.raw_path("enrich", "puredns", f"a1d-brute-{apex}-{unit}.txt")
        r = exec_tool("puredns", cmd, raw_path=br, timeout=ctx.http_timeout)
        ctx.run.record("enrich", r)
        if r.status is not Status.SKIPPED and apex not in apexes_run:
            # an invocation that never spawned is not an apex we brute-forced (review v17#3)
            apexes_run.add(apex)
            submitted_apexes = len(apexes_run)
        if r.raw_path and r.raw_path.exists():
            for row in normalize.hosts(r.raw_path.read_text(), "target-wordlist", str(br)):
                if scope.in_scope(row["host"]) and not scope.is_oos(row["host"]):
                    ctx.run.add("subdomain", row)
                    discovered.add(row["host"])
        return r

    # review v18#1: the registry gate is for THIS source only. `enrich.wildcard_a1d` is a separate lane
    # with its own entry, and a disabled or unavailable puredns lane must not suppress eligible wildcard
    # differentiation — so the gate skips the sweep and the function continues.
    if registered(sid):
        events.tool_start(sid, cmd=["puredns", "bruteforce", "(scheduled)"],
                          input_total=len(prof.apex_domains), work_unit=fp)
        # review v18#2 / v19#1: the WHOLE start-to-terminal interval is protected, and the terminal is
        # emitted in `finally` — exactly once, whatever happened. Reporting is fallible too (`record()`
        # can raise), and a `tool_start` with no `tool_finish` is a source that never answered.
        outcome = (Status.FAILED, "the scheduled brute did not report an outcome")
        try:
            tool_ok = have("puredns")               # ONE observation, used for setup AND the gate
            if tool_ok:
                resolvers, trusted = _resolvers(ctx)
            swept = _a1d_sweep(ctx, prof, kept, origins, _brute, dependency_ok=lambda: tool_ok)
            _a1d_fold_sweep(ctx, prof, swept, wl_loss)          # may raise: still inside the boundary
            outcome = _a1d_terminal(swept, len(discovered))
        except (KeyboardInterrupt, SystemExit):
            outcome = (Status.PARTIAL if discovered else Status.FAILED,
                       "CANCELLED mid-sweep — evidence KEPT" if discovered
                       else "CANCELLED mid-sweep — nothing extracted")
            raise                                               # after the terminal, never before
        except Exception as ex:                                 # a broken acquisition, a broken record …
            wl_loss["sweep_machinery"] = f"{type(ex).__name__}: {ex}"
            wl_loss["sweep_error"] = f"{type(ex).__name__}: {ex}"
            outcome = (Status.PARTIAL if discovered else Status.FAILED,
                       f"the scheduled brute failed ({type(ex).__name__}: {ex})")
        finally:
            events.tool_finish(sid, status=outcome[0].value, reason=outcome[1], work_unit=fp,
                               produced={"subdomains": len(discovered)})

    # ── the wildcard differ is its own lane and runs regardless of the brute above. NOTE: today
    #    `enrich.wildcard_a1d` is a COVERAGE identity only — `_wildcard_differentiate` does not yet gate on
    #    the registry or emit its own start/terminal. Making it an enforced lifecycle is 4.3. ──

    # wildcard-zone differ with the target words folded in (zones persisted by vertical)
    zones = set(ctx.run.values("wildcard_zone"))
    wc: dict = {}
    if zones:
        discovered.update(_wildcard_differentiate(ctx, zones, extra_words=wc_words, phase="enrich",
                                                  label="wildcard-a1d", source="wildcard-http-a1d",
                                                  source_id="enrich.wildcard_a1d", stats=wc))
    # ── ONE A1d outcome, chosen AFTER the work (review-B-audit-13#1): the earlier note claimed "the
    #    brute ran with less vocabulary" before anything had run — including when it never ran at all.
    if wc.get("eligible_zones", 0) > 0:
        wl_loss["wildcard_withheld"] = max(0, len(kept) - A1D_WILDCARD_WORD_CAP)
    # review v19#3: `after_base` is the RETAINED WORD count and other wording (wildcard withholding, the
    # unreadable-input sentence) reads it as such — the scheduler's candidate-target PAIRS are a different
    # unit and live in their own fields.
    unsubmitted = max(0, len(prof.apex_domains) - submitted_apexes)
    unsubmitted_why = (swept.stop if swept is not None and swept.stop
                       else wl_loss.get("sweep_error")
                       or ("the source is not registered" if swept is None else None)
                       # nothing STOPPED the run: every candidate sat in a slot no bound can admit, which
                       # is exactly why no apex was brute-forced (v37#2). Without this the note said
                       # "no reason recorded" beside the reason.
                       or ("no candidate is schedulable under the current bounds"
                           if wl_loss.get("unschedulable_pairs") else "no reason recorded"))
    # review-B-audit-14: "there were wildcard zones" is not "the wildcard pass ran" — passive mode, a
    # missing httpx, no wordlist, the self-contact guard and the zone cap all leave zones UNSUBMITTED.
    # The differentiator now says what it actually probed, and both facts are reported.
    wc_eligible, wc_probed = wc.get("eligible_zones", 0), wc.get("probed_zones", 0)
    wc_unsubmitted = max(0, wc_eligible - wc_probed)
    lost = _a1d_loss_why(wl_loss, len(kept))        # `produced` here is USABLE WORDS, not pairs (v19#3)
    parts = ([lost] if lost else []) + ([f"{unsubmitted} apex brute(s) unsubmitted "
                                         f"({unsubmitted_why})"] if unsubmitted else [])
    if wc_unsubmitted:
        parts.append(f"{wc_unsubmitted}/{wc_eligible} wildcard zone(s) not differentiated"
                     + (f" ({wc['blocked_reason']})" if wc.get("blocked_reason") else ""))
    # review-B-audit-16#2: vocabulary the wildcard pass could not use is A1d's loss too, and it was only
    # ever looked at when zones went unsubmitted — so a probed run with a damaged wordlist read clean.
    _v = wc.get("vocabulary") or {}
    _vlost = _v.get("undecodable", 0) + _v.get("rejected", 0)
    if _v.get("unreadable"):
        parts.append("the wildcard wordlist is present and UNREADABLE — only the mined vocabulary was used")
    if _vlost:
        parts.append(f"{_vlost} wildcard vocabulary word(s) unusable ({_v.get('undecodable', 0)} not valid "
                     f"UTF-8, {_v.get('rejected', 0)} not a single DNS label)")
    if _v.get("withheld"):
        parts.append(f"{_v['withheld']} usable wildcard word(s) withheld by the word cap")
    if parts:
        ran = bool(submitted_apexes or wc_probed)
        why = (f"A1d ran with less than its eligible work ({'; '.join(parts)})" if ran else
               f"A1d did NOT run ({'; '.join(parts)})")
        ctx.run.record("enrich", RunResult("a1d", ["a1d"], Status.PARTIAL if ran else Status.FAILED,
                                           None, 0.0, None, 0, note=why))
        ctx.echo(f"  A1d: {why}")
    if discovered:
        ctx.echo(f"  A1d: +{len(discovered)} host(s) via target-specific recursive re-brute")
    return discovered


def run(ctx) -> None:
    prof, scope = ctx.profile, ctx.scope
    # A1d recursion FIRST — its discoveries then flow through the resolve/probe/takeover pass below.
    a1d_hosts = _a1d_recursive_brute(ctx)
    resolved = set(ctx.run.values("resolved"))
    # hosts known (subdomain) but never resolved → the crawl/CSP-discovered ones.
    # A1d's wildcard-differentiator adds its hits to `resolved` too (it needs its own httpx pass),
    # which would exclude them from this catch-up — force them back in so they still get the full
    # enrich treatment (dns-record, CNAME/takeover, rich httpx fingerprint, screenshots/WAF/smap).
    new = sorted({h for h in set(ctx.run.values("subdomain"))
                  if h and h not in resolved and scope.in_scope(h) and not scope.is_oos(h)}
                 | {h for h in a1d_hosts if scope.in_scope(h) and not scope.is_oos(h)})
    if not new:
        ctx.run.record("enrich", skipped("enrich", "no late-discovered hosts to enrich"))
        return
    ctx.echo(f"  enriching {len(new)} late-discovered host(s) "
             f"({'crawl/CSP/A1d' if a1d_hosts else 'crawl/CSP'})")
    targets = ctx.write_list("enrich_hosts.txt", new)

    # 1. resolve (A) — pull the late hosts into `resolved`
    if have("dnsx"):
        res = ctx.run.raw_path("enrich", "dnsx", "resolved.txt")
        r = exec_tool("dnsx", ["dnsx", "-l", str(targets), "-a", "-resp", "-json", "-silent"],
                      raw_path=res, timeout=ctx.http_timeout)
        ctx.run.record("enrich", r)
        if r.raw_path:
            for e in normalize.dnsx_resolved(r.raw_path.read_text(), "dnsx", str(res)):
                if scope.in_scope(e["host"]) and not scope.is_oos(e["host"]):
                    ctx.run.add("resolved", e)
        resolved = set(ctx.run.values("resolved"))

    # 2. CNAME / takeover over the late hosts (same signal as vertical's CNAME collection) —
    # a host with a CNAME but no A of its own = takeover candidate.
    if prof.takeover and have("dnsx"):
        cn = ctx.run.raw_path("enrich", "dnsx", "cnames.jsonl")
        # -a so dangling = has CNAME but no A in THIS result (enrich itself can add a no-A host
        # to `resolved` with a:[], so resolved-set membership is not a reliable dangling signal).
        r = exec_tool("dnsx", ["dnsx", "-l", str(targets), "-cname", "-a", "-json", "-silent"],
                      raw_path=cn, timeout=ctx.http_timeout)
        ctx.run.record("enrich", r)
        if r.raw_path:
            ntk = 0
            for line in r.raw_path.read_text().splitlines():
                try:
                    o = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                host = o.get("host")
                dangling = not o.get("a")          # has a CNAME (loop below) but no A record
                for c in (o.get("cname") or []):
                    ctx.run.add("review", {"id": f"cname:{host}->{c}", "klass": "cname",
                                           "value": f"{host} -> {c}", "host": host,
                                           "cname": c, "takeover_candidate": dangling,
                                           "sources": ["dnsx"]})
                    if dangling:
                        ntk += 1
            if ntk:
                ctx.echo(f"  enrich: +{ntk} dangling CNAME → takeover candidate")

    # 3. probe the newly-resolved hosts (live + tech), so link/CSP-only hosts get fingerprinted
    new_set = set(new)
    new_resolved = sorted(h for h in resolved if h in new_set)

    # DNS-record catch-up: late hosts (crawl/CSP) resolved here missed the `dns` phase, so run the
    # same wildcard-filtered dnsx enrichment over just these (deferred "dns incremental catch-up").
    if new_resolved and have("dnsx"):
        from . import dns as _dns
        nd = _dns.enrich_hosts(ctx, new_resolved, "enrich")
        if nd:
            ctx.echo(f"  dns-enrich (late): +{nd} record(s) over {len(new_resolved)} host(s)")

    if not scope.passive_only and have("httpx") and new_resolved:
        # v0.3.5: share probe's fingerprint path — SYN web-port prefilter → httpx on open ports only,
        # same fallback discipline. Late A1d/crawl/CSP hosts don't fall back to the slow direct behavior.
        from .probe import fingerprint_hosts
        new_live: list[str] = []
        for raw_ref, glines in fingerprint_hosts(ctx, new_resolved, "enrich"):   # per-group raw provenance
            for e in normalize.httpx_json("\n".join(glines), "httpx", raw_ref):
                if scope.in_scope(e.get("host") or normalize.host_of_url(e["url"])):
                    if ctx.run.add("live", e):
                        new_live.append(e["url"])
                        for tech in e.get("tech") or []:
                            ctx.run.add("tech", {"id": f"{e['url']}|{tech}", "tech": tech,
                                                 "url": e["url"], "sources": ["httpx"]})
        ctx.echo(f"  enrich: +{len(new_live)} live (late-discovered)")

        # ── fingerprint the late hosts the same way probe does (probe ran before they existed) ──
        if new_live:
            if have("nuclei"):                          # WAF fingerprint
                wi = ctx.write_list("enrich_waf.txt", new_live)
                wo = ctx.run.raw_path("enrich", "nuclei", "waf.jsonl")
                wcmd = ["nuclei", "-l", str(wi), "-tags", "waf", "-jsonl", "-o", str(wo)]
                if prof.http_rl:
                    wcmd += ["-rl", str(prof.http_rl)]
                ctx.run.record("enrich", exec_tool(
                    "nuclei", wcmd, timeout=nuclei_timeout(len(new_live), ctx.http_timeout)))
                if wo.exists():
                    for line in wo.read_text().splitlines():
                        try:
                            o = _json.loads(line)
                        except _json.JSONDecodeError:
                            continue
                        ex = o.get("extracted-results") or []
                        name = (ex[0] if ex else None) or o.get("matcher-name") or "unknown"
                        host = o.get("matched-at", o.get("host", ""))
                        ctx.run.add("tech", {"id": f"{host}|waf:{name}", "tech": f"WAF:{name}",
                                             "url": host, "sources": ["nuclei-waf"]})

            if prof.screenshots and have("gowitness"):  # screenshots
                lf = ctx.write_list("enrich_live.txt", new_live)
                shot_dir = fresh_artifact_dir(ctx.run.dir / "raw" / "enrich" / "gowitness")   # FRESH per invocation
                gr = exec_tool("gowitness",
                    ["gowitness", "scan", "file", "-f", str(lf),
                     "--screenshot-path", str(shot_dir), "--write-jsonl",
                     "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                    timeout=ctx.http_timeout)
                # same file-output reclassification as probe — count THIS attempt's dir only (a reused/
                # pre-populated dir must not inflate the count; T1.6 core precondition: fresh artifact)
                shots = len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
                reclassify_from_files(gr, shots, "screenshot")
                ctx.run.record("enrich", gr)
                for ext in ("*.jpeg", "*.png"):
                    for img in shot_dir.glob(ext):
                        ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

            if have("smap"):                            # passive (Shodan) ports — parse like probe (C12)
                sm_targets = [normalize.host_of_url(u) for u in new_live]
                si = ctx.write_list("enrich_smap.txt", sm_targets)
                sm = ctx.run.raw_path("enrich", "smap", "smap.json")
                sm.unlink(missing_ok=True)              # -o file: clear stale before the run
                sr = exec_tool("smap", ["smap", "-iL", str(si), "-oJ", str(sm)], timeout=600)
                # was recorded raw-only — enrich's passive port yield was lost (C12). Parse + reclassify +
                # ingest via the SAME shared helper probe uses (-oJ structured; status reflects yield).
                from .probe import _smap_ingest
                _smap_ingest(ctx, sr, sm, "enrich", sm_targets)
