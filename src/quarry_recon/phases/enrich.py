"""Enrich phase — catch-up over hosts discovered after vertical and probe.

CSP siblings (probe, httpx -irh) and crawl link-only needles surface after the vertical resolve/CNAME
and probe passes, so without this they never get takeover analysis. This phase resolves them, runs the
CNAME/takeover signal, and probes those that resolve — the same treatment vertical-discovered hosts get.
"""
from __future__ import annotations

from pathlib import Path

import json as _json

from .. import normalize, policy
from .. import settings
from ..runner import (RunResult, Status, fresh_artifact_dir, have, nuclei_timeout, reclassify_from_files,
                      run as exec_tool, scaled_timeout, skipped)
from ..runner_repository import RepositoryOutput
from .. import budget, events, remainder, sweep
from ..contract import registered


#: mined labels A1d may brute-force per apex (puredns, DNS) — a spend bound.
A1D_WORD_CAP = 2000

#: mined labels A1d may hand the wildcard HTTP differentiator, per zone. A separate bound from the DNS
#: one, so widening one lane's selection cannot widen the other's.
A1D_WILDCARD_WORD_CAP = 2000


def _a1d_subtract_base(ctx, words: list, wordlist_fn, loss: dict) -> list:
    """Drop mined words the base dictionary already covers, streaming the base file so only our side is
    held in memory. A base file that cannot be read is a reported loss, not a stop — the mined words are
    simply not deduped against it."""
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
    """One accurate sentence for everything A1d lost, or "" when nothing was lost. States what the
    readable files yielded rather than asserting a blanket failure."""
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
    # a run withholds candidate-target pairs in the scheduler's unit, each named by the bound that
    # withheld it; only dispositions the per-zone count cannot express are rendered here.
    _pairs = loss.get("wildcard_pairs", 0)
    for _key, _sentence in (
            ("bound", f"withheld by the {A1D_WILDCARD_WORD_CAP}-per-zone spend bound — they rotate in on "
                      f"a later run"),
            ("unselectable", "in slot(s) no bound can admit — they will NOT be retried"),
            ("stopped", f"left unsubmitted when the wildcard pass stopped "
                        f"({loss.get('wildcard_stop') or 'no reason recorded'})")):
        if (loss.get("wildcard_by_cause") or {}).get(_key):
            parts.append(f"{loss['wildcard_by_cause'][_key]}/{_pairs} wildcard candidate(s) {_sentence}")
    if loss.get("unschedulable_pairs"):
        parts.append(f"{loss['unschedulable_pairs']} candidate(s) in {loss['unschedulable_slots']} "
                     f"slot(s) cannot be scheduled under the current bounds and will NOT be retried")
    if loss.get("sweep_stop"):
        parts.append(f"the scheduled brute stopped early ({loss['sweep_stop']})")
    if loss.get("sweep_machinery"):
        parts.append(loss["sweep_machinery"])
    if loss.get("withheld_by_word_cap"):
        # counted in candidate-target pairs as the scheduler measures them, from what it actually
        # submitted — whole buckets can underfill the bound, so `corpus - cap` would be wrong.
        parts.append(f"{loss['withheld_by_word_cap']}/{loss.get('sweep_eligible_pairs', 0)} candidate(s) "
                     f"withheld by the {A1D_WORD_CAP}-per-apex A1d spend bound")
    return "; ".join(parts)


def _a1d_sweep(ctx, prof, kept, origins, execute, *, dependency_ok):
    """The scheduled apex brute, isolated so its caller can bracket it in one source lifecycle."""
    return sweep.run_sweep(
        lane="a1d_brute",
        # the schema is part of the path: a `BUCKETS` change bumps it and starts a fresh rotation, rather
        # than meeting a document `RotationProgress` refuses to overwrite.
        state_dir=Path(ctx.run.project_dir) / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}",
        targets=list(prof.apex_domains), vocabulary=lambda _apex: list(kept), execute=execute,
        budget_s=budget.budget_seconds("A1D_BUDGET_S"), coverage_lane="enrich.a1d_brute",
        dependency_ok=dependency_ok, max_pairs_per_target=A1D_WORD_CAP,
        attribution=lambda w: sweep.owner_of(w, sorted(origins.get(w) or ["crawl"])))


def _a1d_fold_sweep(ctx, prof, swept, wl_loss) -> None:
    """Fold the sweep into the lane's reported facts. Fallible on purpose — the caller contains it."""
    # what the apex brute still OWES, for a supervisor (settle prerequisite B). Best effort: a report is
    # never a stop.
    try:
        if swept.remainder_known:
            remainder.emit(remainder.from_sweep("enrich.a1d_brute", swept))
        else:                              # ...ran, but cannot say — which is not the same as not running
            remainder.unknown("enrich.a1d_brute", why="the eligible set was never established")
    except Exception:                                        # noqa: BLE001
        pass
    # machinery is folded unchanged: unschedulable slots are their own structured fact, rendered once
    # from the counters below.
    if swept.machinery:
        wl_loss["sweep_machinery"] = "; ".join(swept.machinery)
    if swept.stop_kind not in (None, "bound"):
        wl_loss["sweep_stop"] = swept.stop
    if swept.stop_kind == "dependency" and not swept.slots_attempted:
        # an eligible brute that never ran must say so: the note carries how much work went unsubmitted.
        # A tool that vanished mid-sweep is a different fact, carried by the terminal.
        ctx.run.record("enrich", skipped("puredns", f"not installed — {len(prof.apex_domains)} A1d "
                                                    f"apex brute(s) unsubmitted"))
    # only a `bound` stop is the spend bound withholding work: contention, a dependency stop, machinery
    # and the clock each leave `eligible - attempted` behind with their own fact.
    if swept.stop_kind == "bound":
        wl_loss["withheld_by_word_cap"] = max(0, swept.eligible_pairs - swept.attempted_pairs)
        wl_loss["sweep_eligible_pairs"] = swept.eligible_pairs
    if swept.unselectable_pairs:
        # NOT a remainder any later run collects, and not the spend bound either: candidates in a slot no
        # bound can admit. The scheduler carries the slots structurally; the verdict carries the size.
        wl_loss["unschedulable_pairs"] = swept.unselectable_pairs
        wl_loss["unschedulable_slots"] = swept.unselectable_slots


def _a1d_terminal(swept, produced: int):
    """One terminal for the source over the whole multi-bucket sweep, derived from what was produced and
    from the slot classes (not from "the runner returned": `slots_obtained` counts SUCCESS and EMPTY
    alike)."""
    # degrading facts are orthogonal and accumulate (lost slots, submitted-slot failures, unadmittable
    # candidates). The reason is built once for every path; the status keeps its precedence.
    facts = []
    if swept.machinery:
        facts.append("; ".join(swept.machinery))
    if swept.classes:
        # both currencies: with batching, 10 failed slots may be one failed call or ten, and the
        # slot-weighted map alone cannot say which.
        facts.append(f"slot outcomes {dict(sorted(swept.classes.items()))} in "
                     f"{swept.invocations} invocation(s) "
                     f"{dict(sorted(swept.invocation_classes.items()))}")
    if swept.unselectable_pairs:
        facts.append(f"{swept.unselectable_pairs} candidate(s) in {swept.unselectable_slots} slot(s) "
                     f"cannot be scheduled under the current bounds")
    # `or None`: a clean sweep has nothing to say, and an empty string is a reason field carrying no
    # reason. `events.emit` omits None.
    _why = "; ".join(p for p in ([swept.stop] if swept.stop else []) + facts) or None

    if swept.contended:
        _st = Status.FAILED
    elif swept.stop_kind == "dependency" and not swept.slots_attempted:
        _st = Status.SKIPPED                            # nothing ran at all
    elif facts or swept.stop_kind == "dependency":
        # PARTIAL asserts something was produced — a slot answering "nothing here" is not production. A
        # tool that vanished mid-sweep degrades the same way.
        _st = Status.PARTIAL if produced else Status.FAILED
    else:
        _st = Status.SUCCESS if produced else Status.EMPTY
    return _st, _why


def _a1d_recursive_brute(ctx) -> set[str]:
    """A1d — recursion: re-brute with the target's own naming vocabulary mined during the crawl.

    The crawl (after vertical) mines the vocabulary via xnLinkFinder over waymore/JS; here we re-brute
    apexes (puredns) and any wildcard zones with it. Bounded: the wordlist is capped and deduped against
    the base dictionary. Returns the hosts discovered, for run() to force into the catch-up set."""
    prof, scope = ctx.profile, ctx.scope
    if scope.passive_only:
        return set()
    from .vertical import _target_wordlist, _wildcard_differentiate, _resolvers, _wordlist
    wl_loss: dict = {}
    # retention (crawl-mined, in encounter order), subtraction (streamed against the base dictionary),
    # then selection (the spend bound, applied last).
    mined = _target_wordlist(ctx, loss=wl_loss)
    kept = _a1d_subtract_base(ctx, mined, _wordlist, wl_loss)
    wl_loss["mined_words"] = len(mined)
    wl_loss["after_base"] = len(kept)
    # `kept` = mined corpus minus base-dictionary coverage. Each active lane selects under its own bound,
    # so widening one cannot widen the other; `twords` is only the "any vocabulary at all" answer.
    twords = kept
    # the whole retained corpus goes to the differ; `A1D_WILDCARD_WORD_CAP` is the per-zone spend the
    # scheduler applies, so the tail rotates in on later runs instead of being cut off.
    wc_words = sorted(kept)                                    # -> the wildcard differ (HTTP), per zone
    # the DNS withholding is the sweep's own fact; the wildcard withholding is not a fact until the pass
    # runs. One outcome, chosen once from what was produced and what was lost.
    lost = _a1d_loss_why(wl_loss, len(twords))
    if not twords:
        # the base list only dedups mined words, so a base-only failure with nothing mined is not A1d
        # damage — a genuine no-input skip survives it. Damage to the mined input still fails.
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

    # the apex brute is scheduled: stable buckets, resumable rotation, `A1D_WORD_CAP` candidates per apex.
    # Which candidates is not a fixed first-N — a bounded run advances the rotation for the next to continue.
    submitted_apexes = 0
    swept = None
    origins = wl_loss.get("origins") or {}
    apexes_run: set = set()
    resolvers = trusted = None
    # dependency detection and resolver prep happen inside the guarded interval below, so a raising
    # `_resolvers()` cannot abort the phase before the A1d lifecycle opens, and `have()` is observed once.
    sid = "enrich.a1d_brute"
    # the resume key covers everything that shapes the partition, not just the spend: root count,
    # invocation maximum and slot-space schema. A different partition is a different question.
    fp = events.work_unit(sid,
                          # input is the retained vocabulary, not only the apexes (two corpora over the
                          # same apexes are different work); the rotation owns per-slot identity.
                          inputs={"apexes": sorted(prof.apex_domains),
                                  "vocabulary": sweep.content_digest(sorted(kept))},
                          config={"per_apex": A1D_WORD_CAP, "buckets": sweep.BUCKETS,
                                  "invocation_max": sweep.MAX_BATCH_WORDS},
                          schema_version=sweep.SCHEMA)

    def _brute(apex: str, unit: str, words):
        """One puredns invocation. `unit` names it — a lone slot keeps its own id, a batched one reads
        `<first>+<n>` — and `words` is the union of every slot it carries."""
        nonlocal submitted_apexes
        wl_file = ctx.write_list(f"a1d_words_{apex.replace('.', '_')}_{unit}.txt", sorted(words))
        cmd = ["puredns", "bruteforce", str(wl_file), apex, "--resolvers-trusted", str(trusted), "-q"]
        if resolvers:
            cmd += ["-r", str(resolvers)]
        if prof.dns_rate:
            cmd += ["--rate-limit", str(prof.dns_rate)]
        br = ctx.run.raw_path("enrich", "puredns", f"a1d-brute-{apex}-{unit}.txt")
        r = exec_tool(
            "puredns", cmd,
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*br.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        )
        ctx.run.record("enrich", r)
        if r.status is not Status.SKIPPED and apex not in apexes_run:
            # an invocation that never spawned is not an apex we brute-forced
            apexes_run.add(apex)
            submitted_apexes = len(apexes_run)
        if r.raw_path and r.raw_path.exists():
            for row in normalize.hosts(r.raw_path.read_text(), "target-wordlist", str(br)):
                if scope.in_scope(row["host"]) and not scope.is_oos(row["host"]):
                    ctx.run.add("subdomain", row)
                    discovered.add(row["host"])
        return r

    # the registry gate is for this source only: `enrich.wildcard_a1d` is a separate lane, so a disabled
    # or unavailable puredns lane skips the sweep but the function continues.
    if registered(sid):
        events.tool_start(sid, cmd=["puredns", "bruteforce", "(scheduled)"],
                          input_total=len(prof.apex_domains), work_unit=fp)
        # the whole start-to-terminal interval is protected and the terminal is emitted in `finally`,
        # exactly once: a `tool_start` with no `tool_finish` is a source that never answered.
        outcome = (Status.FAILED, "the scheduled brute did not report an outcome")
        try:
            tool_ok = have("puredns")               # one observation, used for setup and the gate
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

    # the wildcard differ is its own lane and runs regardless of the brute above: `_wildcard_differentiate`
    # gates on the registry and emits its own start/terminal under `enrich.wildcard_a1d`.

    # wildcard-zone differ with the target words folded in (zones persisted by vertical)
    zones = set(ctx.run.values("wildcard_zone"))
    wc: dict = {}
    if zones:
        discovered.update(_wildcard_differentiate(ctx, zones, extra_words=wc_words, phase="enrich",
                                                  label="wildcard-a1d", source="wildcard-http-a1d",
                                                  source_id="enrich.wildcard_a1d", stats=wc,
                                                  word_spend=policy.limit('A1D_WILDCARD_WORD_CAP')))
    # one A1d outcome, chosen after the work.
    if wc.get("eligible_zones", 0) > 0:
        wl_loss["wildcard_withheld"] = wc.get("candidate_pairs_withheld", 0)
        wl_loss["wildcard_pairs"] = wc.get("candidate_pairs_eligible", 0)
        wl_loss["wildcard_by_cause"] = wc.get("candidate_pairs_by_cause") or {}
        wl_loss["wildcard_stop"] = wc.get("sweep_stop") or wc.get("blocked_reason") or ""
    # `after_base` is the retained-word count; the scheduler's candidate-target pairs are a different unit
    # in their own fields.
    unsubmitted = max(0, len(prof.apex_domains) - submitted_apexes)
    unsubmitted_why = (swept.stop if swept is not None and swept.stop
                       else wl_loss.get("sweep_error")
                       or ("the source is not registered" if swept is None else None)
                       # nothing stopped the run: every candidate sat in a slot no bound can admit, which
                       # is why no apex was brute-forced.
                       or ("no candidate is schedulable under the current bounds"
                           if wl_loss.get("unschedulable_pairs") else "no reason recorded"))
    # "there were wildcard zones" is not "the wildcard pass ran": passive mode, a missing httpx, no
    # wordlist, the self-contact guard and the zone cap all leave zones unsubmitted. Both facts are reported.
    wc_eligible, wc_probed = wc.get("eligible_zones", 0), wc.get("probed_zones", 0)
    wc_unsubmitted = max(0, wc_eligible - wc_probed)
    lost = _a1d_loss_why(wl_loss, len(kept))        # `produced` here is usable words, not pairs
    parts = ([lost] if lost else []) + ([f"{unsubmitted} apex brute(s) unsubmitted "
                                         f"({unsubmitted_why})"] if unsubmitted else [])
    if wc_unsubmitted:
        parts.append(f"{wc_unsubmitted}/{wc_eligible} wildcard zone(s) not differentiated"
                     + (f" ({wc['blocked_reason']})" if wc.get("blocked_reason") else ""))
    # vocabulary the wildcard pass could not use is A1d's loss too, even on a probed run with a damaged
    # wordlist (which was only looked at when zones went unsubmitted before).
    _v = wc.get("vocabulary") or {}
    _vlost = _v.get("undecodable", 0) + _v.get("rejected", 0)
    if _v.get("unreadable"):
        parts.append("the wildcard wordlist is present and UNREADABLE — only the mined vocabulary was used")
    if _vlost:
        parts.append(f"{_vlost} wildcard vocabulary word(s) unusable ({_v.get('undecodable', 0)} not valid "
                     f"UTF-8, {_v.get('rejected', 0)} not a single DNS label)")
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
    # hosts known but never resolved (crawl/CSP-discovered). A1d's wildcard differentiator marks its hits
    # `resolved`, so force those back in for the full enrich treatment (takeover, httpx, screenshots).
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
        r = exec_tool(
            "dnsx", ["dnsx", "-l", str(targets), "-a", "-resp", "-json", "-silent"],
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*res.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        )
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
        r = exec_tool(
            "dnsx", ["dnsx", "-l", str(targets), "-cname", "-a", "-json", "-silent"],
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*cn.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
        )
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
        # share probe's fingerprint path — SYN web-port prefilter, then httpx on open ports only, so
        # late A1d/crawl/CSP hosts get the same fast treatment, not the slow direct behaviour.
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
                    "nuclei", wcmd,
                    repository=ctx.run,
                    stdout=RepositoryOutput.discard(),
                    stderr=RepositoryOutput.discard(),
                    timeout=nuclei_timeout(len(new_live), ctx.http_timeout)))
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
                shot_dir = fresh_artifact_dir(ctx.run.dir / "raw" / "enrich" / "gowitness")
                gr = exec_tool("gowitness",
                    ["gowitness", "scan", "file", "-f", str(lf),
                     "--screenshot-path", str(shot_dir), "--write-jsonl",
                     "--write-jsonl-file", str(shot_dir / "gowitness.jsonl")],
                    repository=ctx.run,
                    stdout=RepositoryOutput.discard(),
                    stderr=RepositoryOutput.discard(),
                    timeout=ctx.http_timeout)
                # same reclassification as probe; count this attempt's dir only, so a reused/
                # pre-populated dir cannot inflate the count (the dir is fresh per invocation)
                shots = len(list(shot_dir.glob("*.jpeg"))) + len(list(shot_dir.glob("*.png")))
                reclassify_from_files(gr, shots, "screenshot")
                ctx.run.record("enrich", gr)
                for ext in ("*.jpeg", "*.png"):
                    for img in shot_dir.glob(ext):
                        ctx.run.add("screenshot", {"url": str(img), "sources": ["gowitness"]})

            if have("smap"):                            # passive (Shodan) ports — parse like probe
                sm_targets = [normalize.host_of_url(u) for u in new_live]
                si = ctx.write_list("enrich_smap.txt", sm_targets)
                sm = ctx.run.raw_path("enrich", "smap", "smap.json")
                sm.unlink(missing_ok=True)              # -o file: clear stale before the run
                sr = exec_tool(
                    "smap", ["smap", "-iL", str(si), "-oJ", str(sm)],
                    repository=ctx.run,
                    stdout=RepositoryOutput.discard(),
                    stderr=RepositoryOutput.discard(), timeout=600,
                )
                # parse + reclassify + ingest via the same shared helper probe uses (-oJ structured;
                # status reflects yield), so enrich's passive port yield is not lost as raw-only.
                from .probe import _smap_ingest
                _smap_ingest(ctx, sr, sm, "enrich", sm_targets)
