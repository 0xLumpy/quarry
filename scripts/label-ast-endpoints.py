#!/usr/bin/env python3
"""STEP 3 of the ast-analyzer evaluation — a hand-labelled precision sample, EXPLORATORY.

Step 2 measured that the analyzer's endpoint output contains api-shaped paths jsluice never sees, inside
~3100 net-new items that are mostly tz-database entries, bundled class names and package specifiers. The
obvious next move — keep the api-shaped ones — is a rule READ OFF that corpus.

**This corpus cannot validate that rule, and this script no longer claims it can.** Step 2 ran over all
1321 bundles and the rules were written after looking at the results; hashing the same bundles into
dev/eval halves afterwards does not make 662 of them unseen. What a sample here CAN do is estimate, by
hand, how precise each rule is ON THIS CORPUS — an exploratory number that says whether a rule is worth
carrying to a corpus nobody has looked at yet. The validation decision waits for that second corpus (the
next OTC run, or another engagement's `js_files`).

    worksheet   draw a stratified random sample, with enough evidence per row to judge it without
                opening the bundle
    score       given a worksheet a HUMAN has labelled, report each candidate rule's precision/recall

    it never labels anything itself. A model-generated label scored against a model-generated rule is not
    validation, it is a mirror.

    ./scripts/label-ast-endpoints.py worksheet --n 100 -o notes/ast-endpoint-worksheet.jsonl
    $EDITOR notes/ast-endpoint-worksheet.jsonl        # set "label" on each row
    ./scripts/label-ast-endpoints.py score notes/ast-endpoint-worksheet.jsonl

Labels: `endpoint` (a path a server would route), `not-endpoint` (class name, tz entry, MIME fragment,
package specifier, format string), `unsure` (never imputed — see the scorer).

No network. Bundles come from a previous run's artifacts; the analyzer runs in the step-1 sandbox.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import inspect
import json
import random
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABELS = ("endpoint", "not-endpoint", "unsure")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / f"{name}.py")
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import {name}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def split_of(bundle: str) -> str:
    """A deterministic half of the corpus, by BUNDLE.

    It is NOT a hold-out and is not called one: every bundle here was already inspected in step 2. The
    split exists only so that a future run over an UNSEEN corpus can be compared against the same kind of
    slice, and so a rule is not tuned twice on identical rows. A split by candidate would additionally
    put items from the same file, library and generator on both sides.
    """
    return "a" if int(hashlib.sha256(bundle.encode()).hexdigest()[:8], 16) % 2 == 0 else "b"


# ── the candidate filters, in ONE place so they can be scored against each other ─────────────────────
def filter_plausible(row: dict, delta) -> bool:
    return delta.plausible_path(row["key"])


def filter_api_words(row: dict, delta) -> bool:
    return delta.plausible_path(row["key"]) and delta.bucket(row["key"]) == "api-shaped"


def filter_not_noise(row: dict, delta) -> bool:
    """A deliberately different shape: keep a plausible path unless it looks like the noise families the
    corpus showed (a tz entry, a class-path, a package specifier). Scored beside the others so the
    comparison is between RULES, not between one rule and nothing."""
    if not delta.plausible_path(row["key"]):
        return False
    segs = [s for s in row["key"].strip("/").split("/") if s]
    if row["key"].startswith("/@"):                       # /@sentry/browser
        return False
    if segs and segs[0] in ("Africa", "America", "Asia", "Europe", "Australia", "Pacific", "Antarctica",
                            "Atlantic", "Indian", "Arctic", "Etc"):
        return False                                      # tz database
    if any(s[:1].isupper() and any(c.islower() for c in s) and len(s) > 3 for s in segs[:1]):
        return False                                      # /AbstractList/… — a class path, not a route
    return True


FILTERS = {"plausible-only": filter_plausible, "api-words": filter_api_words,
           "not-noise": filter_not_noise}


#: everything a labeller may touch. Any other field is part of the frozen draw.
EDITABLE = ("label", "note")


def worksheet_digest(meta: dict, rows: list) -> str:
    """One digest over the rows' IMMUTABLE fields AND the metadata that drives the score.

    Rows alone were not enough: the population estimates read `_meta.strata`, so editing those counts
    moved every weight without tripping anything, and `slice`, `sampled`, the frozen rule names and even
    `editable_fields` were equally loose. Everything except the digest itself and the two editable row
    fields is bound. Order-insensitive, because a hand-edited JSONL gets reordered.
    """
    blobs = sorted(json.dumps({k: v for k, v in r.items() if k not in EDITABLE},
                              sort_keys=True, separators=(",", ":")) for r in rows)
    scope = {k: v for k, v in meta.items() if k != "worksheet_digest"}
    payload = json.dumps(scope, sort_keys=True, separators=(",", ":")) + "\n" + "\n".join(blobs)
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def rule_digests(delta) -> dict:
    """A fingerprint per rule, plus one for the shared machinery they all lean on.

    A rule that can be edited after the labels are read is not a prediction, it is a postdiction. The
    worksheet therefore stores each rule's VERDICT PER ROW and this digest; scoring replays the stored
    verdicts and refuses on drift. Freezing the corpus without freezing the rule leaves the same hole at
    the other end.
    """
    parts = {name: inspect.getsource(fn) for name, fn in FILTERS.items()}
    parts["_shared"] = "".join([inspect.getsource(delta.plausible_path), inspect.getsource(delta.bucket),
                                repr(sorted(delta.API_WORDS)), repr(sorted(delta._META)),
                                repr(sorted(delta.MIME_SUBTYPES))])
    return {k: hashlib.sha256(v.encode()).hexdigest()[:16] for k, v in parts.items()}


def fold_occurrence(agg: dict, key: str, *, readable: bool, has_it: bool, prov: dict) -> dict:
    """Fold ONE occurrence of `key` into the aggregate — the property being maintained is that
    comparability and agreement belong to the KEY, not to whichever bundle happened to be read first."""
    e = agg.setdefault(key, {"comparable": False, "jsluice_has_it": False,
                             "occurrences": 0, "provenance": []})
    e["comparable"] = e["comparable"] or readable          # ANY readable occurrence
    e["jsluice_has_it"] = e["jsluice_has_it"] or (readable and has_it)
    e["occurrences"] += 1
    if len(e["provenance"]) < 3:                           # a few representative sites, no more
        e["provenance"].append(prov)
    return e


def allocate(strata: dict, n: int, census_max: int = 30) -> dict:
    """Spend the whole label budget: CENSUS the small strata, sample the rest.

    Two failures this replaces. An even `n // len(strata)` wasted the quota of any stratum smaller than
    its share — the first POAB draw asked for 100 and produced 85. Plain round-robin then spent the
    leftovers but still left a 25-item family one short, which is the worst outcome available: a family
    small enough to label COMPLETELY gains nothing from being sampled, and leaves a population estimate
    where a census was free.
    """
    names = sorted(strata, key=lambda k: (len(strata[k]), k))
    alloc = {k: 0 for k in names}
    left = n
    rest = []
    for k in names:                                   # census: take the whole family
        if len(strata[k]) <= census_max and len(strata[k]) <= left:
            alloc[k] = len(strata[k])
            left -= alloc[k]
        else:
            rest.append(k)
    while left > 0 and any(alloc[k] < len(strata[k]) for k in rest):   # round-robin the remainder
        for k in rest:
            if left == 0:
                break
            if alloc[k] < len(strata[k]):
                alloc[k] += 1
                left -= 1
    return alloc


def build_worksheet(args) -> int:
    probe, delta = _load("probe-jxscout-ast"), _load("measure-ast-delta")
    run = Path(args.run)
    corpus = Path(args.corpus_dir) if args.corpus_dir else (run / "raw" / "crawl" / "js_files")
    if not corpus.is_dir():
        print(f"no corpus at {corpus}", file=sys.stderr)
        return 2
    all_files = sorted(corpus.glob("*.js"))
    files = [f for f in all_files if split_of(f.name) == args.slice] if args.slice else all_files
    print(f"corpus {corpus} — {len(files)} bundle(s)"
          + (f" in slice {args.slice!r} of {len(all_files)}" if args.slice else " (whole corpus)"))
    if not args.unseen:
        print("  EXPLORATORY: pass --unseen only for a corpus whose candidates have NOT been inspected")

    # AGGREGATE BY KEY FIRST. Keeping only a key's first occurrence let one bundle decide its fate: a key
    # first seen in a bundle jsluice could not read stayed `uncomparable` even though a later readable
    # bundle contained it, and a key jsluice found only in a later occurrence stayed falsely `net-new`.
    # It also made the strata depend on filename order. Comparability and agreement are properties of the
    # KEY across every occurrence, so they are folded before anything is classified.
    agg: dict = {}
    unreadable: list = []
    with tempfile.TemporaryDirectory(prefix="quarry-astlabel-") as tmp:
        scratch = Path(tmp)
        if not probe.sandbox(["true"], scratch):
            print("REFUSING: bwrap unavailable", file=sys.stderr)
            return 2
        for i, f in enumerate(files, 1):
            r = probe.analyze(f, scratch, keep_doc=True, wall_s=args.timeout)
            if r["disposition"] == "killed":
                for mb in (8192, 16384, 32768):
                    r = probe.analyze(f, scratch, keep_doc=True, wall_s=args.timeout,
                                      address_space_mb=mb)
                    # climb until the analyzer actually ANSWERS. Stopping at "not killed" left the two
                    # 27 MB POAB bundles excluded as `analyzer-error`: at 16 GB the analyzer catches its
                    # own allocation failure and exits 1, which is not a refusal — at 32 GB the same
                    # bytes parse cleanly in 92 s. A rung that merely changes the SHAPE of the failure is
                    # not a result.
                    if r["disposition"] in ("success", "empty"):
                        break
            if r["disposition"] not in ("success", "empty"):
                # EXCLUDED EVIDENCE, counted and named. A validation that quietly calls 144 of 148 "the
                # corpus" is overstating its own population.
                unreadable.append({"bundle": f.name, "disposition": r["disposition"],
                                   "size": f.stat().st_size})
                continue
            js_ok, js_keys = delta.jsluice_file(f, "urls")
            for m in (r.get("doc") or []):
                if m.get("analyzerName") not in delta.ENDPOINT_ANALYZERS:
                    continue
                key = delta.path_key((m.get("extra") or {}).get("pathname") or m.get("value", ""))
                if not key:
                    continue
                fold_occurrence(agg, key, readable=js_ok, has_it=(key in js_keys),
                                prov={"bundle": f.name, "analyzer": m.get("analyzerName"),
                                      "value": (m.get("value") or "")[:200],
                                      "start": m.get("start"), "readable": js_ok,
                                      "tags": sorted(m.get("tags") or {}),
                                      "context": _context(f, m.get("start") or {})})
            if i % 100 == 0:
                print(f"  {i}/{len(files)} …")

    rows = []
    for key, e in sorted(agg.items()):
        first = e["provenance"][0]
        rows.append({"key": key, "occurrences": e["occurrences"],
                     "bundle": first["bundle"], "analyzer": first["analyzer"], "value": first["value"],
                     "start": first["start"], "tags": first["tags"], "context": first["context"],
                     "jsluice_has_it": e["jsluice_has_it"], "comparable": e["comparable"],
                     "provenance": e["provenance"],
                     "bucket": delta.bucket(key) if delta.plausible_path(key) else "implausible"})

    # STRATIFIED: the net-new families the decision is about, plus the two controls that make recall
    # meaningful — items jsluice also found (agreement) and items the current filters would DROP.
    strata = collections.defaultdict(list)
    for row in rows:
        if not row["comparable"]:
            # its own stratum, and it never enters a novelty number: jsluice could not read the bundle,
            # so "jsluice does not have this path" is unknown, not true. Filing it under net-new would
            # convert an inability to compare into analyzer novelty.
            strata["uncomparable/jsluice-unreadable"].append(row)
        elif row["jsluice_has_it"]:
            strata["also-in-jsluice"].append(row)
        else:
            strata[f"net-new/{row['bucket']}"].append(row)
    rng = random.Random(args.seed)
    alloc = allocate(strata, args.n, args.census_max)
    sample: list = []
    for name, items in sorted(strata.items()):
        pick = rng.sample(items, alloc[name])
        for row in pick:
            row["stratum"] = name
            row["label"] = None                          # ← the human fills this in
            row["note"] = ""
            # FROZEN at draw time, before any label exists
            row["predictions"] = {rule: bool(fn(row, delta)) for rule, fn in FILTERS.items()}
            sample.append(row)
    rng.shuffle(sample)                                  # unordered, so the labeller cannot pattern-match

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    meta = {"purpose": "hand-label each row's `label` field", "labels": list(LABELS),
            "slice": args.slice,
            "status": ("UNSEEN — drawn before any candidate from this corpus was inspected"
                       if args.unseen else
                       "EXPLORATORY — the rules were derived from this corpus; validation needs an "
                       "unseen one"),
            "seed": args.seed, "corpus": str(corpus),
            # the POLICY this draw was made under. A filter validated at 60 s is validated on a
            # NARROWER population than a lane that runs at 300 s would process — and the bundles the
            # short wall excludes are the 30 MB ones where jsluice gives up, i.e. exactly where the
            # analyzer is supposed to earn its place.
            "policy": {"timeout_s": args.timeout, "address_space_ladder_mb": [4096, 8192, 16384, 32768],
                       "census_max": args.census_max},
            "population": {"files_offered": len(files),
                           "files_read": len(files) - len(unreadable),
                           "excluded_unreadable": unreadable},
            "strata": {k: len(v) for k, v in sorted(strata.items())},
            "rule_digests": rule_digests(delta),
            "editable_fields": list(EDITABLE), "sampled": len(sample)}
    meta["worksheet_digest"] = worksheet_digest(meta, sample)     # LAST: it binds everything above
    with out.open("w") as fh:
        fh.write(json.dumps({"_meta": meta}) + "\n")
        for row in sample:
            fh.write(json.dumps(row) + "\n")
    if unreadable:
        print(f"  EXCLUDED as unreadable: {len(unreadable)} bundle(s) — "
              f"{collections.Counter(u['disposition'] for u in unreadable)}")
    print(f"\nwrote {out} — {len(sample)} rows to label, drawn from {len(rows)} candidates")
    for name, items in sorted(strata.items()):
        print(f"  {name:<28} population {len(items):>5}  sampled {sum(1 for r in sample if r['stratum'] == name)}")
    print("\nLabel each row: \"endpoint\" | \"not-endpoint\" | \"unsure\", then run `score`.")
    return 0


def _context(path: Path, start: dict) -> str:
    """±120 characters around the match, so a row can be judged without opening a 5 MB bundle."""
    line = (start or {}).get("line")
    if not isinstance(line, int):
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for n, text in enumerate(fh, 1):
                if n == line:
                    col = (start or {}).get("column") or 0
                    return text[max(0, col - 120): col + 120].strip()
    except OSError:
        return ""
    return ""


def score(args) -> int:
    delta = _load("measure-ast-delta")
    now = rule_digests(delta)
    rows, meta = [], {}
    for i, line in enumerate(Path(args.worksheet).read_text().splitlines()):
        if not line.strip():
            continue
        d = json.loads(line)
        if i == 0 and "_meta" in d:
            meta = d["_meta"]
            continue
        rows.append(d)
    # RULE FREEZE. The worksheet carries each rule's verdict per row and the digest of the code that
    # produced it. Recomputing verdicts here would let a rule be edited after the labels were read and
    # still be presented as a prediction.
    frozen = meta.get("rule_digests") or {}
    drift = sorted(k for k in set(frozen) | set(now) if frozen.get(k) != now.get(k))
    if not frozen:
        print("REFUSING: this worksheet carries no rule digests — it predates the freeze and cannot "
              "support a validation claim", file=sys.stderr)
        return 3
    if drift and not args.allow_rule_drift:
        print(f"REFUSING: the rules changed since this worksheet was drawn: {drift}\n"
              f"  worksheet {[(k, frozen.get(k)) for k in drift]}\n"
              f"  current   {[(k, now.get(k)) for k in drift]}\n"
              f"  draw a NEW worksheet, or pass --allow-rule-drift to score it as EXPLORATORY only",
              file=sys.stderr)
        return 3
    if drift:
        print(f"  RULE DRIFT accepted by flag {drift} — this is post-hoc analysis, not validation")
    missing = [r for r in rows if not isinstance(r.get("predictions"), dict)]
    if missing:
        print(f"REFUSING: {len(missing)} row(s) carry no frozen predictions", file=sys.stderr)
        return 3
    # EXACT booleans. `"false"`, `0` and `null` all pass an `isinstance(dict)` check and then get read
    # through truthiness, which silently turns a typo into a rule verdict.
    # a predeclared rule with an incomplete verdict vector cannot produce an estimate at all: the rows it
    # says nothing about would silently count as "not kept".
    incomplete = sorted({name for name in (meta.get("rule_digests") or {}) if name != "_shared"
                         for r in rows if name not in r["predictions"]})
    if incomplete:
        print(f"REFUSING: frozen rule(s) {incomplete} have no verdict on every row", file=sys.stderr)
        return 3
    bad_types = [(r.get("key"), rule, v) for r in rows for rule, v in r["predictions"].items()
                 if v is not True and v is not False]
    if bad_types:
        print(f"REFUSING: {len(bad_types)} frozen prediction(s) are not exact booleans: "
              f"{bad_types[:3]}", file=sys.stderr)
        return 3
    stored = meta.get("worksheet_digest")
    if not stored:
        print("REFUSING: this worksheet carries no digest — neither its predictions nor the weights that "
              "score them can be shown to be the ones drawn before labelling", file=sys.stderr)
        return 3
    if worksheet_digest(meta, rows) != stored:
        print(f"REFUSING: the worksheet changed since it was drawn (digest "
              f"{worksheet_digest(meta, rows)} != {stored}). Only {list(EDITABLE)} may be edited — that "
              f"includes the metadata the estimates are weighted by; re-draw rather than repair.",
              file=sys.stderr)
        return 3
    labelled = [r for r in rows if r.get("label") in ("endpoint", "not-endpoint")]
    unsure = [r for r in rows if r.get("label") == "unsure"]
    unlabelled = [r for r in rows if r.get("label") not in LABELS]
    print(f"worksheet: {len(rows)} rows · labelled {len(labelled)} · unsure {len(unsure)} · "
          f"UNLABELLED {len(unlabelled)}  (slice: {meta.get('slice', '?')})")
    print(f"  status: {meta.get('status', 'unknown')}")
    if unlabelled:
        print("  scoring the labelled rows only — an unlabelled row is not a negative", file=sys.stderr)
    if not labelled:
        print("nothing to score yet", file=sys.stderr)
        return 1
    truth_pos = [r for r in labelled if r["label"] == "endpoint"]
    print(f"  ground truth: {len(truth_pos)} endpoint · {len(labelled) - len(truth_pos)} not-endpoint\n")
    # The sample is STRATIFIED, and the strata have wildly different sizes (1996 implausible against 24
    # api-shaped in one run). Precision counted over the raw sample would therefore describe the sampling
    # plan, not the corpus: each stratum must be weighted back to its population before the numbers mean
    # anything about what a filter would do in a lane.
    pops = (meta.get("strata") or {})
    by_stratum: dict = collections.defaultdict(list)
    for r in labelled:
        by_stratum[r.get("stratum", "?")].append(r)
    if not pops:
        print("  (no stratum populations in _meta — reporting UNWEIGHTED sample numbers only)")

    # WEIGHTS divide a stratum's population by the rows that got a usable label. If some rows are unsure
    # or unlabelled, that expansion silently makes the resolved rows speak for them — and ambiguity is
    # exactly the thing least likely to be distributed at random. So point estimates are refused until a
    # stratum is fully resolved, and BOUNDS are reported instead.
    sampled_by_stratum: dict = collections.defaultdict(int)
    for r in rows:
        sampled_by_stratum[r.get("stratum", "?")] += 1
    unresolved_by_stratum: dict = collections.defaultdict(int)
    for r in rows:
        if r.get("label") not in ("endpoint", "not-endpoint"):
            unresolved_by_stratum[r.get("stratum", "?")] += 1
    fully_resolved = not any(unresolved_by_stratum.values())

    def weight(stratum: str) -> float:
        n = sampled_by_stratum.get(stratum, 0)
        return (pops.get(stratum, n) / n) if n else 0.0

    if not fully_resolved:
        print(f"  {sum(unresolved_by_stratum.values())} row(s) unresolved (unsure/unlabelled): population "
              f"estimates are reported as BOUNDS, never as a point value\n")
    print(f"  {'filter':<16} {'kept':>5} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}"
          f"   {'est. kept':>10} {'est. prec':>12} {'est. recall':>14}")
    # the WORKSHEET's rules, not today's list: a rule deleted since the draw would otherwise vanish from
    # the report while its predictions sit right there in the file.
    frozen_rules = [k for k in frozen if k != "_shared"]
    for name in frozen_rules:
        kept = [r for r in labelled if r["predictions"][name]]
        tp = sum(1 for r in kept if r["label"] == "endpoint")
        fp = len(kept) - tp
        fn_ = len(truth_pos) - tp
        prec = (tp / len(kept)) if kept else float("nan")
        rec = (tp / len(truth_pos)) if truth_pos else float("nan")
        # bounds over the UNRESOLVED rows a rule would keep: best case they are all endpoints, worst
        # case none of them are. With nothing unresolved the two collapse to one number.
        kept_all = [r for r in rows if r["predictions"][name]]
        kept_unres = [r for r in kept_all if r.get("label") not in ("endpoint", "not-endpoint")]
        w_tp = sum(weight(r["stratum"]) for r in kept if r["label"] == "endpoint")
        w_kept = sum(weight(r["stratum"]) for r in kept_all)
        w_unres = sum(weight(r["stratum"]) for r in kept_unres)
        w_pos = sum(weight(r["stratum"]) for r in truth_pos)
        w_pos_hi = w_pos + sum(weight(r["stratum"]) for r in rows
                               if r.get("label") not in ("endpoint", "not-endpoint"))
        lo = (w_tp / w_kept) if w_kept else float("nan")
        hi = ((w_tp + w_unres) / w_kept) if w_kept else float("nan")
        rec_lo = (w_tp / w_pos_hi) if w_pos_hi else float("nan")
        # if the kept-but-unresolved rows are endpoints they join the POSITIVE population too, so the
        # denominator has to grow with the numerator — otherwise recall can print above 1.0.
        rec_hi = ((w_tp + w_unres) / (w_pos + w_unres)) if (w_pos + w_unres) else float("nan")
        band = (f"{lo:.2f}" if fully_resolved else f"{lo:.2f}-{hi:.2f}")
        rband = (f"{rec_hi:.2f}" if fully_resolved else f"{rec_lo:.2f}-{rec_hi:.2f}")
        print(f"  {name:<16} {len(kept):>5} {tp:>4} {fp:>4} {fn_:>4} {prec:>10.2f} {rec:>8.2f}"
              f"   {w_kept:>10.0f} {band:>12} {rband:>14}")
    new_rules = [k for k in FILTERS if k not in frozen_rules]
    if new_rules:
        print(f"\n  rules that exist NOW but were not predeclared here: {new_rules} — each needs its own "
              f"worksheet; scoring them against these labels would be postdiction")
    print("\n  est.* weight each SAMPLED row by its stratum's population/sample ratio; unresolved rows "
          "widen the band rather than being spoken for by their neighbours.")
    for s, items in sorted(by_stratum.items()):
        print(f"    {s:<28} labelled {len(items):>3} of population {pops.get(s, '?')}"
              f" → weight {weight(s):.1f}")
    print("\nEXPLORATORY. The rules were derived from this corpus, so these numbers cannot validate them "
          "— they say whether a rule is worth carrying to a corpus nobody has looked at yet.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("worksheet",
                       help="draw an EXPLORATORY stratified sample to hand-label (not a hold-out)")
    w.add_argument("--run", default=str(Path.home() / "workspace" / "otc-service" / "recon" /
                                        "20260725-143341-1a636b47"))
    w.add_argument("--n", type=int, default=100, help="rows to label in total")
    w.add_argument("--seed", type=int, default=20260804)
    w.add_argument("--slice", choices=("a", "b"), default=None,
                   help="sample one deterministic half (omit to use the whole corpus)")
    w.add_argument("--corpus-dir", help="a bare directory of .js bodies, instead of <run>/raw/crawl/js_files")
    w.add_argument("--census-max", type=int, default=30,
                   help="strata at or below this size are labelled COMPLETELY rather than sampled")
    w.add_argument("--timeout", type=int, default=300,
                   help="per-bundle wall, in seconds. Default is the intended PRODUCTION policy: the "
                        "four 27-30 MB POAB bundles need 96-102 s (measured), so 60 s silently drops "
                        "the corpus's largest evidence")
    w.add_argument("--unseen", action="store_true",
                   help="mark this draw as UNSEEN — only truthful when no candidate from this corpus has "
                        "been inspected")
    w.add_argument("-o", "--out", default="ast-endpoint-worksheet.jsonl")
    s = sub.add_parser("score", help="score the candidate rules against a hand-labelled sample")
    s.add_argument("worksheet")
    s.add_argument("--allow-rule-drift", action="store_true",
                   help="score anyway when the rules changed since the draw (marks it post-hoc)")
    args = ap.parse_args()
    return build_worksheet(args) if args.cmd == "worksheet" else score(args)


if __name__ == "__main__":
    sys.exit(main())
