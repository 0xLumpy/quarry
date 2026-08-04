#!/usr/bin/env python3
"""STEP 2 of the ast-analyzer evaluation — the DELTA, over bytes Quarry has already collected.

Step 1 measured what the analyzer promises. This answers the only question that decides adoption: does it
add to the RESULTS, and which half of it does. It runs the analyzer over a previous run's `js_files` and
compares each of its three output families against the tools Quarry already runs on the same bytes:

    SINKS       postMessage, innerHTML, eval, localStorage, location, cookie, …   nothing in Quarry emits
                                                                                  these — net-new by
                                                                                  construction, so what is
                                                                                  measured is VOLUME and
                                                                                  SHAPE, not novelty
    ENDPOINTS   robust-paths / fetch / graphql   vs   jsluice urls · xnLinkFinder · katana
    SECRETS     1609 detectors                   vs   jsluice secrets · gitleaks · trufflehog

jsluice is re-run per file: the stored `jsluice/urls.jsonl` records `filename: /tmp/jsluice-raw-input…`
because Quarry feeds it over stdin, so per-file attribution is not recoverable from the artifact. The
other incumbents are read from the run's own outputs — this contacts NO network and re-fetches nothing.

    ./scripts/measure-ast-delta.py                      # the whole corpus of the last OTC run
    ./scripts/measure-ast-delta.py -n 200 --json d.json # a sample, machine-readable

Containment comes from the step-1 probe (bwrap allow-list, bounded output, address-space ladder); this
script imports it rather than re-deriving it, so the two can never drift apart.
"""
from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
DEFAULT_RUN = Path.home() / "workspace" / "otc-service" / "recon" / "20260725-143341-1a636b47"


def _load_probe():
    """The step-1 probe IS the containment. Importing it keeps one sandbox definition, one output bound
    and one disposition vocabulary; a second copy here would drift the moment either is fixed."""
    path = HERE / "probe-jxscout-ast.py"
    spec = importlib.util.spec_from_file_location("probe_jxscout_ast", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import the step-1 probe at {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The path normalisation and the plausibility rule live in `quarry_recon.ast_obs` now that the LANE uses
# them too. A second copy here would drift the moment either side is corrected — and both were corrected
# three times already (source-aware relatives, case preservation, tool failures as unreadable).
from quarry_recon import ast_obs                                              # noqa: E402

path_key = ast_obs.path_key
plausible_path = ast_obs.plausible


def secret_key(value) -> str | None:
    if not isinstance(value, str):        # a record can carry `{"Secret": 7}`; `.strip()` would abort
        return None
    v = value.strip()
    return v if 6 <= len(v) <= 512 else None


# ── the incumbents, read from the run that already produced them ────────────────────────────────────
def incumbent_endpoints(run: Path) -> dict:
    out: dict = {}
    jl = run / "raw" / "crawl" / "jsluice" / "urls.jsonl"
    if jl.exists():
        vals = set()
        for line in jl.read_text("utf-8", "replace").splitlines():
            try:
                vals.add(json.loads(line).get("url", ""))
            except ValueError:
                continue
        out["jsluice(stored)"] = {k for k in map(path_key, vals) if k}
    xn = run / "raw" / "crawl" / "xnLinkFinder" / "js_links.txt"
    if xn.exists():
        out["xnLinkFinder"] = {k for k in (path_key(x, host_prefixed=True)
                                           for x in xn.read_text("utf-8", "replace").splitlines()) if k}
    kt = run / "raw" / "crawl" / "katana" / "katana.txt"
    if kt.exists():
        out["katana"] = {k for k in map(path_key, kt.read_text("utf-8", "replace").splitlines()) if k}
    return out


def incumbent_secrets(run: Path) -> dict:
    out: dict = {}
    gl = run / "raw" / "crawl" / "gitleaks" / "report.json"
    if gl.exists():
        try:
            doc = json.loads(gl.read_text("utf-8", "replace"))
        except ValueError:
            doc = []
        out["gitleaks"] = {k for k in (secret_key(f.get("Secret") or f.get("Match") or "")
                                       for f in doc) if k}
    th = run / "raw" / "crawl" / "trufflehog" / "out.jsonl"
    if th.exists():
        vals = set()
        for line in th.read_text("utf-8", "replace").splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            vals.add(d.get("Raw") or d.get("RawV2") or "")
        out["trufflehog"] = {k for k in map(secret_key, vals) if k}
    return out


def jsluice_file(path: Path, mode: str) -> tuple:
    """`(readable, values)` — never a bare set.

    A timeout, a launch failure or a non-zero exit used to come back as `set()`, indistinguishable from a
    file jsluice read cleanly and found nothing in. That mixes measured zeroes with unreadable inputs in
    every number downstream, including the one that says the analyzer was "silent" on 815 bundles.
    """
    try:
        r = subprocess.run(["jsluice", mode, str(path)], capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return False, set()
    if r.returncode != 0:
        return False, set()
    vals, bad = set(), 0
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except ValueError:
            bad += 1
            continue
        vals.add(d.get("url", "") if mode == "urls" else (d.get("data") or d.get("value") or ""))
    keyer = path_key if mode == "urls" else secret_key
    return (bad == 0), {k for k in map(keyer, vals) if k}


#: a bundle's own module graph (`./index-6d95a4bc.js`) is not an endpoint. jsluice counts every import
#: specifier as a URL and the analyzer's `robust-paths` does not — MEASURED, and it explains most of the
#: apparent disagreement, so the report splits the difference rather than letting a definitional gap read
#: as a coverage gap.
ASSET_SUFFIXES = (".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".svg", ".gif",
                  ".woff", ".woff2", ".ttf", ".ico", ".webp", ".mp4", ".json")


def split_assets(keys: set) -> dict:
    assets = {k for k in keys if k.endswith(ASSET_SUFFIXES)}
    return {"asset_or_module": sorted(assets)[:200], "asset_or_module_n": len(assets),
            "other": sorted(keys - assets)[:200], "other_n": len(keys - assets)}


#: what a hunter would call a SINK or a SOURCE, separated from the analyzers that are merely
#: informational. `regex-match`/`regex-pattern` report interesting regexes and `hostname` reports host
#: literals — both useful, neither a DOM data-flow finding, and together they dominate the raw count.
DOM_SINKS = {"postmessage", "onmessage", "add-event-listener", "eval", "inner-html",
             "react-dangerously-set-inner-html", "location", "document-domain", "window-name",
             "window-open", "onhashchange", "local-storage", "session-storage", "cookie",
             "url-search-params"}

#: the analyzer's OWN MIME table (extracted from `robust-paths.ts`). A bundle mentioning "video/3gpp"
#: yields `/3gpp`, which is a MIME subtype, not an endpoint — and it is a large share of what looks like
#: net-new coverage until the categories are counted instead of eyeballed.
MIME_SUBTYPES = frozenset(('3gpp', '3gpp2', 'bmp', 'calendar', 'cgm', 'collection', 'css', 'csv', 'ecmascript', 'form-data', 'g3fax', 'gif', 'gltf+json', 'gltf-binary', 'h261', 'h263', 'h264', 'html', 'ief', 'iges', 'javascript', 'jpeg', 'json', 'ld+json', 'mesh', 'midi', 'mixed', 'mp4', 'mpeg', 'octet-stream', 'ogg', 'otf', 'pdf', 'pjpeg', 'plain', 'png', 'prs.btif', 'quicktime', 'related', 'report', 'rfc822', 'richtext', 'sgml', 'svg+xml', 'tab-separated-values', 'tiff', 'troff', 'ttf', 'vnd.adobe.photoshop', 'vnd.collada+xml', 'vnd.curl', 'vnd.curl.dcurl', 'vnd.curl.mcurl', 'vnd.curl.scurl', 'vnd.djvu', 'vnd.dvb.subtitle', 'vnd.dwf', 'vnd.dwg', 'vnd.dxf', 'vnd.fastbidsheet', 'vnd.fly', 'vnd.fmi.flexstor', 'vnd.fpx', 'vnd.gdl', 'vnd.graphviz', 'vnd.gtw', 'vnd.in3d.3dml', 'vnd.in3d.spot', 'vnd.microsoft.icon', 'vnd.mpegurl', 'vnd.ms-modi', 'vnd.ms-playready.media.pyv', 'vnd.mts', 'vnd.net-fpx', 'vnd.opengex', 'vnd.parasolid.transmit.binary', 'vnd.parasolid.transmit.text', 'vnd.sun.j2me.app-descriptor', 'vnd.usdz+zip', 'vnd.uvvu.mp4', 'vnd.valve.source.compiled-map', 'vnd.vivo', 'vnd.vrml', 'vnd.wap.si', 'vnd.wap.sl', 'vnd.wap.wbmp', 'vnd.wap.wml', 'vnd.wap.wmlscript', 'vnd.xiff', 'webm', 'webp', 'woff', 'woff2', 'x-aac', 'x-aiff', 'x-asm', 'x-c', 'x-cdx', 'x-cif', 'x-cmdf', 'x-cml', 'x-cmu-raster', 'x-cmx', 'x-cooltalk', 'x-csml', 'x-f4v', 'x-fli', 'x-flv', 'x-fortran', 'x-httpd-php', 'x-icon', 'x-java-source', 'x-m4v', 'x-matroska', 'x-mng', 'x-mpegurl', 'x-ms-asf', 'x-ms-msdownload', 'x-ms-vob', 'x-ms-wax', 'x-ms-wm', 'x-ms-wma', 'x-ms-wmv', 'x-ms-wmx', 'x-ms-write', 'x-ms-wvx', 'x-ms-xbap', 'x-msaccess', 'x-msbinder', 'x-mscardfile', 'x-msclip', 'x-msdownload', 'x-msmediaview', 'x-msmetafile', 'x-msmoney', 'x-mspublisher', 'x-msschedule', 'x-msterminal', 'x-msvideo', 'x-mswrite', 'x-netcdf', 'x-nfo', 'x-opml', 'x-pascal', 'x-perfmon', 'x-pkcs10', 'x-pkcs12', 'x-pkcs7-mime', 'x-pkcs7-signature', 'x-pn-realaudio', 'x-pn-realaudio-plugin', 'x-portable-anymap', 'x-portable-bitmap', 'x-portable-graymap', 'x-portable-pixmap', 'x-realaudio', 'x-rgb', 'x-setext', 'x-sgi-movie', 'x-sh', 'x-shar', 'x-shockwave-flash', 'x-silverlight-app', 'x-stuffit', 'x-stuffitx', 'x-sv4cpio', 'x-sv4crc', 'x-tar', 'x-tcl', 'x-tex', 'x-tex-tfm', 'x-tex-xdvi', 'x-texinfo', 'x-troff', 'x-troff-man', 'x-troff-me', 'x-troff-ms', 'x-troff-msvideo', 'x-ustar', 'x-uuencode', 'x-vcalendar', 'x-vcard', 'x-wais-source', 'x-wav', 'x-www-form-urlencoded', 'x-x509-ca-cert', 'x-xbitmap', 'x-xfig', 'x-xpinstall', 'x-xpixmap', 'x-xwindowdump', 'x-xyz', 'x-xz', 'x-zip', 'x-zip-compressed', 'x3d+binary', 'x3d+vrml', 'x3d+xml', 'xhtml+xml', 'xml', 'xml-dtd', 'xml-external-parsed-entity', 'zip'))
#: DESCRIPTIVE ONLY. This bucketing explains what the net-new set is made of ON THIS CORPUS; it is not a
#: validated filter and must not become one without a held-out, hand-labelled precision sample. Shipping
#: it as production policy would be fitting a rule to the data it was read off.
API_WORDS = frozenset(("api", "v1", "v2", "v3", "graphql", "gql", "rest", "auth", "oauth", "login",
                       "admin", "user", "users", "account", "accounts", "token", "session", "upload",
                       "download", "search", "config", "callback", "webhook", "internal"))


def bucket(key: str) -> str:
    segs = [s for s in key.strip("/").split("/") if s]
    if any("expr" in s for s in segs):
        return "placeholder"
    if len(segs) == 1 and segs[0] in MIME_SUBTYPES:
        return "mime-subtype"
    if any(s in API_WORDS for s in segs):
        return "api-shaped"
    if len(segs) == 1 and "." not in segs[0]:
        return "single-word"
    return "other"


SINK_ANALYZERS = {"postmessage", "onmessage", "add-event-listener", "eval", "inner-html",
                  "react-dangerously-set-inner-html", "location", "document-domain", "window-name",
                  "window-open", "onhashchange", "local-storage", "session-storage", "cookie",
                  "url-search-params", "hostname", "regex-match", "regex-pattern"}
ENDPOINT_ANALYZERS = {"robust-paths", "fetch", "fetch-options", "graphql", "http-methods"}


#: EVERY directory scanner the secrets comparison depends on. An absent one is not a smaller comparison,
#: it is an incomplete incumbent set — and publishing a "measured" verdict against it would credit the
#: analyzer with net-new that a missing tool simply never had the chance to find.
EXPECTED_SCANNERS = ("gitleaks(same-input)", "trufflehog(same-input)")


def first_secret(rec: dict, keys: tuple) -> tuple:
    """`(value_or_None, unusable)` — the first NON-EMPTY candidate, with every PRESENT candidate's type
    checked.

    `rec.get("Secret", rec.get("Match"))` falls back only when the key is ABSENT, so a record carrying
    `Secret: ""` alongside a populated `Match` was dropped — an incumbent finding lost, which inflates the
    analyzer's net-new by exactly that much. Type-checking only the selected field would equally let
    `{"Secret": "x", "Match": 7}` through unnoticed.
    """
    picked = None
    for k in keys:
        if k not in rec or rec[k] is None:
            continue
        v = rec[k]
        if not isinstance(v, str):
            return None, True
        if v.strip() and picked is None:
            picked = v
    return picked, False


def _dir_scanners(files: list) -> dict:
    """gitleaks and trufflehog over EXACTLY the paired bundles, each with a READABILITY status.

    `{name: {"ok": bool, "values": set, "why": str}}`. A timeout used to escape and abort the script; a
    non-zero exit, a missing or malformed report, or unparsed trufflehog output used to become an empty
    set — which reads as "the incumbents found nothing", the exact conclusion this comparison exists to
    test. An unmeasured scanner must be able to REFUSE the delta, not quietly win it.
    """
    out: dict = {}
    with tempfile.TemporaryDirectory(prefix="quarry-astdelta-scan-") as tmp:
        stage = Path(tmp) / "stage"
        stage.mkdir()
        failed = []
        for f in files:
            try:
                shutil.copy2(f, stage / f.name)
            except OSError as exc:
                failed.append(f"{f.name}: {type(exc).__name__}")
        if failed:
            # a silently skipped copy restores the unequal-input defect while the scanners still report
            # ok — fewer files scanned than the analyzer saw, with nothing saying so.
            why = f"{len(failed)} of {len(files)} paired file(s) could not be staged: {failed[:3]}"
            return {"staging": {"ok": False, "why": why, "values": set()}}
        if not shutil.which("gitleaks"):
            out["gitleaks(same-input)"] = {"ok": False, "why": "not installed", "values": set()}
        else:
            rep = Path(tmp) / "gitleaks.json"
            ok, why, doc = True, "", []
            try:
                r = subprocess.run(["gitleaks", "detect", "--no-git", "--source", str(stage),
                                    "--report-format", "json", "--report-path", str(rep),
                                    "--exit-code", "0"], capture_output=True, timeout=1800, check=False)
                if r.returncode != 0:
                    ok, why = False, f"exit {r.returncode}"
                elif not rep.exists():
                    ok, why = False, "no report written"
                else:
                    try:
                        doc = json.loads(rep.read_text("utf-8", "replace") or "[]") or []
                    except ValueError as exc:
                        ok, why = False, f"malformed report ({type(exc).__name__})"
                    # SHAPE, not just syntax. A report that parses as a scalar, or as a list holding
                    # anything but records, used to reach `.get()` and abort the whole measurement
                    # instead of marking this scanner unreadable.
                    if ok and not isinstance(doc, list):
                        ok, why, doc = False, f"report is {type(doc).__name__}, expected a list", []
                    elif ok and not all(isinstance(x, dict) for x in doc):
                        ok, why, doc = False, "report contains non-record entries", []
            except (subprocess.TimeoutExpired, OSError) as exc:
                ok, why = False, type(exc).__name__
            # FIELD types, not just record types. `{"Secret": 7}` reaching `.strip()` aborted the run.
            vals, unusable = set(), 0
            for rec in doc if ok else []:
                raw, bad_rec = first_secret(rec, ("Secret", "Match"))
                if bad_rec:
                    unusable += 1
                    continue
                k = secret_key(raw) if raw is not None else None
                if k:
                    vals.add(k)
            if ok and unusable:
                ok, why, vals = False, f"{unusable} record(s) with a non-string secret field", set()
            out["gitleaks(same-input)"] = {"ok": ok, "why": why, "values": vals if ok else set()}
        if not shutil.which("trufflehog"):
            out["trufflehog(same-input)"] = {"ok": False, "why": "not installed", "values": set()}
        else:
            ok, why, vals, bad = True, "", set(), 0
            try:
                r = subprocess.run(["trufflehog", "filesystem", str(stage), "--json",
                                    "--no-verification"], capture_output=True, text=True,
                                   timeout=3600, check=False)
                if r.returncode != 0:
                    ok, why = False, f"exit {r.returncode}"
                for line in r.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        d = json.loads(line)
                    except ValueError:
                        bad += 1
                        continue
                    if not isinstance(d, dict):        # valid JSON, wrong shape: still unreadable
                        bad += 1
                        continue
                    raw, bad_rec = first_secret(d, ("Raw", "RawV2"))
                    if bad_rec:                        # `{"Raw": []}` — a record we cannot read
                        bad += 1
                        continue
                    if raw is not None:
                        vals.add(raw)
                if bad:
                    ok, why = False, f"{bad} unusable output line(s) (unparsable or not a record)"
            except (subprocess.TimeoutExpired, OSError) as exc:
                ok, why = False, type(exc).__name__
            out["trufflehog(same-input)"] = {"ok": ok, "why": why,
                                             "values": {k for k in map(secret_key, vals) if k}
                                             if ok else set()}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", default=str(DEFAULT_RUN), help="a previous run directory")
    ap.add_argument("-n", "--sample", type=int, default=0, help="0 = the whole corpus")
    ap.add_argument("--seed", type=int, default=20260804)
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--corpus-dir", help="a bare directory of .js bodies, instead of <run>/raw/crawl/js_files")
    ap.add_argument("--only", choices=("all", "secrets", "endpoints", "sinks"), default="all",
                    help="report one family. `secrets` prints NO endpoint or sink values — used when the "
                         "same corpus is being kept unseen for an endpoint-rule worksheet")
    args = ap.parse_args()

    probe = _load_probe()
    run = Path(args.run)
    corpus = Path(args.corpus_dir) if args.corpus_dir else (run / "raw" / "crawl" / "js_files")
    if not corpus.is_dir():
        print(f"no corpus at {corpus}", file=sys.stderr)
        return 2
    if not shutil.which("jsluice"):
        print("jsluice is required for the endpoint/secret comparison", file=sys.stderr)
        return 2
    want_ep = args.only in ("all", "endpoints")
    want_sec = args.only in ("all", "secrets")
    want_sinks = args.only in ("all", "sinks")
    files = sorted(corpus.glob("*.js"))
    if args.sample:
        files = random.Random(args.seed).sample(files, min(args.sample, len(files)))
    print(f"corpus: {len(files)} bundle(s) from {corpus}")

    ast_sinks: collections.Counter = collections.Counter()
    ast_endpoints, ast_secrets, ast_sink_files = set(), set(), set()
    js_endpoints, js_secrets = set(), set()
    dispositions: collections.Counter = collections.Counter()
    laddered, t0, silent_on = 0, time.perf_counter(), []
    #: only files BOTH tools read cleanly may enter a comparison; the rest are reported, not averaged in
    paired, paired_sec, ast_unreadable, js_unreadable = [], [], 0, 0
    ast_readable_files = 0

    with tempfile.TemporaryDirectory(prefix="quarry-astdelta-") as tmp:
        scratch = Path(tmp)
        if not probe.sandbox(["true"], scratch):
            print("REFUSING: bwrap unavailable — the analyzer does not run uncontained", file=sys.stderr)
            return 2
        for i, f in enumerate(files, 1):
            r = probe.analyze(f, scratch, keep_doc=True)
            if r["disposition"] == "killed":
                for mb in (8192, 16384, 32768):      # the step-1 ladder: our bound, not the tool's
                    r = probe.analyze(f, scratch, keep_doc=True, address_space_mb=mb)
                    # climb until the analyzer actually ANSWERS. Stopping at "not killed" left the two
                    # 27 MB POAB bundles excluded as `analyzer-error`: at 16 GB the analyzer catches its
                    # own allocation failure and exits 1, which is not a refusal — at 32 GB the same
                    # bytes parse cleanly in 92 s. A rung that merely changes the SHAPE of the failure is
                    # not a result.
                    if r["disposition"] in ("success", "empty"):
                        laddered += 1
                        break
            dispositions[r["disposition"]] += 1
            ast_ok = r["disposition"] in ("success", "empty")
            ast_unreadable += 0 if ast_ok else 1
            # PER FILE first, merged only once the relevant PAIR is known readable. Accumulating the
            # analyzer's side unconditionally while gating jsluice's meant an unreadable bundle still
            # contributed analyzer findings to a comparison it was excluded from — the printed claim that
            # every headline is paired would have been false the first time either tool failed.
            f_sinks: collections.Counter = collections.Counter()
            f_endpoints, f_secrets = set(), set()
            for m in (r.get("doc") or []):
                name = m.get("analyzerName", "")
                if name in SINK_ANALYZERS:
                    if want_sinks:
                        f_sinks[name] += 1
                elif name in ENDPOINT_ANALYZERS and want_ep:
                    k = path_key((m.get("extra") or {}).get("pathname") or m.get("value", ""))
                    if k:
                        f_endpoints.add(k)
                elif name == "secrets" and want_sec:
                    k = secret_key(m.get("value", ""))
                    if k:
                        f_secrets.add(k)
            # a family that was not requested is not measured either: `--only secrets` must not leave
            # endpoint candidates anywhere, and computing them "just for the JSON" is exactly how the
            # POAB run persisted 120 net-new paths for a corpus being kept unseen.
            js_ok, here_js = jsluice_file(f, "urls") if want_ep else (True, set())
            js_sec_ok, here_sec = jsluice_file(f, "secrets") if want_sec else (True, set())
            js_unreadable += 0 if (js_ok and js_sec_ok) else 1
            if ast_ok:
                # the sink INVENTORY is analyzer-only (no incumbent produces these), so its denominator
                # is "bundles the analyzer read", stated as such rather than as the corpus size
                ast_sinks.update(f_sinks)
                if f_sinks:
                    ast_sink_files.add(f.name)
                ast_readable_files += 1
            if ast_ok and js_ok:
                paired.append(f)
                ast_endpoints |= f_endpoints
                js_endpoints |= here_js
                if want_ep and not (r.get("doc") or []) and here_js:
                    silent_on.append(f.name)
            if ast_ok and js_sec_ok:
                paired_sec.append(f)
                ast_secrets |= f_secrets
                js_secrets |= here_sec
            if i % 100 == 0:
                print(f"  {i}/{len(files)} … {time.perf_counter() - t0:.0f}s")

    # SAME INPUT SET on both sides, or the arithmetic is theatre. The stored katana/xnLinkFinder/jsluice
    # artifacts cover the WHOLE site, so subtracting them from an N-file analyzer run reports the sample
    # size as a coverage failure. They are reported as CONTEXT and never enter the net-new numbers.
    same_ep = {"jsluice(re-run)": js_endpoints}
    same_sec = {"jsluice(re-run)": js_secrets}
    # staged over the SECRETS-paired files, not the corpus: the moment either tool cannot read a bundle,
    # scanning it anyway would compare two different input sets again.
    scanners = _dir_scanners(paired_sec) if want_sec else {}
    scanner_status = {k: {"ok": v["ok"], "why": v["why"]} for k, v in scanners.items()}
    for name, res in scanners.items():
        if res["ok"]:
            same_sec[name] = res["values"]
    # EVERY expected scanner, present AND readable. `bool(scanners)` only proved one of them ran.
    secrets_measurable = want_sec and all(scanners.get(name, {}).get("ok") for name in EXPECTED_SCANNERS)
    for name in EXPECTED_SCANNERS:
        scanner_status.setdefault(name, {"ok": False, "why": "not reported by the scanner pass"})
    # a bare corpus has no run beside it, so there is nothing to show as context — and nothing is
    # invented to fill the gap
    context_ep = incumbent_endpoints(run) if not args.corpus_dir else {}
    context_sec = incumbent_secrets(run) if not args.corpus_dir else {}
    union_ep = set().union(*same_ep.values()) if same_ep else set()
    ast_ep_p = {k for k in ast_endpoints if plausible_path(k)}
    union_ep_p = {k for k in union_ep if plausible_path(k)}
    union_sec = set().union(*same_sec.values()) if same_sec else set()

    report = {
        "corpus": str(corpus), "files": len(files), "wall_s": round(time.perf_counter() - t0, 1),
        "compared_on": len(paired), "compared_on_secrets": len(paired_sec),
        "ast_readable_files": ast_readable_files,
        "ast_unreadable": ast_unreadable, "jsluice_unreadable": js_unreadable,
        "scanner_status": scanner_status, "secrets_measurable": secrets_measurable,
        "dispositions": dict(dispositions), "laddered": laddered,
        "silent_on_n": len(silent_on),
        "sinks": ({"total": sum(ast_sinks.values()), "files_with_sinks": len(ast_sink_files),
                   "by_class": dict(ast_sinks.most_common())}
                  if want_sinks else {"disposition": "not_requested"}),
        "silent_on": silent_on if want_ep else [],
        "endpoints": {"disposition": "not_requested"} if not want_ep else {"ast": len(ast_endpoints),
                      "same_input": {k: len(v) for k, v in same_ep.items()},
                      "context_whole_corpus": {k: len(v) for k, v in context_ep.items()},
                      "union_incumbent": len(union_ep),
                      "ast_plausible": len(ast_ep_p), "union_plausible": len(union_ep_p),
                      "plausible_net_new_n": len(ast_ep_p - union_ep_p),
                      "plausible_net_new": sorted(ast_ep_p - union_ep_p)[:120],
                      "net_new_buckets": dict(collections.Counter(
                          bucket(k) for k in (ast_ep_p - union_ep_p)).most_common()),
                      "net_new_api_shaped": sorted(k for k in (ast_ep_p - union_ep_p)
                                                   if bucket(k) == "api-shaped")[:60],
                      "plausible_missed_n": len(union_ep_p - ast_ep_p),
                      "plausible_missed": sorted(union_ep_p - ast_ep_p)[:120],
                      "ast_net_new_n": len(ast_endpoints - union_ep),
                      "ast_net_new": split_assets(ast_endpoints - union_ep),
                      "missed_by_ast_n": len(union_ep - ast_endpoints),
                      "missed_by_ast": split_assets(union_ep - ast_endpoints)},
        # a REFUSED delta publishes no comparison integers. They are the numbers a consumer would read
        # first, and a separate top-level flag is too easy to miss — so the disposition lives inside this
        # block and the metrics are null, with what WAS observed kept under a name that says so.
        "secrets": ({"disposition": "not_requested"} if not want_sec else
                    {"disposition": "measured", "ast": len(ast_secrets),
                     "same_input": {k: len(v) for k, v in same_sec.items()},
                     "context_whole_corpus": {k: len(v) for k, v in context_sec.items()},
                     "union_incumbent": len(union_sec),
                     "ast_net_new_n": len(ast_secrets - union_sec),
                     "ast_net_new": sorted(ast_secrets - union_sec)[:100],
                     "missed_by_ast_n": len(union_sec - ast_secrets)}
                    if secrets_measurable else
                    {"disposition": "refused", "why": scanner_status,
                     "union_incumbent": None, "ast_net_new_n": None, "missed_by_ast_n": None,
                     "diagnostic_only": {"ast": len(ast_secrets),
                                         "readable_scanners": {k: len(v) for k, v in same_sec.items()},
                                         "context_whole_corpus": {k: len(v)
                                                                  for k, v in context_sec.items()}}}),
    }

    print(f"\ndispositions: {dict(dispositions)}  (laddered past the 4 GB bound: {laddered})")
    print(f"COMPARED on {len(paired)} of {len(files)} bundles for endpoints and {len(paired_sec)} for "
          f"secrets — both tools read them cleanly (analyzer unreadable {ast_unreadable}, jsluice "
          f"unreadable {js_unreadable}); every comparison below is over its own paired set only. The "
          f"sink inventory is analyzer-only: its denominator is the {ast_readable_files} bundles the "
          f"analyzer read.")
    if args.only in ("all", "endpoints"):
        print(f"\nast produced NOTHING on {len(silent_on)} of {len(paired)} PAIRED bundles where jsluice found "
              f"endpoints in the same bytes")
    if args.only in ("all", "sinks"):
        print(f"\nSINKS — nothing in Quarry emits these:")
        dom_n = sum(n for k, n in ast_sinks.items() if k in DOM_SINKS)
        report["sinks"]["dom_flow"] = dom_n
        report["sinks"]["informational"] = report["sinks"]["total"] - dom_n
        print(f"  {report['sinks']['total']} in {report['sinks']['files_with_sinks']} of "
              f"{ast_readable_files} bundles the analyzer READ — {dom_n} are DOM source/sink, "
              f"{report['sinks']['total'] - dom_n} informational (regex/hostname)")
        for name, n in ast_sinks.most_common(12):
            print(f"    {name:<34} {n}")
    if args.only in ("all", "endpoints"):
        print(f"\nENDPOINTS — same input set ({len(paired)} paired bundles): ast {len(ast_endpoints)} vs "
              f"incumbent union {len(union_ep)}")
        for k, v in sorted(same_ep.items()):
            print(f"    {k:<20} {len(v)}")
        print("  context only (WHOLE corpus, a different input set — not in the arithmetic):")
        for k, v in sorted(context_ep.items()):
            print(f"    {k:<20} {len(v)}")
        ep = report["endpoints"]
        print(f"  PLAUSIBLE paths only (no regex/placeholder noise): ast {ep['ast_plausible']} vs "
              f"incumbent {ep['union_plausible']}")
        print(f"    ast net-new {ep['plausible_net_new_n']} · missed by ast {ep['plausible_missed_n']}")
        print(f"    net-new by CATEGORY (descriptive for THIS corpus, not a validated filter): "
              f"{ep['net_new_buckets']}")
        for s in ep["net_new_api_shaped"][:8]:
            print(f"      + (api-shaped) {s[:88]}")
        for s in ep["plausible_missed"][:6]:
            print(f"      - {s[:96]}")
        nn, ms = report["endpoints"]["ast_net_new"], report["endpoints"]["missed_by_ast"]
        print(f"  ast NET-NEW: {report['endpoints']['ast_net_new_n']} "
              f"({nn['other_n']} non-asset, {nn['asset_or_module_n']} asset/module)")
        for s in nn["other"][:6]:
            print(f"    + {s[:100]}")
        print(f"  MISSED by ast: {report['endpoints']['missed_by_ast_n']} "
              f"({ms['other_n']} non-asset, {ms['asset_or_module_n']} asset/module — the latter is mostly "
              f"jsluice counting import specifiers)")
        for s in ms["other"][:6]:
            print(f"    - {s[:100]}")
    if want_sec:
        if not secrets_measurable:
            print(f"\nSECRETS — DELTA REFUSED: a scanner did not complete readably {scanner_status}. "
                  f"Reporting the incumbents as zero here would be inventing the answer.")
        print(f"\nSECRETS — same input set ({len(paired_sec)} bundles): ast {len(ast_secrets)} vs "
              f"incumbent union {len(union_sec)}"
              + ("" if secrets_measurable else "  [NOT A VERDICT — see the refusal above]"))
        for k, v in sorted(same_sec.items()):
            print(f"    {k:<20} {len(v)}")
        print("  context only (whole corpus):")
        for k, v in sorted(context_sec.items()):
            print(f"    {k:<20} {len(v)}")
        print(f"  ast NET-NEW: {report['secrets']['ast_net_new_n']} · "
              f"missed by ast: {report['secrets']['missed_by_ast_n']}")
        for s in sorted(ast_secrets - union_sec)[:8]:
            print(f"    + {s[:80]}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))
        print(f"\nwrote {args.json_out}")
    print(f"\nMEASURED in {report['wall_s']}s. This is a measurement, not a gate: the adoption decision "
          f"is the operator's.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
