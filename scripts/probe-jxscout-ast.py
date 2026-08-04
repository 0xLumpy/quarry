#!/usr/bin/env python3
"""CONTRACT PROBE — jxscout AST analysis. Measurement only; builds no lane and contacts no target.

Step 1 of the ast-analyzer evaluation. The question is NOT "does it find things" (step 2, the delta
against jsluice/xnLinkFinder/trufflehog/gitleaks over the same bytes) but the two that decide whether a
delta is even worth measuring:

    what does it PROMISE   the runtime it needs, its output schema, and what each failure looks like
    what does it DO WRONG  what a hostile bundle can make it do to this machine

Both are measured here, never assumed. Every claim in the write-up must trace to a line this prints.

    ./scripts/probe-jxscout-ast.py                       # fixtures + a real-bundle sample, sandboxed
    ./scripts/probe-jxscout-ast.py --corpus <dir> -n 40  # a bigger sample from an existing run's js_files
    ./scripts/probe-jxscout-ast.py --json out.json       # machine-readable, for the write-up

It reaches no network — the sandbox is part of what is being measured — and it writes only to a private
temporary directory. Real bundles are read from a PREVIOUS run's artifacts; nothing is fetched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TREE = Path.home() / ".local" / "share" / "quarry" / "jxscout"
#: upstream ships BOTH halves prebuilt: a 285 KB bundled analyzer and a native parser per platform
#: (`go:embed` in internal/modules/ast-analyzer/module.go). No npm/bun install of the 14 dependencies is
#: involved — this is measured, and it is the single biggest correction to the earlier research note.
ANALYZER = TREE / "internal" / "modules" / "ast-analyzer" / "ast-analyzer.js"
NATIVE = TREE / "internal" / "modules" / "ast-analyzer" / "parser.linux-x64-gnu.node"

#: MEASURED: the analyzer runs under bun and FAILS under node ("Failed to load native binding" — the
#: bundler stubbed every native `require`, so the binding can only arrive through the napi env var, and
#: node's `process.dlopen` on the webpack module descriptor throws). jxscout itself shells out to
#: `bun run` (module.go:365) with the same variable (module.go:372). The probe asserts BOTH halves, so an
#: install can never silently fall back to node and report an empty analysis as an answer.
BUN = shutil.which("bun") or str(Path.home() / ".bun" / "bin" / "bun")
NODE = shutil.which("node") or "node"

#: the containment the chunk lane arrived at, applied here from the start: an allow-list, not the host
#: root. This analyzer does not evaluate target code (oxc parses; only the chunk engine runs Sval), but
#: it does run 1609 secret regexes over attacker-controlled bytes inside a process that must not be able
#: to read the operator's keys if it is ever escaped.
RUNTIME_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache",
                 "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives")
ADDRESS_SPACE_MB = 4096
OUTPUT_MB = 64
STDERR_TAIL = 8192
WALL_S = 60


def sandbox(cmd: list, scratch: Path, ro: Path | None = None) -> list:
    """Allow-list containment, or nothing. `--ro-bind / /` is not containment: read-only is not absent,
    and secrets.yaml, SSH material and previous engagements' evidence are all readable.

    The EXECUTABLE bound is the one in `cmd`, never a fixed one: binding bun while running node made the
    node control fail with "executable not found", and that would have been accepted as proof that node
    cannot load the native binding. A negative control that can pass for the wrong reason proves nothing.
    """
    if not shutil.which("bwrap"):
        return []
    exe = shutil.which(cmd[0]) or cmd[0]
    if not Path(exe).is_file():
        return []
    args = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv", "--chdir", "/",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in RUNTIME_PATHS:
        args += ["--ro-bind-try", path, path]
    args += ["--ro-bind", str(Path(exe).resolve()), str(Path(exe).resolve()),
             "--ro-bind", str(ANALYZER), str(ANALYZER),
             "--ro-bind", str(NATIVE), str(NATIVE),
             "--bind", str(scratch), str(scratch)]
    if ro is not None and ro.exists() and not str(ro).startswith(str(scratch)):
        # the ONE input, read-only. Without this a real bundle outside the scratch is simply not in the
        # namespace, and the analyzer's "File not found" refusal reads exactly like a broken tool — which
        # is what the first run of this probe reported for all 8 real bundles.
        args += ["--ro-bind", str(ro), str(ro)]
    args += [
             "--setenv", "NAPI_RS_NATIVE_LIBRARY_PATH", str(NATIVE),
             "--setenv", "PATH", "/usr/bin:/bin",
             "--setenv", "HOME", str(scratch),        # bun writes nothing here, but it does READ $HOME
             "--setenv", "TMPDIR", str(scratch)]
    return args + cmd


#: stderr markers worth knowing about wherever they sit in the stream.
MARKERS = ("Failed to load native binding", "File not found", "JavaScriptCore", "out of memory",
           "already exists")


def _scan(path: Path, markers: tuple) -> list:
    """Which markers appear anywhere in a bounded file, read in chunks with an overlap so a marker split
    across a boundary is still seen. Never holds the file."""
    found, chunk, overlap = set(), 1 << 16, max(len(m) for m in markers)
    try:
        with path.open("rb") as fh:
            tail = b""
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                hay = tail + block
                for m in markers:
                    if m.encode() in hay:
                        found.add(m)
                tail = hay[-overlap:]
    except OSError:
        return []
    return sorted(found)


def _limits(address_space_mb: int = ADDRESS_SPACE_MB) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (address_space_mb * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_MB * 1024 * 1024,) * 2)


def _measure(cmd: list, *, wall_s: int = WALL_S, address_space_mb: int = ADDRESS_SPACE_MB,
             keep_doc: bool = False) -> dict:
    """One contained run, and what actually happened to it.

    Output goes to FILES bounded by RLIMIT_FSIZE, never into this process: `capture_output=True` would
    accumulate attacker-controlled bytes where none of the child's limits apply.
    """
    with tempfile.TemporaryDirectory(prefix="quarry-astprobe-io-") as tmp:
        op, ep = Path(tmp) / "out", Path(tmp) / "err"
        with op.open("wb") as ofh, ep.open("wb") as efh:
            t0 = time.perf_counter()
            proc = subprocess.Popen(cmd, stdout=ofh, stderr=efh, stdin=subprocess.DEVNULL,
                                    preexec_fn=lambda: _limits(address_space_mb),
                                    start_new_session=True)
            timed_out, status, ru = False, 0, None
            deadline = t0 + wall_s
            while True:
                pid, status, ru = os.wait4(proc.pid, os.WNOHANG)
                if pid:
                    break
                if time.perf_counter() > deadline:
                    timed_out = True
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except OSError:
                        pass
                    _pid, status, ru = os.wait4(proc.pid, 0)
                    break
                time.sleep(0.02)
            wall = time.perf_counter() - t0
        proc.returncode = status
        rc = None if timed_out else os.waitstatus_to_exitcode(status)
        cap = OUTPUT_MB * 1024 * 1024
        out_bytes, err_bytes = op.stat().st_size, ep.stat().st_size
        # BOTH streams. RLIMIT_FSIZE bounds each file, and bun swallows the EFBIG the same way node does,
        # so a run that filled stderr and exited 0 would otherwise be classified success or empty — the
        # exact defect the chunk lane fixed. The ceiling is a property of the RUN, not of stdout.
        truncated = out_bytes >= cap or err_bytes >= cap
        raw = op.read_bytes() if out_bytes <= cap else b""
        digest = hashlib.sha256(raw).hexdigest() if raw else ""
        with ep.open("rb") as fh:                     # a TAIL: the file is bounded, this process is not
            fh.seek(max(0, err_bytes - STDERR_TAIL))
            err = fh.read(STDERR_TAIL).decode("utf-8", "replace")
        # a marker may sit anywhere in a 280 KB stack dump, so it is STREAMED for, never read whole: the
        # tail alone would miss it and the file alone would defeat the point of bounding the read.
        markers = _scan(ep, MARKERS)

    matches, parsed, doc = None, "n/a", None
    if raw and not truncated:
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
            matches, parsed = (len(doc) if isinstance(doc, list) else None), "ok"
        except ValueError as exc:
            parsed = f"INVALID JSON: {type(exc).__name__}"
    elif truncated:
        # THE finding of the containment section, and the one place this analyzer differs from the chunk
        # engine: it emits ONE `JSON.stringify` of everything at the end, so a cut at the ceiling is not
        # a shorter answer — it is an unparseable one. There is no partial evidence to keep.
        parsed = "TRUNCATED (single JSON document — no partial evidence is recoverable)"

    if timed_out:
        disposition = "timeout"
    elif truncated:
        disposition = "truncated"
    elif rc == 0:
        disposition = "success" if matches else ("empty" if matches == 0 else "unparseable")
    elif rc == 1:
        disposition = "analyzer-error"
    else:
        disposition = "killed"
    return {"disposition": disposition, "rc": rc, "matches": matches, "parsed": parsed,
            "digest": digest, "doc": doc if keep_doc else None, "err_truncated": err_bytes >= cap,
            "markers": markers,
            # NOT the analyzer's memory. MEASURED: a payload that touched 600 MB inside this sandbox came
            # back as 11 MB — `wait4` reports the direct child, which is bwrap, and the analyzer's usage
            # does not propagate through it. Keeping the number under an honest NAME instead of deleting
            # it, because it is still the only figure this loop can obtain; the address-space ladder below
            # is what actually measures the analyzer's appetite. (A metric with nothing to check it
            # against will confidently report a wrong number — that is how dalfox "used 8 GB".)
            "wall_s": round(wall, 2), "wrapper_rss_mb": (ru.ru_maxrss // 1024) if ru else None,
            "out_bytes": out_bytes, "err_bytes": err_bytes, "truncated": truncated,
            "stderr": err.strip().splitlines()[-1][:200] if err.strip() else ""}


def analyze(target: Path, scratch: Path, *, runtime: str = "bun", contained: bool = True,
            wall_s: int = WALL_S, address_space_mb: int = ADDRESS_SPACE_MB,
            keep_doc: bool = False) -> dict:
    exe = BUN if runtime == "bun" else NODE
    cmd = [exe, "run", str(ANALYZER), str(target)] if runtime == "bun" else [exe, str(ANALYZER),
                                                                            str(target)]
    if contained:
        wrapped = sandbox(cmd, scratch, ro=target)
        if not wrapped:
            return {"disposition": "no-sandbox", "rc": None, "matches": None,
                    "parsed": "n/a", "stderr": "bwrap unavailable"}
        cmd = wrapped
    else:
        os.environ["NAPI_RS_NATIVE_LIBRARY_PATH"] = str(NATIVE)
    return _measure(cmd, wall_s=wall_s, address_space_mb=address_space_mb, keep_doc=keep_doc)


# ── fixtures ────────────────────────────────────────────────────────────────────────────────────────
SMOKE = ('const p=new URLSearchParams(location.search);'
         'window.addEventListener("message",e=>{document.getElementById("x").innerHTML=e.data});'
         'localStorage.setItem("tok","abc");'
         'fetch("/api/v1/users",{method:"POST"});\n')


def write_fixtures(d: Path, seed: int) -> dict:
    """Every hostile shape gets a NAME and an expectation, so a silent change of behaviour is visible.

    The random fixture uses its OWN generator: `random` is module-global, `write_fixtures` ran before the
    corpus sampler seeded it, and the binary refusal input therefore changed on every run while the file
    claimed to be reproducible. A fixture whose bytes drift is not a pinned contract.
    """
    rng = random.Random(seed)
    f = {}
    (d / "benign.js").write_text(SMOKE)
    f["benign"] = d / "benign.js"
    (d / "empty.js").write_text("")
    f["empty"] = d / "empty.js"
    (d / "malformed.js").write_text("function ( { <<< unclosed 'string\n")
    f["malformed"] = d / "malformed.js"
    (d / "binary.js").write_bytes(bytes(rng.randrange(256) for _ in range(4096)))
    f["binary"] = d / "binary.js"
    # REGEX LOAD, not a proven ReDoS: one very long token-shaped line is what 1609 secret patterns are
    # each asked to scan. The claim being measured is only "the wall clock is what ends it, if anything".
    (d / "regex-load.js").write_text('const s="' + ("aB3" * 700_000) + '";\n')
    f["regex-load"] = d / "regex-load.js"
    # OUTPUT PRESSURE: many small matches, so the single JSON document grows without the input being huge.
    (d / "many-matches.js").write_text('fetch("/api/v1/x");' * 300_000)
    f["many-matches"] = d / "many-matches.js"
    # INPUT PRESSURE against RLIMIT_AS: a large but ordinary bundle shape.
    (d / "huge.js").write_text(('function f%d(){return fetch("/api/%d");}\n' % (0, 0)) * 1 +
                               "".join('function f%d(){return "/api/%d";}\n' % (i, i)
                                       for i in range(400_000)))
    f["huge"] = d / "huge.js"
    (d / "network.js").write_text('fetch("https://example.invalid/x");\n')
    f["network"] = d / "network.js"
    # a finite allocation, used as the memory CONTROL. Finite by construction, like every other pressure
    # fixture here: a safety test that runs away is not a safety test.
    (d / "alloc.js").write_text('const a=new Uint8Array(900*1024*1024);'
                                'for(let i=0;i<a.length;i+=4096)a[i]=1;console.log("survived");\n')
    f["alloc"] = d / "alloc.js"
    return f


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(Path.home() / "workspace" / "otc-service" / "recon" /
                                            "20260725-143341-1a636b47" / "raw" / "crawl" / "js_files"),
                    help="directory of REAL bundles from a previous run (read-only)")
    ap.add_argument("-n", "--sample", type=int, default=20, help="how many real bundles to analyse")
    ap.add_argument("--seed", type=int, default=20260803, help="sample seed (the sample is reproducible)")
    ap.add_argument("--json", dest="json_out", help="write the full measurement here")
    ap.add_argument("--fixtures-only", action="store_true",
                    help="accept a run with no real bundles (that waiver ONLY)")
    ap.add_argument("--allow-no-node", action="store_true",
                    help="accept a run where the node negative control could not be measured")
    ap.add_argument("--allow-no-cgroup", action="store_true",
                    help="accept a run where the cgroup memory instrument could not be measured")
    args = ap.parse_args()

    report: dict = {"analyzer": str(ANALYZER), "native": str(NATIVE), "bun": BUN,
                    "broken": [], "weaker": []}
    broken: list = report["broken"]
    #: controls that were NOT measured on this host. Each needs its OWN opt-in flag: a caller reading
    #: only the exit status must never be told "passed" about evidence that was never gathered, and one
    #: waiver (say, fixtures-only) may not silently authorise an unrelated omission. Unwaived omissions
    #: exit INCOMPLETE (3), which is neither the pass nor the failure a gate would act on.
    weaker: list = report["weaker"]
    missing: list = []                                   # (name, flag, what went unmeasured)

    for path, what in ((ANALYZER, "analyzer bundle"), (NATIVE, "native parser")):
        if not path.is_file():
            print(f"missing {what}: {path}", file=sys.stderr)
            return 2
    if not Path(BUN).is_file():
        print(f"bun is required and missing: {BUN}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="quarry-astprobe-") as tmp:
        scratch = Path(tmp)
        if not sandbox(["true"], scratch):
            print("REFUSING: bwrap unavailable, so the containment being measured cannot be provided.",
                  file=sys.stderr)
            return 2
        fx = write_fixtures(scratch, args.seed)
        report["fixture_digests"] = {k: hashlib.sha256(v.read_bytes()).hexdigest()[:16]
                                     for k, v in fx.items()}

        # ── A. the RUNTIME contract ────────────────────────────────────────────────────────────────
        print("runtime (a) — what actually runs this analyzer:")
        bun_run = analyze(fx["benign"], scratch)
        node_run = analyze(fx["benign"], scratch, runtime="node")
        report["runtime"] = {"bun": bun_run, "node": node_run}
        print(f"  bun  -> {bun_run['disposition']} rc={bun_run['rc']} matches={bun_run['matches']} "
              f"({bun_run['wall_s']}s)")
        print(f"  node -> {node_run['disposition']} rc={node_run['rc']} "
              f"markers={node_run.get('markers')} [{(node_run['stderr'] or '')[:40] or 'no stderr'}]")
        if bun_run["disposition"] != "success":
            broken.append("bun cannot run the analyzer on a benign fixture")
        # the CONTROL, and it must fail for the measured reason. "Some non-success" would also be
        # satisfied by a node that is missing, unbound, or broken for any unrelated cause.
        node_present = bool(shutil.which("node"))
        node_reason = "Failed to load native binding" in (node_run.get("markers") or [])
        report["node_control"] = {"present": node_present, "reason_measured": node_reason}
        if not node_present:
            missing.append(("node", "--allow-no-node",
                            "the runtime negative control was NOT measured"))
        elif node_run["disposition"] == "success":
            broken.append("node now succeeds — the install may silently pick the wrong runtime")
        elif not node_reason:
            broken.append(f"node failed for an UNMEASURED reason ({node_run['disposition']}): the "
                          f"control does not prove the native binding rejects node")

        # ── B. the OUTPUT schema ───────────────────────────────────────────────────────────────────
        print("schema (b) — the shape a lane would have to consume:")
        benign_doc = analyze(fx["benign"], scratch, keep_doc=True)
        doc = _schema(benign_doc.get("doc") or [])
        report["schema"] = doc
        if doc.get("keys"):
            print(f"  keys={doc['keys']}  analyzers={doc['analyzers']}")
            print(f"  positions: {doc['position']}  (line/column, not byte offsets)")
        required = {"filePath", "analyzerName", "value", "start", "end", "tags"}
        if not required.issubset(set(doc.get("keys", []))):
            broken.append(f"output schema lost a required key: {required - set(doc.get('keys', []))}")

        # ── C. the REFUSAL contract ────────────────────────────────────────────────────────────────
        print("refusals (c) — what each failure LOOKS like, and each one is PINNED:")
        # MEASURED expectations. Printing a refusal is not gating it: the analyzer could start returning
        # results for binary input, or start dying on it, and a probe that only displays the row would
        # still say the contract was intact. Each fixture pins disposition, rc and match count.
        expected = {"empty": ("empty", 0, 0), "malformed": ("empty", 0, 0), "binary": ("empty", 0, 0),
                    "missing": ("analyzer-error", 1, None)}
        #: the missing-file case must fail for the MEASURED reason too — any unrelated rc 1 would
        #: otherwise satisfy it, exactly as any non-success would have satisfied the node control.
        expected_marker = {"missing": "File not found"}
        refusals = {}
        for name in ("empty", "malformed", "binary", "missing"):
            target = (scratch / "does-not-exist.js") if name == "missing" else fx[name]
            r = analyze(target, scratch)
            refusals[name] = r
            want = expected[name]
            got = (r["disposition"], r["rc"], r["matches"])
            ok = got == want
            print(f"  {name:<10} -> {r['disposition']:<16} rc={r['rc']} matches={r['matches']} "
                  f"{'PINNED' if ok else 'CHANGED, expected ' + str(want)}"
                  f"{(' ' + str(r['markers'])) if r['markers'] else ''}")
            if not ok:
                broken.append(f"refusal contract changed for {name}: expected {want}, measured {got}")
            need_marker = expected_marker.get(name)
            if need_marker and need_marker not in (r["markers"] or []):
                broken.append(f"{name}: rc/disposition matched but the reason did not — expected "
                              f"{need_marker!r} in stderr, measured {r['markers']}")
        report["refusals"] = refusals
        # the ambiguity this pins is the POINT: three different unreadable inputs all exit 0 with `[]`,
        # so an empty answer can never be read as "this bundle contains nothing".
        if {refusals[n]["disposition"] for n in ("empty", "malformed", "binary")} != {"empty"}:
            broken.append("the ambiguity of `empty` changed — a lane's coverage vocabulary depends on it")

        # ── D. CONTAINMENT ─────────────────────────────────────────────────────────────────────────
        print("containment (d) — what a hostile bundle can do to this machine")
        print("  (RSS is the WRAPPER's: a 600 MB allocation inside this sandbox reports ~11 MB, so the "
              "address-space ladder is the memory instrument, not the number)")
        contain = {}
        for name, wall in (("regex-load", 20), ("many-matches", WALL_S), ("huge", WALL_S)):
            r = analyze(fx[name], scratch, wall_s=wall)
            contain[name] = r
            print(f"  {name:<13} -> {r['disposition']:<10} rc={r['rc']} "
                  f"{r['wall_s']}s rss={r['wrapper_rss_mb']} MB(wrapper) out={r['out_bytes']}B "
                  f"[{r['parsed'][:52]}]")
            if r["disposition"] not in ("success", "empty", "timeout", "truncated", "killed"):
                broken.append(f"{name}: uncontained ending {r['disposition']}")
            if r["disposition"] == "killed":
                # WHOSE limit stopped it? An abort under OUR bound is a cap that needs sizing; an abort
                # with headroom is the tool's own ceiling. Reporting the first as the second would ship a
                # number nobody measured — the mistake the nuclei timeout took three runs to unlearn.
                ladder = {}
                for mb in (8192, 16384, 32768):
                    rr = analyze(fx[name], scratch, wall_s=wall, address_space_mb=mb)
                    ladder[mb] = f"{rr['disposition']}/rss={rr['wrapper_rss_mb']}MB(wrapper)"
                    if rr["disposition"] not in ("killed", "timeout"):
                        break
                contain[name + ":address-space"] = ladder
                print(f"    address-space ladder: " +
                      "  ".join(f"{mb}MB->{v}" for mb, v in ladder.items()))
        # the STDERR ceiling, exercised rather than asserted. The analyzer cannot be made to fill stderr
        # on demand, so a finite writer stands in for it: the claim under test is this probe's own
        # classification rule — a run that saturates a stream and exits 0 is NOT an answer. Finite by
        # construction (cap + 1 MB): an endless writer in a safety test is how 32 GB once landed on disk.
        spill = OUTPUT_MB + 1
        writer = sandbox(["/bin/sh", "-c",
                          f"dd if=/dev/zero bs=1M count={spill} 2>/dev/null | tr '\\\\0' 'x' >&2; exit 0"],
                         scratch)
        r = _measure(writer)
        contain["stderr-ceiling"] = r
        print(f"  stderr spill  -> {r['disposition']} rc={r['rc']} err_bytes>=cap={r['err_truncated']}")
        if r["disposition"] != "truncated" or not r["err_truncated"]:
            broken.append("a run that saturated STDERR was not classified truncated — an EFBIG swallowed "
                          "by the child would read as a clean answer")
        cg = _cgroup_bound(scratch, fx)
        contain["cgroup"] = cg
        print(f"  cgroup        -> {cg['verdict']}")
        if cg["available"] and not cg.get("control_ok"):
            broken.append("the uncapped memory control did not succeed: nothing can be attributed to a "
                          "cgroup when the workload fails without one")
        if cg["available"] and cg.get("control_ok") and not cg["enforced"]:
            if cg.get("hard_ok") and not cg.get("contrast_ok") and cg.get("swap_total_kb") == 0:
                # a swapless host cannot show the contrast; the bound still held, but the CLAIM that the
                # swap property is what made it hold is unsupported here and may not be printed as proven
                missing.append(("cgroup-contrast", "--allow-no-cgroup",
                                "MemoryMax-only could not be shown to survive (no swap on this host)"))
            else:
                broken.append(f"the cgroup triplet does not hold: {cg['verdict']}")
        if cg["available"] and not all(cg.get("units_settled", [True])):
            broken.append("a transient unit could not be confirmed stopped: the probe cannot report a "
                          "containment verdict while its own workload may still be running")
        if not cg["available"]:
            missing.append(("cgroup", "--allow-no-cgroup",
                            "the proposed memory instrument was NOT measured"))
        net = _network_denied(scratch)
        contain["network"] = net
        print(f"  network       -> {net}")
        if "DENIED" not in net:
            broken.append("the sandbox did not deny network")
        host = _host_files_absent(scratch)
        contain["host_files"] = host
        print(f"  host files    -> {host}")
        if "ABSENT" not in host:
            broken.append("operator files are reachable from inside the sandbox")
        report["containment"] = contain

        # ── E. DETERMINISM ─────────────────────────────────────────────────────────────────────────
        a = analyze(fx["benign"], scratch)["digest"]
        b = analyze(fx["benign"], scratch)["digest"]
        report["deterministic"] = (a == b)
        print(f"determinism (e) — same bytes twice: {'IDENTICAL' if a == b else 'DIFFERENT'} ({a[:12]})")
        if a != b:
            broken.append("the analyzer is not deterministic over identical input")

        # ── F. REAL bundles ────────────────────────────────────────────────────────────────────────
        corpus = Path(args.corpus)
        real = sorted(corpus.glob("*.js")) if corpus.is_dir() else []
        if real:
            random.seed(args.seed)
            pick = random.sample(real, min(args.sample, len(real)))
            print(f"real bundles (f) — {len(pick)} of {len(real)} from {corpus}:")
            rows, worst = [], None
            for p in pick:
                r = analyze(p, scratch)
                r["file"], r["size"] = p.name, p.stat().st_size
                if r["disposition"] == "killed":
                    # An ORDINARY bundle dying under our own bound is not containment working — it is a
                    # cap that cannot do the job. Ladder it, and record the bound the file actually needs
                    # so the number in a lane comes from this line and not from intuition.
                    for mb in (8192, 16384, 32768):
                        rr = analyze(p, scratch, address_space_mb=mb)
                        # climb until it ANSWERS: at an intermediate bound the analyzer catches its own
                        # allocation failure and exits 1, which is a different SHAPE of the same fault,
                        # not a result (measured on a 27 MB bundle: killed at 4/8 GB, analyzer-error at
                        # 16 GB, success at 32 GB in 92 s).
                        if rr["disposition"] in ("success", "empty"):
                            rr["file"], rr["size"] = p.name, p.stat().st_size
                            rr["bound_needed_mb"], r = mb, rr
                            break
                    else:
                        r["bound_needed_mb"] = None      # no bound made it analysable: the TOOL's ceiling
                rows.append(r)
                if worst is None or (r["wall_s"] or 0) > (worst["wall_s"] or 0):
                    worst = r
            ok = [r for r in rows if r["disposition"] == "success"]
            bad = [r for r in rows if r["disposition"] not in ("success", "empty")]
            tot = sum(r["matches"] or 0 for r in rows)
            print(f"  {len(ok)}/{len(rows)} analysed, {tot} matches, "
                  f"slowest {worst['wall_s']}s on {worst['size']}B ({worst['file'][:16]}), "
                  f"wall total {round(sum(r['wall_s'] or 0 for r in rows), 2)}s")
            for r in rows:                       # EVERY file, because 0 matches is not self-explanatory
                print(f"    {r['file'][:20]:<22} {r['size']:>9}B {r['disposition']:<15} "
                      f"matches={str(r['matches']):<5} {r['wall_s']}s "
                      f"{('[' + r['stderr'][:44] + ']') if r['stderr'] else ''}")
            report["real"] = rows
            need = [r for r in rows if r.get("bound_needed_mb")]
            if need:
                print(f"  ADDRESS SPACE: {len(need)} of {len(rows)} ordinary bundles need more than the "
                      f"{ADDRESS_SPACE_MB} MB default "
                      f"(needed: {sorted({r['bound_needed_mb'] for r in need})} MB) — RLIMIT_AS is not a "
                      f"usable memory bound for bun; a lane needs a cgroup, not a rlimit")
            stuck = [r for r in rows if r["disposition"] == "killed" and r.get("bound_needed_mb") is None]
            for r in stuck:
                print(f"  UNANALYSABLE at any bound: {r['file'][:24]} ({r['size']}B)")
            if not ok:
                broken.append("not one real bundle analysed cleanly")
            if stuck:
                broken.append(f"{len(stuck)} real bundle(s) unanalysable at every address-space bound")
        else:
            print(f"real bundles (f) — no corpus at {corpus}")
            report["real"] = []
            # The ordinary-input memory ladder and the "bun copes with production bundles" claim live
            # ENTIRELY in this section. Losing it silently would leave PROBE PASSED asserting a contract
            # measured only against fixtures this probe wrote itself.
            missing.append(("real-bundles", "--fixtures-only",
                            f"no ordinary-input measurement: nothing at {corpus}"))

    # RESOLVE first, publish second. The JSON used to be written before `missing` was turned into
    # waived-or-not, so a report could carry broken=[] and weaker=[] while the process exited 3 — a
    # machine reading the artifact would have seen a clean run that the exit code called incomplete.
    waived = {"--fixtures-only": args.fixtures_only, "--allow-no-node": args.allow_no_node,
              "--allow-no-cgroup": args.allow_no_cgroup}
    unwaived = [m for m in missing if not waived.get(m[1])]
    for name, flag, what in missing:
        line = f"{name}: {what}" + ("" if waived.get(flag) else f" (pass {flag} to accept)")
        (weaker if waived.get(flag) else broken).append(line)
    report["unmeasured"] = [{"control": n, "flag": f, "what": w, "waived": bool(waived.get(f))}
                            for n, f, w in missing]
    report["verdict"] = ("failed" if [b for b in broken if b not in
                                      [f"{n}: {w} (pass {f} to accept)" for n, f, w in unwaived]]
                         else "incomplete" if unwaived else "passed-weaker" if weaker else "passed")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))
        print(f"\nwrote {args.json_out}")

    hard_failures = [b for b in broken
                     if b not in [f"{n}: {w} (pass {f} to accept)" for n, f, w in unwaived]]
    if hard_failures:
        print("\nPROBE FAILED — the contract was not certified:", file=sys.stderr)
        for b in hard_failures:
            print(f"  - {b}", file=sys.stderr)
        return 1
    if unwaived:
        print("\nPROBE INCOMPLETE — a required control was not measured:", file=sys.stderr)
        for name, flag, what in unwaived:
            print(f"  - {name}: {what} — pass {flag} to accept this omission", file=sys.stderr)
        return 3
    if weaker:
        print("\nPROBE PASSED (WEAKER) — intact where measured, but these were WAIVED, not measured:")
        for w in weaker:
            print(f"  - {w}")
        return 0
    print("\nPROBE PASSED — runtime, schema, refusals and containment all measured and intact")
    return 0


def _schema(doc: list) -> dict:
    """The schema, read off a real run rather than off the TypeScript. The run itself goes through the
    bounded measurement primitive — `capture_output=True` would put analyzer-controlled bytes straight
    into this process, where RLIMIT_FSIZE does not apply and the acceptance gate itself becomes the
    thing that runs out of memory."""
    if not isinstance(doc, list) or not doc:
        return {}
    return {"keys": sorted(doc[0].keys()),
            "analyzers": sorted({m["analyzerName"] for m in doc}),
            "position": doc[0]["start"],
            "tags": sorted({tag for m in doc for tag in m.get("tags", {})})}


#: one bus call's ceiling, and the whole cleanup's ceiling. They compose: a poll loop whose per-call
#: timeout is not capped by its own remaining time is not bounded by the number in its signature —
#: `_settle(seconds=2)` could take 2 + 10 because the deadline was only checked BETWEEN calls.
BUS_S = 10.0
CLEANUP_S = 30.0


def _left(end: float) -> float:
    return max(0.0, end - time.perf_counter())


def _sysctl(args: list, timeout: float = BUS_S):
    """`systemctl --user …`, always BOUNDED. A stalled user bus would otherwise block a cleanup path that
    is supposed to be the thing keeping this probe inside its own wall budget."""
    if timeout <= 0:
        return None
    try:
        return subprocess.run(["systemctl", "--user"] + args, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _unit_props(unit: str, timeout: float = BUS_S) -> dict:
    show = _sysctl(["show", unit, "-p", "Result", "-p", "MemoryPeak", "-p", "ExecMainStatus",
                    "-p", "ActiveState", "-p", "InvocationID", "-p", "LoadState"], timeout=timeout)
    if show is None:
        return {}
    return dict(line.split("=", 1) for line in show.stdout.splitlines() if "=" in line)


def _settle(unit: str, end: float) -> bool:
    """Wait — until an ABSOLUTE deadline — for the unit to actually stop being active.

    The deadline is passed into every bus call, not merely checked between them: a stalled `show` would
    otherwise spend its own full timeout AFTER the last check, so the caller's budget was advisory. Now
    each poll is capped at `min(BUS_S, remaining)` and the loop cannot outlive `end`.
    """
    while _left(end) > 0:
        props = _unit_props(unit, timeout=min(BUS_S, _left(end)))
        # NOT being able to look is not evidence that it stopped. A timed-out or failed `show` returns
        # {}, and defaulting that to "inactive" turned an unreadable bus into proof of settlement — the
        # one reading that must never settle, because it is exactly the state a hung unit produces.
        if props.get("LoadState") == "not-found":
            return True                                   # garbage-collected: it is genuinely gone
        if props.get("ActiveState") in ("inactive", "failed"):
            return True
        time.sleep(min(0.05, _left(end)))                 # empty/unknown: keep asking until the deadline
    return False


def _merge_props(earlier: dict, late: dict) -> dict:
    """FINAL state wins — except when the late read is not a reading at all.

    `systemctl show` on a garbage-collected unit answers with DEFAULTS (`Result=success`,
    `ActiveState=inactive`) and `LoadState=not-found`. Letting that overwrite a real `oom-kill` would
    turn the strongest evidence this probe has into its opposite, so a not-found read only fills fields
    the earlier snapshot never had.
    """
    if not late:
        return earlier
    if late.get("LoadState") == "not-found":
        return {**late, **{k: v for k, v in earlier.items() if v}}
    return {**{k: v for k, v in earlier.items() if v}, **{k: v for k, v in late.items() if v}}


def _unit_run(cmd: list, *, unit: str, props: list, wall_s: int = WALL_S) -> dict:
    """Run `cmd` as a transient SERVICE and ask systemd what ended it.

    Polling a scope's `memory.events` was the first attempt and it was not evidence: the transient unit
    is removed the instant the child exits, so the counter read back 0 even when the peak sat exactly on
    the cap. A `--wait` service survives long enough to be interrogated, and `Result=oom-kill` is the
    memory controller's own verdict — not an exit code this probe interpreted.

    The whole call is bounded, and the bound is the SUM of its parts, not one of them: a pre-run
    `reset-failed` (<= BUS_S) + the run itself (<= wall_s) + one settled-state read (<= BUS_S) + the
    cleanup (<= CLEANUP_S). MEASURED against a bus where every call blocks for its full timeout:
    50 s for wall_s=3, against the 53 s that arithmetic predicts. Stating a smaller number would be the
    same mistake as trusting `_settle`'s `seconds` before its deadline was threaded into each poll.

    The unit is STOPPED in a finally. `_measure`'s deadline kills the systemd-run CLIENT's process
    group; the service systemd started is not in it, so a timeout or an exception here would otherwise
    leave a 900 MB allocator running after a CONTAINMENT probe returned. Properties are collected after
    the unit is inactive, and `reset-failed` — which does not stop anything — comes last.
    """
    _sysctl(["reset-failed", unit])          # a stale unit would refuse the next run — and BOUNDED, like
    #                                          every other bus call: this one runs BEFORE the cleanup
    #                                          deadline exists, so a stalled bus would hang with no
    #                                          budget watching it at all.
    full = ["systemd-run", "--user", f"--unit={unit}", "--wait", "-q"]
    for prop in props:
        full += ["-p", prop]
    r: dict = {"disposition": "not-run", "rc": None}
    read: dict = {}
    try:
        r = _measure(full + cmd, wall_s=wall_s, address_space_mb=32768)
        # WHILE it still exists. A transient unit is garbage-collected once it goes inactive, so a read
        # taken only after `stop` comes back empty — including the InvocationID that proves this run is
        # not a previous unit's evidence.
        read = _unit_props(unit)
    finally:
        # `--no-block` on purpose: a synchronous stop has no timeout of its own, so a stalled unit or bus
        # would hang HERE, before the deadline below ever started counting. Ask, then watch the clock.
        # ONE absolute deadline for the entire cleanup, threaded through every call inside it, so the
        # worst case is CLEANUP_S rather than the sum of six independent ten-second ceilings.
        end = time.perf_counter() + CLEANUP_S
        _sysctl(["stop", "--no-block", unit], timeout=min(BUS_S, _left(end)))
        settled = _settle(unit, end=time.perf_counter() + min(_left(end), CLEANUP_S / 2))
        read = _merge_props(read, _unit_props(unit, timeout=min(BUS_S, _left(end))))
        if not settled:
            _sysctl(["kill", "--signal=SIGKILL", unit], timeout=min(BUS_S, _left(end)))
            settled = _settle(unit, end=time.perf_counter() + min(_left(end), CLEANUP_S / 4))
            read = _merge_props(read, _unit_props(unit, timeout=min(BUS_S, _left(end))))
        _sysctl(["reset-failed", unit], timeout=min(BUS_S, _left(end)))
    peak = read.get("MemoryPeak", "")
    r["settled"] = bool(settled)
    # a snapshot taken while the unit was still RUNNING reads `Result=success` — that is systemd's
    # default until something ends it, not a verdict. On the timeout path this probe is what ended the
    # unit, so the field says so instead of carrying a word that means the opposite.
    result = read.get("Result", "?")
    if r.get("disposition") == "timeout":
        result = f"probe-timeout (stopped by the probe; last state {read.get('ActiveState', '?')})"
    r.update({"unit": unit, "result": result,
              "main_status": read.get("ExecMainStatus", "?"),
              "active_state": read.get("ActiveState", "?"),
              # an InvocationID identifies THIS start. Without it, a unit name that systemd-run refused
              # to create (PID reuse, an interrupted earlier run) would be read back with the OLD run's
              # `Result=oom-kill` — stale evidence for a run that never happened.
              "invocation": read.get("InvocationID", ""),
              "peak_mb": (int(peak) // (1 << 20)) if peak.isdigit() else None})
    return r


def _cgroup_bound(scratch: Path, fx: dict) -> dict:
    """Is a cgroup an instrument this lane could actually use? THREE runs of ONE finite workload, and the
    claim is the TRIPLET — a single bounded run cannot tell "the controller killed it" from "it died",
    and the final oom-kill alone does not show that the swap property is what made the bound real.

        uncapped                          rc 0            the workload is sound without any bound
        MemoryMax only                    success         it survives — so the cap alone is NOT a bound
        MemoryMax + MemorySwapMax=0       oom-kill        the controller's own verdict

    All three, or the conclusion is not supported. A timeout is never enforcement. On a host with no
    swap the middle row cannot exist, and that is reported as an unmeasured CONTRAST, not as a pass.
    """
    if not shutil.which("systemd-run") or not shutil.which("systemctl"):
        return {"available": False, "enforced": False, "contrast": "n/a",
                "verdict": "NOT MEASURED (no systemd-run)"}
    alloc = fx["alloc"]
    payload = sandbox([BUN, "run", str(alloc)], scratch, ro=alloc)
    nonce = f"{os.getpid()}-{random.Random().randrange(1 << 32):08x}"
    base = _measure(payload, address_space_mb=32768)          # judged by RC: it prints text, not JSON
    soft = _unit_run(payload, unit=f"quarry-ast-mem-{nonce}", props=["MemoryMax=512M"])
    hard = _unit_run(payload, unit=f"quarry-ast-oom-{nonce}",
                     props=["MemoryMax=512M", "MemorySwapMax=0"])
    try:
        swap_kb = int(next(l.split()[1] for l in Path("/proc/meminfo").read_text().splitlines()
                           if l.startswith("SwapTotal:")))
    except (OSError, StopIteration, ValueError):
        swap_kb = -1
    # FRESHNESS, without depending on a property that is not always readable. systemd garbage-collects a
    # SUCCESSFUL transient unit the moment `--wait` returns, so its InvocationID is gone by then (the
    # failed one lingers until reset-failed). What is always available is whether systemd-run created the
    # unit at all: a name that already existed makes it refuse, and refusing is the only way stale
    # evidence could be read back. The unit names carry a random nonce as well, so a collision needs a
    # 32-bit coincidence AND an interrupted earlier run.
    created = [("already exists" not in (u["markers"] or [])) for u in (soft, hard)]
    settled = [bool(u.get("settled")) for u in (soft, hard)]
    ids = [u["invocation"] for u in (soft, hard) if u["invocation"]]
    fresh = all(created) and len(set(ids)) == len(ids)
    control_ok = base["rc"] == 0
    contrast_ok = soft["result"] == "success"
    hard_ok = hard["result"] == "oom-kill" and hard["disposition"] != "timeout"
    out = {"available": True, "enforced": bool(control_ok and contrast_ok and hard_ok and fresh),
           "control_ok": control_ok, "contrast_ok": contrast_ok, "hard_ok": hard_ok,
           "fresh_invocations": fresh, "units_created": created, "units_settled": settled,
           "swap_total_kb": swap_kb,
           "contrast": ("measured" if contrast_ok else
                        ("unmeasurable: this host has no swap" if swap_kb == 0 else "FAILED")),
           "uncapped": {"rc": base["rc"], "disposition": base["disposition"]},
           "memorymax_only": {"result": soft["result"], "rc": soft["rc"], "peak_mb": soft["peak_mb"],
                              "invocation": soft["invocation"], "active_state": soft["active_state"]},
           "memorymax_plus_swap0": {"result": hard["result"], "rc": hard["rc"],
                                    "main_status": hard["main_status"], "peak_mb": hard["peak_mb"],
                                    "invocation": hard["invocation"],
                                    "active_state": hard["active_state"]}}
    out["enforced"] = bool(out["enforced"] and all(settled))
    out["verdict"] = (
        f"uncapped rc={base['rc']} · MemoryMax=512M -> Result={soft['result']} · "
        f"+MemorySwapMax=0 -> Result={hard['result']} (status {hard['main_status']}, "
        f"peak {hard['peak_mb']}MB) — "
        + ("ENFORCED — all three rows hold, and each run is a distinct systemd invocation"
           if out["enforced"] else
           f"NOT PROVEN (control={control_ok}, contrast={contrast_ok}, oom-kill={hard_ok}, "
           f"fresh={fresh})"))
    return out


def _network_denied(scratch: Path) -> str:
    """Measured through the namespace, not asserted from the flag list."""
    probe = sandbox([BUN, "-e", 'try{await fetch("https://example.com")}catch(e){console.log("ERR:"+e)}'],
                    scratch)
    r = subprocess.run(probe, capture_output=True, text=True, timeout=WALL_S)
    blob = (r.stdout + r.stderr).strip().replace("\n", " ")
    return ("DENIED (" + blob[:70] + ")") if blob else f"UNKNOWN rc={r.returncode}"


def _host_files_absent(scratch: Path) -> str:
    targets = [str(Path.home() / ".config" / "quarry" / "secrets.yaml"),
               str(Path.home() / ".ssh"), str(Path.home() / "workspace")]
    probe = sandbox(["/bin/sh", "-c", "ls -d " + " ".join(targets) + " 2>&1 || true"], scratch)
    r = subprocess.run(probe, capture_output=True, text=True, timeout=WALL_S)
    got = r.stdout + r.stderr
    return ("ABSENT (%d/%d not found)" % (got.count("No such file"), len(targets))
            if got.count("No such file") == len(targets) else "REACHABLE: " + got[:120])


if __name__ == "__main__":
    sys.exit(main())
