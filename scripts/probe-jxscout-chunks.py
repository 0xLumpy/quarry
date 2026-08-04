#!/usr/bin/env python3
"""CONTRACT PROBE — jxscout chunk discovery. Measurement only; builds no lane and contacts no target.

The question this answers is not "does it work" but "what exactly does it promise, and what does it do
when it fails". A producer whose failure looks like an empty answer cannot be wired into a coverage
contract, so the probe measures the disposition of every ending, not just the happy path.

    ./scripts/probe-jxscout-chunks.py                  # the installed corpus, both limits, sandboxed
    ./scripts/probe-jxscout-chunks.py --json out.json  # machine-readable, for the write-up

It runs ONLY against fixtures on disk (upstream ships 26 with the tree). Nothing here reaches a network:
the sandbox is part of what is being measured.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TREE = Path.home() / ".local" / "share" / "quarry" / "jxscout"
ENGINE = Path.home() / ".local" / "share" / "quarry" / "jxscout-chunk-discoverer.cjs"
FIXTURES = TREE / "pkg" / "chunk-discoverer" / "tests" / "files"

#: node's own heap ceiling. Sized ABOVE the legitimate corpus: the largest upstream fixture needs ~931 MB,
#: so a smaller cap would report gaps on ordinary large bundles rather than on runaway ones.
HEAP_MB = 2048
#: the hard backstop, in case the heap flag is not what runs away (native allocations, a huge input read).
ADDRESS_SPACE_MB = 4096
WALL_S = 60
#: what the child may WRITE. A memory cap does not bound output: the engine prints one line per candidate,
#: and a bundle designed to emit forever would fill a disk, or a parent buffer, while every other limit
#: holds. `RLIMIT_FSIZE` stops it at the source; the read below stops at the same ceiling.
OUTPUT_MB = 64


def sandbox(cmd: list) -> list:
    """Wrap in containment that isolates BOTH the filesystem and the network, or return nothing.

    `unshare -rn` was here as a fallback and has been removed: it denies networking while leaving every
    path the user can write to reachable by the evaluated code. Calling that "contained" would be the
    dangerous half of a promise — the engine runs the TARGET's code through Sval, so an escape writes to
    the operator's home directory. No bwrap, no probe.

    `--ro-bind / /` was here too, and is gone for the same reason the LANE stopped using it: read-only is
    not absent. It left secrets.yaml, SSH material and every previous engagement's evidence readable by
    code we deliberately evaluate. The allow-list below is the runtime, the engine, and the pinned
    upstream tree the fixtures live in — nothing of the operator's. Output never needs a bind: the child
    writes to inherited FDs, not to paths inside the namespace.
    """
    if not shutil.which("bwrap"):
        return []
    node = shutil.which("node")
    if not node:
        return []
    args = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv", "--chdir", "/",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/ld.so.conf",
                 "/etc/ld.so.conf.d", "/etc/alternatives"):
        args += ["--ro-bind-try", path, path]
    args += ["--ro-bind", node, node,
             "--ro-bind-try", str(ENGINE), str(ENGINE),
             "--ro-bind-try", str(TREE), str(TREE),          # the pinned upstream fixtures, read-only
             "--setenv", "PATH", "/usr/bin:/bin",
             "--setenv", "HOME", "/tmp"]
    return args + cmd


def run_one(fixture: Path, limit: int, *, contained: bool = True, heap_mb: int = HEAP_MB) -> dict:
    cmd = ["node", f"--max-old-space-size={heap_mb}", str(ENGINE), str(fixture), str(limit)]
    if contained:
        wrapped = sandbox(cmd)
        if not wrapped:
            return {"disposition": "no-sandbox", "rc": None, "candidates": 0,
                    "detail": "bwrap is not available: filesystem+network isolation cannot be provided"}
        cmd = wrapped
    return _measure(cmd)


def _limits(address_space_mb: int = ADDRESS_SPACE_MB) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (address_space_mb * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_MB * 1024 * 1024,) * 2)


def _measure(cmd: list, *, address_space_mb: int = ADDRESS_SPACE_MB) -> dict:
    """Run one contained command and report what actually happened to it.

    Output goes to FILES the child can only fill to `RLIMIT_FSIZE`, never to a parent buffer:
    `capture_output=True` accumulates attacker-controlled bytes inside this process, where none of the
    child's limits apply. Peak RSS comes from `wait4`, which reports THIS child's usage — the
    `RUSAGE_CHILDREN` high-water mark cannot be differenced into a per-run figure, and doing so reported
    0 MB for every fixture after the first big one.
    """
    with tempfile.TemporaryDirectory() as tmp:
        op, ep = Path(tmp) / "out", Path(tmp) / "err"
        with op.open("wb") as ofh, ep.open("wb") as efh:
            t0 = time.perf_counter()
            proc = subprocess.Popen(cmd, stdout=ofh, stderr=efh,
                                    preexec_fn=lambda: _limits(address_space_mb),
                                    start_new_session=True)
            timed_out, status, ru = False, 0, None
            deadline = t0 + WALL_S
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
        proc.returncode = status                     # reaped by wait4; keep Popen from waiting again
        rc = (os.waitstatus_to_exitcode(status) if not timed_out else None)
        cap = OUTPUT_MB * 1024 * 1024
        out_bytes, err_bytes = op.stat().st_size, ep.stat().st_size
        out = op.read_bytes()[:cap].decode("utf-8", "replace")
        err = ep.read_bytes()[:8192].decode("utf-8", "replace")

    candidates = [line for line in out.splitlines() if line.strip()]
    truncated = out_bytes >= cap

    # THE DISPOSITION IS THE POINT. A memory kill can be completely silent (measured: SIGABRT with empty
    # stdout AND empty stderr), so "no candidates" may never be inferred from an empty result — only a
    # clean exit can say that a bundle declares none.
    if timed_out:
        disposition = "timeout"
    elif truncated:
        disposition = "truncated"                 # a GAP: we bounded it, so we do not know the rest
    elif rc == 0:
        disposition = "success" if candidates else "empty"
    elif rc == 1:
        # MEASURED: this is an I/O refusal (missing/unreadable file), NOT a parse refusal. The engine uses
        # acorn-LOOSE, which never throws — garbage parses into a best-effort AST and comes back as a
        # clean, empty answer. So the engine cannot tell us a bundle was unparseable, and `empty` is
        # genuinely ambiguous: "no chunk loader here" or "we could not understand this file".
        disposition = "engine-error"
    else:
        disposition = "killed"                    # signal / OOM — a GAP, never an answer
    return {"disposition": disposition, "rc": rc, "candidates": len(candidates),
            "wall_s": round(wall, 2), "peak_rss_mb": (ru.ru_maxrss // 1024) if ru else None,
            "out_bytes": out_bytes, "truncated": truncated,
            "stderr": err.strip()[:200], "sample": candidates[:3]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixtures", default=str(FIXTURES), help="directory of .js bundles")
    ap.add_argument("--limits", default="0,3000", help="brute-force limits to compare")
    ap.add_argument("--json", dest="json_out", help="write the full measurement here")
    args = ap.parse_args()

    if not ENGINE.is_file():
        print(f"engine missing: {ENGINE}\n  run: quarry install --only jxscout-chunks", file=sys.stderr)
        return 2
    if not sandbox(["true"]):
        print("REFUSING: bwrap is not available, so filesystem AND network isolation cannot be provided. "
              "The engine executes target code; running it uncontained is not a measurement, it is a "
              "risk.", file=sys.stderr)
        return 2

    #: every invariant the probe must be able to certify. A probe that prints failures and exits 0 is a
    #: green light nobody checked — this is meant to be usable as an acceptance gate, so each broken
    #: invariant lands here and the exit code carries them out.
    broken: list = []

    files = sorted(Path(args.fixtures).glob("*.js"), key=lambda p: int(p.stem) if p.stem.isdigit() else 0)
    if not files:
        print(f"REFUSING: no fixtures in {args.fixtures} — a probe over nothing certifies nothing",
              file=sys.stderr)
        return 2
    limits = [int(x) for x in args.limits.split(",")]
    report: dict = {"engine": str(ENGINE), "fixtures": len(files), "limits": limits,
                    "sandbox": sandbox(["X"])[0], "heap_mb": HEAP_MB, "results": {}}

    print(f"{'fx':>4} {'bytes':>9} " + " ".join(f"{('lim=' + str(l)):>12}" for l in limits))
    for f in files:
        row = {}
        cells = []
        for lim in limits:
            r = run_one(f, lim)
            row[str(lim)] = r
            cells.append(f"{r['candidates']:>5}/{r['disposition'][:6]:<6}")
        report["results"][f.name] = row
        print(f"{f.stem:>4} {f.stat().st_size:>9} " + " ".join(f"{c:>12}" for c in cells))

    # ── the two facts a lane would be built on ────────────────────────────────────────────────────
    derived = {n: r[str(limits[0])]["candidates"] for n, r in report["results"].items()}
    print(f"\nDERIVED (limit {limits[0]}): {sum(derived.values())} candidates over {len(files)} fixtures; "
          f"{sum(1 for v in derived.values() if v == 0)} fixture(s) declare none")
    if len(limits) > 1:
        wide = {n: r[str(limits[1])]["candidates"] for n, r in report["results"].items()}
        saturated = [n for n, v in wide.items() if v >= limits[1]]
        print(f"BRUTE FORCE (limit {limits[1]}): {sum(wide.values())} candidates, "
              f"{len(saturated)} fixture(s) SATURATED at the limit — "
              f"{sum(wide.values()) - sum(derived.values())} of those are enumeration, not evidence")
    # ALLOW-LIST, not a deny-list: a deny-list silently blesses every disposition nobody thought of, and
    # `engine-error` was exactly that — the whole corpus could start exiting 1 and still read as clean.
    # `empty` is admitted because it is MEASURED and understood (acorn-loose never throws), not because it
    # is good news.
    bad = {n: r for n, r in report["results"].items()
           if any(v["disposition"] not in ("success", "empty") for v in r.values())}
    print(f"NON-CLEAN endings: {len(bad)}" + (f" -> {sorted(bad)}" if bad else ""))
    if bad:
        broken.append(f"{len(bad)} fixture(s) ended non-clean: {sorted(bad)}")

    # ── containment, measured in two honest halves ────────────────────────────────────────────────
    # (a) the MECHANISM: a runaway under exactly the wrapper the lane would use. Note this is NOT routed
    #     through the engine — a runaway that the fingerprinter never recognises is never evaluated, so
    #     driving the mechanism directly is the measurement, and a FINGERPRINTED hostile bundle is a range
    #     fixture we still owe.
    print("\ncontainment (a) — the mechanism, under the lane's own wrapper:")
    runaway = "var a=[];var s='x'.repeat(1e6);for(;;){a.push(s+a.length)}"
    for heap in (128, HEAP_MB):
        cmd = sandbox(["node", f"--max-old-space-size={heap}", "-e", runaway])

        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_MB * 1024 * 1024,) * 2)
        try:
            p_ = subprocess.run(cmd, capture_output=True, text=True, timeout=WALL_S, preexec_fn=limits)
            rc, err = p_.returncode, p_.stderr
        except subprocess.TimeoutExpired:
            rc, err = None, "wall timeout"
        # containment means a RESOURCE LIMIT stopped it — a finite, non-zero termination. Exhausting the
        # wall clock instead proves only that we eventually gave up: with the memory limits removed, a
        # runaway would burn the whole budget and this check would have called it contained.
        if rc is None:
            verdict = "TIMED OUT (not contained)"
            broken.append(f"a runaway allocation ran until the {WALL_S}s wall at heap={heap} MB — "
                          f"no resource limit stopped it")
        elif rc == 0:
            verdict = "ESCAPED"
            broken.append(f"a runaway allocation was NOT contained at heap={heap} MB")
        else:
            verdict = "CONTAINED"
        print(f"  heap={heap:>5} MB -> {verdict} rc={rc} stderr={'present' if err.strip() else 'EMPTY'}")
        report.setdefault("containment", {})[f"heap_{heap}"] = {"rc": rc, "stderr_present": bool(err.strip())}
        if not err.strip() and rc not in (0, None):
            report["containment"]["silent_kill_observed"] = True

    # (a2) the OUTPUT bound. A memory cap does not bound what a child PRINTS, and every ordinary fixture
    #      stays far under the ceiling — so without this case, removing `RLIMIT_FSIZE` would be invisible
    #      here while the parent quietly buffers whatever a hostile bundle emits.
    #
    #      The writer is FINITE: exactly the ceiling plus a 1 MB margin, then it exits. An endless writer
    #      was the obvious way to test this and the wrong one — with the guard removed it produced 32 GB
    #      before the wall timeout, so the safety test stopped being safe precisely when its guard broke.
    #      Bounded, both outcomes still separate cleanly: with the limit it is killed at the ceiling
    #      (`truncated`, non-zero); without it, it writes 65 MB, exits 0, and the gate fails on that.
    print("containment (a2) — the output ceiling:")
    # one 1 MiB line per megabyte of ceiling, plus one: `cap + ~1 MiB`. (Dividing the target byte count by
    # the line length floored back to exactly 64 lines — cap + 64 BYTES of margin, which distinguished the
    # mutant by luck rather than by design.)
    lines_needed = OUTPUT_MB + 1
    flood = _measure(sandbox(["node", "-e",
                              f"var s='x'.repeat(1024*1024);"
                              f"for(var i=0;i<{lines_needed};i++) console.log(s)"]))
    cap_bytes = OUTPUT_MB * 1024 * 1024
    # EXACTLY the ceiling is the signal. The kernel stops the write at the limit, so a guarded run lands
    # on `cap` to the byte; an unguarded one writes cap+1 MB and lands past it. (The exit code is NOT the
    # signal: node swallows the write error and still exits 0 when its stdout is a file.)
    ok = flood["disposition"] == "truncated" and flood["out_bytes"] == cap_bytes
    print(f"  finite writer (cap+1 MB) -> {flood['disposition']} rc={flood['rc']} "
          f"bytes={flood['out_bytes']} (cap {cap_bytes})")
    report.setdefault("containment", {})["output_flood"] = flood
    if not ok:
        broken.append(f"the output ceiling did not hold: {flood['disposition']} rc={flood['rc']} "
                      f"bytes={flood['out_bytes']} (cap {cap_bytes})")

    # (a3) the ADDRESS-SPACE bound, on allocation the heap flag does NOT cover. `--max-old-space-size`
    #      bounds the JS heap only; Buffers live outside it. Deliberately run against a SMALL limit and a
    #      BOUNDED allocation (1 GB against 512 MB) so the check trips the guard without ever putting the
    #      host under memory pressure — and so removing `RLIMIT_AS` becomes visible as a clean exit 0.
    print("containment (a3) — the address-space bound (off-heap):")
    offheap = _measure(sandbox(["node", f"--max-old-space-size={HEAP_MB}", "-e",
                                "var b=[];for(var i=0;i<16;i++){b.push(Buffer.allocUnsafe(64*1024*1024))}"]),
                       address_space_mb=512)
    print(f"  16x64 MB off-heap under a 512 MB cap -> rc={offheap['rc']} "
          f"peak_rss={offheap['peak_rss_mb']} MB")
    report.setdefault("containment", {})["offheap"] = offheap
    if offheap["rc"] in (0, None):
        broken.append("off-heap allocation was not bounded: the address-space limit did not apply "
                      f"(rc={offheap['rc']}) — the heap flag alone does not cover Buffers")

    # (b) the REFUSAL CONTRACT, ASSERTED. These two were measured and printed but could not fail the gate,
    #     so the engine's contract could change under a future lane without anyone being told. They are
    #     pinned now — including the uncomfortable one: malformed input comes back CLEAN AND EMPTY, and a
    #     lane that reads `empty` as "no chunks exist" would be wrong. If that ever changes, this fails and
    #     the change gets reviewed rather than absorbed.
    print("containment (b) — the engine's refusal contract (asserted):")
    expected = {"malformed": "empty", "absent": "engine-error"}
    malformed = Path(args.fixtures).parent / "_probe_broken.js"
    malformed.write_text("function ( { unterminated")
    try:
        checks = {"malformed": run_one(malformed, 0)}
    finally:
        malformed.unlink(missing_ok=True)
    checks["absent"] = run_one(Path(args.fixtures) / "_does_not_exist.js", 0)
    for name, r in checks.items():
        got = r["disposition"]
        mark = "as contracted" if got == expected[name] else f"CHANGED (expected {expected[name]})"
        print(f"  {name:<10} -> {got} rc={r['rc']} [{mark}] "
              f"stderr={(r['stderr'][:50] or 'EMPTY')}")
        report.setdefault("containment", {})[name] = r
        if got != expected[name]:
            broken.append(f"the engine's refusal contract changed: {name} is now {got!r}, "
                          f"not {expected[name]!r} — a lane built on the old mapping must be revisited")

    net = run_one(files[0], 0)
    probe = subprocess.run(sandbox(["node", "-e",
                                    "require('http').get('http://1.1.1.1',()=>console.log('REACHED'))"
                                    ".on('error',e=>console.log('DENIED',e.code))"]),
                           capture_output=True, text=True, timeout=30)
    reached = probe.stdout.strip()
    print(f"  network from inside the sandbox -> {reached or probe.stderr.strip()[:60]}")
    report["network_check"] = reached
    report["clean_run_after_containment"] = net["disposition"]
    if not reached.startswith("DENIED"):
        broken.append(f"the sandbox did not deny network access ({reached or 'no verdict'})")
    if net["disposition"] != "success":
        broken.append(f"a known-good fixture did not succeed under containment ({net['disposition']})")

    report["broken_invariants"] = broken

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2, default=str))
        print(f"\nwrote {args.json_out}")

    if broken:
        print("\nPROBE FAILED — the contract was not certified:", file=sys.stderr)
        for b in broken:
            print(f"  · {b}", file=sys.stderr)
        return 1
    print("\nPROBE PASSED — every fixture ended cleanly and containment held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
