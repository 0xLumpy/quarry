"""Phase 5: crawl + URL/archive + JS mining.

katana + gau + waymore -> url corpus; JS download, beautify, dedup; jsluice urls+secrets; xnLinkFinder
over the JS dir and the waymore response dirs; source-map recovery; gitleaks + trufflehog.
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

from .. import (ast_obs, budget, cgroup, events, fetch, normalize, policy,
                registry, remainder, secrets, settings, store)
from ..contract import registered, run_contract
from ..runner import (Status, _NativeFacadeFence, _NativeFacadeOwner,
                      _finish_native_outputs, _preferred_native_fault, have,
                      native_output_current, reclassify_from_artifact,
                      run as exec_tool, skipped)
from ..runner_native import (NativeOutputAdoption, RepositoryNativeOutput,
                             prepare_native_outputs)
from ..runner_repository import RepositoryOutput

# deep-mine patterns; each findall() yields the value to store (full match or capture group).
_WS_RX = re.compile(r"\bwss?://[A-Za-z0-9.\-_/:?=&%]+", re.I)                       # ws/wss endpoint URLs
_APIBASE_RX = re.compile(r"(?:baseURL|base_url|api[_-]?base|apiUrl|API_BASE|API_URL)"
                         r"\s*[:=]\s*[\"'`]([^\"'`]+)[\"'`]", re.I)                 # API base assignments
_GQL_RX = re.compile(r"[\"'`]([^\"'`]*?/(?:graphql|gql)\b[^\"'`]*)[\"'`]", re.I)    # GraphQL endpoint paths


def _gitleaks_report(rep):
    """Findings from a gitleaks `-f json` report, or None when it is missing, unreadable or malformed."""
    try:
        if rep.exists() and rep.stat().st_size:
            data = json.loads(rep.read_text() or "[]")
            if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                return data
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    return None


def _gitleaks_status(r, rep):
    """Validate the report, set `r.status` from it, and return the validated findings or None."""
    if r.status == Status.SKIPPED:
        return None                                        # never ran -> no report to ingest
    items = _gitleaks_report(rep) if native_output_current(r, rep) else None
    reclassify_from_artifact(r, None if items is None else len(items), label="gitleaks")
    return items


def _deep_mine(ctx, files, tag: str) -> int:
    """Extract GraphQL / WebSocket / API-base endpoints from JS / recovered source. Tag-only, no fetch."""
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
            # a host first seen only via a crawl link is a real discovery, and without this it
            # never reaches the takeover/CNAME analysis. Dedups on host in the store.
            if host:
                ctx.run.add("subdomain", {"host": host, "sources": [source]})
    return n


def _synthetic(ctx, tool, lines, note="", status=Status.SUCCESS):
    ctx.run.record("crawl", type("R", (), {
        "tool": tool, "status": status, "exit_code": 0, "duration": 0.0,
        "stdout_lines": lines, "note": note, "cmd": [tool], "stderr_tail": ""})())


def _jsluice_run(ctx, sub, files, raw, origin):
    """Run `jsluice <sub> -j` per file through the runner. Returns (concatenated stdout, overall Status).

    A chunk that ends in any non-clean status is degraded and makes the whole source partial; a file with
    nothing to mine is empty, not degraded. One slow file times out only itself.
    """
    # Only the two registered jsluice lanes are valid.  Keeping this finite mapping local makes the
    # source identity explicit at the runner boundary instead of deriving authority from a basename.
    sid = {"urls": "crawl.jsluice_urls", "secrets": "crawl.jsluice_secrets"}.get(sub)
    if sid is None:
        raise ValueError(f"unknown jsluice lane: {sub!r}")
    events.tool_start(sid, cmd=["jsluice", sub, "-j"], input_total=len(files), discovery_context=origin)
    t0 = time.monotonic()
    degraded = 0
    aggregate = RepositoryOutput.publish(*raw.relative_to(ctx.run.dir).parts)
    written = 0
    with ctx.run.artifact_claim(*aggregate.components) as aggregate_claim:
        aggregate_fd = aggregate_claim.open_writer()
        try:
            for i, f in enumerate(files, 1):
                # Each invocation owns an immutable, independently useful artifact.  The aggregate is
                # assembled through a separate repository claim; no reusable ambient scratch name is
                # overwritten or unlinked between executions.
                chunk = raw.with_name(f"{raw.stem}.chunk-{uuid.uuid4().hex}.jsonl")
                res = exec_tool(
                    "jsluice", ["jsluice", sub, "-j"],
                    repository=ctx.run,
                    stdout=RepositoryOutput.publish(*chunk.relative_to(ctx.run.dir).parts),
                    stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
                    stdin_data=f.read_bytes().decode("utf-8", "replace"),
                    source_id=sid,
                )
                if res.status not in (Status.SUCCESS, Status.EMPTY):
                    degraded += 1
                    events.coverage_partial(sid, reason=f"{f.name}: {res.status.value}")
                if res.raw_path:
                    payload = res.raw_path.read_bytes()
                    view = memoryview(payload)
                    while view:
                        count = os.write(aggregate_fd, view)
                        if count <= 0:
                            raise OSError("jsluice aggregate write made no progress")
                        written += count
                        view = view[count:]
                events.tool_progress(
                    sid, current_index=i, input_total=len(files), artifact_size=written,
                )
        finally:
            os.close(aggregate_fd)
        aggregate_claim.publish()
    size = written
    status = Status.PARTIAL if degraded else Status.SUCCESS
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded}/{len(files)} file(s) degraded" if degraded else None),
                       duration=round(time.monotonic() - t0, 2),
                       raw_ref=str(raw), artifact_size=size, discovery_context=origin)
    return (raw.read_text(encoding="utf-8", errors="replace") if raw.exists() else ""), status


JS_BEAUTIFY_TIMEOUT = 60          # per-file cap on a local reformat


def _beautify_run(ctx, files, builder, expected_entries):
    """Beautify JS per file through the runner. Returns (beautified_ok, degraded, overall Status).

    Each clean formatter stdout is a unique retained repository artifact.  The
    enclosing TREE transaction remains claimed across execution and copies the
    authenticated artifact into its private generation.  A degraded formatter
    falls back to the immutable ledger source.
    """
    sid = "crawl.js_beautify"
    events.tool_start(sid, cmd=["js-beautify"], input_total=len(files), discovery_context="js")
    t0 = time.monotonic()
    degraded = ok = 0
    cpu_total = 0.0
    rss_peak = 0.0
    for i, f in enumerate(files, 1):
        output = ctx.run.raw_path(
            "crawl", "js-beautify",
            f"{f.stem}-{uuid.uuid4().hex}.beauty.js",
        )
        try:
            res = exec_tool("js-beautify", ["js-beautify", str(f)],
                            repository=ctx.run,
                            stdout=RepositoryOutput.publish(
                                *output.relative_to(ctx.run.dir).parts,
                            ),
                            stderr=RepositoryOutput.discard(), timeout=JS_BEAUTIFY_TIMEOUT,
                            source_id="crawl.js_beautify")
        except Exception:
            res = None
        cpu_total += getattr(res, "cpu_s", 0.0) or 0.0
        rss_peak = max(rss_peak, getattr(res, "peak_rss_mb", 0.0) or 0.0)
        complete = bool(
            res is not None
            and res.status in (Status.SUCCESS, Status.EMPTY)
            and res.raw_path == output
            and native_output_current(res, output)
        )
        chosen = output if complete else f
        evidence = builder.copy_repository_file(
            tuple(chosen.relative_to(ctx.run.dir).parts), f.name,
        )
        expected_entries[evidence.components] = (
            False, evidence.size, evidence.sha256,
        )
        if complete:
            ok += 1
        else:
            degraded += 1
            reason = res.status.value if res is not None else "exception"
            events.coverage_partial(sid, reason=f"{f.name}: {reason}")
        events.tool_progress(sid, current_index=i, input_total=len(files))
    status = Status.PARTIAL if degraded else Status.SUCCESS
    dur = round(time.monotonic() - t0, 2)
    events.tool_finish(sid, status=status.value,
                       reason=(f"{degraded}/{len(files)} file(s) degraded" if degraded else None),
                       duration=dur, discovery_context="js")
    # record an aggregate result so the manifest/metrics can explain resource use + degradation
    ctx.run.record("crawl", type("R", (), {
        "tool": "js-beautify", "status": status, "exit_code": None, "duration": dur,  # synthetic multi-proc: no single exit code
        "stdout_lines": ok, "cmd": ["js-beautify"], "stderr_tail": "",
        "note": f"{ok}/{len(files)} beautified" + (f", {degraded} degraded" if degraded else ""),
        "cpu_s": round(cpu_total, 2), "peak_rss_mb": round(rss_peak, 1)})())
    return ok, degraded, status


def _owned_tree(ctx, destination: Path, build) -> bool:
    """Build and atomically publish one canonical tree under native authority."""
    if type(ctx.run) is not store.Run:
        return False
    components = destination.relative_to(ctx.run.dir).parts
    command = ("quarry-owned-tree", str(destination))
    policy = RepositoryNativeOutput.tree(((1, ()),), *components)
    owner = _NativeFacadeOwner(NativeOutputAdoption())
    operation_fault = None
    finish_fault = None
    built = False
    try:
        with _NativeFacadeFence(owner):
            with _NativeFacadeFence(owner):
                owner.transaction = prepare_native_outputs(
                    ctx.run, command, (policy,), adoption=owner.adoption,
                )
                builder = owner.transaction.open_tree_builder(0)
                expectation = build(builder)
                built = bool(
                    type(expectation) is tuple
                    and len(expectation) == 4
                    and type(expectation[0]) is bool
                    and type(expectation[1]) is int
                    and type(expectation[2]) is int
                    and type(expectation[3]) is str
                    and expectation[0]
                    and expectation[1] >= 0
                    and expectation[2] >= 0
                )
                build_receipt = builder.seal() if built else None
                built = bool(
                    build_receipt is not None
                    and build_receipt.sealed
                    and build_receipt.cleanup_settled
                    and build_receipt.directories == expectation[1]
                    and build_receipt.files == expectation[2]
                    and build_receipt.sha256 == expectation[3]
                )
                owner.receipt, finish_fault = _finish_native_outputs(
                    owner.transaction, owner.adoption, clean=built,
                )
    except BaseException as exc:
        operation_fault = exc
    fault = _preferred_native_fault(
        operation_fault, finish_fault, owner.cleanup_fault,
    )
    if fault is not None and not isinstance(fault, Exception):
        raise fault
    receipt = owner.receipt
    committed = () if receipt is None else receipt.committed
    current = bool(
        built
        and fault is None
        and receipt is not None
        and receipt.clean
        and len(committed) == 1
        and committed[0].components == tuple(components)
        and committed[0].present
    )
    if not current and fault is not None:
        ctx.echo(
            f"    could not publish {destination.name}: "
            f"{type(fault).__name__}"
        )
    return current


def _expected_tree_digest(entries) -> str:
    """Digest an exact expected TREE manifest using the native tree domain."""
    digest = hashlib.sha256()
    digest.update(b"quarry-native-tree-v1\0")
    for suffix, (directory, size, file_digest) in sorted(entries.items()):
        path = "/".join(suffix).encode("utf-8")
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(b"d" if directory else b"f")
        digest.update(size.to_bytes(8, "big"))
        if file_digest is not None:
            digest.update(bytes.fromhex(file_digest))
    return digest.hexdigest()


def _katana_scope_flags(scope) -> list[str]:
    """Out-of-scope host patterns as katana `-cos` regexes, so katana never crawls an excluded host."""
    flags: list[str] = []
    for p in getattr(scope, "oos_patterns", ()):
        pat = getattr(p, "pattern", "")
        if not pat:
            continue
        if pat.startswith("^"):                     # host-start anchor -> right after scheme `://`
            pat = "://" + pat[1:]
        # a trailing `$` anchors the host end; in a URL the host ends at :/?# or end-of-string, so a path,
        # port or query would otherwise escape the exclusion entirely.
        if pat.endswith("$") and not pat.endswith("\\$"):
            pat = pat[:-1] + r"(?:[:/?#]|$)"
        # Quarry compiles out-of-scope patterns case-insensitively; carry that into RE2 with `(?i)`.
        flags += ["-cos", "(?i)" + pat]
    return flags


def _safe_srcpath(name: str) -> str:
    """Sourcemap `sources` entry -> a safe relative path (drops webpack:// etc; no traversal)."""
    n = name.split("://", 1)[-1].replace("\\", "/")
    parts = [p for p in n.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "source"


def _js_download(ctx):
    """The crawl JS-download lane: every active-allowed JS URL, host-fair, under a throughput budget,
    resumably. Returns (ledger, raw_dir).

    The ledger maps each obtained URL to the immutable raw artifact holding that URL's body; downstream
    lanes ask it rather than re-deriving a filename. Artifacts are content-addressed, so two URLs serving
    identical bytes share one file and both get an entry pointing at it.
    """
    # downloading JS is an active fetch: gate on active_allowed (scope + OOS + passive-skip) and go
    # through the shared choke point (rate pace + bounded read + off-scope-redirect guard).
    MAX_JS = 15 * 1024 * 1024      # per-item guard; bounds one file's cost, never which files
    # eligible is counted after gating: in passive mode active_allowed is empty, so there is no phantom
    # tested for URLs we will never fetch. Membership is never capped; the budget and ledger bound spend.
    eligible = [u for u in ctx.run.values("js_url")
                if ctx.scope.active_allowed(normalize.host_of_url(u))]
    raw_dir = ctx.run.dir / "raw" / "crawl" / "js_files"
    # state lives outside js_files/: that dir is scanned by the secret scanners and mined by
    # xnLinkFinder, so a ledger inside it would feed them its own URLs and sha256 digests.
    ledger = budget.Ledger(raw_dir.parent / "js_fetch.state.json", lane="crawl.js_fetch")
    js_budget = budget.Budget(budget.budget_seconds("JS_FETCH_BUDGET_S"))
    # fairness is computed over pending work only: interleaving a host's already-done URLs would delay
    # its genuinely-new remainder past the end of a bounded run.
    resumed = [u for u in eligible if ledger.has(u)]
    pending = budget.order_fairly([u for u in eligible if not ledger.has(u)],
                                  lambda u: normalize.host_of_url(u))
    attempted, obtained = len(resumed), len(resumed)     # a validated completion counts as both
    fail: dict[str, int] = {}
    persisted = True
    try:
        for u in pending:
            if js_budget.exhausted():
                break                                   # checked between items, never mid-write
            attempted += 1
            try:
                data, _final, status = fetch.scoped_get(
                    ctx, u, max_body=MAX_JS, source_id="crawl.js_fetch",
                )
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
                dest = raw_dir / (digest + ".js")        # content-addressed, on the full sha256
                if not budget.publish_bytes(dest, data, digest=digest):
                    fail["write_failed"] = fail.get("write_failed", 0) + 1
                    continue                             # never record an artifact we could not prove landed
                obtained += 1
                ledger.record(u, dest, digest=digest)    # every url gets an entry, duplicates included
            except Exception:
                fail["error"] = fail.get("error", 0) + 1
                continue
    finally:
        # a kill mid-lane must not discard completed network work; record() journals every completion.
        persisted = ledger.save()
        if not persisted:                           # persistence can fail — say so
            _persistence_gap(ctx, "crawl.js_fetch", ledger, len(eligible))
        else:
            events.coverage_partial("crawl.js_fetch", kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                                    unit="state_persisted", eligible=1, tested=1, omitted=0,
                                    reason="completion state persisted")
    # selection (did the budget stop us short?) and outcome (did the target give us what we asked for?)
    # are separate facts with separate causes, so each gets its own report.
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
    """Report that a lane's completion state could not be persisted: the work happened, but no future run
    can build on it.
    """
    ctx.echo(f"    {lane}: completion state NOT persisted"
             + (" (state file belongs to another lane)" if getattr(ledger, "foreign", False) else ""))
    events.coverage_partial(lane, kind=events.COVERAGE_TIMEOUT, measure="state_persisted",
                            unit="state_persisted", eligible=1, tested=0, omitted=1,
                            reason=(f"completion state for {eligible} item(s) could not be persisted"
                                    + (" — the state path is owned by a different lane"
                                       if getattr(ledger, "foreign", False) else "")
                                    + "; a resume will redo this lane"))


#: rounds of chunk discovery per run. A chunk can name another chunk, so this bounds the depth of that
#: traversal (0 = until no new chunk appears). It never decides which chunks are eligible.
JXSCOUT_ROUNDS = 3
#: integers the analyzer may guess when a bundle's loader concatenates an unresolvable identifier. 0 =
#: never guess: a guess is a request for a path the bundle never named, so it lives in `target.yaml`.
JXSCOUT_BRUTE_LIMIT = 0
#: the engine, installed beside its whole pinned tree (GPL-3.0, invoked as a separate program).
JXSCOUT_SHIM = "jxscout-chunks"
#: the file the shim execs, bound explicitly because the sandbox mounts an allow-list, not the host root.
JXSCOUT_ENGINE = Path.home() / ".local" / "share" / "quarry" / "jxscout-chunk-discoverer.cjs"
#: `__webpack_require__.p = "…"` — the loader's public path. The analyzer evaluates only the chunk-name
#: function, so a candidate comes back without this prefix and reading it here is what completes the URL.
_WEBPACK_PUBLIC_PATH = re.compile(r"""\.p\s*=\s*["']([^"']{0,200})["']""")


#: the analyzer's ceilings. The largest legitimate bundle needs ~931 MB, so the heap sits above that and
#: the address space above the heap; a cap under the legitimate corpus reports gaps on ordinary files.
_JXSCOUT_HEAP_MB = 2048
_JXSCOUT_ADDRESS_SPACE_MB = 4096
#: what the analyzer may write. A memory cap does not bound what a program prints, and the runner reads
#: stdout into this process, so the output is bounded in the child by a file limit.
_JXSCOUT_OUTPUT_MB = 64
#: how much of the analyzer's stderr we read back for a diagnostic. The file is bounded; our memory is
#: bounded only by reading a tail rather than the whole thing.
_JXSCOUT_STDERR_TAIL = 4096


#: everything the analyzer needs to execute, and nothing else. Read-only access to the rest of the host
#: is not enough: the sandbox has to hold even if the interpreter itself is escaped.
_JXSCOUT_RUNTIME_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ld.so.cache",
                          "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives")


def _jxscout_sandbox(cmd: list, out_file, err_file) -> list:
    """Wrap the analyzer in bwrap containment, or return [] when bwrap is absent.

    It evaluates the bundle's own chunk-name function, so the sandbox is an allow-list: the runtime, the
    pinned engine, the one input bundle and this invocation's private scratch, with no network, a cleared
    environment, and address-space / heap / output-file ceilings. Without bwrap the lane does not run.
    """
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
             "--ro-bind-try", str(JXSCOUT_ENGINE), str(JXSCOUT_ENGINE),
             "--ro-bind", str(bundle), str(bundle),           # the one input
             "--bind", scratch, scratch,                      # this call's scratch, and nothing else
             "--setenv", "NODE_OPTIONS", f"--max-old-space-size={_JXSCOUT_HEAP_MB}",
             "--setenv", "PATH", "/usr/bin:/bin",
             # the shim resolves the engine through $HOME. The variable is set; the directory is not
             # mounted — only the one engine file inside it is, so this names a path and grants nothing.
             "--setenv", "HOME", str(Path.home())]
    inner = ("ulimit -v %d; ulimit -f %d; exec %s > %s 2> %s"
             % (_JXSCOUT_ADDRESS_SPACE_MB * 1024, _JXSCOUT_OUTPUT_MB * 2048,
                " ".join(shlex.quote(c) for c in [engine] + list(cmd[1:])),
                shlex.quote(str(out_file)), shlex.quote(str(err_file))))
    return args + ["sh", "-c", inner]


def _jxscout_public_path(text: str) -> str:
    """The loader's public path, or "". Never absolute-URL and never traversal: a bundle is untrusted input,
    and either would move the fetch off the origin we resolved against.
    """
    m = _WEBPACK_PUBLIC_PATH.search(text)
    p = (m.group(1) if m else "").strip()
    if not p or "://" in p or p.startswith("//") or ".." in p:
        return ""
    return p if p.startswith("/") else "/" + p


def _jxscout_resolve(js_url: str, candidate: str, public_path: str) -> str | None:
    """The candidate's URL, resolved against the bundle that named it, or None.

    The analyzer returns what the loader computes, not a URL: the origin comes from the bundle's own URL
    (port included), the prefix from the bundle's text, and a chunk's query string is preserved.
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
    """`(candidates, disposition, result)` for one bundle, through the runner.

    The disposition is the point: a memory or output kill can be entirely silent, and the parser is
    error-tolerant, so an empty result is an answer only when the process ended cleanly — and even then
    an ambiguous one.
    """
    stem = Path(artifact).stem[:32]
    # a private scratch per invocation: with a shared output directory one bundle's evaluated code could
    # rewrite or delete another's artifacts, inside the evidence trail the sandbox exists to protect.
    with tempfile.TemporaryDirectory(prefix="quarry-jxscout-") as _scratch:
        out, err = Path(_scratch) / "out.txt", Path(_scratch) / "err.txt"
        cmd = _jxscout_sandbox([JXSCOUT_SHIM, str(artifact), str(max(0, limit))], out, err)
        if not cmd:
            return [], "no-sandbox", skipped(JXSCOUT_SHIM,
                                             "no bwrap: the analyzer EVALUATES target code, so it does "
                                             "not run uncontained")
        # through the registered source, like every other tool in this phase: a direct runner call would
        # bypass the contract's events and ledger. The work unit is the bundle's content plus the guess limit.
        wu = events.work_unit("crawl.jxscout_chunks", inputs={"bundle": str(artifact)},
                              config={"brute_limit": max(0, limit)})
        res = run_contract(
            "crawl.jxscout_chunks", cmd,
            repository=ctx.run,
            stdout=RepositoryOutput.discard(),
            stderr=RepositoryOutput.discard(), work_unit=wu, timeout=timeout,
        )
        lines: list = []
        ceiling = _JXSCOUT_OUTPUT_MB * 1024 * 1024
        at_ceiling = False
        try:
            # both files: node swallows an EFBIG write and exits 0, so a bundle that fills either stream would
            # otherwise classify as success or empty. What stdout wrote is kept; the answer is what is incomplete.
            for f in (out, err):
                if f.exists() and f.stat().st_size >= ceiling:
                    at_ceiling = True
            raw_out = out.read_bytes() if out.exists() else b""
            lines = [l.strip() for l in raw_out.decode("utf-8", "replace").splitlines() if l.strip()]
        except OSError:
            return [], "unreadable", res
        blob = b""
        if err.exists():
            try:                                    # a tail only: the file is bounded, our memory is not
                with err.open("rb") as fh:
                    fh.seek(max(0, err.stat().st_size - _JXSCOUT_STDERR_TAIL))
                    blob = fh.read(_JXSCOUT_STDERR_TAIL)   # the tail, never the whole file
            except OSError:
                blob = b""
        # published out of the private scratch into the run's evidence tree, atomically and content-bound.
        # The scratch dies with this call, so nothing the next bundle runs can reach what this one wrote.
        published = ctx.run.raw_path("crawl", "jxscout", f"{stem}.txt")
        kept = budget.publish_bytes(published, raw_out, digest=hashlib.sha256(raw_out).hexdigest())
        if blob:
            kept = budget.publish_bytes(ctx.run.raw_path("crawl", "jxscout", f"{stem}.stderr.txt"), blob,
                                        digest=hashlib.sha256(blob).hexdigest()) and kept
        res.raw_path = published if kept else None      # never name an artifact we could not prove landed
    if blob:
        # the note says how much was read, so "we only ever read the tail" is checkable rather than
        # merely asserted — the display slice would hide a full-file read otherwise.
        res.note = (res.note or "") + f" [stderr {len(blob)}B tail] " + secrets.redact(
            blob.decode("utf-8", "replace").strip()[-400:])
    if res.status is Status.TIMED_OUT:
        return [], "timeout", res
    if at_ceiling:
        # not success with fewer rows: the write was cut at the ceiling, so what else the bundle named is
        # unknown, and certifying the truncated set would report a coverage number nobody measured.
        return lines, "truncated", res
    if not kept:
        # the answer survived and its evidence did not: candidates are returned, the bundle stays owed
        return lines, "unpublished", res
    if res.exit_code == 0:
        return lines, ("success" if lines else "empty"), res
    if res.exit_code == 1:
        return [], "engine-error", res
    return [], "killed", res                        # signal / OOM — a gap, never "no chunks"


def _jxscout_coverage(stats: dict) -> None:
    """What this lane has read, cumulatively. `tested` is what produced a clean answer, and the dispositions
    accumulate across rounds.
    """
    events.coverage_partial("crawl.jxscout_chunks", kind=events.COVERAGE_TIMEOUT, measure="bundles",
                            unit="bundles", eligible=stats["eligible"], tested=stats["analysed"],
                            omitted=max(0, stats["eligible"] - stats["analysed"]),
                            reason="; ".join(f"{d}={n}" for d, n in sorted(stats["dispositions"].items()))
                                   or "no bundles analysed")


def _jxscout_chunks(ctx, ledger) -> int:
    """One round of lazy-chunk discovery over the JS already downloaded. Returns how many new `js_url`
    entities it added; the caller re-runs the fetch lane so the next round sees the new bundles.

    Quarry owns resolution, scope, rate, fetching, evidence and resume. The analyzer is a candidate
    producer and nothing else.
    """
    stats = getattr(ctx, "_jxscout_stats", None)
    if stats is None:
        stats = ctx._jxscout_stats = {"dispositions": {}, "eligible": 0, "attempted": 0, "analysed": 0}
    seen_art = getattr(ctx, "_jxscout_seen", None)
    if seen_art is None:
        seen_art = ctx._jxscout_seen = set()
    dispositions = stats["dispositions"]

    # work first, capability second: an empty eligible set is a clean zero, and a missing optional tool
    # only matters when there are bundles it would have read.
    eligible = [(u, art) for u, art in ledger.items() if art and art.suffix == ".js"]
    fresh = [(u, art) for u, art in eligible if str(art) not in seen_art]
    if not fresh:
        return 0
    stats["eligible"] += len(fresh)
    if getattr(ctx.run, "_network_policy_scope", None) is not None:
        reason = (
            "v0.3.10 network-policy boundary refuses the unsupported nested bwrap launcher "
            "for a bound Run; no analyzer subprocess was started"
        )
        ctx.run.record("crawl", skipped(JXSCOUT_SHIM, reason))
        dispositions["policy-refused"] = dispositions.get("policy-refused", 0) + len(fresh)
        seen_art.update(str(a) for _u, a in fresh)
        _jxscout_coverage(stats)
        ctx.echo(f"  jxscout chunks: refused by bound network policy — {len(fresh)} bundle(s) not analysed")
        return 0
    if not have(JXSCOUT_SHIM):
        # not the zero of a clean convergence: these bundles went unread, so the remainder is counted in
        # bundles — a supervisor reading only "0 added" would call an unrun lane a fixed point.
        ctx.run.record("crawl", skipped(JXSCOUT_SHIM, "not installed (optional)"))
        dispositions["missing-tool"] = dispositions.get("missing-tool", 0) + len(fresh)
        seen_art.update(str(a) for _u, a in fresh)
        _jxscout_coverage(stats)
        return 0
    # the engagement knob, straight from target.yaml — not a flag, not machine config.
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
            # the same fault stops every remaining bundle, so it is their disposition too: counting only
            # the one we tried would report nine of ten bundles covered when none was analysed.
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
            # provenance is the bundle that named it: a chunk nothing links to is only explicable by the
            # loader it came from, and `raw_ref` points at that artifact.
            entity = {"url": resolved, "sources": ["jxscout-chunks"], "raw_ref": str(art),
                      "discovered_from": url}
            if ctx.run.add("js_url", entity):
                added += 1
                ctx.run.add("url", dict(entity))
                if host:
                    ctx.run.add("subdomain", {"host": host, "sources": ["jxscout-chunks"]})
    # coverage is per disposition, because "no candidates" is not one fact: a clean empty answer, a
    # silent kill and an unreadable bundle look identical in a count.
    _jxscout_coverage(stats)
    # the console shows the lifecycle delta, the same number the manifest carries: a shared refusal
    # leaves the untouched bundles unanalysed too.
    _short = stats["eligible"] - stats["analysed"]
    ctx.echo(f"  jxscout chunks: {added} new JS URL(s) from {produced} candidate(s) "
             f"over {len(fresh)} bundle(s)" + (f" — {_short} not analysed" if _short else ""))
    return added


# ── AST analysis: collect once, interpret later ─────────────────────────────────────────────────────
#: runs under bun, fails under node; the shim carries the napi variable (see tools.yaml)
AST_SHIM = "jxscout-ast"
AST_ENGINE = Path.home() / ".local" / "share" / "quarry" / "jxscout" / "internal" / "modules" / \
    "ast-analyzer" / "ast-analyzer.js"
AST_NATIVE = AST_ENGINE.parent / "parser.linux-x64-gnu.node"
#: the wall clock for one bundle. A 27-30 MB bundle takes 93-102 s, and those are exactly the files
#: jsluice gives up on, so a wall under them drops the matches this analyzer exists to find.
_AST_WALL_S = 300
#: physical memory requested per MB of bundle. Observed peaks run to 225x, so this keeps about a third
#: in hand; an under-request is not a smaller answer, the cgroup kills the analysis outright.
_AST_MEM_PER_MB = 300
_AST_MEM_FLOOR_MB = 1024
#: the configured maximum for one invocation. A bundle needing more is a structured gap, never a silent
#: skip; at 300x that is a ~40 MB bundle.
_AST_MEM_CEILING_MB = 12288
_AST_OUTPUT_MB = 64
_AST_ADDRESS_SPACE_MB = 65536              # a secondary guard: address space is not the production cap


def _ast_engine_digest() -> str:
    """The executable's identity — analyzer bundle and native parser — computed when the lane runs, so an
    install that replaces the engine is a different identity.
    """
    h = hashlib.sha256()
    for f in (AST_ENGINE, AST_NATIVE):
        try:
            h.update(f.read_bytes())
        except OSError:
            h.update(b"absent:" + str(f).encode())
    return h.hexdigest()


def _ast_identity(bundle_digest: str, engine: str, mem_mb: int) -> dict:
    """Everything that can change what the analysis says. An input left out here silently resumes as done."""
    return {"bundle": bundle_digest, "engine": engine, "wall_s": _AST_WALL_S,
            "mem_request_mb": mem_mb, "output_ceiling_mb": _AST_OUTPUT_MB,
            "address_space_mb": _AST_ADDRESS_SPACE_MB}


def _ast_mem_request_mb(size_bytes: int) -> int:
    """What this bundle is allowed to use, in physical memory."""
    return max(_AST_MEM_FLOOR_MB, int(_AST_MEM_PER_MB * (size_bytes / (1 << 20))))


def _ast_headroom_mb() -> int:
    """MemAvailable, for admission only: admission does not guarantee the memory (another process can take
    it a moment later), so the cgroup remains the enforcement boundary.
    """
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _ast_command(bundle: Path, out: Path, err: Path, peak: Path, mem_mb: int, scratch: Path,
                 unit: str) -> list:
    """The full containment, or [] when it is unavailable: a per-invocation cgroup outside as the enforcement
    boundary, an allow-list bwrap inside, output to files the child cannot overrun, and the unit's own
    `memory.peak` read while the unit still exists.
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
    """Analyse one bundle and publish its complete artifact. Returns `(disposition, result, meta)`.

    The artifact is the product: everything the analyzer emitted, immutable and content-bound. Nothing is
    normalised or named as a finding here — that is a later step, so the expensive part is paid once and
    interpreted many times.
    """
    size = artifact.stat().st_size
    want_mb = _ast_mem_request_mb(size)
    ident = _ast_identity(digest, engine, want_mb)
    key = hashlib.sha256(json.dumps(ident, sort_keys=True).encode()).hexdigest()
    meta = {"bundle_bytes": size, "mem_request_mb": want_mb, "mem_peak_mb": None,
            "wall_s": None, "engine": engine[:16], "work_key": key[:16]}
    # `run_contract` emits the work unit as evidence but skips nothing, so the lane keeps its own
    # completion ledger, keyed on the full identity: a new engine or policy is new work.
    if ledger is not None and ledger.has(key):
        prior = ledger.artifact(key)
        if prior and prior.exists():
            meta["artifact"] = str(prior)
            return "resumed", None, meta
    if want_mb > _AST_MEM_CEILING_MB:
        # a gap with a number attached, not a silent skip: the bundle needs more than the configured
        # maximum for one invocation.
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
            res = run_contract(
                "crawl.jxscout_ast", cmd,
                repository=ctx.run,
                stdout=RepositoryOutput.discard(),
                stderr=RepositoryOutput.discard(),
                work_unit=wu, timeout=_AST_WALL_S + 30,
            )
        finally:
            # always: a timeout kills the systemd-run client, never the service it started.
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
            # one JSON document: a cut is not a shorter answer but an unparseable one, so there is no
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
        # the path carries the work identity, not just the bundle: two runs under different engines or
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


def _ast_corroboration(ctx) -> dict:
    """`{path key: [sources that already have it]}` — who corroborates each path.

    Corroboration is confidence; it is deliberately not part of what the analyzer added, which is about
    the paths nobody else found.
    """
    seen: dict = {}
    for entity in ("url", "js_url", "endpoint"):
        for rec in ctx.run.read(entity):
            if not isinstance(rec, dict):
                continue
            k = ast_obs.path_key(str(rec.get(store.ENTITY_KEYS.get(entity, "value"), "")))
            if not k:
                continue
            names = seen.setdefault(k, [])
            for s in (rec.get("sources") or []):
                if isinstance(s, str) and s not in names:
                    names.append(s)
    return {k: sorted(v) for k, v in seen.items()}


def _ast_normalise(ctx, artifact: Path, bundle: Path, digest: str, url: str, corroborated: set) -> tuple:
    """Turn one published artifact into observations. Returns `(added, total, error, sinks)`.

    Every readable observation is normalised — the analysis is already paid for. Nothing here is
    promoted, requested or named as a finding.
    """
    try:
        doc = json.loads(artifact.read_text("utf-8", "replace"))
    except (OSError, ValueError):
        return 0, 0, "unreadable-artifact", 0
    if not isinstance(doc, list):
        return 0, 0, "unreadable-artifact", 0
    lines: dict = {}

    def context(m):
        # one validator for every consumer (`ast_obs.position`): a hostile or simply broken artifact can
        # carry `true` or a dict where a number belongs, and `bool` is an int in Python.
        ln, col = ast_obs.position(m.get("start"))
        if ln is None:
            return ""
        col = col or 0
        if not lines:
            try:
                with bundle.open("r", encoding="utf-8", errors="replace") as fh:
                    for n, text in enumerate(fh, 1):
                        lines[n] = text
            except OSError:
                lines[0] = ""
        text = lines.get(ln, "")
        return text[max(0, col - 120): col + 120].strip()

    try:
        recs = ast_obs.observations(doc, bundle=bundle.name, bundle_digest=digest, bundle_url=url,
                                    artifact=str(artifact), corroborated=corroborated, context=context)
        # the same artifact, read once for both families: sources and sinks are a different kind of
        # evidence from paths, but re-reading the file to split them would pay twice for one answer.
        sinks = ast_obs.sink_observations(doc, bundle=bundle.name, bundle_digest=digest,
                                          bundle_url=url, artifact=str(artifact), context=context)
    except (TypeError, ValueError, OSError):
        # a malformed record is a gap in one bundle, not a crash — and the shape must match the promise,
        # or the caller dies unpacking it instead of recording the gap
        return 0, 0, "unreadable-artifact", 0
    added = sum(1 for r in recs if ctx.run.add("path_observation", r))
    # `add` is True only for a key the run had not seen: a sink in two bundles is one observation, and
    # summing per-artifact counts would report it twice while the store and the report show it once
    new_sinks = sum(1 for s in sinks if ctx.run.add("sink_observation", s))
    return added, len(recs), "", new_sinks


def _ast_bundles(ctx, ledger) -> int:
    """Analyse every eligible bundle once and publish its artifact. Returns the number published.

    The work unit is (bundle content digest, engine digest, policy), so a re-run skips what already
    landed and resumes the rest. One bundle at a time: two 30 MB bundles want 10.6 GB of real memory
    between them, and this lane's job is collection, not speed.
    """
    stats = getattr(ctx, "_ast_stats", None)
    if stats is None:
        stats = ctx._ast_stats = {"eligible": 0, "published": 0, "dispositions": {}, "peaks": [],
                                  "observations": 0, "distinct": 0, "sinks": 0, "normalised": 0,
                                  "unnormalised": 0}
    engine = _ast_engine_digest()
    disp = stats["dispositions"]
    seen = getattr(ctx, "_ast_seen", None)
    if seen is None:
        seen = ctx._ast_seen = set()

    # work first, capability second: an absent optional tool with no JS to read is a clean zero, not a
    # dependency failure.
    eligible = [(u, a) for u, a in ledger.items() if a and a.suffix == ".js" and str(a) not in seen]
    if not eligible:
        return 0
    stats["eligible"] += len(eligible)
    if getattr(ctx.run, "_network_policy_scope", None) is not None:
        reason = (
            "v0.3.10 network-policy boundary refuses the unsupported systemd-run launcher "
            "for a bound Run; no analyzer subprocess was started"
        )
        ctx.run.record("crawl", skipped(AST_SHIM, reason))
        disp["policy-refused"] = disp.get("policy-refused", 0) + len(eligible)
        seen.update(str(a) for _u, a in eligible)
        _ast_coverage(ctx, stats)
        ctx.echo(f"  ast analysis: refused by bound network policy — {len(eligible)} bundle(s) not analysed")
        return 0
    if not have(AST_SHIM):
        ctx.run.record("crawl", skipped(AST_SHIM, "not installed (optional)"))
        disp["missing-tool"] = disp.get("missing-tool", 0) + len(eligible)
        seen.update(str(a) for _u, a in eligible)
        _ast_coverage(ctx, stats)
        return 0
    # the completion ledger lives beside the artifacts, never inside the directory a later miner walks
    state = ctx.run.raw_path("crawl", "ast", "x.json").parent.parent / "ast.state.json"
    led = budget.Ledger(state, lane="crawl.jxscout_ast")
    # what Quarry's other tools already found this run, read once: corroboration is confidence, and is
    # never counted as something the analyzer added
    corroborated = _ast_corroboration(ctx)
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
            # requested and actual, per bundle: this is what revises the memory ratio
            stats["peaks"].append({"bytes": meta["bundle_bytes"], "request_mb": meta["mem_request_mb"],
                                   "peak_mb": meta["mem_peak_mb"], "wall_s": meta.get("wall_s")})
        # `empty` and `resumed` too: a published artifact that declares nothing is a measured zero, and
        # leaving either out desynchronises the observations and artifact denominators across runs.
        if d in ("success", "empty", "resumed") and meta.get("artifact"):
            # every readable observation in the artifact. It is published and content-bound first, so an
            # interrupted normalisation re-runs from durable evidence rather than re-paying for the analysis.
            n_add, n_tot, err, n_sink = _ast_normalise(ctx, Path(meta["artifact"]), art, digest, _url,
                                                       corroborated)
            if err:
                stats["unnormalised"] += 1
                disp[err] = disp.get(err, 0) + 1
            else:
                stats["normalised"] += 1
                # what this artifact contributed: distinct paths within it, not raw matches. The raw
                # count lives per bundle in each record's `sightings`, where a consumer can sum it.
                stats["observations"] += n_tot
                stats["distinct"] += n_add              # keys this artifact contributed that were new
                stats["sinks"] += n_sink
                meta["observations"] = n_tot
        if d == "success":
            published += 1
            stats["published"] += 1
        elif d in ("empty", "resumed"):
            # a resumed bundle is covered: its artifact is on disk and content-verified, and re-analysing
            # it would pay a hundred seconds to produce the same bytes
            stats["published"] += 1
        if d == "no-containment":
            # the same refusal stops every remaining bundle, so it is their disposition too
            rest = len(eligible) - (eligible.index((_url, art)) + 1)
            if rest:
                disp[d] = disp.get(d, 0) + rest
                seen.update(str(a) for _u, a in eligible[-rest:])
            break
    # durability is part of the claim: without it coverage reports every artifact as covered while the
    # next run re-analyses all of them.
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
    ctx.echo(f"  ast analysis: {published} artifact(s), {stats['distinct']} path + {stats['sinks']} "
             f"sink observation(s) from {len(eligible)} bundle(s)"
             + (f" — {stats['eligible'] - stats['published']} not analysed" if
                stats["eligible"] - stats["published"] else ""))
    return published


def _ast_coverage(ctx, stats: dict) -> None:
    """What was read, cumulatively, and why the rest was not. `tested` counts bundles whose artifact landed."""
    events.coverage_partial("crawl.jxscout_ast", kind=events.COVERAGE_TIMEOUT, measure="bundles",
                            unit="bundles", eligible=stats["eligible"], tested=stats["published"],
                            omitted=max(0, stats["eligible"] - stats["published"]),
                            reason="; ".join(f"{d}={n}" for d, n in sorted(stats["dispositions"].items()))
                                   or "no bundles analysed")
    if stats["normalised"] or stats["unnormalised"]:
        # a distinct unit: an un-normalisable artifact is an evidence gap even when analysis succeeded, and
        # sharing "bundles" would replace that row
        events.coverage_partial("crawl.jxscout_ast", kind=events.COVERAGE_TIMEOUT, measure="observations",
                                unit="observations",
                                eligible=stats["normalised"] + stats["unnormalised"],
                                tested=stats["normalised"], omitted=stats["unnormalised"],
                                reason=f"{stats['distinct']} distinct path(s) and {stats['sinks']} "
                                       f"source/sink observation(s) from "
                                       f"{stats['observations']} bundle-path pair(s) across "
                                       f"{stats['normalised']} artifact(s)"
                                       + (f"; {stats['unnormalised']} artifact(s) could not be read back"
                                          if stats["unnormalised"] else ""))
    if stats["peaks"]:
        hi = max(stats["peaks"], key=lambda p: p["peak_mb"])
        # a distinct unit: reconciliation keeps only the latest record per (source, unit), so sharing
        # "bundles" here would replace the eligible/tested row this lane exists to publish.
        events.coverage_partial("crawl.jxscout_ast", kind=events.COVERAGE_UNKNOWN, measure="memory",
                                unit="memory",
                                reason=f"memory policy is PROVISIONAL: requested "
                                       f"{_AST_MEM_PER_MB}x bundle size, peak observed "
                                       f"{hi['peak_mb']} MB on {hi['bytes']} B "
                                       f"({round(hi['peak_mb'] / max(1, hi['bytes'] / (1 << 20)))}x) "
                                       f"over {len(stats['peaks'])} bundle(s)")


def _jxscout_traverse(ctx, ledger, raw_dir):
    """Analyse, queue, re-fetch, repeat until a round adds nothing or the round bound stops us. Returns the
    ledger/dir the later lanes read, so a chunk fetched in the last round is mined like any other bundle.
    """
    rounds = policy.limit("JXSCOUT_ROUNDS")
    rnd, owed = 0, 0
    while rounds <= 0 or rnd < rounds:
        rnd += 1
        owed = _jxscout_chunks(ctx, ledger)
        if not owed:
            break                                    # a round that adds nothing is the fixed point
        ledger, raw_dir = _js_download(ctx)
    # what this lane owes, emitted every exit so a converged traversal clears a bounded one's remainder.
    # `owed == 0` only says the last round added no URL, so rounds alone cannot express an unread bundle
    _stats = getattr(ctx, "_jxscout_stats", {}) or {}
    _disp = _stats.get("dispositions", {})
    try:
        remainder.emit(remainder.for_rounds("crawl.jxscout_chunks",
                                            stop="bound" if owed else "converged",
                                            rounds=rounds, ran=rnd, made=bool(owed)))
        # a bundle we could not analyse splits by repeat behaviour: a timeout, kill or unreadable artifact
        # is retriable, while a missing tool/sandbox and a deterministic refusal are terminal.
        _terminal: dict = {}
        _retriable = 0
        for _d, _n in _disp.items():
            if _d in ("missing-tool", "no-sandbox", "policy-refused"):
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
        # no counters: a round still producing proves another round is reachable and nothing about how
        # many remain, so an exact denominator would certify a depth nobody measured.
        events.coverage_partial("crawl.jxscout_chunks", kind=events.COVERAGE_UNKNOWN, measure="rounds",
                                unit="rounds",
                                reason=f"chunk traversal stopped by JXSCOUT_ROUNDS={rounds} while still "
                                       f"producing ({owed} newly-queued bundle(s) never analysed) — the "
                                       f"remaining depth is UNKNOWN, and a later run repeats rounds "
                                       f"1..{rounds} rather than continuing (raise it, or --unbound, to "
                                       f"reach the fixed point)")
    return ledger, raw_dir


def _js_publish_derived(ctx, ledger, raw_dir):
    """Publish the exact derived JS tree through one owned TREE transaction."""
    active = raw_dir.parent / "js_derived"
    wanted = ledger.artifacts()
    copied = 0

    def build(builder):
        nonlocal copied
        expected_entries = {}
        ordered = sorted(wanted, key=lambda path: path.name)
        if ordered and have("js-beautify"):
            ok, degraded, bstatus = _beautify_run(
                ctx, ordered, builder, expected_entries,
            )
            events.ledger(
                "crawl.js_beautify", beautified=ok, degraded=degraded,
                input_total=len(ordered), status=bstatus.value,
            )
            copied = len(ordered)
        else:
            for source in ordered:
                evidence = builder.copy_repository_file(
                    tuple(source.relative_to(ctx.run.dir).parts), source.name,
                )
                expected_entries[evidence.components] = (
                    False, evidence.size, evidence.sha256,
                )
                copied += 1
        return (
            copied == len(wanted), 0, copied,
            _expected_tree_digest(expected_entries),
        )

    published = _owned_tree(ctx, active, build)
    if not published:
        _js_mineable(ctx, eligible=len(wanted), tested=0)
        return None
    _js_mineable(ctx, eligible=len(wanted), tested=copied)
    return active


def _js_mineable(ctx, *, eligible: int, tested: int) -> None:
    """Coverage for whether every validated JS artifact is available to the miners. A tree we could not
    publish exactly means none of it is.
    """
    omitted = max(0, eligible - tested)
    events.coverage_partial("crawl.js_fetch", kind=events.COVERAGE_TIMEOUT, measure="js_mineable",
                            unit="js_mineable", eligible=eligible, tested=tested, omitted=omitted,
                            reason=(f"{omitted} validated artifact(s) not available for mining"
                                    if omitted else
                                    f"all {tested} validated artifact(s) available for mining"))


_SOURCEMAP_VERSION = 3          # the only source-map revision whose sourcesContent layout we extract


def _payload_key(label: str, ref_index: int, payload: bytes) -> str:
    """A stable, collision-resistant identity for one sourcemap payload: (origin url, reference index,
    payload digest), domain-separated.
    """
    h = hashlib.sha256()
    for part in (label.encode(), str(ref_index).encode(), payload):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()


def _sourcemap_schema(obj):
    """Validate an untrusted sourcemap: returns `(sources, contents)`, `"index_map"`, or None.

    A map must declare `version: 3` and carry string-or-null members whose `sourcesContent` lines up with
    `sources`. An index map (`sections`) is a real sourcemap we do not extract, attributed as unsupported
    rather than accepted.
    """
    if not isinstance(obj, dict):
        return None
    version = obj.get("version")
    # `type(...) is int`, not ==: bool is an int subclass and 3.0 == 3 is True, so an equality check
    # would admit `{"version": 3.0}` and `{"version": True}`.
    if type(version) is not int or version != _SOURCEMAP_VERSION:
        return None
    if "sections" in obj:                             # index map: valid spec, unsupported here
        return "index_map"
    sources, contents = obj.get("sources"), obj.get("sourcesContent")
    # `sources` is required by the spec: treating it as optional counts `{"version": 3}` and a JSON
    # error body as valid maps.
    if not isinstance(sources, list):
        return None
    if contents is not None and not isinstance(contents, list):
        return None
    # `sourcesContent` must line up with `sources`, or an extra content gets a synthetic filename.
    if contents is not None and len(contents) != len(sources):
        return None
    for member in (sources, contents or []):
        for x in member:
            if x is not None and not isinstance(x, str):
                return None                           # a non-string member makes the whole map untrusted
    return (sources, contents or [])


def _path_fingerprint(rels) -> str:
    """A stable fingerprint of an exact relative-path set. Domain-separated and length-prefixed so no
    concatenation of two paths can ever equal a third."""
    h = hashlib.sha256()
    for r in sorted(rels):
        b = r.encode()
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)
    return h.hexdigest()


def _extract_payload(text, key, builder, tally):
    """Validate one sourcemap and write its complete payload through ``builder``."""
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
    # `sourcesContent` is optional in a valid source map: its absence means "valid map, no embedded
    # source", not failed recovery. Validity is one measure, extraction another.
    tally["valid_maps"] += 1
    if not any(isinstance(c, str) and c for c in contents):
        return None
    tally["with_content"] += 1
    sub = key[:32]
    prepared: list[tuple[tuple[str, ...], bytes]] = []
    rels: list[str] = []
    directories: set[tuple[str, ...]] = set()
    try:
        for i, content in enumerate(contents):
            if not isinstance(content, str) or not content:
                continue                                         # null entries are normal and legal
            name = sources[i] if i < len(sources) else None
            # sanitizing alone collides: `../a.js`, `./a.js`, `/a.js` and `webpack:///./a.js` all reduce
            # to `a.js`, so the source index is what makes every output path unique.
            safe = _safe_srcpath(name if isinstance(name, str) and name else f"src{i}.js")
            suffix = (sub, f"{i:04d}", *Path(safe).parts)
            prepared.append((suffix, content.encode("utf-8")))
            rels.append("/".join(suffix[1:]))
            for depth in range(1, len(suffix)):
                directories.add(suffix[:depth])
    except (UnicodeError, ValueError, TypeError):
        # valid_maps is already incremented, so extraction needs its own measure — otherwise the outcome
        # report sees obtained == attempted and drops the class from its reason.
        tally["extract_fail"]["extract_error"] = tally["extract_fail"].get("extract_error", 0) + 1
        return None
    try:
        for suffix, payload in prepared:
            builder.write_bytes(payload, *suffix)
    except Exception:
        tally["extract_fail"]["extract_error"] = (
            tally["extract_fail"].get("extract_error", 0) + 1
        )
        raise
    # commit the count only once the payload finished: per-file increments would stay on the books
    # when a later error deletes the whole payload directory.
    local = len(prepared)
    tally["recovered"] += local
    tally["extracted"] += 1
    tally["directories"].update(directories)
    for directory in directories:
        tally["tree_entries"][directory] = (True, 0, None)
    for suffix, payload in prepared:
        tally["tree_entries"][suffix] = (
            False, len(payload), hashlib.sha256(payload).hexdigest(),
        )
    # a count is not containment — a planted symlink leaves it unchanged — so the manifest is the exact
    # set of relative paths, fingerprinted, and verification refuses any symlink inside a payload.
    tally["manifest"][sub] = (local, _path_fingerprint(rels))
    return sub


def _sourcemap_recover_build(ctx, js_ledger, builder, obtained_js):
    """Build one recovered-source generation in an owned private tree."""
    recov_dir = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered"
    MAX_MAP = 20 * 1024 * 1024     # per-item guard
    live_subdirs: set = set()      # map subdirs backed by a payload this run; everything else is pruned
    tally = {"valid_maps": 0, "with_content": 0, "extracted": 0, "recovered": 0,
             "parse_fail": {}, "extract_fail": {}, "manifest": {}, "directories": set(),
             "tree_entries": {}}
    map_urls: set = set()          # in-scope http(s) .map candidates (for the review queue)
    inline_n, inline_fail = 0, {}  # data: URIs are candidates too, and must be accounted for
    payload_n = 0                  # every payload we actually looked at (inline + resumed + fetched)
    m_att = m_got = 0
    m_fail: dict = {}
    map_budget = budget.Budget(budget.budget_seconds("SOURCEMAP_BUDGET_S"))
    map_persisted = True
    if obtained_js:
        import base64
        from urllib.parse import urljoin
        js_read_ok, js_read_fail = 0, 0
        for u, art in obtained_js:
            try:
                text = art.read_text(errors="replace")
            except OSError:
                # this lane cannot refetch JS, so it reports the inspection gap: skipping silently would
                # report a clean 0/0, indistinguishable from a target that simply has no sourcemaps.
                js_read_fail += 1
                continue
            js_read_ok += 1
            refs = [line.split("sourceMappingURL=", 1)[1].strip()
                    for line in text.splitlines() if "sourceMappingURL=" in line]
            refs.append(u.split("?")[0] + ".map")               # conventional fallback
            for ref_i, ref in enumerate(refs):
                if ref.startswith("data:"):                     # inline base64 sourcemap
                    # an inline map that fails to decode or busts the size guard is still a candidate, and
                    # must reach a measure rather than being dropped here.
                    inline_n += 1
                    try:
                        raw = base64.b64decode(ref.split(",", 1)[1])
                    except Exception:
                        inline_fail["decode_error"] = inline_fail.get("decode_error", 0) + 1
                        continue
                    if len(raw) > MAX_MAP:
                        inline_fail["size_guard"] = inline_fail.get("size_guard", 0) + 1
                        continue
                    payload_n += 1                               # extract now; never accumulate the body
                    got = _extract_payload(raw.decode("utf-8", "replace"),
                                           _payload_key(u, ref_i, raw), builder, tally)
                    if got:
                        live_subdirs.add(got)
                    del raw
                else:
                    # resolved against this url, which is why the per-url loop must cover deduplicated bodies
                    m = urljoin(u, ref)
                    # fetching is active — a malicious sourceMappingURL can point off-scope.
                    if ctx.scope.active_allowed(normalize.host_of_url(m)):
                        map_urls.add(m)
            del text
        # membership is uncapped: sorted order clusters by host, so a slice would hand one alphabetically
        # early host the whole budget. Host-fair order, a budget and a ledger bound this instead.
        map_dir = ctx.run.dir / "raw" / "crawl" / "sourcemaps"
        # same reasoning as js_fetch: keep state out of any directory a scanner or miner walks
        map_ledger = budget.Ledger(map_dir.parent / "sourcemap_fetch.state.json", lane="crawl.sourcemaps")
        cache_dir = map_dir / "fetched"                          # the raw .map bodies: the ledger's artifacts
        # resumed maps: read one body at a time from its cached artifact, extract, release. An entry whose
        # artifact is gone is requeued for fetching, so it surfaces only if the re-fetch also fails.
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
            got = _extract_payload(body.decode("utf-8", "replace"), _payload_key(m, 0, body), builder, tally)
            if got:
                live_subdirs.add(got)
            del body
        # order only pending work, so a host's already-fetched history cannot push its new remainder
        # behind other hosts in a bounded run.
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
                    data, _final, status = fetch.scoped_get(
                        ctx, m, max_body=MAX_MAP,
                        source_id="crawl.sourcemaps",
                    )
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
                                           _payload_key(m, 0, data), builder, tally)
                    if got:
                        live_subdirs.add(got)
                    del data
                except Exception:
                    m_fail["error"] = m_fail.get("error", 0) + 1
                    continue
        finally:
            map_persisted = map_ledger.save()                    # persistence can fail
            if not map_persisted:
                _persistence_gap(ctx, "crawl.sourcemaps", map_ledger, len(map_urls))
            else:                                                # emit both ways, or a prior gap lingers
                events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT,
                                        measure="state_persisted", unit="state_persisted",
                                        eligible=1, tested=1, omitted=0,
                                        reason="completion state persisted")
        sm_raw = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "candidates.txt"
        sm_payload = ("\n".join(sorted(map_urls)) + "\n").encode()
        if not budget.publish_bytes(
            sm_raw, sm_payload, digest=hashlib.sha256(sm_payload).hexdigest(),
        ):
            ctx.echo("    sourcemaps: candidate evidence could not be published")
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
    if obtained_js or True:
        # validity and extraction are separate outcomes, and inline candidates that never became payloads
        # are still counted.
        budget.report_outcome("crawl.sourcemaps", measure="sourcemaps_valid",
                              attempted=payload_n + sum(inline_fail.values()),
                              obtained=tally["valid_maps"],
                              classes={**tally["parse_fail"], **inline_fail}, noun="sourcemap payload")
        budget.report_outcome("crawl.sourcemaps", measure="sourcemaps_extracted",
                              attempted=tally["with_content"], obtained=tally["extracted"],
                              classes=tally["extract_fail"], noun="sourcemap with embedded source")
    if not obtained_js:
        # no JS -> zero eligible sourcemaps. Emit zero observations anyway so the structured auto-reset
        # opens a fresh generation and a prior gap does not linger as stale.
        events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_CAP, measure="sourcemaps",
                                eligible=0, tested=0, omitted=0, reason="no JS files this run -> 0 sourcemaps")
        events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT, measure="sourcemaps_fetched",
                                eligible=0, tested=0, omitted=0, reason="no JS files this run -> 0 fetches")
        events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT, measure="js_inspected",
                                eligible=0, tested=0, omitted=0, reason="no JS files this run -> 0 inspected")
    return {
        "ready": True,
        "directories": len(tally["directories"]),
        "live_subdirs": live_subdirs,
        "tally": tally,
        "map_urls": map_urls,
        "inline_n": inline_n,
        "payload_n": payload_n,
        "m_att": m_att,
        "m_got": m_got,
        "map_persisted": map_persisted,
    }


def _sourcemap_recover(ctx, js_ledger):
    """Recover sourcemaps and publish the exact tree through native authority."""
    recov_dir = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered"
    obtained_js = list(js_ledger.items())
    state = {}

    def build(builder):
        state.update(_sourcemap_recover_build(ctx, js_ledger, builder, obtained_js))
        return (
            state["ready"], state["directories"],
            state["tally"]["recovered"],
            _expected_tree_digest(state["tally"]["tree_entries"]),
        )

    published = _owned_tree(ctx, recov_dir, build)
    if not state:
        ctx.echo("    sourcemaps: could not acquire an owned staging generation — extraction skipped")
        for measure in (
            "sourcemaps", "sourcemaps_fetched", "sourcemaps_valid",
            "sourcemaps_extracted", "js_inspected",
        ):
            events.coverage_partial(
                "crawl.sourcemaps", kind=events.COVERAGE_UNKNOWN,
                measure=measure, unit=measure,
                reason=(
                    f"no owned generation — {len(obtained_js)} JS artifact(s) "
                    "were never inspected for sourcemaps; coverage UNMEASURED"
                ),
            )
        state = {
            "live_subdirs": set(),
            "tally": {
                "valid_maps": 0, "with_content": 0, "extracted": 0,
                "recovered": 0, "parse_fail": {}, "extract_fail": {},
                "manifest": {}, "directories": set(), "tree_entries": {},
            },
            "directories": 0,
            "map_urls": set(), "inline_n": 0, "payload_n": 0,
            "m_att": 0, "m_got": 0, "map_persisted": False,
        }
    live_subdirs = state["live_subdirs"]
    tally = state["tally"]
    map_urls = state["map_urls"]
    inline_n = state["inline_n"]
    payload_n = state["payload_n"]
    m_att = state["m_att"]
    m_got = state["m_got"]
    map_persisted = state["map_persisted"]
    events.coverage_partial("crawl.sourcemaps", kind=events.COVERAGE_TIMEOUT, measure="sourcemaps_published",
                            unit="sourcemaps_published", eligible=1, tested=1 if published else 0,
                            omitted=0 if published else 1,
                            reason=(f"recovered-source tree published ({len(live_subdirs)} map(s))"
                                    if published else
                                    "recovered-source tree could NOT be published; extraction unavailable "
                                    "and the directory on disk is a stale generation"))
    # a ledger every lifecycle: event folding carries the latest one forward, so omitting it on
    # failure or empty would leave the previous generation's counts on display as current.
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
    # every xnLinkFinder input, mined together at the end of the phase under one source lifecycle.
    xnl_units: list = []
    prof, scope = ctx.profile, ctx.scope
    roots = ctx.write_list("roots.txt", prof.apex_domains)

    live_urls = ctx.run.values("live")
    targets = ctx.write_list("crawl_targets.txt",
                             [u for u in live_urls if scope.in_scope(normalize.host_of_url(u))])

    # ── active crawl (katana) + store responses for xnLinkFinder ──
    kat_resp = ctx.run.dir / "raw" / "crawl" / "katana_resp"
    kat_resp_current = False
    if not scope.passive_only and targets.stat().st_size:
        kat = ctx.run.raw_path("crawl", "katana", "katana.txt")
        # katana is network-bound, so crawl concurrency (-c) and parallel-host count (-p) come from
        # settings. The headless SPA pass below stays low: it spawns chromium.
        cmd = ["katana", "-duc", "-list", str(targets), "-jc", "-d", "2", "-kf", "all",
               "-c", str(settings.workers("katana", 10)),
               "-p", str(settings.concurrency("KATANA_PARALLELISM", 10)),
               "-timeout", "15", "-silent",
               "-srd", str(kat_resp)]   # store response dir -> mine with xnLinkFinder
        cmd += _katana_scope_flags(scope)   # never crawl an OOS sibling; rdn scope would otherwise reach it
        if prof.http_rl:
            cmd += ["-rl", str(prof.http_rl)]
        # resume: the work unit is the target-list digest plus the crawl config, so a changed target set
        # or crawl depth is a new unit.
        kat_wu = events.work_unit("crawl.katana_standard",
                                  file_digests={"targets": events.file_digest(targets)},
                                  config={"depth": 2, "jc": True, "kf": "all"})
        r = run_contract("crawl.katana_standard", cmd,
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*kat.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(),
            native_outputs=(RepositoryNativeOutput.tree(
                ((16, ()),), *kat_resp.relative_to(ctx.run.dir).parts,
            ),),
            work_unit=kat_wu, timeout=ctx.http_timeout,
        )
        ctx.run.record("crawl", r)
        kat_resp_current = native_output_current(r, kat_resp)
        if r.raw_path:
            ctx.echo(f"  katana: +{_collect_url(ctx, r.raw_path.read_text(), 'katana', str(kat))} urls")

        # headless SPA pass on JS-heavy / app hosts (memory-heavy; opt-in via MODES.HEADLESS)
        if prof.headless:
            _cap = policy.limit("SPA_CAP")
            _spa_all = sorted({u for u in targets.read_text().splitlines()
                               if any(k in u.lower() for k in
                               ("app", "portal", "dashboard", "account", "my-", "/app"))})
            spa = _spa_all if not _cap else _spa_all[:_cap]
            # MODES.HEADLESS enables headless crawling; it does not request "first 10 only", so the cap is a
            # hidden one and gates when it drops hosts. Emitted every run, so a clean rerun clears it.
            _n_spa = len(_spa_all)
            events.coverage_partial("crawl.katana_headless", kind=events.COVERAGE_CAP, measure="spa_hosts",
                                    eligible=_n_spa, tested=len(spa), omitted=_n_spa - len(spa),
                                    reason=f"headless SPA {len(spa)}/{_n_spa} app-like hosts "
                                           f"(cap {_cap or 'none'})")
            if spa:
                spa_f = ctx.write_list("spa_targets.txt", spa)
                kh = ctx.run.raw_path("crawl", "katana", "headless.txt")
                # the headless pass is its own resume unit: the SPA host set plus the headless crawl config.
                kh_wu = events.work_unit("crawl.katana_headless", inputs={"spa_hosts": spa},
                                         config={"depth": 2, "headless": True, "jc": True})
                r = run_contract("crawl.katana_headless",
                              ["katana", "-duc", "-list", str(spa_f), "-headless",
                                         "-system-chrome", "-jc", "-d", "2", "-c", "2", "-p", "1",
                                         "-timeout", "20", "-silent"] +
                                        _katana_scope_flags(scope) +   # the same OOS exclusion on the headless pass
                                        (["-rl", str(prof.http_rl)] if prof.http_rl else []),
                              repository=ctx.run,
                              stdout=RepositoryOutput.publish(*kh.relative_to(ctx.run.dir).parts),
                              stderr=RepositoryOutput.discard(),
                              work_unit=kh_wu, timeout=ctx.http_timeout)
                ctx.run.record("crawl", r)
                if r.raw_path:
                    ctx.echo(f"  katana headless SPA: +{_collect_url(ctx, r.raw_path.read_text(), 'katana-headless', str(kh))} urls")
    else:
        ctx.run.record("crawl", skipped("katana", "passive-only or no live targets"))

    # ── passive urls (gau) ──
    gau_raw = ctx.run.raw_path("crawl", "gau", "gau.txt")
    # gau reads domains from positional args or stdin, never both, and args win — so the apexes go in
    # as args and nothing is piped. The resume unit is the apex set plus the gau config.
    gau_wu = events.work_unit("crawl.gau", inputs={"apexes": sorted(prof.apex_domains)}, config={"subs": True})
    r = run_contract("crawl.gau", ["gau", "--subs", "--threads", "5"] + prof.apex_domains,
                     repository=ctx.run,
                     stdout=RepositoryOutput.publish(*gau_raw.relative_to(ctx.run.dir).parts),
                     stderr=RepositoryOutput.discard(),
                     work_unit=gau_wu, timeout=ctx.http_timeout)
    ctx.run.record("crawl", r)
    if r.raw_path:
        ctx.echo(f"  gau: +{_collect_url(ctx, r.raw_path.read_text(), 'gau', str(gau_raw))} urls")

    # ── archive URLs + responses (waymore -mode B) -> xnLinkFinder over the dir ──
    # -mode B downloads archived responses so xnLinkFinder can mine them; -oijs saves inline JS
    for d in prof.apex_domains:
        wdir = ctx.run.dir / "raw" / "crawl" / "waymore" / d
        wm = wdir / "waymore.txt"   # name xnLinkFinder auto-detects in the dir
        mode = "B" if not scope.passive_only else "U"
        # -ci d (one capture/day) and -l <cap> bound response volume; the runner timeout catches the rest.
        cmd = ["waymore", "-i", d, "-mode", mode, "-oU", str(wm), "-f", "-ci", "d", "-p", "3"]
        if mode == "B":
            cmd += ["-oR", str(wdir), "-oijs", "-l", str(prof.waymore_limit)]
        # per-apex work unit; the source_id reflects the mode (URLs vs responses), and the config binds the
        # mode and response limit so a wider-limit re-run is a new unit.
        sid = "crawl.waymore_responses" if mode == "B" else "crawl.waymore_urls"
        wu = events.work_unit(sid, inputs={"apex": d, "mode": mode},
                              config={"limit": prof.waymore_limit if mode == "B" else None, "ci": "d"})
        native_outputs = ((RepositoryNativeOutput.tree(
            ((13, ()), (6, ("waymore.txt",))),
            *wdir.relative_to(ctx.run.dir).parts,
        ),) if mode == "B" else (RepositoryNativeOutput.file(
            6, *wm.relative_to(ctx.run.dir).parts, required=False,
        ),))
        r = run_contract(
            sid, cmd,
            repository=ctx.run,
            stdout=RepositoryOutput.discard(),
            stderr=RepositoryOutput.discard(), native_outputs=native_outputs,
            work_unit=wu, timeout=ctx.http_timeout,
        )
        ctx.run.record("crawl", r)
        waymore_current = native_output_current(r, wdir if mode == "B" else wm)
        if waymore_current and wm.exists():
            _collect_url(ctx, wm.read_text(), "waymore", str(wm))
        # mine the response dir (only if responses were actually downloaded)
        if (mode == "B" and waymore_current
                and len([p for p in wdir.iterdir() if p.name != "waymore.txt"]) > 1):
            # collected, not run: every input is mined under one source lifecycle at the end of the phase, so
            # `crawl.xnlinkfinder` has one terminal instead of four competing ones.
            xnl_units.append((str(wdir), f"waymore-{d}", True))

    # ── download JS, dedup, beautify ──
    js_ledger, js_raw_dir = _js_download(ctx)

    # ── lazy chunks: bundles name JS nothing else links to. Analyse, resolve candidates, re-run the
    #    fetch lane (resumes, so only new URLs cost). A chunk can name another chunk, hence rounds. ──
    js_ledger, js_raw_dir = _jxscout_traverse(ctx, js_ledger, js_raw_dir)

    # the mineable tree is a staged generation, beautified before publication and swapped in atomically,
    # so `None` means it could not be published exactly and nothing is mined from it.
    js_derived_dir = _js_publish_derived(ctx, js_ledger, js_raw_dir)
    js_files = sorted(js_derived_dir.glob("*.js")) if js_derived_dir else []

    # the sourcemap lane reads the raw bodies — immutable, and a reformat could disturb the trailing
    # sourceMappingURL comment — and takes its URL->artifact truth from the ledger.
    recov_dir = _sourcemap_recover(ctx, js_ledger)

    # ── re-mine recovered source (jsluice + xnLinkFinder), provenance = sourcemap ──
    # None means publication failed; `is_file()` follows symlinks, so filter them at the consumers too
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
                        d = e.get("data", "")
                        basis = d or f"{e.get('kind', 'secret')}|{e.get('id', '')}"
                        # the complete value stays on the entity; `preview` is only a short recognizable
                        # form beside it, never a substitute
                        e["value"] = d
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

    # ── deep-mine: GraphQL / WebSocket / API-base over JS + recovered source ──
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
                        d = e.get("data", "")
                        basis = d or f"{e.get('kind', 'secret')}|{e.get('id', '')}"
                        # keep the value: this is local evidence for the operator who is hunting, and a masked
                        # finding has to be reconstructed from raw files before it can even be triaged.
                        e["value"] = d
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

    # ── xnLinkFinder over katana's stored responses ──
    if kat_resp_current and kat_resp.exists() and any(kat_resp.iterdir()):
        xnl_units.append((str(kat_resp), "katana-resp", False))

    # (waymore response mining happens per-apex above via -mode B + xnLinkFinder)

    # ── secret scanners on JS dir + sourcemap-recovered sources ──
    # both dirs, or a secret only in a recovered source is missed; the derived tree, not raw (immutable)
    scan_dirs = [d for d in (js_derived_dir, recov_dir)
                 if d and d.exists() and any(p.is_file() for p in d.rglob("*"))]
    if scan_dirs and have("gitleaks"):
        # `gitleaks dir <path>` writes JSON to -r and exits 1 when it finds leaks (success), so the report
        # contents classify the run; one path per invocation means one report per dir
        for sd in scan_dirs:
            rep = ctx.run.raw_path("crawl", "gitleaks",
                                   "report.json" if sd == js_derived_dir else "report-sourcemap.json")
            # gitleaks runs twice under one source_id, so each invocation needs its own work unit: the dir name
            # plus a per-file content digest, because a same-size edit must still re-scan.
            digests = {}
            for p in sorted(sd.rglob("*")):
                try:
                    if p.is_file():
                        digests[str(p.relative_to(sd))] = events.file_digest(p)
                except OSError:
                    continue
            gl_wu = events.work_unit("crawl.gitleaks", inputs={"dir": sd.name}, file_digests=digests)
            # reclassify (status-only) inside the contract so the terminal event carries the final file-output
            # status. The ingest below re-reads the report, fail-closed.
            r = run_contract("crawl.gitleaks", ["gitleaks", "dir", str(sd), "-r", str(rep), "-f", "json"],
                             repository=ctx.run,
                             stdout=RepositoryOutput.discard(),
                             stderr=RepositoryOutput.discard(),
                             native_outputs=(RepositoryNativeOutput.file(
                                 4, *rep.relative_to(ctx.run.dir).parts,
                             ),),
                             work_unit=gl_wu,
                             reclassify=lambda res: (_gitleaks_status(res, rep), res)[1],
                             ok_codes=(0, 1), timeout=ctx.http_timeout)
            items = (_gitleaks_report(rep) if native_output_current(r, rep)
                     else None)                            # authenticated findings for ingest
            for item in (items or []):
                sec = item.get("Secret", "")
                # fingerprint from the secret; fall back to rule+file+line so an empty Secret cannot
                # collapse distinct findings onto fingerprint("").
                basis = sec or f"{item.get('RuleID')}|{item.get('File')}|{item.get('StartLine')}"
                ctx.run.add("secret", {"id": f"gitleaks:{item.get('RuleID')}:{secrets.fingerprint(basis)}",
                                       "kind": item.get("RuleID"), "value": sec,
                                       "preview": secrets.mask(sec),
                                       "file": item.get("File"), "line": item.get("StartLine"),
                                       "raw_ref": str(rep),
                                       "occurrences": [{"file": item.get("File"),
                                                        "line": item.get("StartLine"),
                                                        "end_line": item.get("EndLine"),
                                                        "raw_ref": str(rep)}],
                                       "provider_record": item,
                                       "sources": ["gitleaks"]})
            ctx.run.record("crawl", r)

    if scan_dirs and have("trufflehog"):
        # `filesystem` accepts multiple paths — hand it both dirs in one pass.
        th = ctx.run.raw_path("crawl", "trufflehog", "out.jsonl")
        # TruffleHog verification is an active credential use.  The v0.3.10 boundary keeps this lane
        # offline regardless of MODES.SECRET_VERIFICATION; discovery is unaffected.
        th_cmd = ["trufflehog", "filesystem", *[str(d) for d in scan_dirs], "--json",
                  "--no-update", "--no-verification"]
        r = exec_tool(
            "trufflehog", th_cmd,
            repository=ctx.run,
            stdout=RepositoryOutput.publish(*th.relative_to(ctx.run.dir).parts),
            stderr=RepositoryOutput.discard(), timeout=ctx.http_timeout,
            source_id="crawl.trufflehog",
        )
        if prof.verify_secrets:
            r.note = (r.note + "; " if r.note else "") + (
                "v0.3.10 network-policy boundary refused online credential verification; "
                "discovery ran offline with --no-verification"
            )
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
                # fingerprint from Raw; if Raw is empty, fall back to detector + redacted + source
                # context so distinct findings do not collapse onto fingerprint("").
                basis = raw_s or f"{det}|{red}|{o.get('SourceMetadata') or ''}"
                # Every launch is offline under the v0.3.10 boundary, so a profile request for online
                # verification is recorded as not attempted rather than laundering the detector's
                # `Verified` field into a claim that credentials were checked.
                verified = None
                verification = "not_checked"
                ctx.run.add("secret", {"id": f"trufflehog:{det}:{secrets.fingerprint(basis)}",
                                       "kind": det, "value": raw_s,
                                       "preview": red or secrets.mask(raw_s),
                                       "verified": verified, "verification": verification,
                                       "raw_ref": str(r.raw_path),
                                       "occurrences": [{"raw_ref": str(r.raw_path),
                                                        "source_metadata": o.get("SourceMetadata")}],
                                       "provider_record": o,
                                       "sources": ["trufflehog"]})

    # ── xnLinkFinder: one lifecycle over every collected input, last so each input is complete ──
    _xnl_lane(ctx, xnl_units)

    # ── AST analysis (MODES.JS_AST, default off): collect once, interpret later. Last in the phase, so
    #    an observation records which incumbents already have a path. ──
    if getattr(ctx.profile, "js_ast", False):
        _ast_bundles(ctx, js_ledger)

    ctx.echo(f"  urls: {ctx.run.count('url')}  js: {ctx.run.count('js_url')}  "
             f"endpoints: {ctx.run.count('endpoint')}  params: {ctx.run.count('parameter')}  "
             f"secrets: {ctx.run.count('secret')}")


#: bump when classification or ingest meaning changes: it is part of a unit's identity, because the same
#: bytes parsed under different rules are a different result and must not be replayed as an answer.
XNL_PARSER_SCHEMA = 2
#: app-like hosts the headless SPA pass may take. A hidden cut on hosts already retained, so it gates
#: when it drops any and `--unbound` lifts it: 0 = every app-like host.
SPA_CAP = 10
XNL_MAX_INPUT = 200 * 1024 * 1024      # cap the stdin blob so a huge dir cannot blow memory
XNL_WORDLIST_LIMIT = 10 * 1024 * 1024  # -owl/-os are permutation timekillers on big input -> small only
# there is no retention cap on the mined corpus: nothing turns a stored `parameter` into a request, and
# what does spend — the A1d brute vocabulary, the wildcard candidate set — is bounded downstream.


#: one line of xnLinkFinder output. Its `-sf` scope regex is unanchored (admits `acme.com.evil.net`),
#: so the output is untrusted and re-validated against Quarry's scope before storage
XNL_ENDPOINT = "endpoint"        # an absolute URL, inside Quarry's scope
XNL_PATH = "path"                # a relative path — no host, so not contactable and not scope-checkable
XNL_SCHEMELESS = "schemeless"    # `//host/path` — a host, but its scheme is the source document's, and the
# blob destroyed which document that was. Evidence, never a contact target.
XNL_OOS = "oos"                  # an absolute URL outside scope: review evidence, never an endpoint
XNL_CREDENTIAL = "credential"    # a URL carrying userinfo: unsafe to contact, but possibly a real finding
XNL_MALFORMED = "malformed"      # not usable as a reference at all — counted, never stored as surface
XNL_IGNORED = "ignored"          # blank lines and the tool's own `<stdin>` token: not a finding, not an error

#: a potential parameter name. xnLinkFinder mines path words, JSON keys, JS variables, input names and meta
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

    The authority is parsed structurally and what gets stored is rebuilt from the parsed parts, so a
    downstream re-parse cannot disagree with the scope decision that admitted it. Refused: any scheme but
    http/https, userinfo, an unparseable authority, and a host that is not a canonical hostname.
    """
    v = raw.strip()
    # one authority: `normalize.host_of_url`, what every scope check runs through, fail-closed on a
    # non-http scheme, userinfo, an unparseable port or IPv6 literal
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
    """`(kind, value)` for one line of xnLinkFinder link output. Never raises.

    Absolute URLs are scoped by Quarry (`in_scope` and not `is_oos`) on a canonical host, not by the
    tool's substring regex. An off-scope URL is real evidence and is kept as review, but never as
    surface: `endpoint` is consumed by lanes that go on to contact things.
    """
    v = (raw or "").strip()
    if not v or v == "<stdin>":
        # ignored noise gets its own disposition, so the rejected count means what it says.
        return XNL_IGNORED, ""
    if any(ch in v for ch in "\t \x00") or len(v) > 4096:
        return XNL_MALFORMED, v               # whitespace, a NUL or an absurd length: not a link
    schemeless = v.startswith("//")
    if schemeless or _XNL_ABSOLUTE_RX.match(v):
        # a protocol-relative reference's scheme is unknown (the blob lost its document), so `https:` is a
        # parsing device only: an in-scope link keeps its verbatim `//host/...` form
        probe = ("https:" + v) if schemeless else v
        if _safe_netloc(probe) and "@" in _urlsplit(probe).netloc:
            # unsafe to contact is not the same as worthless: `user:pass@host` carries credentials someone
            # published, so it is retained verbatim as review evidence and never as surface.
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
    """`(ok, value)` for one line of xnLinkFinder param output. Never raises."""
    v = (raw or "").strip()
    if not v or v == "<stdin>":
        return False, ""
    return bool(_XNL_PARAM_RX.match(v)), v


def _xnl_wants_secrets(written: int) -> bool:
    """Whether `-os` was asked for at this input size. One authority, so "the tool wrote no secrets file"
    and "we never asked" stay distinguishable on the fresh path and on replay alike.
    """
    return written < XNL_WORDLIST_LIMIT


def _xnl_secret_row(item) -> bool:
    """Whether a row matches the `-os` row schema exactly. All four fields, or the document is not one this
    parser has a contract for.
    """
    src = item.get("sources") if isinstance(item, dict) else None
    return bool(isinstance(item, dict)
                and isinstance(item.get("type"), str) and item["type"].strip()
                and isinstance(item.get("value"), str) and item["value"].strip()
                # this lane always streams the concatenated blob on stdin, so every row carries `["<stdin>"]`.
                # A different source list is a document from a mode this parser has no contract for.
                and isinstance(src, list) and src and all(s == "<stdin>" for s in src)
                # a real occurrence count: a positive int, and `bool` is not an int here.
                and isinstance(item.get("count"), int) and not isinstance(item.get("count"), bool)
                and item["count"] >= 1)


def _xnl_secrets(ctx, tag: str, shot: tuple, *, requested: bool,
                 artifact_ref: str | None = None, carrier: dict | None = None) -> tuple:
    """Ingest xnLinkFinder's `-os` output. Returns (stored, unusable, parse_gap).

    The schema is a JSON array of `{"type": str, "value": str, "sources": [str], "count": int}`, and a
    run that finds nothing writes `[]` — so "found no secrets" and "the artifact is missing" stay
    different facts. Anything the schema does not explain is a parse gap that keeps the unit retryable.
    A discovered secret is bounty evidence and is stored verbatim: not masked, not truncated.
    """
    res = carrier if carrier is not None else _xnl_result(tag)
    state, raw = shot
    if state == "absent":
        if requested:
            # -os requested and no file written: the no-find shape is `[]`, so fail closed rather
            # than call a blind spot a zero
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
        # id from the verbatim value, so the same secret from two inputs is one row; `secrets.fingerprint`
        # is a digest, not a redaction — the value itself is stored beside it.
        ctx.run.add("secret", {"id": f"xnLinkFinder:{kind}:{secrets.fingerprint(value)}",
                               "kind": kind, "value": value, "preview": value,
                               "verified": None, "verification": "not_checked",
                               "sources": ["xnLinkFinder"], "context": f"xnLinkFinder-{tag}",
                               "raw_ref": artifact_ref,
                               "occurrences": [{"source": f"xnLinkFinder-{tag}",
                                                **({"raw_ref": artifact_ref}
                                                   if artifact_ref else {}),
                                                "reported_count": item["count"]}]})
        # counted into the carrier the moment the write returns, so a sink dying on the second secret
        # cannot report zero while the first one sits in the store.
        stored += 1
        res["secrets"] += 1
    gap = (f"{tag}: {bad}/{len(doc)} -os entries do not match the measured schema — artifact RETAINED, "
           f"unit retryable") if bad else ""
    return stored, bad, gap


def _xnl_decode(shot: tuple) -> tuple:
    """`(lines, undecodable, unreadable)` from a snapshot entry `(state, bytes)`. Decoding is per line and
    strict: a whole-file replacing decode turns invalid UTF-8 into characters that look like good values.
    """
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


def _xnl_snapshot(outs: dict, result=None) -> dict:
    """Read a unit's four artifacts once: `{key: (state, bytes)}`. The bytes that produce the entities are
    the bytes bound into the ledger, so parsing, publication and verification cannot disagree.
    """
    meta = getattr(result, "meta", None)
    legacy = result is None or not isinstance(meta, dict) or "native_outputs" not in meta
    return {
        k: (_xnl_read(outs[k]) if legacy or native_output_current(result, outs[k])
            else ("absent", b""))
        for k in ("links", "params", "secrets", "wordlist")
    }


def _xnl_lines(path) -> tuple:
    """`(lines, undecodable, unreadable)` — read tool output as bytes and decode per line, strictly.

    Absence is a legitimate zero; an artifact that exists and cannot be read is our own machinery
    failing, and `unreadable` says which happened.
    """
    # no `exists()` pre-check: it would collapse a stat/permission failure to "absent" and add a
    # check/read race. Read, then let the error say which happened.
    return _xnl_decode(_xnl_read(path))


def _xnl_read(path):
    """Read an artifact once and say what it is: `("absent"|"ok"|"unreadable", bytes)`."""
    try:
        return "ok", Path(path).read_bytes()
    except FileNotFoundError:
        return "absent", b""
    except OSError:
        return "unreadable", b""


def _xnl_state_dir(ctx):
    """Project-owned state for the lane: `<project>/recon/state/xnlinkfinder/v<schema>/`."""
    d = (Path(ctx.run.project_dir) / "recon" / "state" / "xnlinkfinder"
         / f"v{XNL_PARSER_SCHEMA}")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _xnl_engine() -> str:
    """The installed xnLinkFinder's proven identity (pipx metadata for the executable that resolves on the
    path), or "" when it cannot be proven. The engine is part of what produced the output.
    """
    try:
        tool = next((x for x in registry.load_tools() if x.bin == "xnLinkFinder"), None)
        return registry.installed_identity(tool) if tool is not None else ""
    except Exception:
        return ""                       # an unprovable engine is handled by the caller, never guessed


def _xnl_unit_identity(ctx, tag: str, spo: bool, blob_digest: str, engine: str) -> str:
    """The unit's work identity: the exact bounded input artifact, plus everything else that changes the
    output — the scope roots, `spo`, the caps and the parser schema.
    """
    if not blob_digest:
        # a unit we cannot identify is a unit we must not own: an empty digest would collapse every
        # such unit onto one identity, so mining one would own them all.
        raise ValueError(f"{tag}: input artifact could not be digested — unit has no identity")
    return events.work_unit("crawl.xnlinkfinder",
                            inputs={"tag": tag, "apexes": sorted(ctx.profile.apex_domains)},
                            file_digests={"input_blob": blob_digest},
                            config={"engine": engine, "spo": bool(spo),
                                    "input_cap": XNL_MAX_INPUT, "wordlist_limit": XNL_WORDLIST_LIMIT},
                            schema_version=XNL_PARSER_SCHEMA)


def _xnl_bundle(state_dir, wu: str) -> dict:
    """Where a unit's outputs are kept so a later run can re-ingest them."""
    return {"links": state_dir / f"{wu}_links.txt", "params": state_dir / f"{wu}_params.txt",
            "secrets": state_dir / f"{wu}_secrets.json", "wordlist": state_dir / f"{wu}_wordlist.txt"}


def _xnl_publish_bundle(ledger, state_dir, wu: str, snap: dict) -> dict:
    """Copy a unit's outputs into project state, digest-bound, and record the unit.

    Returns `{"stored", "journaled"}`. Evidence travels with the completion, so a resumed run re-ingests
    what the mining run found instead of skipping and storing nothing.
    """
    bundle = _xnl_bundle(state_dir, wu)
    manifest = {}
    for key, dst in bundle.items():
        # the bytes come from the snapshot the parser used, never a fresh read: the ledger must bind
        # exactly what produced the entities. Absence is an answer; an unreadable artifact fails here.
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
    # every one of these is a durability answer, evaluated eagerly and never short-circuited, so each
    # artifact is actually bound before the verdict is taken.
    bound = [ledger.add_evidence(wu, dst, digest=manifest[key]["digest"])
             for key, dst in bundle.items() if manifest[key]["present"]]
    recorded = bool(ledger.record(wu, man_path, digest=hashlib.sha256(raw).hexdigest()))
    return {"stored": True, "journaled": recorded and all(bound)}


def _xnl_replay_bundle(ledger, state_dir, wu: str) -> dict | None:
    """The stored outputs for an owned unit as a verified snapshot, or None when they no longer validate."""
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
        state, data = _xnl_read(path)          # one read: the verified bytes are the bytes used
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


def _repository_write_all(descriptor: int, data: bytes) -> None:
    """Write exact bytes to one descriptor retained by a repository owner."""
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("repository artifact write made no progress")
        view = view[written:]


def _xnl_artifact_claim(run: store.Run, components: tuple[str, ...]):
    """Acquire one exact repository claim; test doubles adapt this seam explicitly."""
    if type(run) is not store.Run:
        raise TypeError("XNL bounded input requires exact Run authority")
    return run.artifact_claim(*components)


def _xnl_publish_run_bytes(
    run: store.Run,
    components: tuple[str, ...],
    data: bytes,
) -> bool:
    """Publish one run-local XNL artifact through an exact artifact claim."""
    if type(run) is not store.Run or type(data) is not bytes:
        raise TypeError("XNL materialization requires exact Run bytes authority")
    try:
        with run.artifact_claim(*components) as claim:
            writer = claim.open_writer()
            _repository_write_all(writer, data)
            claim.publish()
    except Exception:
        return False
    return True


def _xnl_publish_run_absence(
    run: store.Run,
    components: tuple[str, ...],
) -> bool:
    """Commit an authenticated absence without ambiently unlinking a prior final."""
    if type(run) is not store.Run:
        raise TypeError("XNL absence requires exact Run authority")
    destination = run.dir.joinpath(*components)
    policy = RepositoryNativeOutput.file(
        1, *components, required=False,
    )
    owner = _NativeFacadeOwner(NativeOutputAdoption())
    operation_fault = None
    finish_fault = None
    try:
        with _NativeFacadeFence(owner):
            with _NativeFacadeFence(owner):
                owner.transaction = prepare_native_outputs(
                    run,
                    ("quarry-owned-absence", str(destination)),
                    (policy,),
                    adoption=owner.adoption,
                )
                owner.receipt, finish_fault = _finish_native_outputs(
                    owner.transaction, owner.adoption, clean=True,
                )
    except BaseException as exc:
        operation_fault = exc
    fault = _preferred_native_fault(
        operation_fault, finish_fault, owner.cleanup_fault,
    )
    if fault is not None and not isinstance(fault, Exception):
        raise fault
    receipt = owner.receipt
    committed = () if receipt is None else receipt.committed
    return bool(
        fault is None
        and receipt is not None
        and receipt.clean
        and len(committed) == 1
        and committed[0].components == components
        and not committed[0].present
    )


def _xnl_materialize(ctx, tag: str, snap: dict) -> None:
    """Write an owned unit's verified bytes into this run's raw tree, for the operator to inspect.

    The snapshot returned by verification is what is written here and what is ingested: verified evidence
    is immutable, and a run works on its own copy.
    """
    outs = _xnl_outputs(ctx, tag)
    for key, dst in outs.items():
        state, data = snap[key]
        components = tuple(dst.relative_to(ctx.run.dir).parts)
        if state == "ok":
            settled = _xnl_publish_run_bytes(ctx.run, components, data)
        elif state == "absent":
            settled = _xnl_publish_run_absence(ctx.run, components)
        else:
            settled = False
        if not settled:
            raise OSError(
                f"{tag}: {key} could not be materialized through repository authority",
            )


def _xnl_lane(ctx, units: list) -> None:
    """Mine every collected input under one `crawl.xnlinkfinder` lifecycle.

    One `tool_start`, one `tool_finish`, and independently identified units in between, whose state is
    project-owned, locked for the whole lifecycle, and re-ingested on every run.
    """
    if not units:
        return
    sid = "crawl.xnlinkfinder"
    if not registered(sid):
        # the registry is authoritative for execution and that authority lives in `contract`: a phase
        # asking `sources` directly would be a second copy of the same gate.
        return
    fp = events.work_unit(sid, inputs={}, config={"input_cap": XNL_MAX_INPUT},
                          schema_version=XNL_PARSER_SCHEMA)
    events.tool_start(sid, cmd=["xnLinkFinder", "(stdin)"], input_total=len(units), work_unit=fp)

    # the units are eligible whether or not the binary exists; only the mining depends on it. Checking at
    # the collection sites instead would make an uninstalled tool silent for a `tier: core` source.
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
        # one lock, held from before prune/load through save, or two runs would unlink each other's journal.
        # State creation, pruning and load are inside the boundary, so an IO error cannot end the phase.
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
        # the terminal is emitted here, saying what actually happened, before the signal continues upward:
        # computed in a `finally` it would not know the run was cancelled and would sign off clean.
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
                # without a digest there is no identity, and every such unit would collapse onto the same
                # one. Named as the input problem it is, not as a machinery failure.
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
                # replay, not skip: the stored outputs are re-ingested so this run's store holds the same
                # entities the run that mined them did. Read-only — we ingest our own copies.
                st["replayed"] += 1
                _xnl_materialize(ctx, tag, bundle)     # the verified bytes, copied for the operator
                res = _xnl_result(tag)
                st["results"].append(res)          # registered before the writes, not after them
                _xnl_ingest(ctx, tag, bundle, blob=prep["blob"], written=prep["written"],
                            replay=True, carrier=res)
                events.coverage_partial(sid, kind=events.COVERAGE_CAP, unit=f"{tag}:unit",
                                        measure="units", eligible=1, tested=1, omitted=0,
                                        reason=f"{tag}: replayed from owned evidence (same bytes)")
                continue
            run = _xnl_run(ctx, tag, prep["blob"], prep["written"], spo=spo)
            # one read of each artifact; these exact bytes parse, publish and are digest-bound.
            snap = _xnl_snapshot(run["outs"], run["result"])
            # the carrier joins the accounting before any entity is written, so a sink that raises — or a
            # cancellation — cannot leave the terminal claiming "nothing extracted" over a non-empty store.
            res = _xnl_result(tag)
            st["results"].append(res)
            _xnl_ingest(ctx, tag, snap, blob=prep["blob"], written=prep["written"], carrier=res)
            # a unit whose input was truncated by the byte cap, or whose files could not all be read, has
            # not mined everything it was given: completion needs the whole input and readable output too.
            whole_input = (prep["files_completed"] == prep["files"] and not prep["capped"]
                           and not prep["partial_files"] and not prep["unreadable_files"])
            if not engine:
                # an unprovable engine cannot be bound into the identity, so a later upgrade could not
                # invalidate this unit. Mine it, keep the evidence, own nothing.
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
                    # a failed append still leaves the completion in memory, and a later successful
                    # snapshot persists it — so this stays pending until `save()` answers.
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
            # contain an ordinary failure in one unit, and keep what the other units found: uncontained it
            # would end the phase and leave the lane's terminal claiming success.
            st["incomplete"] += 1
            st["machinery"].append(f"{tag}: {type(e).__name__}: {e}")
            events.coverage_partial(
                sid, kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:unit", measure="units",
                eligible=1, tested=0, omitted=1,
                reason=f"{tag}: our own machinery failed ({type(e).__name__}: {e})")


def _xnl_settle(sid: str, ledger, st: dict) -> None:
    """Compact the ledger and resolve every pending completion — still under the lane's lock."""
    try:
        saved = bool(ledger.save())
    except Exception as e:                          # `save()` promises a bool; a broken promise is ours
        saved = False
        st["machinery"].append(f"ledger save failed ({type(e).__name__}: {e})")
    # the durability fallback is a fallback: a successful snapshot has already answered the question, and
    # reading `durable` anyway lets a raising property fabricate machinery on a clean run.
    durable = True
    if not saved:
        try:
            durable = bool(getattr(ledger, "durable", False))
        except Exception as e:
            durable = False
            st["machinery"].append(f"ledger durability unreadable ({type(e).__name__}: {e})")
    # `durable` alone says the journal is readable, not that every completion reached it: a record that
    # failed to append leaves an older journal perfectly intact.
    st["persisted"] = saved or (durable and not st["pending"])
    # what is lost is exactly the completions that reached neither the journal nor a snapshot. The
    # fraction is over units that attempted a completion, not over every result.
    pending, attempted = len(st["pending"]), st["done"] + len(st["pending"])
    if not st["persisted"]:
        st["persist_note"] = (f"{pending}/{attempted} completion(s) reached neither the journal nor a "
                              f"snapshot — those re-mine" if durable else
                              f"the journal is unusable and the snapshot failed — {attempted} "
                              f"completion(s) from this run re-mine; units owned by an earlier snapshot "
                              f"still replay")
    for tag in st["pending"]:
        if saved:
            # the snapshot carries it, so the unit is owned and the earlier "not recorded" reading was wrong.
            # Coverage is latest per (source, unit), so this replaces the gap rather than adding a fact.
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
    """The lane's one terminal, computed from what actually happened."""
    results, machinery = st["results"], st["machinery"]
    # production is every evidence category, replayed evidence included, and it counts what the parser
    # accepted rather than what the store found new: a parameter jsluice already had is still output.
    got = sum(r["endpoints"] + r["paths"] + r["schemeless"] + r["oos"] + r["credentials"]
              + r["params"] + r["wordlist"] + r["secrets"] for r in results)
    produced = {"references": sum(r["endpoints"] + r["paths"] + r["schemeless"] + r["oos"]
                                  + r["credentials"] for r in results),
                "params": sum(r["params"] for r in results),
                "wordlist": sum(r["wordlist"] for r in results),
                "secrets": sum(r["secrets"] for r in results)}
    incomplete = st["incomplete"]
    if st["cancelled"]:
        # an interrupted lane has not covered its input, whatever it extracted first. Partial asserts
        # something was produced, so a cancellation before any ingestion is a failed lifecycle.
        status = Status.PARTIAL.value if got else Status.FAILED.value
        reason = (f"CANCELLED after {st['done'] + st['replayed']}/{len(units)} input(s)"
                  + (" — evidence KEPT" if got else " — nothing extracted")
                  + ("; " + "; ".join(machinery) if machinery else ""))
    elif st["busy"]:
        # skipped would claim we chose not to run, and losing the lock is not a choice. Zero evidence is
        # failed, as everywhere else, and the `lock` coverage gap says who bounded us.
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
        # the note always rides along, and may only make the verdict worse: turning a failed lane into a
        # partial one because its state also failed to persist would hide the first, larger fact.
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
    root = ctx.run.dir / "raw" / "crawl" / "xnLinkFinder"
    return {"links": root / f"{safe}_links.txt",
            "params": root / f"{safe}_params.txt",
            "secrets": root / f"{safe}_secrets.json",
            "wordlist": root / f"{safe}_wordlist.txt"}


def _xnl_blob(ctx, indir: str, tag: str) -> dict:
    """Build the bounded input artifact for one unit — the exact bytes that will be mined.

    That artifact is the unit's identity: it already reflects the byte cap and the path order that
    decided which bytes made it in, which a per-file digest map does not.
    """
    safe_tag = tag.replace("/", "_").replace(".", "_")
    # only stdin parses file content offline, so the dir is concatenated into a blob and streamed via
    # stdin; the copy stops exactly at the byte cap and `capped` records any omission
    blob = ctx.run.dir / "raw" / "crawl" / "xnLinkFinder" / f"{safe_tag}_input.txt"
    components = tuple(blob.relative_to(ctx.run.dir).parts)
    written = 0
    capped = False
    files_completed = 0                              # files read to EOF (honest `tested`)
    partial_files = 0                                # files cut off mid-body by the byte cap; not tested
    unreadable = 0                                   # files that raised on open/read; not tested
    files = [f for f in sorted(Path(indir).rglob("*")) if f.is_file()]
    try:
        with _xnl_artifact_claim(ctx.run, components) as claim:
            writer = claim.open_writer()
            # A leading blank line forces fileContent mode: xnLinkFinder would
            # otherwise treat http/`//` first lines as a URL list to crawl.
            _repository_write_all(writer, b"\n")
            written += 1
            for f in files:
                if written >= XNL_MAX_INPUT:
                    capped = True                        # remaining files omitted
                    break
                eof = False
                try:
                    with f.open("rb") as src:
                        while written < XNL_MAX_INPUT:
                            chunk = src.read(min(1 << 20, XNL_MAX_INPUT - written))
                            if not chunk:
                                eof = True               # read the whole file
                                break
                            _repository_write_all(writer, chunk)
                            written += len(chunk)
                        else:
                            if src.read(1):              # cap hit mid-file
                                capped = True
                                partial_files += 1
                            else:
                                eof = True
                except Exception:
                    unreadable += 1
                    continue
                if eof:
                    files_completed += 1
                if written < XNL_MAX_INPUT:
                    _repository_write_all(writer, b"\n")
                    written += 1
            claim.publish()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        written = 0
    # input coverage per tag, every run so an uncapped rerun clears it. `tested` counts files read to
    # EOF only; a capped or raised one is `omitted`. Measure is `files`, never summed with params.
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
            "digest": events.file_digest(blob) if written else ""}


def _xnl_run(ctx, tag: str, blob, written: int, *, spo: bool = False) -> dict:
    """Run the tool over one prepared blob. Returns the tool's own status and its four artifacts."""
    roots = ctx.write_list("roots.txt", ctx.profile.apex_domains)
    outs = _xnl_outputs(ctx, tag)
    out_links, out_params, out_secrets, out_wl = (outs["links"], outs["params"], outs["secrets"],
                                                  outs["wordlist"])
    # -ow is retained for the tool's own semantics; the facade rewrites every output slot to a
    # worker-private destination, so no prior final can be appended to or truncated.
    cmd = ["xnLinkFinder", "-sp", str(roots), "-sf", str(roots), "-ow",
           "-o", str(out_links), "-op", str(out_params), "-all", "-mfs", "0"]
    # -owl and -os hang for minutes on a large blob, so they run only on small input; a large dir gets a
    # derived wordlist below, and -os is covered by trufflehog/gitleaks/jsluice
    small = _xnl_wants_secrets(written)
    if small:
        cmd += ["-owl", str(out_wl), "-os", str(out_secrets)]
    if spo:
        # -spo (scope-prefix-original) is meaningful because `-sp` is always supplied above. Append it
        # after output bindings so their argv indices remain fixed across the two concrete commands.
        cmd.append("-spo")
    # always -d 0: this lane extracts from bytes we hold and requests nothing. Any depth makes
    # xnLinkFinder fetch what it extracts under its unanchored `-sf` regex, so depth is not a caller arg.
    cmd += ["-d", "0"]
    native_outputs = (
        RepositoryNativeOutput.file(
            7, *out_links.relative_to(ctx.run.dir).parts, required=False,
        ),
        RepositoryNativeOutput.file(
            9, *out_params.relative_to(ctx.run.dir).parts, required=False,
        ),
    )
    if small:
        native_outputs += (
            RepositoryNativeOutput.file(
                14, *out_wl.relative_to(ctx.run.dir).parts, required=False,
            ),
            RepositoryNativeOutput.file(
                16, *out_secrets.relative_to(ctx.run.dir).parts, required=False,
            ),
        )
    # PYTHONHASHSEED=0: xnLinkFinder dedups via list(set(...)), whose iteration order is hash-seed
    # randomized, so on link-dense input the extracted set varies run to run without a pinned seed.
    r = exec_tool(
        "xnLinkFinder", cmd,
        repository=ctx.run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.discard(),
        native_outputs=native_outputs,
        timeout=ctx.http_timeout, input_file=blob, env={"PYTHONHASHSEED": "0"},
        source_id="crawl.xnlinkfinder",
    )
    ctx.run.record("crawl", r)
    # `-ow` truncates the four artifacts at start, so a killed run leaves whatever was flushed: real
    # evidence, and not a completed extraction. Both facts travel out of here.
    extraction_complete = r.status in (Status.SUCCESS, Status.EMPTY)
    return {"status": r.status, "complete": extraction_complete, "outs": outs,
            "small": small, "result": r}


def _xnl_result(tag: str) -> dict:
    """A unit's outcome carrier, zeroed. Created before ingestion and updated as each entity lands, so an
    interruption cannot leave the terminal disagreeing with the store.
    """
    return {"tag": tag, "endpoints": 0, "paths": 0, "schemeless": 0, "oos": 0, "credentials": 0,
            "params": 0, "params_seen": 0, "params_kept": 0, "wordlist": 0, "secrets": 0,
            "unusable": 0, "undecodable": 0, "unreadable": False, "parse_gap": ""}


def _xnl_ingest(ctx, tag: str, snap: dict, *, blob=None, written: int = 0, replay: bool = False,
                carrier: dict | None = None) -> dict:
    """The parser boundary and the entity writes, over one unit's four artifacts.

    Used by the fresh path and by replay: fresh and replayed evidence owe the same contract, and a second
    implementation is how the two drift apart. Counts land in `carrier` as they happen, so an
    interruption part-way through leaves the terminal agreeing with the store.
    """
    res = carrier if carrier is not None else _xnl_result(tag)
    # ── links: untrusted output, re-validated against Quarry's scope before anything is stored. The
    # tool's own filter admits `acme.com.evil.net` and `notacme.com` for apex `acme.com`. ──
    src_tag = f"xnLinkFinder-{tag}"
    lines, undecodable, links_unreadable = _xnl_decode(snap["links"])
    # acceptance is a parser fact and novelty is a store fact, so both are counted separately: an endpoint
    # jsluice already stored would otherwise look like a line this parser rejected.
    n_ignored = n_bad_links = 0                            # local aliases for the telemetry lines below
    # the derived wordlist consumes only values this boundary accepted: these words drive an active
    # puredns brute in A1d, so a line the strict reader rejected must not contribute any.
    accepted: list = []
    res["undecodable"] += undecodable
    res["unreadable"] = res["unreadable"] or links_unreadable
    # ...and new to the store, for every category: novelty tracked for surface alone would make a re-run
    # that recorded a fresh off-scope link or credential look like it stored nothing.
    new_endpoints = new_paths = new_schemeless = new_oos = new_credential = 0
    for line in lines:
        kind, v = _xnl_classify_link(line, ctx.scope)
        if kind == XNL_ENDPOINT:
            # counted after the write returns: a line the parser accepted and the store refused as already
            # present is still production, but a write that raised never happened.
            stored = ctx.run.add("endpoint", {"value": v, "sources": [src_tag]})
            res["endpoints"] += 1
            accepted.append(v)
            new_endpoints += 1 if stored else 0
        elif kind == XNL_PATH:
            # a relative path has no host and the concatenated blob destroyed which file it came from, so
            # `origin: unbound` stops a consumer assuming it belongs to some particular site.
            stored = ctx.run.add("endpoint", {"value": v, "kind": "path", "origin": "unbound",
                                              "sources": [src_tag]})
            res["paths"] += 1
            accepted.append(v)
            new_paths += 1 if stored else 0
        elif kind == XNL_SCHEMELESS:
            # a host we may well own, but with no scheme we were told: kept verbatim and marked unbound on
            # both axes, so nothing downstream can turn it into a request.
            stored = ctx.run.add("endpoint", {"value": v, "kind": "scheme-relative", "scheme": "unbound",
                                              "origin": "unbound", "sources": [src_tag]})
            res["schemeless"] += 1
            accepted.append(v)
            new_schemeless += 1 if stored else 0
        elif kind == XNL_CREDENTIAL:
            # discovered credentials are a finding, not noise, and are kept verbatim: masking one would destroy
            # the evidence. Only Quarry's own configured credentials are redacted from telemetry.
            stored = ctx.run.add("review", {"id": f"{src_tag}:cred:{v}", "klass": "credential-in-url",
                                            "value": v,
                                            "note": f"{src_tag} extracted a URL carrying USERINFO — never "
                                                    f"contacted (the authority is ambiguous), retained "
                                                    f"verbatim as evidence",
                                            "sources": [src_tag]})
            res["credentials"] += 1
            new_credential += 1 if stored else 0
        elif kind == XNL_IGNORED:
            n_ignored += 1                     # blank lines and the tool's token: neither finding nor error
        elif kind == XNL_OOS:
            # the archive really did link there: real evidence, but not surface. `endpoint` feeds lanes that
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
                            # ignored noise is neither eligible nor omitted: it was never a candidate.
                            measure="links", eligible=len(lines) - n_ignored + undecodable,
                            tested=n_endpoints + n_paths + n_schemeless + n_oos + n_credential,
                            omitted=n_bad_links + undecodable,
                            reason=(f"{tag}: {n_endpoints} in-scope, {n_paths} relative, {n_schemeless} "
                                    f"scheme-relative, {n_oos} off-scope, {n_credential} credential-bearing "
                                    f"(evidence only); {n_bad_links} unusable, {undecodable} undecodable"
                                    + ("; LINK OUTPUT UNREADABLE" if links_unreadable else "")))

    # ── params: xnLinkFinder emits potential params, not confirmed ones; all stored as candidates,
    #    and nothing turns one into a request; the tool's own `<stdin>` token is dropped. ──
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
    # production is what was delivered; parser-seen and novelty are their own counters. Assigning the
    # parser-seen count up front would report every candidate as produced even if the first write raised.
    res["params_seen"] = n_params_seen
    res["unusable"] += n_bad_params
    # every accepted candidate is stored. Sorted so a re-run writes them in the same order (the tool's
    # -op order is set-derived and unstable); nothing is dropped.
    for v in cand:
        stored = ctx.run.add("parameter", {"value": v, "kind": "potential",
                                           "sources": [f"xnLinkFinder-{tag}"]})
        res["params"] += 1                     # delivered: the write returned (novel or already present)
        if stored:
            n_params_added += 1
            res["params_kept"] = n_params_added
    # param coverage per tag, every run: eligible = distinct potential params produced, tested = stored.
    # Nothing is dropped by policy, so `omitted` is 0; only unusable lines count as rejected.
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_CAP, unit=f"{tag}:params",
                            measure="potential_params",
                            eligible=n_params_seen, tested=n_params_seen, omitted=0,
                            reason=f"{tag}: {n_params_seen}/{n_params_seen} potential params retained "
                                   f"(no cap); {n_bad_params} rejected as unusable")

    # ── A1d vocabulary: if -owl was skipped (large input), derive a target wordlist from the mined
    #    links+params so A1d is not starved (how much is brute-forced is `vertical._target_wordlist`). ──

    # the small-input threshold decides whether to derive, from the blob size so replay and fresh agree.
    # Absence only — an unreadable artifact is each reader's own machinery verdict.
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
        # the derived vocabulary is retained whole; how much is ever brute-forced is the A1d selection's
        # decision (`vertical._target_wordlist`), not this pass's.
        derived = ("\n".join(sorted(words)) + "\n").encode()
        out_wl = _xnl_outputs(ctx, tag)["wordlist"]
        digest = hashlib.sha256(derived).hexdigest()
        if budget.publish_bytes(out_wl, derived, digest=digest):
            snap["wordlist"] = ("ok", derived) # OUR artifact now, and the bytes that will be published
        else:
            snap["wordlist"] = ("unreadable", b"")
        events.coverage_partial("crawl.xnlinkfinder",
                                reason=f"{tag}: -owl skipped ({written // (1024*1024)}MB input, timekiller) — "
                                       f"wordlist DERIVED from links/params ({len(words)}); -os skipped "
                                       f"(secrets covered by trufflehog/gitleaks/jsluice)")

    # ── ledger over all four artifacts + suspicious-empty (real input, none produced) ──
    # the wordlist is counted as strictly as every artifact: an undecodable line is rejected, not a word
    wl_lines, wl_undecodable, wl_unreadable = _xnl_decode(snap["wordlist"])
    res["unreadable"] = res["unreadable"] or wl_unreadable
    res["undecodable"] += wl_undecodable
    n_words = len([ln for ln in wl_lines if ln.strip()])
    res["wordlist"] = n_words
    # structured counters, not a reason-only event (which never reaches the verdict): these words arm an
    # active brute, so a dropped line is un-mined vocabulary and must gate. Every run, so a rerun clears.
    events.coverage_partial("crawl.xnlinkfinder", kind=events.COVERAGE_TIMEOUT, unit=f"{tag}:wordlist",
                            measure="wordlist_lines", eligible=n_words + wl_undecodable,
                            tested=n_words, omitted=wl_undecodable,
                            reason=(f"{tag}: {n_words} wordlist line(s) usable, {wl_undecodable} not valid "
                                    f"UTF-8 and DROPPED (this vocabulary drives the A1d brute)"
                                    + ("; WORDLIST OUTPUT UNREADABLE" if wl_unreadable else "")))
    n_secrets, n_secret_bad, secret_gap = _xnl_secrets(
        ctx, tag, snap["secrets"], requested=_xnl_wants_secrets(written),
        artifact_ref=str(_xnl_outputs(ctx, tag)["secrets"]), carrier=res,
    )
    # `-o`/`-op`/`-owl` are requested explicitly, and their no-find shape is an empty file, not an absent
    # one; a requested artifact that is missing is our blind spot, and the unit stays retryable
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
    # the carrier is the result: everything above wrote into it. A parse gap is retained evidence we
    # could not fully account for, so the unit stays retryable.
    return res
