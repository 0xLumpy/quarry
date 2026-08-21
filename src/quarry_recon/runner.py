"""Tool runner — executes external tools with explicit limits and a status taxonomy.

Every execution is explainable: stdout/stderr/exit/duration are captured, raw output is stored before
any parsing, and the result is classified so downstream phases never treat a failure/block/timeout as a
genuine "nothing found" (design §3).
"""
from __future__ import annotations

import json
import os
import select
import signal
import socket
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .state import Fault

try:
    import resource                              # unix-only; per-tool child CPU via getrusage delta
except ImportError:                              # pragma: no cover — non-unix fallback
    resource = None


def _rss_tree_mb(root_pid: int) -> float:
    """Proportional physical RAM (MB) of `root_pid` and all its descendants: PSS (a shared page divided
    among its sharers) from `/proc/<pid>/smaps_rollup`, else VmRSS. 0.0 on error or non-Linux."""
    try:
        parents: dict[int, int] = {}
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            parents[int(name)] = int(line.split()[1])
                            break
            except (OSError, ValueError):
                continue
        children: dict[int, list[int]] = {}
        for pid, ppid in parents.items():
            children.setdefault(ppid, []).append(pid)
        total_kb = 0
        stack, seen = [root_pid], set()
        while stack:
            p = stack.pop()
            if p in seen or p not in parents:
                continue
            seen.add(p)
            total_kb += _proc_mem_kb(p)
            stack.extend(children.get(p, []))
        return total_kb / 1024.0
    except Exception:
        return 0.0


def _proc_mem_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if line.startswith("Pss:"):
                    return int(line.split()[1])
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0

# Some tools write stray files to the current directory (gowitness's sqlite, github-subdomains'
# <domain>.txt, …), so tools run in a per-run scratch dir; all real tool I/O uses absolute paths.
_TOOL_CWD: str | None = None


def _execution_timestamp() -> str:
    """Return the parent runner's precise, timezone-aware observation time."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z",
    )


def set_tool_cwd(path) -> None:
    global _TOOL_CWD
    _TOOL_CWD = str(path) if path else None


def fresh_artifact_dir(base) -> "Path":
    """A fresh per-invocation subdirectory `base/attempt-N` — the first N whose name is free — created
    atomically, so two concurrent callers never share an attempt. For file-output tools whose result count
    is derived by globbing a directory (gowitness): a reused or pre-populated directory would let a prior
    run's artifacts inflate this attempt's count. Prior attempts are preserved as evidence."""
    base = Path(base)
    # Compatibility callers still use an ambient Path, but a path inside a
    # Run is immediately rebound to the exact repository authority.  New
    # production code should prefer ``Run.fresh_artifact_dir`` directly.
    from . import store as _store
    managed = _store.managed_run_for_artifact(base / "attempt-probe")
    if managed is not None:
        run, components = managed
        return run.fresh_artifact_dir(*components[:-1])
    base.mkdir(parents=True, exist_ok=True)
    n = 0
    while True:
        d = base / f"attempt-{n}"
        try:
            d.mkdir(exist_ok=False)                        # atomic: raises if the name is taken
            return d
        except FileExistsError:
            n += 1


def reclassify_from_artifact(r: "RunResult", n: "int | None", *, label: str = "tool") -> "RunResult":
    """Shared file-output status matrix. A file-output tool leaves an empty stdout, so the generic
    classifier mislabels it from a stderr line; the artifact is authoritative. `n` = count of validated
    results (>=0) when the artifact is a trustworthy complete result, or None when there is no trustworthy
    artifact (missing / unreadable / malformed). The caller owns the format-specific fail-closed parse and
    MUST clear the stale artifact before running the tool. Matrix:
      - SKIPPED / LIMITED           -> unchanged
      - clean (SUCCESS/EMPTY only):  n>0 -> SUCCESS · n==0 -> EMPTY · None -> PARTIAL (completion uncertain)
      - degraded (anything else — FAILED/TIMED_OUT/BLOCKED/PARTIAL): n>0 -> PARTIAL (evidence, incomplete);
        n==0 or None -> keep the original status, so a hard run is never laundered into SUCCESS/EMPTY."""
    if r.status in (Status.SKIPPED, Status.LIMITED):
        # LIMITED is a proven provider boundary and is never re-derived from an artifact: the matrix
        # would either launder it into SUCCESS or demote it to a degraded PARTIAL.
        return r
    # only a real int >= 0 is a trustworthy count: bool (an int subclass), float, str or a negative
    # reads as no trustworthy artifact, so a bad count fails closed instead of laundering the status.
    if n is not None and (isinstance(n, bool) or not isinstance(n, int) or n < 0):
        n = None
    clean = r.status in (Status.SUCCESS, Status.EMPTY)
    if n is not None:
        r.stdout_lines = n
    if n:                                              # n > 0
        r.status = Status.SUCCESS if clean else Status.PARTIAL
        r.note = f"{label}: {n} result(s)" + ("" if clean else " (degraded — scan did not complete)")
    elif clean and n is not None:                      # clean + 0 valid results
        r.status, r.note = Status.EMPTY, f"{label}: 0 results (clean)"
    elif clean:                                        # clean but no trustworthy artifact
        r.status, r.note = Status.PARTIAL, f"{label}: artifact missing/malformed — completion uncertain"
    # else: degraded + empty/absent -> keep the original (hard) status
    return r


def reclassify_from_files(r: "RunResult", produced: int, note_word: str = "item") -> "RunResult":
    """Count-based file-output adapter (gowitness screenshots, …): `produced` = artifact count. Thin
    wrapper over `reclassify_from_artifact`, so a non-empty count on a degraded run is PARTIAL."""
    return reclassify_from_artifact(r, produced, label=note_word)


def ffuf_results(out_file) -> "list | None":
    """Parse an ffuf `-o` JSON artifact into its results list, or None when there is no valid current
    artifact — missing / unreadable / JSON root not an object / `results` not a list / any non-object row.
    A caller can then distinguish "ffuf completed and served this" from "no trustworthy artifact"."""
    import json as _json
    from pathlib import Path as _Path
    if out_file is None:
        return None
    try:
        data = _json.loads(_Path(out_file).read_text() or "{}")
    except (OSError, _json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    results = data.get("results")
    if not isinstance(results, list):
        return None
    # ffuf does not emit non-object rows, so one is corruption: fail closed for the whole artifact
    # rather than ingest a subset of a broken file.
    if any(not isinstance(row, dict) for row in results):
        return None
    return list(results)


def ffuf_usable_rows(rows, validate) -> "tuple[list, int]":
    """Split structurally-valid ffuf rows into (usable, dropped_count). `validate` is a per-lane
    predicate: structural validity is not usability, and a "non-empty field" check is fail-open."""
    usable = [r for r in rows if validate(r)]
    return usable, len(rows) - len(usable)


def ffuf_http_row(row) -> bool:
    """A usable ffuf row for a URL-ingesting lane: an absolute http(s) URL whose authority parses with a
    real host and port, and an HTTP status in 100..599 (`bool` excluded — it is an int subclass)."""
    from urllib.parse import urlsplit
    u, st = row.get("url"), row.get("status")
    if not isinstance(st, int) or isinstance(st, bool) or not (100 <= st <= 599):
        return False
    if not isinstance(u, str) or len(u) > 8192:
        return False
    try:
        parts = urlsplit(u)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if parts.port is not None and not (1 <= parts.port <= 65535):
            return False
    except ValueError:                                   # urlsplit raises on a malformed port
        return False
    return True


def reclassify_ffuf(r: "RunResult", out_file, stderr_file=None, maxtime=None) -> "RunResult":
    """ffuf artifact adapter: ffuf writes hits to `-o` JSON while `-s` keeps stdout empty, so the generic
    classifier (stdout + stderr only) can't see the real result and a transport line mislabels the run. A
    valid artifact (dict root + list `results`) means ffuf reached completion; refine on it:
      - SKIPPED / LIMITED      -> unchanged
      - FAILED / TIMED_OUT     -> hard stop: findings upgrade to PARTIAL (coverage incomplete), never
                                  SUCCESS; 0 findings keeps the hard state
      - BLOCKED + hits         -> PARTIAL (any exit code — findings are evidence some paths were served)
      - BLOCKED + 0, exit 0    -> PARTIAL: a clean exit proves ffuf finished, so the block hit some
                                  request rather than the whole job
      - BLOCKED + 0, exit != 0 -> stay BLOCKED (nonzero exit + nothing served), as does a missing or
                                  invalid artifact (a real block before the write)
      - PARTIAL (transport)    -> stay PARTIAL, with or without hits
      - clean                  -> hits => SUCCESS; 0 => EMPTY
    A missing / invalid `-o` keeps the classifier verdict. Repository-native callers bind `out_file`
    through a native-output receipt; unmanaged callers remain responsible for a fresh path. Sets
    `stdout_lines` to the result count and returns the mutated RunResult."""
    if not native_output_current(r, out_file):
        out_file = None
    if r.status in (Status.SKIPPED, Status.LIMITED):
        # LIMITED is a proven provider boundary and is never re-derived from an artifact: the matrix
        # would either launder it into SUCCESS or demote it to a degraded PARTIAL.
        return r
    # ffuf hit its native -maxtime ceiling: it stops mid-wordlist, finalizes the artifact, then exits
    # clean, so demote to PARTIAL first and the matrix below can never launder a truncated run.
    _err, _full = r.stderr_tail or "", False     # the tail is 8 lines; a persisted file has it complete
    if stderr_file is not None and r.meta.get("stderr_published", True):   # never read a preserved PRIOR file
        try:
            if Path(stderr_file).is_file():
                _err, _full = Path(stderr_file).read_text(errors="replace"), True
        except OSError:
            pass
    if r.status in (Status.SUCCESS, Status.EMPTY):
        capped = "maximum running time" in _err.lower()
        if not capped and not _full and maxtime:
            # without the full text the cap notice may have been evicted from the tail, so duration
            # decides: reaching the ceiling means truncated, an early natural finish stays clean.
            capped = r.duration >= maxtime
        if capped:
            r.status = Status.PARTIAL
            r.note = ("ffuf: hit its -maxtime ceiling — run TRUNCATED, coverage incomplete"
                      + ("" if _full else " (inferred from duration; full stderr unavailable)"))
    results = ffuf_results(out_file)
    if results is None:
        # fail closed on a clean exit: `-o` is ffuf's required output, so a missing or malformed artifact
        # after a clean run means completion is unproven. A degraded status keeps its own verdict.
        if r.status in (Status.SUCCESS, Status.EMPTY):
            r.status = Status.PARTIAL
            r.note = "ffuf: -o artifact missing/malformed — completion uncertain"
        return r
    n = len(results)
    r.stdout_lines = n
    # ffuf errored or was killed: a partial artifact can only lift the run to PARTIAL, never SUCCESS.
    if r.status in (Status.FAILED, Status.TIMED_OUT):
        if n > 0:
            r.status, r.note = Status.PARTIAL, f"ffuf: {n} result(s) ({r.status.value}; coverage incomplete)"
        return r                                             # 0 findings -> keep the hard state
    if r.status == Status.BLOCKED:
        # findings prove ffuf served some paths despite the block -> PARTIAL (evidence, incomplete)
        if n > 0:
            r.status, r.note = Status.PARTIAL, f"ffuf: {n} result(s) (some blocked)"
        # with 0 findings only a clean exit proves the job completed; a nonzero exit stays fully BLOCKED
        elif r.exit_code == 0:
            r.status, r.note = Status.PARTIAL, "ffuf: block observed, 0 candidates (completed)"
        return r
    degraded = r.status == Status.PARTIAL                    # transport degradation (not a block)
    if n > 0:
        r.status = Status.PARTIAL if degraded else Status.SUCCESS
        r.note = f"ffuf: {n} result(s)" + (" (degraded coverage)" if degraded else "")
    else:
        r.note = ("ffuf: 0 results, transport-degraded (completion uncertain)" if degraded
                  else "ffuf: 0 results (clean)")
        r.status = Status.PARTIAL if degraded else Status.EMPTY
    return r


def scaled_timeout(n_units: int, floor: int, per_unit: float) -> int:
    """Workload-scaled wall-clock ceiling, not a duration: the tool exits when it finishes, so a generous
    ceiling only lets a big job complete and never slows a small one. The budget grows `per_unit` seconds
    per unit of work above `floor`, with no upper cap — scope size must never truncate coverage. Used by
    nuclei (per target), httpx (per host, port-weighted) and ffuf (per wordlist entry). `floor <= 0` means
    fully unbounded, with no kill at all."""
    if floor <= 0:
        return 0
    return max(int(floor), int(per_unit * max(int(n_units), 1)))


def nuclei_timeout(n_targets: int, floor: int, per_target: int = 240) -> int:
    """`scaled_timeout` for nuclei, whose runtime grows with target count (roughly templates × targets /
    concurrency): `floor` (the base `--timeout`) is the ceiling for small scopes and the budget grows
    `per_target` seconds per target. `floor <= 0` (`--timeout 0`) means fully unbounded."""
    return scaled_timeout(n_targets, floor, per_target)


class Status(str, Enum):
    SUCCESS = "success"     # ran clean, produced output
    EMPTY = "empty"         # ran clean, zero output (genuine nothing-found)
    PARTIAL = "partial"     # produced output but stderr shows trouble
    FAILED = "failed"       # nonzero exit
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"     # stderr matches WAF/rate-limit/forbidden signatures
    SKIPPED = "skipped"     # not run (scope/mode/missing tool/no input)
    # a limit is a clean execution that something cut short: outside `store._DEGRADED`, it feeds
    # `complete_with_limits`, and who bounded us is carried by `error_class` — not by the status.
    LIMITED = "limited"     # ran clean; a provider or operator boundary cut coverage short


# stderr signatures of a real denial — the target stopped us (WAF/rate-limit/forbidden).
BLOCK_SIGNATURES = (
    "403 forbidden", "429", "too many requests", "rate limit", "rate-limit",
    "access denied", "captcha", "cloudflare", "akamai", "web application firewall", " waf ",
)
# stderr signatures of transport degradation — the connection failed or timed out and the tool kept
# going. Degraded coverage, not a block: downgrades a clean run to PARTIAL, never to BLOCKED.
TRANSPORT_SIGNATURES = (
    "connection reset", "i/o timeout", "context deadline exceeded", "deadline exceeded",
    "connection refused", "no such host", "tls handshake", "timeout awaiting", "eof",
)


@dataclass
class RunResult:
    tool: str
    cmd: list[str]
    status: Status
    exit_code: int | None
    duration: float
    raw_path: Path | None
    stdout_lines: int
    stderr_tail: str = ""
    note: str = ""
    cpu_s: float = 0.0                 # child CPU seconds for this tool (getrusage delta)
    peak_rss_mb: float = 0.0           # peak RSS of this tool's process tree (/proc sampling)
    meta: dict = field(default_factory=dict)

    @property
    def started(self) -> bool:
        """Whether the process demonstrably started — a pid existed. Set only where a pid was obtained,
        so a missing binary, a cancelled launch or a `Popen` that raised never reads as a run."""
        return self.meta.get("started") is True

    @property
    def ok(self) -> bool:
        """Ran acceptably. LIMITED belongs here: the execution was clean and something external cut it
        short."""
        return self.status in (Status.SUCCESS, Status.PARTIAL, Status.LIMITED)


_REPOSITORY_TESTIMONY_AUTHORITY = object()


@dataclass(frozen=True, slots=True, repr=False)
class _RepositoryExecutionTestimony:
    """Opaque snapshot made only after repository execution has settled."""

    result_identity: int
    repository_identity: int
    document_json: bytes = field(repr=False)
    authority: object = field(repr=False, compare=False)


def _seal_repository_execution_testimony(result: RunResult, repository) -> None:
    """Freeze collector inputs after all publication/native cleanup is complete."""
    meta = result.meta
    fields = {
        "execution_finished_at", "execution_request_id", "execution_settlement",
        "execution_started_at", "execution_terminal",
        "native_outputs", "repository_ownership_settled", "repository_publication",
        "process_group_settled", "process_tree_settled",
        "repository_stderr_path", "repository_stdout_path",
        "runtime_identity", "runtime_identity_ref", "runtime_source_argv",
        "runtime_source_argv_indexes", "streams",
    }
    if not fields.issubset(meta):
        return
    document = {field: meta[field] for field in sorted(fields)}
    encoded = json.dumps(
        document, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", "strict")
    meta["_repository_execution_testimony"] = _RepositoryExecutionTestimony(
        result_identity=id(result), repository_identity=id(repository),
        document_json=encoded, authority=_REPOSITORY_TESTIMONY_AUTHORITY,
    )


def repository_execution_testimony(result: RunResult, *, repository) -> dict:
    """Return the runner-sealed source facts for one exact repository result.

    This is deliberately not a serialization of mutable ``RunResult.meta``.
    A collector may read the returned copy, but cannot synthesize an authority
    object or transplant one onto another result/repository pair.
    """
    if type(result) is not RunResult:
        raise TypeError("repository testimony requires an exact RunResult")
    sealed = result.meta.get("_repository_execution_testimony")
    if (type(sealed) is not _RepositoryExecutionTestimony
            or sealed.authority is not _REPOSITORY_TESTIMONY_AUTHORITY
            or sealed.result_identity != id(result)
            or sealed.repository_identity != id(repository)):
        raise ValueError("result has no sealed testimony for this repository")
    try:
        document = json.loads(sealed.document_json)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:  # pragma: no cover - private bytes
        raise ValueError("sealed repository testimony is malformed") from exc
    if sealed.document_json != json.dumps(
        document, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", "strict"):
        raise ValueError("sealed repository testimony lost canonical form")
    return document


def _preflight_argv(cmd) -> "tuple[list[str] | None, str | None]":
    """Validate and normalize argv without invoking caller-defined container/string methods.

    ``subprocess.Popen`` accepts several sequence-like shapes, but accepting arbitrary iterables here would
    let iteration or string coercion run user code before the invocation is known to be well formed. Quarry's
    contract is deliberately narrower: a concrete list/tuple of strings, with a non-empty, NUL-free executable
    and NUL-free arguments. Empty strings remain valid in argument positions after argv[0].
    """
    if type(cmd) not in (list, tuple):
        return None, "argv must be a list or tuple of strings"
    if not cmd:
        return None, "argv must contain an executable"
    for index, arg in enumerate(cmd):
        if type(arg) is not str:
            return None, f"argv[{index}] must be a string"
        if "\x00" in arg:
            return None, f"argv[{index}] contains a NUL byte"
    if not cmd[0]:
        return None, "argv[0] must be a non-empty executable"
    return list(cmd), None


def _preflight_environment(env) -> "tuple[dict[str, str] | None, str | None]":
    """Validate caller environment overrides without dispatching to caller-defined methods.

    Only an exact builtin ``dict`` containing exact builtin ``str`` keys and values is authority.  The
    base descriptor is used deliberately: even an apparently harmless ``dict``/``str`` subclass can run
    user code during telemetry, sorting, merging, or IPC normalization.
    """
    if env is None:
        return None, None
    if type(env) is not dict:
        return None, "environment must be an exact dict of strings"
    normalized: dict[str, str] = {}
    for key, value in dict.items(env):
        if type(key) is not str or type(value) is not str:
            return None, "environment keys and values must be exact strings"
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            return None, "environment contains an invalid key or value"
        normalized[key] = value
    return normalized, None


def _preflight_failure(tool: str, safe_cmd: "list[str] | None", detail: str) -> RunResult:
    """A side-effect-free, completeness-challenging invocation refusal."""
    message = f"preflight validation failed: {detail}"
    fault = Fault("machinery", where=tool, detail=message).to_dict()
    return RunResult(tool, safe_cmd or [], Status.FAILED, None, 0.0, None, 0,
                     note=message, meta={"started": False, "faults": [fault]})


_NETWORK_INPUT_UNSET = object()


def _canonical_network_hosts(values) -> tuple[str, ...]:
    """Return a bounded canonical host set without consulting ambient NSS."""
    from . import netguard, network_policy, normalize

    if (type(values) not in (tuple, list)
            or len(values) > network_policy._MAX_NETWORK_HOSTS):
        raise ValueError("network host set is not a bounded exact sequence")
    hosts = []
    for value in values:
        if type(value) is not str or not value or "\x00" in value:
            raise ValueError("network host set contains an invalid host")
        try:
            # This deliberately also rejects IPv6 zones.  It is only a parser
            # here; literals are classified below without a DNS query.
            literal = netguard.canonical_ip_set((value,))[0]
        except (TypeError, ValueError):
            literal = None
        if literal is not None:
            hosts.append(literal)
            continue
        canonical = normalize.canon_host_strict(value)
        if canonical is None:
            raise ValueError("network host set contains an invalid host")
        hosts.append(canonical)
    result = tuple(sorted(set(hosts)))
    if len(result) != len(hosts):
        raise ValueError("network host set contains duplicate canonical hosts")
    return result


def _preflight_network_inputs(network_hosts, approved_peers, *,
                              network_hosts_supplied: bool,
                              approved_peers_supplied: bool):
    """Validate exact bounded network inputs before any launch admission."""
    from . import netguard, network_policy

    try:
        hosts = _canonical_network_hosts(network_hosts)
    except (TypeError, ValueError) as exc:
        return (), (), f"network host set is invalid ({type(exc).__name__})"
    if (type(approved_peers) not in (tuple, list)
            or len(approved_peers) > network_policy._maximum_effective_cidrs):
        return (), (), "approved peer set is not a bounded exact sequence"
    try:
        approved = netguard.canonical_ip_set(approved_peers)
    except (TypeError, ValueError):
        return (), (), "approved peer set is invalid"
    if tuple(approved_peers) != approved:
        return (), (), "approved peer set is not canonical"
    if network_hosts_supplied and approved_peers_supplied:
        return (), (), "network_hosts and approved_peers cannot both be supplied"
    return hosts, approved, None


def _trace_runner_dns(scope, *, request_id: str, source_id: str, host: str,
                      record_type: str, decision: str, reason: str,
                      answers=(), resolver=None) -> None:
    """Persist one side of a parent-owned validating DNS effect."""
    destination = {"host": host, "answers": list(answers)}
    if resolver is not None:
        destination["resolver"] = resolver
    scope._trace({
        "schema_version": "quarry.network-policy-trace.v1",
        "record_type": record_type,
        "request_id": request_id,
        "source_id": source_id,
        "tool": "native-dns",
        "decision": decision,
        "reason": reason,
        "destination": destination,
    })


def _resolve_network_hosts(scope, *, request_id: str, source_id: str,
                           network_hosts) -> tuple[str, ...]:
    """Resolve and classify an all-or-nothing peer set before child launch."""
    from . import netguard, network_dns, network_policy, resource_contract
    from .network_broker import BrokerPolicy

    hosts = network_hosts
    if not hosts:
        return ()
    policy = BrokerPolicy.from_json(json.dumps(
        scope.broker_policy(
            request_id=request_id, source_id=source_id, tool="native-dns",
            approved_peers=(),
        ),
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ))
    approved = []
    deadline = time.monotonic() + resource_contract.MAX_RESOLVER_CORPUS_DEADLINE_SECONDS
    for host in hosts:
        _trace_runner_dns(
            scope, request_id=request_id, source_id=source_id, host=host,
            record_type="planned", decision="allow",
            reason="runner will resolve and classify host before external launch",
        )
        planned: set[tuple[str, int]] = set()

        def on_event(stage, peer, port, decision, reason):
            key = (peer, port)
            if stage == "dns-planned":
                _trace_runner_dns(
                    scope, request_id=request_id, source_id=source_id, host=host,
                    record_type="planned", decision=decision, reason=reason,
                    resolver=peer,
                )
                planned.add(key)
                return
            if stage != "dns-settled" or key not in planned:
                raise network_policy.NetworkPolicyError(
                    "validating DNS settlement lacked its durable plan",
                )
            try:
                _trace_runner_dns(
                    scope, request_id=request_id, source_id=source_id, host=host,
                    record_type="settlement", decision=decision, reason=reason,
                    resolver=peer,
                )
            except BaseException:
                # A transient trace failure must not leave the durable plan
                # without a best-effort terminal before DNS cancels its fence.
                try:
                    _trace_runner_dns(
                        scope, request_id=request_id, source_id=source_id, host=host,
                        record_type="settlement", decision="deny",
                        reason="validating DNS trace callback failed", resolver=peer,
                    )
                finally:
                    planned.remove(key)
                raise
            planned.remove(key)

        try:
            host_decision, _host_reason = scope.host_allowed(
                host, source_id=source_id,
                _runner_authority=network_policy._RUNNER_NATIVE_DNS_AUTHORITY,
            )
            if host_decision != "allow":
                raise network_policy.NetworkPolicyError(
                    "network host authority is outside active scope",
                )
            try:
                literal = netguard.canonical_ip_set((host,))
            except (TypeError, ValueError):
                literal = ()
            if literal:
                answers, state = literal, "ok"
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise network_policy.NetworkPolicyError(
                        "network host corpus exceeded its resolver deadline",
                    )
                answers, state = network_dns.resolve(
                    policy, host, timeout=min(5.0, remaining), on_event=on_event,
                    effect_fence=scope.effect_fence,
                )
            if planned:
                raise network_policy.NetworkPolicyError(
                    "validating DNS retained an unsettled effect",
                )
            # The DNS module itself returns this form.  Requiring it here also
            # makes adapters and future resolver implementations fail closed.
            if type(answers) is not tuple or state != "ok" or not answers:
                raise network_policy.NetworkPolicyError(
                    "network host did not obtain a complete address answer set",
                )
            canonical = netguard.canonical_ip_set(answers)
            if canonical != answers:
                raise network_policy.NetworkPolicyError(
                    "network host answer set is not canonical",
                )
            for peer in canonical:
                verdict = scope.decide_peer(
                    peer, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    source_id=source_id,
                    _runner_authority=network_policy._RUNNER_NATIVE_DNS_AUTHORITY,
                )
                if not verdict.allowed:
                    raise network_policy.NetworkPolicyError(
                        "network host answer is outside peer policy",
                    )
            approved.extend(canonical)
        except BaseException as exc:
            settlement_fault = None
            for peer, port in sorted(planned):
                try:
                    _trace_runner_dns(
                        scope, request_id=request_id, source_id=source_id, host=host,
                        record_type="settlement", decision="deny",
                        reason="validating DNS ended before settlement", resolver=peer,
                    )
                except BaseException as trace_exc:
                    if settlement_fault is None:
                        settlement_fault = trace_exc
            planned.clear()
            try:
                _trace_runner_dns(
                    scope, request_id=request_id, source_id=source_id, host=host,
                    record_type="settlement", decision="deny",
                    reason=f"runner DNS/peer validation refused ({type(exc).__name__})",
                )
            except BaseException as trace_exc:
                if settlement_fault is None:
                    settlement_fault = trace_exc
            if settlement_fault is not None:
                raise settlement_fault from exc
            raise
        try:
            _trace_runner_dns(
                scope, request_id=request_id, source_id=source_id, host=host,
                record_type="settlement", decision="allow",
                reason="runner DNS/peer validation settled before external launch",
                answers=canonical,
            )
        except BaseException as exc:
            try:
                _trace_runner_dns(
                    scope, request_id=request_id, source_id=source_id, host=host,
                    record_type="settlement", decision="deny",
                    reason="runner DNS/peer settlement could not be persisted",
                )
            except BaseException as trace_exc:
                raise trace_exc from exc
            raise
    return netguard.canonical_ip_set(approved)


def have(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


# ── concurrent-run CPU accounting ─────────────────────────────────────────────────────────────────────

# getrusage(RUSAGE_CHILDREN) is per-process, so a delta around one tool is only that tool's CPU while
# tools run sequentially. A run overlapping any other, at any moment of its lifetime, is unmeasurable.
_CPU_LOCK = threading.Lock()
_CPU_INFLIGHT: dict[int, bool] = {}
_CPU_NEXT = [0]


def _cpu_start() -> int:
    with _CPU_LOCK:
        token = _CPU_NEXT[0]
        _CPU_NEXT[0] += 1
        overlap = bool(_CPU_INFLIGHT)
        _CPU_INFLIGHT[token] = overlap
        if overlap:
            for k in _CPU_INFLIGHT:                # the runs already in flight are contaminated too
                _CPU_INFLIGHT[k] = True
        return token


def _cpu_finish(token: int) -> bool:
    """True when this run overlapped another and its CPU delta must not be reported."""
    with _CPU_LOCK:
        return _CPU_INFLIGHT.pop(token, False)


def cpu_measured(r: "RunResult") -> bool:
    """Whether `r.cpu_s` is a real measurement (-1.0 = unmeasured, concurrent execution)."""
    return r.cpu_s >= 0.0


# ── cooperative cancellation for concurrent lanes ─────────────────────────────────────────────────────

# Python delivers KeyboardInterrupt to the main thread only, so a tool inside a worker thread never
# reaches run()'s interrupt branch. This registry is how the main thread tears those groups down.
_LIVE_LOCK = threading.Lock()
_LIVE_PROCS: dict[int, "subprocess.Popen"] = {}
_LIVE_SEQ = [0]
_CANCELLED = threading.Event()


def cancelled() -> bool:
    return _CANCELLED.is_set()


def reset_cancel() -> None:
    """Clear the cancellation latch (a fresh lane, or a test)."""
    _CANCELLED.clear()


def cancel_all(grace: "float | None" = None) -> int:
    """Latch cancellation and terminate every live tool process group. Returns how many were signalled.

    Safe to call from the main thread while workers are blocked in run()'s proc.wait(): the group is killed,
    wait() then returns promptly, and each worker unwinds through its own finally. The groups are signalled
    concurrently under one shared grace deadline, so the cost does not grow with concurrency."""
    _CANCELLED.set()
    grace = _TERM_GRACE if grace is None else grace   # resolved at call time (defined later in module)
    with _LIVE_LOCK:
        procs = list(_LIVE_PROCS.values())
    if not procs:
        return 0
    if not _POSIX:                                 # no process groups: fall back to per-process handling
        for p in procs:
            try:
                terminate_group(p, grace=grace)
            except Exception:
                pass
        return len(procs)

    def _sig(p, sig):
        try:
            os.killpg(p.pid, sig)                  # start_new_session=True => pid == pgid
        except (ProcessLookupError, OSError):
            pass                                   # group already gone — fine

    for p in procs:
        _sig(p, signal.SIGTERM)                    # ask them all first, then wait once
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if all(p.poll() is not None for p in procs):
            break
        time.sleep(0.05)
    for p in procs:
        _sig(p, signal.SIGKILL)                    # hard-kill every survivor after the shared deadline
    # the reap deadline is shared too: a per-process wait would grow linearly with concurrency whenever
    # a process is slow to reap.
    reap_deadline = time.monotonic() + _REAP_GRACE
    while time.monotonic() < reap_deadline:
        if all(p.poll() is not None for p in procs):
            break
        time.sleep(0.05)
    for p in procs:
        try:
            p.poll()                               # final non-blocking reap; a survivor is left to the OS
        except (ProcessLookupError, OSError):
            pass
    return len(procs)


def _register(proc) -> int:
    with _LIVE_LOCK:
        token = _LIVE_SEQ[0]
        _LIVE_SEQ[0] += 1
        _LIVE_PROCS[token] = proc
        return token


def _unregister(token: int) -> None:
    with _LIVE_LOCK:
        _LIVE_PROCS.pop(token, None)


def _classify(exit_code: int, has_out: bool, blocked: bool, transport: bool, ok_empty: bool,
              ok_codes: tuple[int, ...] = (0,)) -> tuple[Status, str]:
    # `blocked`/`transport` are scanned incrementally from the whole stderr stream (never a bounded tail),
    # so a signature early in a large stderr is not lost.
    if exit_code not in ok_codes:
        if blocked:
            return Status.BLOCKED, "nonzero exit + block signature in stderr"
        # some tools exit nonzero with valid partial output
        if has_out:
            return Status.PARTIAL, f"exit {exit_code} but produced output"
        return Status.FAILED, f"exit {exit_code}, no output"
    # a nonzero exit code we *accept* (gitleaks 1 = leaks found) is only trustworthy with output:
    # nonzero + nothing is more likely a runtime/config error that happens to share the code
    if exit_code != 0 and not has_out:
        if blocked:
            return Status.BLOCKED, "nonzero exit + block signature in stderr"
        return Status.FAILED, f"exit {exit_code} accepted but produced no output"
    # clean exit: a block signature means the target stopped us; a transport error means degraded
    # coverage -> PARTIAL, never BLOCKED and never a trustworthy EMPTY
    if not has_out:
        if blocked:
            return Status.BLOCKED, "clean exit, no output, block signature in stderr"
        if transport:
            return Status.PARTIAL, "clean exit, no stdout, transport error — degraded coverage (completion uncertain)"
        if not ok_empty:                       # a lane that must produce output: clean-but-empty is a failure
            return Status.FAILED, "clean exit but no output (output required)"
        return Status.EMPTY, "clean exit, zero output"
    if blocked:
        return Status.PARTIAL, "produced output but block signature in stderr"
    if transport:
        return Status.PARTIAL, "produced output + transport errors — degraded coverage"
    return Status.SUCCESS, ""


def _deadline_sigint_completion(request, settlement) -> bool:
    """Recognize only the private OOB deadline shutdown completion.

    The worker's detail is authenticated control traffic.  The request posture
    itself is stamped only by the repository facade for ``params.oob_control``.
    Keeping this predicate shared prevents result classification and native
    artifact finalization from disagreeing about the sole accepted exit-1 path.
    """
    from .runner_protocol import ExecutionTerminal

    return bool(
        request.deadline_sigint
        and settlement is not None
        and settlement.terminal is ExecutionTerminal.COMPLETE
        and settlement.detail == "sigint_deadline_exit"
        and settlement.exit_code == 1
    )


_TERM_GRACE = 3.0        # seconds between SIGTERM and the hard SIGKILL of a tool's process group
_REAP_GRACE = 2.0        # shared post-SIGKILL reap window in cancel_all, never per-process
_POSIX = (os.name == "posix")

_READ_CHUNK = 65536
_STDERR_TAIL_BYTES = 8192    # bounded stderr kept in memory for the diagnostic tail; the rest is scanned + dropped
_SIG_CARRY = 256             # stderr overlap so a block/transport signature straddling two chunks still matches
_GRACE = 3.0                 # one bounded window covering kill + drain after the deadline (see run())

# byte forms of the classifier signatures, matched against the raw binary stderr stream
_BLOCK_SIG_B = tuple(s.encode() for s in BLOCK_SIGNATURES)
_TRANSPORT_SIG_B = tuple(s.encode() for s in TRANSPORT_SIGNATURES)


def _read_ready(fd: int, stop: threading.Event) -> "tuple[bytes | None, str]":
    """select-poll `fd`; returns (chunk, "data"), (b"", "eof"), (None, "stopped") on `stop` with nothing
    pending, or (None, "error"). select, not a blocking read, so the reader can honour `stop`."""
    while True:
        try:
            ready, _, _ = select.select([fd], [], [], 0.3)
        except (OSError, ValueError):
            return None, "error"
        if ready:
            try:
                data = os.read(fd, _READ_CHUNK)
            except (OSError, ValueError):
                return None, "error"
            return data, ("eof" if data == b"" else "data")
        if stop.is_set():
            return None, "stopped"


def _drain_stdout(src, sink, state: dict, cap: "int | None", stop: threading.Event) -> None:
    """Stream binary stdout to `sink`; counters and a running sha256 are committed to `state` even when the
    reader is abandoned (`stop_reason != "eof"`). `cap` bounds retained bytes; observed and successfully
    retained streams are measured independently, and a write error detaches the sink."""
    import hashlib
    observed_h = hashlib.sha256()
    retained_h = hashlib.sha256()
    written = 0
    last = b"\n"
    try:
        fd = src.fileno()
    except (OSError, ValueError):
        state["stop_reason"] = "error"
        return
    while True:
        chunk, reason = _read_ready(fd, stop)
        if reason != "data":
            state["stop_reason"] = reason
            break
        observed_h.update(chunk)
        state["bytes"] += len(chunk)
        state["lines"] += chunk.count(b"\n")
        last = chunk[-1:]
        if not state["nonspace"] and chunk.strip():
            state["nonspace"] = True
        if sink is not None:
            take = chunk if cap is None else chunk[: max(0, cap - written)]
            if take:
                try:
                    _write_all(sink, take)
                    retained_h.update(take)
                    written += len(take)
                except OSError as e:
                    state["pub_error"] = str(e)
                    sink = None
            if cap is not None and written >= cap and state["bytes"] > written:
                state["capped"] = True
    if state["bytes"] and last != b"\n":         # a final unterminated line still counts
        state["lines"] += 1
    state["sha256"] = observed_h.hexdigest() if state["bytes"] else ""
    state["retained_bytes"] = written
    state["retained_sha256"] = retained_h.hexdigest()
    state["complete"] = state["stop_reason"] == "eof"


def _drain_stderr(src, sink, state: dict, stop: threading.Event) -> None:
    """Stream binary stderr to `sink`, scan the whole stream for block/transport signatures (a carry catches
    one split across chunks), keep a bounded tail. `complete`/`stop_reason` mirror the stdout drain."""
    tail = bytearray()
    carry = b""
    try:
        fd = src.fileno()
    except (OSError, ValueError):
        state["tail"], state["stop_reason"] = b"", "error"
        return
    while True:
        chunk, reason = _read_ready(fd, stop)
        if reason != "data":
            state["stop_reason"] = reason
            break
        if sink is not None:
            try:
                _write_all(sink, chunk)
            except OSError as e:
                state["pub_error"] = str(e)
                sink = None
        low = (carry + chunk).lower()
        if not state["blocked"] and any(sig in low for sig in _BLOCK_SIG_B):
            state["blocked"] = True
        if not state["transport"] and any(sig in low for sig in _TRANSPORT_SIG_B):
            state["transport"] = True
        carry = chunk[-_SIG_CARRY:]
        tail += chunk
        if len(tail) > _STDERR_TAIL_BYTES:
            del tail[:-_STDERR_TAIL_BYTES]
    state["tail"] = bytes(tail)
    state["complete"] = state["stop_reason"] == "eof"


def _feed_stdin(stdin, data: "bytes | None", src_file: "str | None", state: dict,
                stop: threading.Event) -> None:
    """Feed the tool's stdin with nonblocking writes, abandoning a full pipe on `stop`. A source open/read
    failure is a machinery fault in `state`; a broken pipe from a tool that closed stdin early is ignored."""
    try:
        fd = stdin.fileno()
        os.set_blocking(fd, False)
    except (OSError, ValueError):
        return
    try:
        if src_file is not None:
            try:
                f = open(src_file, "rb")
            except OSError as e:
                state["error"] = f"stdin source open failed: {e}"
                return
            with f:
                while True:
                    try:
                        block = f.read(_READ_CHUNK)
                    except OSError as e:
                        state["error"] = f"stdin source read failed: {e}"
                        break
                    if not block:
                        break
                    if _nb_write(fd, block, stop) != "done":   # tool closed stdin early, or abandoned on stop
                        break
        elif data is not None:
            _nb_write(fd, data, stop)
    finally:
        try:
            stdin.close()                            # close the write end so the tool sees EOF on stdin
        except (OSError, ValueError):
            pass


def _nb_write(fd: int, data: bytes, stop: threading.Event) -> str:
    """Nonblocking-write every byte of `data` to `fd`, select-waiting for writability so the writer wakes to
    honour `stop`. Returns "done", "epipe" (pipe closed), or "stopped" (abandoned)."""
    mv = memoryview(data)
    while mv:
        if stop.is_set():
            return "stopped"
        try:
            mv = mv[os.write(fd, mv):]
        except BlockingIOError:
            try:
                select.select([], [fd], [], 0.3)
            except (OSError, ValueError):
                return "epipe"
        except (BrokenPipeError, OSError):
            return "epipe"
    return "done"


def _write_all(fp, data) -> None:
    """Write every byte to an unbuffered sink (which may accept a chunk short); a write that cannot progress
    (a full filesystem) raises so the caller records a publication fault."""
    mv = memoryview(data)
    while mv:
        n = fp.write(mv)
        if not n:
            raise OSError("short write to output sink")
        mv = mv[n:]


def _open_stage(final: Path):
    """Create a unique, exclusive private staging file beside `final` and return (fp, path). mkstemp uses
    O_CREAT|O_EXCL at mode 0600, so it never follows a planted symlink or reuses an existing name."""
    final.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(final.parent), prefix=final.name + ".", suffix=".partial")
    return os.fdopen(fd, "wb", buffering=0), Path(name)


def _close_pipes(proc) -> None:
    """Close the child's pipe objects. Non-blocking (the drain/feed threads hold no buffer lock — they use the
    raw fd), so it unblocks a stuck thread and never double-closes at GC. Idempotent."""
    if proc is None:
        return
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if pipe is not None:
                pipe.close()
        except (OSError, ValueError):
            pass


def _finalize_and_publish(fp, stage: "Path | None", final: "Path | None", state: dict, *,
                          publish: bool, authoritative: bool = False,
                          retain_empty: bool = False) -> "Path | None":
    """Close the sink and atomically move the stage onto `final`; return `final` iff the replace ran
    (`authoritative` replaces even an empty stage), else retain a non-empty stage as partial evidence.
    `retain_empty` owns an intentionally empty partial (notably a hit stdout cap of zero)."""
    if fp is not None:
        try:
            fp.flush()
        except (OSError, ValueError) as e:
            state["pub_error"] = state.get("pub_error") or str(e)
        try:
            fp.close()
        except OSError as e:
            state["pub_error"] = state.get("pub_error") or str(e)
    if stage is None or final is None:
        return None
    try:
        size = stage.stat().st_size
    except OSError:
        size = 0
    if publish and not state.get("pub_error") and (size > 0 or authoritative):
        try:
            os.replace(stage, final)
            return final
        except OSError as e:
            state["pub_error"] = state.get("pub_error") or str(e)
    if size == 0 and not retain_empty:
        try:
            stage.unlink()
        except OSError:
            pass
        return None
    _record_partial(stage, state)                 # unpublished bytes exist: own them as partial evidence
    return None


def _record_partial(stage: Path, state: dict) -> None:
    """Record a retained staging file (its unique path, on-disk size, digest of the bytes written) as partial
    evidence in `state`."""
    import hashlib
    state["partial_path"] = str(stage)
    try:
        h = hashlib.sha256()
        n = 0
        with open(stage, "rb") as f:
            for block in iter(lambda: f.read(_READ_CHUNK), b""):
                h.update(block)
                n += len(block)
        state["partial_bytes"] = n
        state["partial_sha256"] = h.hexdigest()
    except OSError:
        pass


def terminate_group(proc, grace: float = _TERM_GRACE, *,
                    graceful_signal: int = signal.SIGTERM) -> None:
    """Signal a tool's process group, then bounded-wait, SIGKILL, and reap it.

    Normal tools use SIGTERM.  A caller whose documented persistence boundary is
    SIGINT may request that signal without weakening the same hard-kill fallback.
    Callers MUST launch with ``start_new_session=True``; ``proc.pid`` remains the
    process-group id even after the leader exits.
    """
    if graceful_signal not in {signal.SIGTERM, signal.SIGINT}:
        raise ValueError("unsupported graceful process-group signal")
    if _POSIX:
        pgid = proc.pid                                # valid while any group member lives
        def _sig(sig):
            try:
                os.killpg(pgid, sig)
            except (ProcessLookupError, OSError):
                pass                                   # group already gone — fine
        _sig(graceful_signal)
        try:
            proc.wait(timeout=grace)                   # let the group exit gracefully on TERM
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass
        _sig(signal.SIGKILL)                           # hard-kill any survivor in the group
        try:
            proc.wait(timeout=grace)                   # reap the leader after the kill (no zombie)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass
        return
    # non-POSIX: no process groups — best-effort single-process TERM -> KILL, reaping after each
    try:
        proc.send_signal(graceful_signal)
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=grace)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            pass
    except (ProcessLookupError, OSError):
        pass


def _legacy_run(
    tool: str,
    cmd: list[str],
    *,
    raw_path: Path | None = None,
    timeout: int = 1800,
    stdin_data: str | None = None,
    input_file: Path | None = None,
    ok_empty: bool = True,
    ok_codes: tuple[int, ...] = (0,),
    env: dict | None = None,
    stderr_path: Path | None = None,
    max_output_bytes: int | None = None,
) -> RunResult:
    """Run `cmd`, streaming binary stdout/stderr to disk, and return a classified RunResult.

    Contract: exact bytes are staged privately and published atomically to `raw_path`; `stderr_path` holds
    this run's stderr (`meta['stderr_published']` flags currency). `ok_codes` are non-failure exits;
    `ok_empty=False` makes clean-but-empty FAILED. `max_output_bytes` is an exact non-negative integer cap
    on retained stdout; a hit cap owns the prefix as a non-authoritative partial and challenges completeness.
    `timeout` plus one `_GRACE` window bounds execute+kill+drain. Preflight/launch/stdin/drain/publication
    failures are `Fault`s in `meta['faults']`, never raised.
    """
    # Validate argv, stdin-source selection and the retention cap before PATH lookup, directory creation,
    # staging, source reads, or subprocess launch. The remaining arguments are migrated to the typed worker
    # request in the next Phase 1 slice; do not describe this preparatory check as the complete boundary.
    argv, argv_error = _preflight_argv(cmd)
    safe_env, env_error = _preflight_environment(env)
    preflight_errors = []
    if argv_error:
        preflight_errors.append(argv_error)
    if env_error:
        preflight_errors.append(env_error)
    if stdin_data is not None and input_file is not None:
        preflight_errors.append("stdin_data and input_file are mutually exclusive")
    if stdin_data is not None and not isinstance(stdin_data, str):
        preflight_errors.append("stdin_data must be a string or None")
    if (max_output_bytes is not None
            and (type(max_output_bytes) is not int or max_output_bytes < 0)):
        preflight_errors.append("max_output_bytes must be an exact non-negative integer or None")
    elif max_output_bytes is not None and raw_path is None:
        preflight_errors.append("max_output_bytes requires raw_path so retained stdout has an evidence sink")
    if preflight_errors:
        return _preflight_failure(tool, argv, "; ".join(preflight_errors))

    # Compatibility callers may still hold a repository Path minted while the
    # run was live. Revalidate that lifecycle before PATH lookup, staging or
    # launch; new production callers use an opaque artifact claim instead.
    from . import store as _store
    for label, destination in (("raw_path", raw_path), ("stderr_path", stderr_path)):
        if destination is None:
            continue
        try:
            managed = _store.managed_run_for_artifact(destination)
        except Exception as exc:
            preflight_errors.append(f"{label} repository identity is unsafe ({type(exc).__name__})")
            continue
        if managed is not None:
            owner, _components = managed
            state = owner.state
            if state not in {"created", "running"}:
                preflight_errors.append(
                    f"{label} belongs to sealed run {owner.run_id} in state {state!r}",
                )
    if preflight_errors:
        return _preflight_failure(tool, argv, "; ".join(preflight_errors))

    cmd = argv                              # normalized concrete list; preflight proved this is not None
    bin_name = cmd[0]
    if not have(bin_name):
        return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0,
                         note=f"{bin_name} not on PATH")

    # stdin over a pipe when there is input, else /dev/null (ProjectDiscovery tools block on an inherited tty).
    want_stdin = input_file is not None or stdin_data is not None
    stdin_bytes = stdin_data.encode("utf-8", "replace") if isinstance(stdin_data, str) else None
    stdin_kw = {"stdin": subprocess.PIPE if want_stdin else subprocess.DEVNULL}

    start = time.monotonic()
    # Popen (not subprocess.run) so the pid is held for RSS/CPU sampling during the run.
    cpu0 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    cpu_base = (cpu0.ru_utime + cpu0.ru_stime) if cpu0 else 0.0
    _cpu_token = _cpu_start()          # marks this run, and every overlapping one, as CPU-unmeasurable
    peak_rss = [0.0]
    stop = threading.Event()

    # env is merged over the inherited environment, not a replacement: callers pass only overrides
    # (e.g. {"PYTHONHASHSEED": "0"}) without dropping PATH.
    proc_env = {**os.environ, **safe_env} if safe_env else None

    faults: list[dict] = []
    out_state = {"bytes": 0, "lines": 0, "nonspace": False, "sha256": "", "capped": False,
                 "retained_bytes": 0, "retained_sha256": "", "pub_error": None,
                 "complete": False, "stop_reason": ""}
    err_state = {"blocked": False, "transport": False, "tail": b"", "pub_error": None,
                 "complete": False, "stop_reason": ""}
    in_state = {"error": None}
    drain_stop = threading.Event()                # signals the reader threads to abandon an escaped pipe holder

    # a failed staging open leaves stage None (nothing published) and marks pub_error, surfaced once at the end.
    raw_stage = err_stage = None
    out_fp = err_fp = None
    if raw_path is not None:
        try:
            out_fp, raw_stage = _open_stage(raw_path)
        except OSError as e:
            out_state["pub_error"] = str(e)
    if stderr_path is not None:
        try:
            err_fp, err_stage = _open_stage(stderr_path)
        except OSError as e:
            err_state["pub_error"] = str(e)

    proc = None
    started = False                               # proven by a pid, never inferred
    live_token = None
    group_settled = False                         # True once this run's process group needs no teardown
    interrupted = False
    timed_out = False
    sampler = None
    out_published = None
    stderr_published = False
    primary_incomplete = False                    # stdout/stdin evidence compromised (stderr is diagnostic-only)
    try:
        try:
            # start_new_session: own group (terminate_group kills the tree; Ctrl-C hits Quarry). Binary: exact bytes.
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=proc_env, cwd=_TOOL_CWD, start_new_session=True, **stdin_kw)
        except (OSError, ValueError) as e:        # launch failure is a typed machinery fault, never an escape
            faults.append(Fault("machinery", where=tool, detail=f"launch failed: {e}").to_dict())
            _finalize_and_publish(out_fp, raw_stage, raw_path, out_state, publish=False)
            _finalize_and_publish(err_fp, err_stage, stderr_path, err_state, publish=False)
            for label, where, st in (("stdout", raw_path, out_state), ("stderr", stderr_path, err_state)):
                if st["pub_error"]:
                    faults.append(Fault("publication" if label == "stdout" else "diagnostic",
                                        where=str(where), detail=st["pub_error"]).to_dict())
            _cpu_finish(_cpu_token)
            return RunResult(tool, cmd, Status.FAILED, None, round(time.monotonic() - start, 3), None, 0,
                             note=f"launch failed: {e}", meta={"started": False, "faults": faults})
        started = True                            # a pid exists: the process really did launch
        live_token = _register(proc)              # reachable by cancel_all() from the main thread
        if _CANCELLED.is_set():                   # cancellation latched between the check above and the launch
            terminate_group(proc)

        def _sample():
            while not stop.wait(0.3):
                r = _rss_tree_mb(proc.pid)
                if r > peak_rss[0]:
                    peak_rss[0] = r
        sampler = threading.Thread(target=_sample, daemon=True)
        sampler.start()

        t_out = threading.Thread(target=_drain_stdout,
                                 args=(proc.stdout, out_fp, out_state, max_output_bytes, drain_stop), daemon=True)
        t_err = threading.Thread(target=_drain_stderr, args=(proc.stderr, err_fp, err_state, drain_stop),
                                 daemon=True)
        t_out.start()
        t_err.start()
        readers = [t_out, t_err]
        t_in = None
        if want_stdin:
            t_in = threading.Thread(target=_feed_stdin, args=(proc.stdin, stdin_bytes,
                                    str(input_file) if input_file is not None else None, in_state, drain_stop),
                                    daemon=True)
            t_in.start()

        try:
            remaining = None if not timeout else max(0.0, (start + timeout) - time.monotonic())
            proc.wait(timeout=remaining)          # readers drain concurrently, so a full pipe never deadlocks
        except subprocess.TimeoutExpired:
            timed_out = True
        except KeyboardInterrupt:
            interrupted = True                    # operator cancel — never reported as a tool FAILED/TIMED_OUT

        # one bounded window (_GRACE) covers BOTH killing the group and draining the readers, so a small
        # `timeout` cannot balloon into many seconds of fixed grace.
        hard = time.monotonic() + _GRACE
        if timed_out or interrupted:
            terminate_group(proc, grace=min(1.0, _GRACE))
        drain_stop.set()
        threads = ([t_in] if t_in is not None else []) + readers
        for t in threads:
            t.join(timeout=max(0.0, hard - time.monotonic()))
        if any(t.is_alive() for t in threads):
            # a grandchild escaped into its own session and still holds a pipe: close the pipes so a blocked
            # read/write returns, then rejoin briefly.
            _close_pipes(proc)
            for t in threads:
                t.join(timeout=0.5)

        # A hit retention cap is incomplete evidence, never the authoritative final artifact. Preserve any prior
        # final and own this attempt's retained prefix under its exclusive staging name (including cap=0).
        out_published = _finalize_and_publish(out_fp, raw_stage, raw_path, out_state,
                                              publish=out_state["bytes"] > 0 and not out_state["capped"],
                                              retain_empty=out_state["capped"])
        # publish stderr only on a clean EOF drain (`complete`), so an abandoned/incomplete stderr is never
        # authoritative; otherwise the prior file is kept and the bytes are retained as a stderr partial.
        if stderr_path is not None:
            stderr_published = _finalize_and_publish(err_fp, err_stage, stderr_path, err_state,
                                                     publish=err_state["complete"], authoritative=True) is not None

        for label, st in (("stdout", out_state), ("stderr", err_state)):
            if st["stop_reason"] not in ("eof", ""):
                # stdout is primary (machinery, challenges completeness); stderr is diagnostic (non-challenging)
                kind = "machinery" if label == "stdout" else "diagnostic"
                faults.append(Fault(kind, where=tool,
                                    detail=f"{label} drain incomplete ({st['stop_reason']})").to_dict())
                if label == "stdout":
                    primary_incomplete = True
        if in_state["error"]:
            faults.append(Fault("machinery", where=str(input_file), detail=in_state["error"]).to_dict())
            primary_incomplete = True
        if t_in is not None and t_in.is_alive():
            faults.append(Fault("machinery", where=tool, detail="stdin feed did not complete within grace").to_dict())
            primary_incomplete = True
        if out_state["capped"]:
            retained = out_state.get("partial_bytes", out_state["retained_bytes"])
            faults.append(Fault(
                "publication", where=str(raw_path),
                detail=(f"stdout retention cap {max_output_bytes} bytes truncated the observed stream "
                        f"({out_state['bytes']} observed, {retained} retained); "
                        f"partial retained at {out_state.get('partial_path', '<unavailable>')}")
            ).to_dict())
            primary_incomplete = True
        group_settled = True
    finally:
        stop.set()                                # sampler shutdown on every path, interrupt included
        drain_stop.set()                          # readers must never linger, even on an unexpected exit
        if sampler is not None:
            sampler.join(timeout=1)
        try:
            # a leader can exit while its children keep the group alive; tear it down on any exceptional exit.
            if proc is not None and (not group_settled or proc.poll() is None):
                terminate_group(proc)
        except Exception:
            pass                                  # best-effort: never mask an exception in flight
        for fp in (out_fp, err_fp):               # backstop: sinks are normally closed by _finalize_and_publish
            try:
                if fp is not None and not fp.closed:
                    fp.close()
            except OSError:
                pass
        _close_pipes(proc)                        # release pipe descriptors deterministically, not at GC
        if live_token is not None:
            _unregister(live_token)
        _cpu_contended = _cpu_finish(_cpu_token)  # always reclaim the token, however we leave

    if interrupted:
        raise KeyboardInterrupt

    dur = round(time.monotonic() - start, 3)
    cpu1 = (resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None)
    # RUSAGE_CHILDREN is process-global, so the delta only attributes cleanly while tools run one at a time.
    cpu_s = -1.0 if _cpu_contended else (
        round((cpu1.ru_utime + cpu1.ru_stime) - cpu_base, 2) if cpu1 else 0.0)
    rss_mb = round(peak_rss[0], 1)

    for label, where, st in (("stdout", raw_path, out_state), ("stderr", stderr_path, err_state)):
        if st["pub_error"]:
            detail = st["pub_error"]
            if st.get("partial_path"):            # the fault self-describes where the retained bytes are
                detail += f" — partial retained at {st['partial_path']} ({st.get('partial_bytes')} bytes)"
            # stdout publication challenges completeness; a lost diagnostic stderr does not (non-challenging kind)
            kind = "publication" if label == "stdout" else "diagnostic"
            faults.append(Fault(kind, where=str(where), detail=detail).to_dict())
            if label == "stdout":
                primary_incomplete = True

    retained_bytes = (out_state.get("partial_bytes") if out_state.get("partial_path")
                      else out_state["retained_bytes"] if out_published is not None else 0)
    retained_sha256 = (out_state.get("partial_sha256") if out_state.get("partial_path")
                       else out_state["retained_sha256"] if out_published is not None else None)
    meta: dict = {
        "started": started,
        # Compatibility: these continue to describe every byte observed from the stdout pipe.
        "stdout_bytes": out_state["bytes"],
        "stdout_observed_bytes": out_state["bytes"],
        # Explicit persistence measurement: authoritative final or owned partial, never inferred from observed.
        "stdout_retained_bytes": retained_bytes,
    }
    if out_state["sha256"]:
        meta["stdout_sha256"] = out_state["sha256"]
        meta["stdout_observed_sha256"] = out_state["sha256"]
    if retained_sha256 is not None:
        meta["stdout_retained_sha256"] = retained_sha256
    if out_state["capped"]:
        meta["output_capped"] = max_output_bytes
        meta["stdout_truncated"] = True
        meta["stdout_truncated_bytes"] = out_state["bytes"] - retained_bytes
    if out_state.get("partial_path"):             # unpublished stdout bytes retained: describe the artifact
        meta["partial_path"] = out_state["partial_path"]
        meta["partial_bytes"] = out_state.get("partial_bytes")
        meta["partial_sha256"] = out_state.get("partial_sha256")
    if stderr_path is not None:
        meta["stderr_published"] = stderr_published    # whether stderr_path holds THIS run's stderr
    if err_state.get("partial_path"):             # unpublished stderr bytes retained
        meta["stderr_partial_path"] = err_state["partial_path"]
        meta["stderr_partial_bytes"] = err_state.get("partial_bytes")
    if faults:
        meta["faults"] = faults

    err_tail = "\n".join(err_state["tail"].decode("utf-8", "replace").strip().splitlines()[-8:])
    raw = out_published                           # a reference only to a published artifact, never observed-but-unwritten

    if timed_out:
        return RunResult(tool, cmd, Status.TIMED_OUT, None, dur, raw, out_state["lines"],
                         stderr_tail=err_tail, note=f"timed out after {timeout}s",
                         cpu_s=cpu_s, peak_rss_mb=rss_mb, meta=meta)

    status, note = _classify(proc.returncode, out_state["nonspace"], err_state["blocked"],
                             err_state["transport"], ok_empty, ok_codes)
    # uncaptured/unpersisted PRIMARY evidence (stdout/stdin) must not read as clean; a diagnostic stderr fault does not.
    if status in (Status.SUCCESS, Status.EMPTY) and primary_incomplete:
        status = Status.PARTIAL
        note = (note + "; " if note else "") + "primary evidence incomplete (machinery/publication fault)"
    return RunResult(
        tool=tool, cmd=cmd, status=status, exit_code=proc.returncode, duration=dur,
        raw_path=raw, stdout_lines=out_state["lines"],
        stderr_tail=err_tail, note=note, cpu_s=cpu_s, peak_rss_mb=rss_mb, meta=meta,
    )


_REPOSITORY_POLICY_UNSET = object()


def _read_published_diagnostic(path: "Path | None") -> tuple[str, bool, bool, str | None]:
    """Return the compatibility stderr tail and whole-stream classifiers.

    A repository-published stderr artifact is immutable before this function is
    called.  Scan it incrementally so classification keeps the legacy
    whole-stream behavior without loading an unbounded diagnostic into memory.
    """
    if path is None:
        return "", False, False, None
    carry = b""
    tail = b""
    blocked = transport = False
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(_READ_CHUNK), b""):
                folded = (carry + chunk).lower()
                blocked = blocked or any(sig in folded for sig in _BLOCK_SIG_B)
                transport = transport or any(sig in folded for sig in _TRANSPORT_SIG_B)
                carry = folded[-_SIG_CARRY:]
                tail = (tail + chunk)[-_STDERR_TAIL_BYTES:]
    except OSError:
        return "", False, False, "published stderr could not be read"
    rendered = "\n".join(tail.decode("utf-8", "replace").strip().splitlines()[-8:])
    return rendered, blocked, transport, None


def _repository_run_result(
    tool: str,
    cmd: list[str],
    outcome,
    *,
    request,
    stdout,
    stderr,
    stdout_path: str | None,
    stderr_path: str | None,
    duration: float,
) -> RunResult:
    """Derive the v0.3 ``RunResult`` view from immutable repository facts."""
    from .runner_protocol import ExecutionTerminal, StreamRole, StreamTerminal
    from .runner_repository import ArtifactDisposition, RepositoryPublication

    execution = outcome.execution
    settlement = execution.settlement
    stream_by_role = (
        {stream.role: stream for stream in settlement.streams}
        if settlement is not None else {}
    )
    stdout_stream = stream_by_role.get(StreamRole.STDOUT)
    published_roles = {proof.role for proof in outcome.published}
    raw = (
        Path(stdout_path)
        if (stdout.disposition is ArtifactDisposition.PUBLISH
            and "stdout" in published_roles
            and stdout_path is not None)
        else None
    )
    stderr_final = (
        Path(stderr_path)
        if (stderr.disposition is ArtifactDisposition.PUBLISH
            and "stderr" in published_roles
            and stderr_path is not None)
        else None
    )
    stderr_tail, blocked, transport, diagnostic_error = (
        _read_published_diagnostic(stderr_final)
    )

    faults: list[dict] = []
    if execution.reason.value != "complete":
        faults.append(Fault(
            "machinery", where=tool,
            detail=f"repository execution ended {execution.reason.value}",
        ).to_dict())
    if outcome.publication not in {
        RepositoryPublication.PUBLISHED,
        RepositoryPublication.NOT_REQUESTED,
    }:
        faults.append(Fault(
            "publication", where=tool,
            detail=f"repository publication ended {outcome.publication.value}",
        ).to_dict())
    if diagnostic_error is not None:
        faults.append(Fault("diagnostic", where=tool, detail=diagnostic_error).to_dict())

    started = bool(settlement is not None and settlement.launched)
    exit_code = settlement.exit_code if settlement is not None else None
    observed = stdout_stream.observed_bytes if stdout_stream is not None else 0
    retained = stdout_stream.retained_bytes if raw is not None and stdout_stream is not None else 0
    lines = stdout_stream.lines if stdout_stream is not None else 0
    primary_incomplete = (
        not outcome.clean
        or stdout_stream is None
        or stdout_stream.terminal is not StreamTerminal.EOF
        or (stream_by_role.get(StreamRole.STDIN) is not None
            and stream_by_role[StreamRole.STDIN].terminal not in {
                StreamTerminal.COMPLETE,
                StreamTerminal.PEER_CLOSED,
                StreamTerminal.NOT_STARTED,
            })
    )

    deadline_sigint_exit = _deadline_sigint_completion(request, settlement)
    if settlement is not None and settlement.terminal is ExecutionTerminal.TIMED_OUT:
        status, note = Status.TIMED_OUT, f"timed out after {request.timeout}s"
    elif not started or exit_code is None:
        status, note = Status.FAILED, f"execution did not complete ({execution.reason.value})"
    elif (request.deadline_sigint and settlement is not None
          and settlement.terminal is ExecutionTerminal.COMPLETE
          and settlement.detail == "sigint_deadline_exit"):
        # Interactsh persists its resumable session from its SIGINT handler and
        # documents exit 1 for that path.  A regular early exit 1 has no
        # witnessed deadline marker and therefore remains an ordinary failure.
        if exit_code != 1:
            status, note = Status.FAILED, (
                f"deadline SIGINT exited {exit_code}, expected 1"
            )
        else:
            status, note = _classify(
                0, observed > 0, blocked, transport,
                request.ok_empty, request.ok_codes,
            )
            note = (note + "; " if note else "") + "deadline SIGINT exit 1"
    else:
        status, note = _classify(
            exit_code, observed > 0, blocked, transport,
            request.ok_empty, request.ok_codes,
        )
    if status in (Status.SUCCESS, Status.EMPTY) and primary_incomplete:
        if deadline_sigint_exit:
            status = Status.FAILED
            note = (note + "; " if note else "") + "deadline SIGINT evidence incomplete"
        else:
            status = Status.PARTIAL
            note = (note + "; " if note else "") + "primary evidence incomplete"

    meta: dict = {
        "started": started,
        "stdout_bytes": observed,
        "stdout_observed_bytes": observed,
        "stdout_retained_bytes": retained,
        "repository_publication": outcome.publication.value,
        "repository_ownership_settled": outcome.ownership_settled,
        "execution_reason": execution.reason.value,
    }
    if request.deadline_sigint:
        meta["deadline_sigint"] = deadline_sigint_exit
    if stdout_stream is not None:
        if stdout_stream.observed_sha256 is not None:
            meta["stdout_sha256"] = stdout_stream.observed_sha256
            meta["stdout_observed_sha256"] = stdout_stream.observed_sha256
        if raw is not None and stdout_stream.retained_sha256 is not None:
            meta["stdout_retained_sha256"] = stdout_stream.retained_sha256
        if stdout_stream.terminal is StreamTerminal.CAPPED:
            meta["output_capped"] = request.max_output_bytes
            meta["stdout_truncated"] = True
            meta["stdout_truncated_bytes"] = observed - retained
    if stderr.disposition is ArtifactDisposition.PUBLISH:
        meta["stderr_published"] = stderr_final is not None
    if settlement is not None:
        # Public, authenticated execution testimony for release collectors.  This
        # is a projection of the supervisor settlement, never collector input.
        meta["execution_terminal"] = settlement.terminal.value
        meta["process_group_settled"] = settlement.process_group_settled
        meta["process_tree_settled"] = settlement.process_tree_settled
        meta["execution_request_id"] = settlement.request_id
        meta["execution_detail"] = settlement.detail
        # Keep the complete parent-validated settlement available to bounded
        # release collectors.  The flattened compatibility fields above remain
        # for existing callers; collectors reconcile both views rather than
        # reconstructing process truth from a result classification.
        meta["execution_settlement"] = settlement.to_dict()
        meta["streams"] = {
            stream.role.value: stream.to_dict() for stream in settlement.streams
        }
    # These paths are derived only from the repository output policy after
    # publication.  Collectors use the sealed values (not RunResult.raw_path)
    # to reopen an exact managed artifact and recompute its retained digest.
    # Keep explicit ``None`` values so the sealed testimony distinguishes a
    # fenced/discarded stream from a caller-added path after return.
    meta["repository_stdout_path"] = None if raw is None else str(raw)
    meta["repository_stderr_path"] = (
        None if stderr_final is None else str(stderr_final)
    )
    if faults:
        meta["faults"] = faults
    return RunResult(
        tool=tool,
        cmd=cmd,
        status=status,
        exit_code=exit_code,
        duration=round(duration, 3),
        raw_path=raw,
        stdout_lines=lines,
        stderr_tail=stderr_tail,
        note=note,
        meta=meta,
    )


def _native_evidence_meta(evidence) -> dict:
    """Render one authenticated native-output fact without exposing a stage path."""
    return {
        "policy_index": evidence.policy_index,
        "kind": evidence.kind.value,
        "components": list(evidence.components),
        "present": evidence.present,
        "size": evidence.size,
        "sha256": evidence.sha256,
    }


def _attach_native_output_receipt(
    result: RunResult,
    repository,
    receipt,
) -> RunResult:
    """Compose native argv publication into the public compatibility result."""
    groups = {
        "committed": receipt.committed,
        "uncertain": receipt.uncertain,
        "unpublished": receipt.unpublished,
    }
    current_paths = tuple(
        os.path.abspath(os.path.normpath(str(
            repository.dir.joinpath(*evidence.components)
        )))
        for evidence in receipt.committed
        if evidence.present
    )
    result.meta["native_outputs"] = {
        "clean": receipt.clean,
        "policy_count": receipt.policy_count,
        "committed": [_native_evidence_meta(item) for item in groups["committed"]],
        "uncertain": [_native_evidence_meta(item) for item in groups["uncertain"]],
        "unpublished": [_native_evidence_meta(item) for item in groups["unpublished"]],
        "current_paths": list(current_paths),
        "cleanup_settled": receipt.cleanup_settled,
        "claim_retained": receipt.claim_retained,
        "fault_operation": receipt.fault_operation,
        "fault_type": receipt.fault_type,
    }
    ownership_settled = receipt.cleanup_settled and not receipt.claim_retained
    result.meta["native_output_ownership_settled"] = ownership_settled
    result.meta["repository_ownership_settled"] = bool(
        result.meta.get("repository_ownership_settled") and ownership_settled
    )
    if not receipt.clean:
        detail = (
            "native output publication did not complete cleanly"
            + (f" ({receipt.fault_operation})" if receipt.fault_operation else "")
        )
        faults = result.meta.setdefault("faults", [])
        faults.append(Fault("publication", where=result.tool, detail=detail).to_dict())
        if result.status in (Status.SUCCESS, Status.EMPTY):
            result.status = Status.PARTIAL
            result.note = (result.note + "; " if result.note else "") + detail
    return result


def _mark_native_outputs_unavailable(
    result: RunResult,
    policy_count: int,
    *,
    operation: str,
    fault_type: str | None = None,
    ownership_settled: bool,
) -> RunResult:
    """Prevent adapters from mistaking preserved finals for this invocation."""
    result.meta["native_outputs"] = {
        "clean": False,
        "policy_count": policy_count,
        "committed": [],
        "uncertain": [],
        "unpublished": [],
        "current_paths": [],
        "cleanup_settled": ownership_settled,
        "claim_retained": not ownership_settled,
        "fault_operation": operation,
        "fault_type": fault_type,
    }
    result.meta["native_output_ownership_settled"] = ownership_settled
    if "repository_ownership_settled" in result.meta:
        result.meta["repository_ownership_settled"] = bool(
            result.meta["repository_ownership_settled"] and ownership_settled
        )
    return result


def _attach_empty_native_output_receipt(result: RunResult) -> RunResult:
    """State explicitly that one repository execution declared no native sinks."""
    result.meta["native_outputs"] = {
        "clean": True,
        "policy_count": 0,
        "committed": [],
        "uncertain": [],
        "unpublished": [],
        "current_paths": [],
        "cleanup_settled": True,
        "claim_retained": False,
        "fault_operation": None,
        "fault_type": None,
    }
    result.meta["native_output_ownership_settled"] = True
    return result


def _preferred_native_fault(*faults):
    """The first cancellation, else the first ordinary settlement fault."""
    for fault in faults:
        if fault is not None and not isinstance(fault, Exception):
            return fault
    return next((fault for fault in faults if fault is not None), None)


def _fence_native_adoption(adoption):
    """Reconcile an adopted prepare/transaction without throwing its fault."""
    try:
        return adoption.fence(), None
    except BaseException as primary:
        try:
            receipt = adoption.fence()
            recovery = None
        except BaseException as recovery:
            receipt = None
        return receipt, _preferred_native_fault(primary, recovery)


def _finish_native_outputs(transaction, adoption, *, clean: bool):
    """Publish/fence, recovering terminal truth through the adoption owner."""
    try:
        return transaction.finish(clean=clean), None
    except BaseException as primary:
        receipt, recovery = _fence_native_adoption(adoption)
        return receipt, _preferred_native_fault(primary, recovery)


class _NativeFacadeOwner:
    """Stable native-output authority shared by nested caller fences.

    Preparation adopts its raw filesystem owner and completed transaction into
    ``adoption`` before returning.  Keeping that adoption object outside both
    context layers means a cancellation at a prepare/handler/cleanup call line
    cannot discard the only cleanup authority.
    """

    __slots__ = ("adoption", "transaction", "receipt", "cleanup_fault")

    def __init__(self, adoption) -> None:
        self.adoption = adoption
        self.transaction = None
        self.receipt = None
        self.cleanup_fault = None

    def reconcile(self):
        receipt, fault = _fence_native_adoption(self.adoption)
        if self.receipt is None and receipt is not None:
            self.receipt = receipt
        self.cleanup_fault = _preferred_native_fault(
            self.cleanup_fault, fault,
        )
        return fault


class _NativeFacadeFence:
    """One recovery layer over a shared native facade owner.

    Two layers are installed before preparation.  If the sole cooperative
    cancellation interrupts the inner layer's cleanup entry, the already-active
    outer layer repeats the idempotent adoption fence before propagating it.
    """

    __slots__ = ("owner",)

    def __init__(self, owner: _NativeFacadeOwner) -> None:
        self.owner = owner

    def __enter__(self):
        return self

    def __exit__(self, _kind, primary, _traceback) -> bool:
        cleanup = self.owner.reconcile()
        preferred = _preferred_native_fault(primary, cleanup)
        if preferred is not None and not isinstance(preferred, Exception):
            if primary is not None and preferred is not primary:
                raise preferred from primary
            raise preferred
        if primary is None and cleanup is not None:
            raise cleanup
        return False


def _native_execution_clean(outcome, request) -> bool:
    """Whether process settlement, containment and accepted exit are clean."""
    from .runner_protocol import ExecutionTerminal

    settlement = outcome.execution.settlement
    return bool(
        outcome.clean
        and settlement is not None
        and settlement.terminal is ExecutionTerminal.COMPLETE
        and (settlement.exit_code in request.ok_codes
             or _deadline_sigint_completion(request, settlement))
    )


def native_output_current(result: RunResult, path) -> bool:
    """Whether ``path`` is authenticated as current by this invocation's receipt.

    Results supplied by legacy test doubles have no native receipt and retain the
    old adapter behavior.  A real native-output facade result always carries the
    key, including on fencing and publication faults, so production consumers
    never infer currency from the ambient final path.
    """
    native = result.meta.get("native_outputs")
    if native is None:
        return True
    if path is None:
        return False
    if type(native) is not dict or type(native.get("current_paths")) is not list:
        return False
    candidate = os.path.abspath(os.path.normpath(os.fspath(path)))
    return candidate in native["current_paths"]


def _native_output_contains_private_value(transaction, policies, values: tuple[str, ...]) -> bool:
    """Scan transaction-private native sinks before publication; a match makes the whole batch unpublished."""
    tokens = tuple(sorted(
        {value.encode("utf-8", "strict") for value in values if len(value) >= 6},
        key=lambda value: (-len(value), value),
    ))
    if not tokens:
        return False
    paths = set()
    for policy in policies:
        for binding in policy.bindings:
            paths.add(Path(transaction.rewritten_cmd[binding.argv_index]))

    def file_contains(path: Path) -> bool:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            carry = b""
            overlap = max(len(token) for token in tokens) - 1
            while True:
                chunk = os.read(fd, 64 * 1024)
                if not chunk:
                    return False
                block = carry + chunk
                if any(token in block for token in tokens):
                    return True
                carry = block[-overlap:] if overlap else b""
        finally:
            os.close(fd)

    for path in sorted(paths, key=lambda item: str(item)):
        if not os.path.lexists(path):
            continue
        observed = path.lstat()
        if stat.S_ISREG(observed.st_mode):
            if file_contains(path):
                return True
        elif stat.S_ISDIR(observed.st_mode):
            for child in sorted(path.rglob("*"), key=lambda item: str(item)):
                child_observed = child.lstat()
                if stat.S_ISDIR(child_observed.st_mode):
                    continue
                if not stat.S_ISREG(child_observed.st_mode):
                    raise RuntimeError("native privacy scan encountered an unsupported object")
                if file_contains(child):
                    return True
        else:
            raise RuntimeError("native privacy scan encountered an unsupported root object")
    return False


def _run_with_repository(
    tool,
    cmd,
    *,
    repository,
    source_id: str | None = None,
    stdout,
    stderr,
    native_outputs,
    timeout,
    stdin_data,
    input_file,
    ok_empty,
    ok_codes,
    env,
    max_output_bytes,
    approved_peers,
    network_hosts,
    approved_peers_supplied,
    network_hosts_supplied,
) -> RunResult:
    """Normalize once, then delegate all execution publication authority."""
    from . import network_policy, runner_native, runner_protocol, runner_repository, store
    from .osint import OsintSession

    safe_cmd, argv_error = _preflight_argv(cmd)
    native_declared = type(native_outputs) is not tuple or bool(native_outputs)

    def mark_native_preflight(failed: RunResult) -> RunResult:
        if native_declared:
            _mark_native_outputs_unavailable(
                failed,
                len(native_outputs) if type(native_outputs) is tuple else 0,
                operation="validate",
                ownership_settled=True,
            )
        return failed

    if argv_error is not None:
        return mark_native_preflight(
            _preflight_failure(tool, safe_cmd, argv_error)
        )

    def preflight_failure(detail: str) -> RunResult:
        failed = _preflight_failure(tool, safe_cmd, detail)
        return mark_native_preflight(failed)

    safe_env, env_error = _preflight_environment(env)
    if env_error is not None:
        return preflight_failure(env_error)

    if type(repository) not in (store.Run, OsintSession):
        return preflight_failure("repository authority type is invalid")
    if (type(stdout) is not runner_repository.RepositoryOutput
            or type(stderr) is not runner_repository.RepositoryOutput):
        return preflight_failure("stdout and stderr require explicit repository policies")
    if type(native_outputs) is not tuple:
        return preflight_failure("native outputs require an exact tuple")
    if native_outputs and type(repository) is not store.Run:
        return preflight_failure("native outputs require Run ownership")

    # A bound policy scope is an explicit request for network-authorized
    # execution.  Admission must carry the literal source identity and the
    # caller's exact argv through the transport-door registry; otherwise a
    # scoped repository must not reach runtime identity preparation or spawn.
    network_hosts, approved_peers, network_input_error = _preflight_network_inputs(
        network_hosts, approved_peers,
        network_hosts_supplied=network_hosts_supplied,
        approved_peers_supplied=approved_peers_supplied,
    )
    if network_input_error is not None:
        return preflight_failure(network_input_error)
    policy_scope = network_policy.scope_for(repository)
    if network_hosts and policy_scope is None:
        return preflight_failure("network_hosts require a bound network policy scope")
    if policy_scope is not None:
        door = network_policy.transport_door(source_id, argv=safe_cmd)
        broker_free_bwrap = network_policy.binds_broker_free_launch_to_repository(
            door, safe_cmd, repository.dir,
        )
        if (door is None or not door.supported
                or (not door.broker_required and not broker_free_bwrap)):
            return preflight_failure(
                "bound network policy requires a supported broker source_id and exact transport door",
            )
        if door.profile in {"target-http-exact", "nuclei-authorized-http"} \
                and not network_hosts:
            return preflight_failure(
                "host-bound target transport requires caller-declared network hosts",
            )

    if type(repository) is store.Run:
        raw_path = runner_repository._expected_output_path(repository, stdout)
        stderr_path = runner_repository._expected_output_path(repository, stderr)
    else:
        raw_path = (None if stdout.disposition.value == "discard" else
                    os.path.abspath(str(repository.dir.joinpath(*stdout.components))))
        stderr_path = (None if stderr.disposition.value == "discard" else
                       os.path.abspath(str(repository.dir.joinpath(*stderr.components))))
    if native_outputs:
        try:
            runner_native._validate_prepare_inputs(repository, safe_cmd, native_outputs)
        except (TypeError, ValueError) as exc:
            return preflight_failure(
                f"native output policy rejected ({type(exc).__name__})"
            )

    if not have(safe_cmd[0]):
        missing = RunResult(
            tool, safe_cmd, Status.SKIPPED, None, 0.0, None, 0,
            note=f"{safe_cmd[0]} not on PATH", meta={"started": False},
        )
        if native_outputs:
            _mark_native_outputs_unavailable(
                missing, len(native_outputs), operation="execute",
                ownership_settled=True,
            )
        return missing

    prepared = None
    network_invocation = None
    network_settlement_attempted = False

    def settle_network_invocation(decision: str):
        """Settle a planned broker claim once without replacing a primary fault."""
        nonlocal network_settlement_attempted
        if network_invocation is None or network_settlement_attempted:
            return None
        network_settlement_attempted = True
        try:
            network_invocation.settle(
                decision=decision,
                reason=(
                    "repository supervisor returned an authenticated outcome"
                    if decision == "allow"
                    else "runner admission or repository supervision did not complete"
                ),
                summary={"runner": "repository"},
            )
        except BaseException as exc:
            return exc
        return None

    def is_authenticated_repository_outcome(outcome, current_invocation) -> bool:
        return bool(
            type(outcome) is runner_repository.RepositoryExecutionOutcome
            and outcome.execution.request_id == current_invocation.worker.request_id
        )

    try:
        from . import runtime_identity
        request_id = runner_protocol.new_request_id(os.urandom(16))
        prepared = runtime_identity.prepare_launch(
            tool, safe_cmd, caller_env=safe_env,
            payload_scope=getattr(repository, "_runtime_payload_scope", None),
        )
        runtime_identity.revalidate_launch(prepared)
        if policy_scope is not None and door.broker_required:
            resolved_peers = _resolve_network_hosts(
                policy_scope, request_id=request_id, source_id=source_id,
                network_hosts=network_hosts,
            ) if network_hosts else approved_peers
            network_invocation = policy_scope.prepare_invocation(
                request_id=request_id,
                source_id=source_id,
                tool=tool,
                argv=safe_cmd,
                environment=prepared.environment,
                runtime_identity=prepared.record,
                approved_peers=resolved_peers,
            )
        sealed_oob_resume = bool(
            type(repository) is store.Run
            and source_id == "params.oob_control"
            and repository.manifest_committed()
        )
        # A sealed OOB poll writes its identity into the unique unpublished
        # revision candidate after this contained execution settles.  Reopening
        # the canonical base identity directory here would violate the seal.
        identity_ref = (
            runtime_identity.publish_launch_identity(repository, request_id, prepared.record)
            if type(repository) is store.Run and not sealed_oob_resume else None
        )
        worker_environment = dict(prepared.environment)
        if prepared.redactions:
            worker_environment["QUARRY_RUNNER_PRIVATE_REDACTIONS"] = json.dumps(
                list(prepared.redactions), ensure_ascii=False, separators=(",", ":"),
            )
        if network_invocation is not None:
            worker_environment = network_invocation.attach(worker_environment)
        invocation = runner_protocol.normalize_invocation(
            request_id=request_id,
            tool=tool,
            cmd=list(prepared.argv),
            timeout=timeout,
            stdin_data=stdin_data,
            input_file=input_file,
            ok_empty=ok_empty,
            ok_codes=ok_codes,
            env=worker_environment,
            base_environment={},
            cwd=_TOOL_CWD,
            raw_path=raw_path,
            stderr_path=stderr_path,
            max_output_bytes=max_output_bytes,
            _deadline_sigint=(source_id == "params.oob_control"),
        )
    except BaseException as exc:
        settlement_fault = settle_network_invocation("deny")
        if prepared is not None:
            try:
                prepared.close()
            except BaseException as cleanup_fault:
                exc = _preferred_native_fault(exc, cleanup_fault)
        exc = _preferred_native_fault(exc, settlement_fault)
        if not isinstance(exc, Exception):
            raise exc.with_traceback(exc.__traceback__)
        return preflight_failure(f"runtime admission rejected ({type(exc).__name__})")

    runtime_meta = {
        "runtime_identity": prepared.record,
        "runtime_identity_ref": identity_ref,
        # The execution collector needs the same source-to-runtime argv mapping
        # that admission used; it must not infer it from rewritten paths.
        "runtime_source_argv_indexes": list(prepared.source_argv_indexes),
        # The original, admission-validated argv is evidence only.  Consumers
        # must bind it through the source-to-runtime mapping and the prepared
        # launch record; they must never resolve argv[0] through ambient PATH.
        "runtime_source_argv": list(safe_cmd),
    }

    started_at = time.monotonic()
    execution_started_at = _execution_timestamp()
    deadline = ((1 << 53) - 1 if invocation.worker.timeout == 0
                else started_at + float(invocation.worker.timeout) + 5.0)
    def supervise(current_invocation):
        supervisor = (
            runner_repository.supervise_repository_execution
            if type(repository) is store.Run
            else runner_repository.supervise_osint_execution
        )
        return supervisor(
            repository, current_invocation,
            stdout=stdout, stderr=stderr, deadline=deadline,
        )

    def machinery_failure(exc, *, started=False):
        failed = RunResult(
            tool, safe_cmd, Status.FAILED, None,
            round(time.monotonic() - started_at, 3), None, 0,
            note=f"repository execution failed ({type(exc).__name__})",
            meta={
                "started": started,
                "faults": [Fault(
                    "machinery", where=tool,
                    detail=f"repository execution failed ({type(exc).__name__})",
                ).to_dict()],
            },
        )
        failed.meta.update(runtime_meta)
        failed.meta["execution_started_at"] = execution_started_at
        failed.meta["execution_finished_at"] = _execution_timestamp()
        return failed

    def attach_runtime_testimony(result: RunResult) -> RunResult:
        """Attach immutable admission facts and parent-observed timing once."""
        result.meta.update(runtime_meta)
        result.meta["execution_started_at"] = execution_started_at
        result.meta["execution_finished_at"] = _execution_timestamp()
        _seal_repository_execution_testimony(result, repository)
        return result

    if not native_outputs:
        outcome = None
        operation_fault = None
        try:
            runtime_identity.revalidate_launch(prepared)
            outcome = supervise(invocation)
            if (network_invocation is not None
                    and not is_authenticated_repository_outcome(outcome, invocation)):
                raise RuntimeError("repository supervisor returned an unauthenticated outcome")
            if network_invocation is not None:
                settlement_fault = settle_network_invocation(
                    "allow" if outcome.clean else "deny",
                )
                if settlement_fault is not None:
                    raise settlement_fault
        except BaseException as exc:
            operation_fault = exc
            operation_fault = _preferred_native_fault(
                operation_fault, settle_network_invocation("deny"),
            )
        try:
            prepared.close()
        except BaseException as exc:
            operation_fault = _preferred_native_fault(operation_fault, exc)
        if operation_fault is not None:
            if not isinstance(operation_fault, Exception):
                raise operation_fault.with_traceback(operation_fault.__traceback__)
            return machinery_failure(operation_fault, started=outcome is not None)
        result = _repository_run_result(
            tool,
            safe_cmd,
            outcome,
            request=invocation.worker,
            stdout=stdout,
            stderr=stderr,
            stdout_path=raw_path,
            stderr_path=stderr_path,
            duration=time.monotonic() - started_at,
        )
        return attach_runtime_testimony(_attach_empty_native_output_receipt(result))

    owner = _NativeFacadeOwner(runner_native.NativeOutputAdoption())
    result = None
    operation_fault = None
    finish_fault = None
    private_output_refused = False
    try:
        with _NativeFacadeFence(owner):
            with _NativeFacadeFence(owner):
                owner.transaction = runner_native.prepare_native_outputs(
                    repository, safe_cmd, native_outputs,
                    adoption=owner.adoption,
                )
                if len(owner.transaction.rewritten_cmd) != len(prepared.source_argv_indexes):
                    raise RuntimeError("native output rewrite does not match admitted source argv")
                rewritten_argv = list(invocation.worker.argv)
                for source_index, runtime_index in enumerate(prepared.source_argv_indexes[1:], start=1):
                    rewritten_argv[runtime_index] = owner.transaction.rewritten_cmd[source_index]
                child_invocation = replace(
                    invocation,
                    worker=replace(
                        invocation.worker,
                        argv=tuple(rewritten_argv),
                    ),
                )
                runtime_identity.revalidate_launch(prepared)
                outcome = supervise(child_invocation)
                if (network_invocation is not None
                        and not is_authenticated_repository_outcome(outcome, child_invocation)):
                    raise RuntimeError("repository supervisor returned an unauthenticated outcome")
                if network_invocation is not None:
                    settlement_fault = settle_network_invocation(
                        "allow" if outcome.clean else "deny",
                    )
                    if settlement_fault is not None:
                        raise settlement_fault
                result = _repository_run_result(
                    tool,
                    safe_cmd,
                    outcome,
                    request=invocation.worker,
                    stdout=stdout,
                    stderr=stderr,
                    stdout_path=raw_path,
                    stderr_path=stderr_path,
                    duration=time.monotonic() - started_at,
                )
                result.meta.update(runtime_meta)
                before_deadline = time.monotonic() < deadline
                private_output_refused = _native_output_contains_private_value(
                    owner.transaction, native_outputs, prepared.redactions,
                )
                owner.receipt, finish_fault = _finish_native_outputs(
                    owner.transaction,
                    owner.adoption,
                    clean=(
                        before_deadline
                        and _native_execution_clean(outcome, invocation.worker)
                        and not private_output_refused
                    ),
                )
    except BaseException as exc:
        operation_fault = exc
        operation_fault = _preferred_native_fault(
            operation_fault, settle_network_invocation("deny"),
        )
    try:
        prepared.close()
    except BaseException as exc:
        operation_fault = _preferred_native_fault(operation_fault, exc)

    receipt = owner.receipt
    fault = _preferred_native_fault(
        operation_fault, finish_fault, owner.cleanup_fault,
    )
    if result is None:
        failed = machinery_failure(
            fault or RuntimeError("native execution did not settle")
        )
        if receipt is not None:
            _attach_native_output_receipt(failed, repository, receipt)
        else:
            _mark_native_outputs_unavailable(
                failed,
                len(native_outputs),
                operation="cleanup",
                fault_type=None if fault is None else type(fault).__name__,
                ownership_settled=False,
            )
        if fault is not None and not isinstance(fault, Exception):
            raise fault
        return failed

    if receipt is not None:
        _attach_native_output_receipt(result, repository, receipt)
    else:
        _mark_native_outputs_unavailable(
            result, len(native_outputs), operation="cleanup",
            fault_type=None if fault is None else type(fault).__name__,
            ownership_settled=False,
        )
        if result.status in (Status.SUCCESS, Status.EMPTY):
            result.status = Status.PARTIAL
            result.note = (
                result.note + "; " if result.note else ""
            ) + "native output settlement did not return a receipt"
    if private_output_refused:
        result.status = Status.FAILED
        result.note = (
            result.note + "; " if result.note else ""
        ) + "native output contained a framework credential and was refused"
        result.meta.setdefault("faults", []).append(
            Fault(
                "publication", where=tool,
                detail="native output contained a framework credential and was refused",
            ).to_dict()
        )
    if fault is not None and isinstance(fault, Exception):
        detail = f"native output settlement raised {type(fault).__name__}"
        result.meta.setdefault("faults", []).append(
            Fault("publication", where=tool, detail=detail).to_dict()
        )
        if result.status in (Status.SUCCESS, Status.EMPTY):
            result.status = Status.PARTIAL
            result.note = (result.note + "; " if result.note else "") + detail
    if fault is not None and not isinstance(fault, Exception):
        raise fault
    return attach_runtime_testimony(result)


def run(
    tool: str,
    cmd: list[str],
    *,
    repository=_REPOSITORY_POLICY_UNSET,
    source_id: str | None = None,
    stdout=_REPOSITORY_POLICY_UNSET,
    stderr=_REPOSITORY_POLICY_UNSET,
    native_outputs=(),
    raw_path: Path | None = None,
    timeout: int = 1800,
    stdin_data: str | None = None,
    input_file: Path | None = None,
    ok_empty: bool = True,
    ok_codes: tuple[int, ...] = (0,),
    env: dict | None = None,
    stderr_path: Path | None = None,
    max_output_bytes: int | None = None,
    approved_peers=_NETWORK_INPUT_UNSET,
    network_hosts=_NETWORK_INPUT_UNSET,
) -> RunResult:
    """Execute with explicit repository ownership and output dispositions.

    Production callers pass ``repository``, ``stdout`` and ``stderr``.  The
    path-based branch remains temporarily available only for unmanaged callers;
    a managed run artifact can no longer reach the legacy publisher.
    """
    approved_peers_supplied = approved_peers is not _NETWORK_INPUT_UNSET
    network_hosts_supplied = network_hosts is not _NETWORK_INPUT_UNSET
    if not approved_peers_supplied:
        approved_peers = ()
    if not network_hosts_supplied:
        network_hosts = ()
    # Do not ask an untrusted container for truthiness: a host declaration is
    # itself a managed-network request, including malformed declarations.
    network_hosts_declared = network_hosts_supplied
    policies = (repository, stdout, stderr)
    explicit = (
        any(value is not _REPOSITORY_POLICY_UNSET for value in policies)
        or type(native_outputs) is not tuple
        or bool(native_outputs)
        or network_hosts_declared
    )
    if explicit:
        safe_cmd, _error = _preflight_argv(cmd)

        def explicit_preflight_failure(detail: str) -> RunResult:
            failed = _preflight_failure(tool, safe_cmd, detail)
            if type(native_outputs) is not tuple or native_outputs:
                _mark_native_outputs_unavailable(
                    failed,
                    len(native_outputs) if type(native_outputs) is tuple else 0,
                    operation="validate",
                    ownership_settled=True,
                )
            return failed

        if any(value is _REPOSITORY_POLICY_UNSET for value in policies):
            return explicit_preflight_failure(
                "repository, stdout and stderr must be declared together",
            )
        if raw_path is not None or stderr_path is not None:
            return explicit_preflight_failure(
                "repository policies cannot be mixed with ambient output paths",
            )
        return _run_with_repository(
            tool,
            cmd,
            repository=repository,
            source_id=source_id,
            stdout=stdout,
            stderr=stderr,
            native_outputs=native_outputs,
            timeout=timeout,
            stdin_data=stdin_data,
            input_file=input_file,
            ok_empty=ok_empty,
            ok_codes=ok_codes,
            env=env,
            max_output_bytes=max_output_bytes,
            approved_peers=approved_peers,
            network_hosts=network_hosts,
            approved_peers_supplied=approved_peers_supplied,
            network_hosts_supplied=network_hosts_supplied,
        )

    return _legacy_run(
        tool,
        cmd,
        raw_path=raw_path,
        timeout=timeout,
        stdin_data=stdin_data,
        input_file=input_file,
        ok_empty=ok_empty,
        ok_codes=ok_codes,
        env=env,
        stderr_path=stderr_path,
        max_output_bytes=max_output_bytes,
    )


def skipped(tool: str, reason: str) -> RunResult:
    return RunResult(tool, [tool], Status.SKIPPED, None, 0.0, None, 0, note=reason)
