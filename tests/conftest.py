"""Shared pytest fixtures, exact lane classification, and the Python deny guard.

Two layers make ordinary Python network/subprocess entry points fail loudly:

1. Stable subprocess guards are installed before collection for every run.  This matters because several
   production functions capture ``subprocess.Popen`` in a default argument while test modules import.
   H0 tests may opt into one tightly constrained current-interpreter child with ``synthetic_process``;
   ordinary H0 tests still fail on every subprocess attempt.
2. When ``QUARRY_OFFLINE_CI`` is set, socket/resolver guards are also installed before collection.  The
   per-test autouse fixture provides the same runtime network tripwire for local H0 runs.

These guards are tracked-test tripwires, not child containment: reviewed Python fixture code could still
use an absolute native executable or its own network API.  The OS-isolated H0 evidence boundary therefore
remains open and is specified in ``docs/releases/RELEASE-GATES.md``.
"""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from quarry_recon import release_evidence as _release_evidence

_PRIMARY_LANES = (
    ("offline", "H0-hermetic"),
    ("integration", "H1-tool-integration"),
    ("corpus", "C0-private-corpus"),
    ("packaging", "P0-package-supply"),
    ("live", "L0-authorized-live"),
)
_PRIMARY_LANE_MARKERS = tuple(marker for marker, _lane in _PRIMARY_LANES)
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_TAXONOMY_SCHEMA = "quarry.pytest-taxonomy.v1"
_MAX_TAXONOMY_MANIFEST_BYTES = 2 * 1024 * 1024
_H0_SHARD_REPORT_SCHEMA = "quarry.h0-shard-outcome-report.v1"
_MAX_H0_SHARD_REPORT_BYTES = 64 * 1024
TAXONOMY_MANIFEST_KEY = pytest.StashKey()
H0_SHARD_REPORT_STATE_KEY = pytest.StashKey()
H0_COLLECTION_FAILURES_KEY = pytest.StashKey()
_h0_collection_config = None


def pytest_addoption(parser):
    group = parser.getgroup("quarry release diagnostics")
    group.addoption(
        "--quarry-taxonomy-manifest",
        metavar="PATH",
        help="write a new canonical diagnostic manifest for this collection",
    )
    group.addoption(
        "--quarry-h0-shard-report",
        metavar="PATH",
        help="write a new canonical H0 shard outcome report after the test session",
    )
    group.addoption(
        "--quarry-shard-count",
        default=1,
        metavar="N",
        type=int,
        help="split the selected tests into N deterministic CI shards",
    )
    group.addoption(
        "--quarry-shard-index",
        default=0,
        metavar="N",
        type=int,
        help="run deterministic CI shard N (zero based)",
    )


def _classify_test_item(item):
    """Return one primary lane and secondary capabilities, or raise a typed usage error."""
    primary = []
    for name in _PRIMARY_LANE_MARKERS:
        marks = tuple(item.iter_markers(name))
        if any(mark.args or mark.kwargs for mark in marks):
            raise pytest.UsageError(f"{item.nodeid}: primary marker {name!r} takes no arguments")
        if len(marks) > 1:
            raise pytest.UsageError(f"{item.nodeid}: duplicate primary marker {name!r}")
        if marks:
            primary.append(name)
    primary = tuple(primary)
    if len(primary) != 1:
        detail = "unmarked" if not primary else "multiple primary lanes: " + ", ".join(primary)
        raise pytest.UsageError(f"{item.nodeid}: {detail}")

    synthetic_marks = tuple(item.iter_markers("synthetic_process"))
    if any(mark.args or mark.kwargs for mark in synthetic_marks):
        raise pytest.UsageError(f"{item.nodeid}: synthetic_process takes no arguments")
    if len(synthetic_marks) > 1:
        raise pytest.UsageError(f"{item.nodeid}: duplicate synthetic_process annotation")
    synthetic = bool(synthetic_marks)
    if synthetic and primary[0] != "offline":
        raise pytest.UsageError(
            f"{item.nodeid}: synthetic_process is valid only in the offline/H0 lane"
        )

    tools = []
    for mark in item.iter_markers("requires_tool"):
        if (
            len(mark.args) != 1
            or mark.kwargs
            or type(mark.args[0]) is not str
            or not _TOOL_NAME_RE.fullmatch(mark.args[0])
        ):
            raise pytest.UsageError(
                f"{item.nodeid}: requires_tool must carry exactly one stable tool name"
            )
        tools.append(mark.args[0])
    if len(set(tools)) != len(tools):
        raise pytest.UsageError(f"{item.nodeid}: duplicate requires_tool annotation")
    if tools and primary[0] not in {"integration", "packaging"}:
        raise pytest.UsageError(
            f"{item.nodeid}: requires_tool is valid only in a reviewed H1/P0 lane"
        )
    if primary[0] == "integration" and not tools:
        raise pytest.UsageError(f"{item.nodeid}: integration/H1 test does not name its real tool")
    return primary[0], tuple(sorted(tools)), synthetic


def _utf8_key(value):
    try:
        return value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise pytest.UsageError("test taxonomy contains a non-Unicode node id") from exc


def _test_shard(nodeid, count):
    try:
        return _release_evidence.h0_shard_index(nodeid, count)
    except _release_evidence.EvidenceError as exc:
        raise pytest.UsageError(str(exc)) from exc


def _h0_roster_digest(nodeids):
    """Return the domain-separated digest for one sorted, unique node roster."""
    try:
        return _release_evidence.h0_roster_digest(nodeids)
    except _release_evidence.EvidenceError as exc:
        raise pytest.UsageError(str(exc)) from exc


def _apply_test_shard(config, items):
    count = config.getoption("quarry_shard_count")
    index = config.getoption("quarry_shard_index")
    if count < 1 or count > 64 or index < 0 or index >= count:
        raise pytest.UsageError("quarry test shard must satisfy 1 <= count <= 64 and 0 <= index < count")
    if count == 1:
        return
    selected = [item for item in items if _test_shard(item.nodeid, count) == index]
    deselected = [item for item in items if _test_shard(item.nodeid, count) != index]
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)


def _taxonomy_manifest_bytes(rows, selected_nodeids, *, mark_expression, keyword_expression):
    """Build the compact canonical diagnostic manifest; rows are the pre-deselection collection."""
    ordered_rows = sorted(rows, key=lambda row: _utf8_key(row[0]))
    nodeids = [row[0] for row in ordered_rows]
    if len(set(nodeids)) != len(nodeids):
        raise pytest.UsageError("test taxonomy contains duplicate node ids")
    selected = set(selected_nodeids)
    unknown = selected - set(nodeids)
    if unknown:
        raise pytest.UsageError(
            f"test selection introduced unknown node ids: {sorted(unknown, key=_utf8_key)!r}"
        )

    lanes = []
    selected_by_lane = []
    for marker, lane in _PRIMARY_LANES:
        members = [nodeid for nodeid, primary, _tools, _synthetic in ordered_rows
                   if primary == marker]
        lanes.append({"lane": lane, "marker": marker, "nodes": members})
        selected_by_lane.append({
            "lane": lane,
            "selected": sum(nodeid in selected for nodeid in members),
        })

    by_tool = {}
    synthetic_nodes = []
    for nodeid, _primary, tools, synthetic in ordered_rows:
        for tool in tools:
            by_tool.setdefault(tool, []).append(nodeid)
        if synthetic:
            synthetic_nodes.append(nodeid)
    capabilities = [
        {"name": name, "nodes": by_tool[name]}
        for name in sorted(by_tool, key=_utf8_key)
    ]
    document = {
        "capabilities": capabilities,
        "collector": {
            "name": "pytest",
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "version": pytest.__version__,
        },
        "lanes": lanes,
        "schema_version": _TAXONOMY_SCHEMA,
        "selection": {
            "collected": len(nodeids),
            "deselected": len(nodeids) - len(selected),
            "keyword_expression": keyword_expression,
            "mark_expression": mark_expression,
            "selected": len(selected),
            "selected_by_lane": selected_by_lane,
        },
        "synthetic_process_nodes": synthetic_nodes,
    }
    try:
        encoded = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", "strict")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise pytest.UsageError(f"cannot encode test taxonomy manifest: {exc}") from exc
    if len(encoded) > _MAX_TAXONOMY_MANIFEST_BYTES:
        raise pytest.UsageError(
            f"test taxonomy manifest is {len(encoded)} bytes; limit is "
            f"{_MAX_TAXONOMY_MANIFEST_BYTES}"
        )
    return encoded


def _write_new_private(path, body, *, label="taxonomy manifest"):
    """Create one diagnostic output without following or overwriting its final path."""
    target = os.fspath(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except OSError as exc:
        raise pytest.UsageError(f"cannot create {label} {target!r}: {exc}") from exc
    created = True
    try:
        view = memoryview(body)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(f"short {label} write")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        created = False
    except BaseException as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        if created:
            try:
                os.unlink(target)
            except OSError:
                pass
        if not isinstance(exc, Exception):
            raise
        raise pytest.UsageError(f"cannot write {label} {target!r}: {exc}") from exc


def _start_h0_shard_report(config, rows, selected_nodeids):
    """Freeze the H0 evidence boundary from taxonomy rows; never recollect."""
    output = config.getoption("quarry_h0_shard_report")
    if not output:
        return
    if (config.getoption("markexpr") or "") != "offline" or (config.getoption("keyword") or ""):
        raise pytest.UsageError(
            "H0 shard outcome report requires exactly '-m offline' and no keyword expression"
        )
    node_lane = {nodeid: lane for nodeid, lane, _tools, _synthetic in rows}
    selected = sorted(selected_nodeids, key=_utf8_key)
    if not selected:
        raise pytest.UsageError("H0 shard outcome report refuses a vacuous selection")
    unknown = set(selected) - set(node_lane)
    if unknown:
        raise pytest.UsageError(
            "H0 shard outcome report selection has unknown node ids: "
            f"{sorted(unknown, key=_utf8_key)!r}"
        )
    non_h0 = [nodeid for nodeid in selected if node_lane[nodeid] != "offline"]
    if non_h0:
        raise pytest.UsageError(
            "H0 shard outcome report accepts only offline/H0 selection: "
            f"{non_h0!r}"
        )
    full_h0 = sorted(
        (nodeid for nodeid, lane, _tools, _synthetic in rows if lane == "offline"),
        key=_utf8_key,
    )
    config.stash[H0_SHARD_REPORT_STATE_KEY] = {
        "collection_failures": config.stash.get(H0_COLLECTION_FAILURES_KEY, 0),
        "full_h0": full_h0,
        "output": output,
        "reports": {nodeid: {} for nodeid in selected},
        "selected": selected,
    }


def _record_h0_report(state, report):
    """Retain exactly one pytest setup/call/teardown report for each selected node."""
    if report.nodeid not in state["reports"]:
        raise pytest.UsageError(f"H0 shard outcome report received unknown result {report.nodeid!r}")
    if report.when not in {"setup", "call", "teardown"}:
        raise pytest.UsageError(f"H0 shard outcome report received unknown phase {report.when!r}")
    if report.outcome not in {"passed", "failed", "skipped"}:
        raise pytest.UsageError(f"H0 shard outcome report received unknown outcome {report.outcome!r}")
    phases = state["reports"][report.nodeid]
    if report.when in phases:
        raise pytest.UsageError(
            f"H0 shard outcome report received duplicate {report.when} result for {report.nodeid!r}"
        )
    phases[report.when] = (report.outcome, getattr(report, "wasxfail", None))


def _h0_node_outcome(nodeid, phases):
    """Compose pytest's phase reports into one mutually exclusive test outcome."""
    setup = phases.get("setup")
    call = phases.get("call")
    teardown = phases.get("teardown")
    if setup is None or teardown is None:
        raise pytest.UsageError(f"H0 shard outcome report has incomplete results for {nodeid!r}")
    if setup[0] == "failed" or teardown[0] == "failed":
        return "failed"
    if call is None:
        if setup[0] == "skipped":
            return "xfailed" if setup[1] else "skipped"
        raise pytest.UsageError(f"H0 shard outcome report has incomplete results for {nodeid!r}")
    terminal = call
    outcome, wasxfail = terminal
    if outcome == "passed":
        return "xpassed" if wasxfail else "passed"
    if outcome == "skipped":
        return "xfailed" if wasxfail else "skipped"
    return "xpassed" if wasxfail else "failed"


def _h0_shard_report_bytes(config, state, exitstatus):
    outcomes = {name: 0 for name in ("failed", "skipped", "xfailed", "xpassed", "passed")}
    passed_nodes = []
    for nodeid in state["selected"]:
        node_outcome = _h0_node_outcome(nodeid, state["reports"][nodeid])
        outcomes[node_outcome] += 1
        if node_outcome == "passed":
            passed_nodes.append(nodeid)
    document = {
        "collector": {
            "name": "pytest",
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "version": pytest.__version__,
        },
        "collection_failures": state["collection_failures"],
        "full_h0_roster": {
            "count": len(state["full_h0"]),
            "digest": _h0_roster_digest(state["full_h0"]),
        },
        "keyword_expression": config.getoption("keyword") or "",
        "mark_expression": config.getoption("markexpr") or "",
        "outcomes": outcomes,
        "passed_roster": {
            "count": len(passed_nodes),
            "digest": _h0_roster_digest(passed_nodes),
        },
        "schema_version": _H0_SHARD_REPORT_SCHEMA,
        "selected_roster": {
            "count": len(state["selected"]),
            "digest": _h0_roster_digest(state["selected"]),
        },
        "session_exit_code": int(exitstatus),
        "shard_count": config.getoption("quarry_shard_count"),
        "shard_index": config.getoption("quarry_shard_index"),
    }
    try:
        body = json.dumps(
            document, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8", "strict")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise pytest.UsageError(f"cannot encode H0 shard outcome report: {exc}") from exc
    if len(body) > _MAX_H0_SHARD_REPORT_BYTES:
        raise pytest.UsageError(
            f"H0 shard outcome report is {len(body)} bytes; limit is {_MAX_H0_SHARD_REPORT_BYTES}"
        )
    return body


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Classify the complete collection before pytest's ``-m`` deselection runs."""
    errors = []
    rows = []
    for item in items:
        try:
            lane, tools, synthetic = _classify_test_item(item)
        except pytest.UsageError as exc:
            errors.append(str(exc))
        else:
            rows.append((item.nodeid, lane, tools, synthetic))
    if errors:
        rendered = "\n".join(f"  - {message}" for message in sorted(errors))
        raise pytest.UsageError(f"test taxonomy violations:\n{rendered}")
    yield
    post_marker_nodeids = [item.nodeid for item in items]
    body = _taxonomy_manifest_bytes(
        rows,
        post_marker_nodeids,
        mark_expression=config.getoption("markexpr") or "",
        keyword_expression=config.getoption("keyword") or "",
    )
    config.stash[TAXONOMY_MANIFEST_KEY] = body
    output = config.getoption("quarry_taxonomy_manifest")
    if output:
        _write_new_private(output, body)
    _apply_test_shard(config, items)
    _start_h0_shard_report(config, rows, [item.nodeid for item in items])


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    state = item.config.stash.get(H0_SHARD_REPORT_STATE_KEY, None)
    if state is not None:
        _record_h0_report(state, outcome.get_result())


def pytest_sessionfinish(session, exitstatus):
    state = session.config.stash.get(H0_SHARD_REPORT_STATE_KEY, None)
    if state is not None:
        _write_new_private(
            state["output"],
            _h0_shard_report_bytes(session.config, state, exitstatus),
            label="H0 shard outcome report",
        )


class FakeDirectContainment:
    """A parent-owned direct-containment handle for supervisor tests."""

    def __init__(self, controller, request_id):
        from quarry_recon import runner_protocol as protocol

        self._controller = controller
        self.request_id = request_id
        self.kind = controller.kind
        self.containment_id = (
            controller.containment_id
            if controller.containment_id is not None
            else f"direct/quarry-{request_id}"
        )
        self.bind_proofs = []
        self.settlement_deadlines = []
        self.close_calls = 0
        self.terminal = False
        self.containment_assurance = protocol.ContainmentAssurance.COOPERATIVE_SCOPE

    def bind_parked_process(self, proof):
        from quarry_recon import runner_containment as containment

        self.bind_proofs.append(proof)
        self._controller.events.append(("bind", proof))
        if self._controller.bind_exception is not None:
            raise self._controller.bind_exception
        result = self._controller.bind_result
        if result is None:
            result = containment.MembershipVerification(
                True, containment.ContainmentReason.VERIFIED,
            )
        return result

    def verify_pid(self, identity):
        from quarry_recon import runner_containment as containment

        self._controller.events.append(("verify", identity))
        return containment.MembershipVerification(
            True, containment.ContainmentReason.VERIFIED,
        )

    def verify_started_pid(self, identity):
        return self.verify_pid(identity)

    def kill_settle_remove(self, deadline):
        from quarry_recon import runner_containment as containment

        self.settlement_deadlines.append(deadline)
        self._controller.events.append(("settle", deadline))
        if self._controller.settlement_exception is not None:
            raise self._controller.settlement_exception
        result = self._controller.settlement_result
        if result is None:
            result = containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
        self.terminal = (
            result.reason is containment.ContainmentReason.SETTLED
            and result.cooperative_settled
        )
        return result

    def close(self):
        self.close_calls += 1
        self._controller.events.append(("close", None))
        if self._controller.close_exception is not None:
            raise self._controller.close_exception
        self.terminal = True


class FakeDirectContainmentFactory:
    """Configurable acquisition seam with durable call-order observations."""

    def __init__(self):
        from quarry_recon import runner_protocol as protocol

        self.kind = protocol.ContainmentKind.CGROUP_V2
        self.containment_id = None
        self.acquire_exception = None
        self.bind_exception = None
        self.bind_result = None
        self.settlement_exception = None
        self.settlement_result = None
        self.close_exception = None
        self.acquire_calls = []
        self.handles = []
        self.events = []

    def __call__(self, request_id):
        self.acquire_calls.append(request_id)
        self.events.append(("acquire", request_id))
        if self.acquire_exception is not None:
            raise self.acquire_exception
        handle = FakeDirectContainment(self, request_id)
        self.handles.append(handle)
        return handle

    @property
    def handle(self):
        assert self.handles, "direct containment was not acquired"
        return self.handles[-1]


class NetworkDenied(RuntimeError):
    """Raised when an offline test attempts a real network connection or spawns a subprocess."""


def _blocked(*a, **k):
    raise NetworkDenied("test lane denied a network or subprocess operation")


_REAL_SUBPROCESS_POPEN = subprocess.Popen
_REAL_SUBPROCESS_RUN = subprocess.run
_SYNTHETIC_INTERPRETER = sys.executable
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if type(_SYNTHETIC_INTERPRETER) is not str or not os.path.isabs(_SYNTHETIC_INTERPRETER):
    raise RuntimeError("pytest requires an absolute current interpreter for synthetic_process")
_PROCESS_DENY = "deny"
_PROCESS_SYNTHETIC = "synthetic"
_PROCESS_EXTERNAL = "external"
_process_mode = _PROCESS_DENY
_synthetic_home_root = None
_SYNTHETIC_BASE_ENV = frozenset({"HOME", "PATH"})
_SYNTHETIC_PROTOCOL_ENV = frozenset({
    "QUARRY_RUNNER_EXECUTION",
    "QUARRY_RUNNER_EXPECTED_PARENT_PID",
    "QUARRY_RUNNER_PREPARED_ABORT",
    "QUARRY_RUNNER_STDERR_FD",
    "QUARRY_RUNNER_STDIN_FD",
    "QUARRY_RUNNER_STDOUT_FD",
})


def _validate_synthetic_spawn(argv, positional, kwargs, *, home_root):
    """Refuse every H0 child shape except the declared current-interpreter fixture."""
    if positional or type(argv) not in (list, tuple) or not argv:
        raise NetworkDenied("synthetic_process requires one argv list/tuple")
    if any(type(part) is not str for part in argv):
        raise NetworkDenied("synthetic_process argv must contain exact strings")
    if not os.path.isabs(argv[0]) or argv[0] != _SYNTHETIC_INTERPRETER:
        raise NetworkDenied("synthetic_process may execute only the absolute current interpreter")
    if kwargs.get("shell", False) is not False:
        raise NetworkDenied("synthetic_process forbids shell execution")
    if kwargs.get("executable") is not None:
        raise NetworkDenied("synthetic_process forbids an executable override")
    if kwargs.get("preexec_fn") is not None:
        raise NetworkDenied("synthetic_process forbids a pre-exec callback")
    if "close_fds" in kwargs and kwargs["close_fds"] is not True:
        raise NetworkDenied("synthetic_process forbids ambient descriptor inheritance")
    for name in ("startupinfo", "user", "group", "extra_groups"):
        if kwargs.get(name) is not None:
            raise NetworkDenied(f"synthetic_process forbids non-default {name}")
    for name, default in (("creationflags", 0), ("umask", -1), ("process_group", -1)):
        if name in kwargs and (type(kwargs[name]) is not int or kwargs[name] != default):
            raise NetworkDenied(f"synthetic_process forbids non-default {name}")

    stream_values = {
        "stdin": (None, subprocess.PIPE, subprocess.DEVNULL),
        "stdout": (None, subprocess.PIPE, subprocess.DEVNULL),
        "stderr": (None, subprocess.PIPE, subprocess.DEVNULL, subprocess.STDOUT),
    }
    for name, allowed_values in stream_values.items():
        value = kwargs.get(name)
        if value is not None and (type(value) is not int or value not in allowed_values):
            raise NetworkDenied(f"synthetic_process forbids a borrowed {name} descriptor")

    cwd = kwargs.get("cwd")
    try:
        cwd_text = os.fspath(cwd)
    except TypeError as exc:
        raise NetworkDenied("synthetic_process requires an explicit absolute cwd") from exc
    if type(cwd_text) is not str or not os.path.isabs(cwd_text):
        raise NetworkDenied("synthetic_process requires an explicit absolute cwd")

    env = kwargs.get("env")
    if type(env) is not dict or any(type(key) is not str or type(value) is not str
                                    for key, value in env.items()):
        raise NetworkDenied("synthetic_process requires an explicit string-only environment")
    worker = tuple(argv[1:]) == ("-I", "-m", "quarry_recon.runner_worker")
    allowed = _SYNTHETIC_PROTOCOL_ENV if worker else _SYNTHETIC_BASE_ENV
    extra = set(env) - allowed
    if extra:
        raise NetworkDenied("synthetic_process environment contains a non-allowlisted key")

    if worker:
        if cwd_text != "/":
            raise NetworkDenied("synthetic worker requires cwd='/'")
        parent = env.get("QUARRY_RUNNER_EXPECTED_PARENT_PID")
        prepared = env.get("QUARRY_RUNNER_PREPARED_ABORT")
        execution = env.get("QUARRY_RUNNER_EXECUTION")
        if not (parent and parent.isascii() and parent.isdigit() and int(parent) > 0):
            raise NetworkDenied("synthetic worker environment has no valid parent identity")
        if prepared not in (None, "1") or execution not in (None, "1"):
            raise NetworkDenied("synthetic worker environment has an invalid execution mode")
        if (prepared == "1") == (execution == "1"):
            raise NetworkDenied("synthetic worker environment needs exactly one execution mode")
        descriptor_names = (
            "QUARRY_RUNNER_STDOUT_FD",
            "QUARRY_RUNNER_STDERR_FD",
            "QUARRY_RUNNER_STDIN_FD",
        )
        descriptor_values = []
        for name in descriptor_names:
            value = env.get(name)
            if value is not None:
                if not (value.isascii() and value.isdigit() and str(int(value)) == value):
                    raise NetworkDenied("synthetic worker environment contains an invalid descriptor")
                descriptor = int(value)
                if descriptor <= 2:
                    raise NetworkDenied("synthetic worker protocol descriptor is ambient stdio")
                descriptor_values.append(descriptor)
        expected_descriptors = set(descriptor_values)
        if len(expected_descriptors) != len(descriptor_values):
            raise NetworkDenied("synthetic worker protocol descriptors must be unique")
        pass_fds = kwargs.get("pass_fds", ())
        if (
            type(pass_fds) is not tuple
            or any(type(fd) is not int or fd < 0 for fd in pass_fds)
            or len(set(pass_fds)) != len(pass_fds)
            or set(pass_fds) != expected_descriptors
        ):
            raise NetworkDenied("synthetic worker pass_fds do not exactly match protocol descriptors")
        if prepared == "1" and (expected_descriptors or pass_fds):
            raise NetworkDenied("synthetic abort worker forbids protocol descriptor handoff")
    else:
        pass_fds = kwargs.get("pass_fds", ())
        if type(pass_fds) is not tuple or pass_fds:
            raise NetworkDenied("synthetic_process ordinary child forbids descriptor inheritance")
        home = env.get("HOME")
        if home_root is None or not home or not os.path.isabs(home):
            raise NetworkDenied("synthetic_process requires a disposable absolute HOME")
        try:
            if not Path(home).resolve().is_relative_to(Path(home_root).resolve()):
                raise NetworkDenied("synthetic_process HOME is outside the pytest temporary root")
        except OSError as exc:
            raise NetworkDenied("synthetic_process HOME cannot be resolved") from exc
        if env.get("PATH") != "":
            raise NetworkDenied("synthetic_process PATH must be empty")
        try:
            resolved_cwd = Path(cwd_text).resolve()
            permitted_roots = (_REPOSITORY_ROOT, Path(home_root).resolve())
            if not any(
                resolved_cwd == root or resolved_cwd.is_relative_to(root)
                for root in permitted_roots
            ):
                raise NetworkDenied("synthetic_process cwd is outside controlled roots")
        except OSError as exc:
            raise NetworkDenied("synthetic_process cwd cannot be resolved") from exc


def _authorize_process(argv, positional, kwargs):
    if _process_mode == _PROCESS_EXTERNAL:
        return
    if _process_mode != _PROCESS_SYNTHETIC:
        raise NetworkDenied("test lane denied subprocess execution")
    _validate_synthetic_spawn(argv, positional, kwargs, home_root=_synthetic_home_root)


class _GuardedPopen(_REAL_SUBPROCESS_POPEN):
    """Stable pre-collection proxy, including for production defaults captured at import."""

    def __init__(self, args, *positional, **kwargs):
        _authorize_process(args, positional, kwargs)
        super().__init__(args, *positional, **kwargs)


def _guarded_run(*popenargs, **kwargs):
    if len(popenargs) != 1:
        if not popenargs and "args" in kwargs:
            argv = kwargs["args"]
            remaining = ()
        else:
            raise NetworkDenied("subprocess.run requires one explicit argv")
    else:
        argv = popenargs[0]
        remaining = ()
    _authorize_process(argv, remaining, kwargs)
    return _REAL_SUBPROCESS_RUN(*popenargs, **kwargs)


def _family_aware_connect(original):
    """Deny an AF_INET/INET6 (network) connect; permit AF_UNIX — that is internal IPC (e.g. multiprocessing's
    forkserver), not network, and blocking it would break the killable-worker resolver."""
    def guard(self, *a, **k):
        if getattr(self, "family", None) == getattr(socket, "AF_UNIX", object()):
            return original(self, *a, **k)
        raise NetworkDenied("test lane denied an Internet-family network connect")
    return guard


# Patch CONNECT/RESOLVE/SEND entry points, not socket.socket itself (replacing the class breaks
# ``ssl.SSLSocket(socket.socket)`` subclassing). AF_UNIX remains available for internal IPC.
def _network_blockers():
    return [
        (socket.socket, "connect", _family_aware_connect(socket.socket.connect)),
        (socket.socket, "connect_ex", _family_aware_connect(socket.socket.connect_ex)),
        (socket.socket, "sendto", _blocked),
        (socket, "create_connection", _blocked), (socket, "getaddrinfo", _blocked),
        (socket, "gethostbyname", _blocked), (socket, "gethostbyname_ex", _blocked),
    ]


# ── layer 1: stable process guard plus CI pre-collection network guard ──
_saved: list = []


def pytest_configure(config):
    global _h0_collection_config
    blockers = [
        (subprocess, "Popen", _GuardedPopen),
        (subprocess, "run", _guarded_run),
    ]
    if os.environ.get("QUARRY_OFFLINE_CI"):
        blockers.extend(_network_blockers())
    for obj, attr, replacement in blockers:
        _saved.append((obj, attr, getattr(obj, attr)))
        setattr(obj, attr, replacement)
    if config.getoption("quarry_h0_shard_report"):
        config.stash[H0_COLLECTION_FAILURES_KEY] = 0
        _h0_collection_config = config


def pytest_collectreport(report):
    """Keep collection errors distinct from per-node execution outcomes."""
    if report.failed:
        config = _h0_collection_config
        if config is not None and config.stash.get(H0_COLLECTION_FAILURES_KEY, None) is not None:
            config.stash[H0_COLLECTION_FAILURES_KEY] += 1


def pytest_unconfigure(config):
    global _h0_collection_config
    for obj, attr, original in reversed(_saved):
        setattr(obj, attr, original)
    _saved.clear()
    if _h0_collection_config is config:
        _h0_collection_config = None


# ── layer 2: per-test autouse guard (local dev) ──
@pytest.fixture(autouse=True)
def _network_deny(request, monkeypatch, tmp_path_factory):
    """Select process authority and deny Python network entry points for network-free lanes."""
    global _process_mode, _synthetic_home_root
    previous_mode, previous_root = _process_mode, _synthetic_home_root
    integration = request.node.get_closest_marker("integration") is not None
    live = request.node.get_closest_marker("live") is not None
    packaging = request.node.get_closest_marker("packaging") is not None
    synthetic = request.node.get_closest_marker("synthetic_process") is not None
    if integration or live or packaging:
        _process_mode = _PROCESS_EXTERNAL
    elif synthetic:
        _process_mode = _PROCESS_SYNTHETIC
    else:
        _process_mode = _PROCESS_DENY
    _synthetic_home_root = tmp_path_factory.getbasetemp()
    if not integration and not live:
        for obj, attr, replacement in _network_blockers():
            monkeypatch.setattr(obj, attr, replacement)
    try:
        yield
    finally:
        _process_mode, _synthetic_home_root = previous_mode, previous_root


# ── shared fixtures ──
@pytest.fixture
def run_result():
    from quarry_recon.runner import RunResult, Status

    def _make(status=Status.SUCCESS, exit_code=0, stderr_tail="", raw_path=None, stdout_lines=0):
        return RunResult("tool", [], status, exit_code, 0.1, raw_path, stdout_lines, stderr_tail=stderr_tail)

    return _make


@pytest.fixture
def profile(tmp_path):
    from quarry_recon.config import TargetProfile

    def _make(body: str = "", apex: str = "example.com"):
        p = tmp_path / "target.yaml"
        p.write_text(f"TARGET: t\nAPEX_DOMAINS:\n  - {apex}\n{body}")
        return TargetProfile.load(p)

    return _make


@pytest.fixture
def fake_direct_containment(monkeypatch):
    """Replace supervisor acquisition with a fresh typed direct handle."""
    from quarry_recon import runner_supervisor as supervisor

    factory = FakeDirectContainmentFactory()
    monkeypatch.setattr(
        supervisor, "acquire_direct_cgroup_v2", factory, raising=False,
    )
    return factory


@pytest.fixture(autouse=True)
def _no_provider_pacing(request, monkeypatch):
    """Offline tests have no provider to be polite to, so they must not SLEEP for one.

    Shodan requests are paced at ~1/s in production (we generated our own 429s without it, and paid up
    to 300 s for each). Offline the network is blocked outright, so the interval protects nothing and
    only makes the suite three times slower. Tests that assert the pacing MECHANISM set the interval
    themselves; `live`/`integration` tests keep the real one."""
    if request.node.get_closest_marker("live") or request.node.get_closest_marker("integration"):
        return
    try:
        from quarry_recon.phases import probe
    except Exception:
        return
    monkeypatch.setattr(probe, "_SHODAN_MIN_INTERVAL_S", 0.0, raising=False)


@pytest.fixture(autouse=True)
def _isolated_pace_state(tmp_path_factory, monkeypatch):
    """The provider pacing state is INSTALLATION-WIDE (`~/.config/quarry/pace`) — which is exactly why a
    test must never write to it: one test's persisted 429 penalty would pace every later test, and the
    suite would be editing the operator's real account state. Each test gets its own directory."""
    try:
        from quarry_recon import pace
    except Exception:
        return
    monkeypatch.setattr(pace, "PACE_DIR", tmp_path_factory.mktemp("pace"), raising=False)
