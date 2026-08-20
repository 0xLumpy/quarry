"""Source identity admission at the repository runner boundary."""

import ast
import hashlib
import shlex
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY

import pytest

from quarry_recon import (contract, events, netguard, network_dns, resource_contract,
                          runner, runner_protocol, runner_repository, runner_supervisor,
                          runtime_identity, store)
import quarry_recon.network_policy as network_policy
from quarry_recon.runner import Status
from quarry_recon.runner_native import RepositoryNativeOutput
from quarry_recon.runner_repository import RepositoryOutput
from quarry_recon.phases import crawl as crawl_phase


pytestmark = pytest.mark.offline


_PRODUCTION_DIRECT_ROOTS = (
    Path(__file__).parents[1] / "src" / "quarry_recon" / "osint.py",
    Path(__file__).parents[1] / "src" / "quarry_recon" / "phases",
)


def _chunks_bwrap_command(tmp_path, monkeypatch, *, artifact_root=None):
    shim = tmp_path / "jxscout-chunks"
    shim.write_text("#!/bin/sh\nexit 0\n")
    shim.chmod(0o755)
    bundle = Path(artifact_root or tmp_path) / "bundle.js"
    bundle.write_text("x")
    scratch = Path(artifact_root or tmp_path) / "quarry-jxscout-test"
    scratch.mkdir(mode=0o700)
    real_which = crawl_phase.shutil.which
    monkeypatch.setattr(
        crawl_phase.shutil, "which",
        lambda name, *args, **kwargs: (
            str(shim) if name == "jxscout-chunks"
            else "/usr/bin/bwrap" if name == "bwrap"
            else real_which(name, *args, **kwargs)
        ),
    )
    return crawl_phase._jxscout_sandbox(
        ["jxscout-chunks", str(bundle), "0"], scratch / "out.txt", scratch / "err.txt",
    )


def _direct_exec_calls():
    """Yield managed production facade calls and their enclosing function names."""
    for root in _PRODUCTION_DIRECT_ROOTS:
        paths = (root,) if root.is_file() else sorted(root.glob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            parents = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "exec_tool"):
                    continue
                owner = node
                while owner is not None and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = parents.get(owner)
                yield path, node, owner.name if owner is not None else None


def test_every_managed_production_direct_call_binds_a_registered_transport_source():
    """A repository-owned direct facade call must not silently lose network authority identity.

    The one parameterized lane (jsluice) is deliberately accepted only through its finite local map;
    arbitrary user input must never become a source id.  For every call, the registered door's
    executable identity is also checked against the literal facade tool name.
    """
    seen = 0
    for path, call, owner in _direct_exec_calls():
        seen += 1
        source_kw = next((kw for kw in call.keywords if kw.arg == "source_id"), None)
        assert source_kw is not None, f"{path}:{call.lineno} omits source_id"
        if isinstance(source_kw.value, ast.Constant):
            source_ids = (source_kw.value.value,)
        elif path.name == "vertical.py" and owner == "_probe_one":
            # `_wc_differentiate` is shared by exactly these two registered
            # wildcard lanes; its caller supplies one of this finite pair.
            source_ids = ("vertical.wildcard_http", "enrich.wildcard_a1d")
        else:
            assert path.name == "crawl.py" and owner == "_jsluice_run"
            source_ids = ("crawl.jsluice_urls", "crawl.jsluice_secrets")
        assert all(isinstance(source_id, str) for source_id in source_ids)
        tool = call.args[0] if call.args else None
        assert isinstance(tool, ast.Constant) and isinstance(tool.value, str), \
            f"{path}:{call.lineno} has no literal runner tool name"
        for source_id in source_ids:
            door = network_policy.TRANSPORT_DOORS.get(source_id)
            assert door is not None, (path, call.lineno, source_id)
            assert door.argv0 and Path(tool.value).name in door.argv0, \
                (path, call.lineno, source_id, tool.value, door.argv0)
            probe_argv = (tool.value, *door.required_argv)
            if door.profile == "nuclei-authorized-http":
                probe_argv += ("-pt", "http,dns")
            assert network_policy.transport_door(source_id, argv=probe_argv) is not None, \
                (path, call.lineno, source_id, probe_argv)
    assert seen >= 30


def _running_run(tmp_path):
    run = store.Run.create(tmp_path, "acme.example", run_id="source-id-test")
    run.write_state("running")
    return run


def _managed_call(run, command, **kwargs):
    return runner.run(
        "fixture", command,
        repository=run,
        stdout=RepositoryOutput.discard(),
        stderr=RepositoryOutput.discard(),
        timeout=1,
        **kwargs,
    )


def _forbid_launch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network admission crossed the launch boundary")

    monkeypatch.setattr(runner, "have", forbidden)
    monkeypatch.setattr(runtime_identity, "prepare_launch", forbidden)
    monkeypatch.setattr(runner.subprocess, "Popen", forbidden)


def _authenticated_outcome(request_id, *, clean=False):
    if clean:
        empty_digest = hashlib.sha256(b"").hexdigest()
        settlement = runner_protocol.WorkerSettlement(
            request_id=request_id,
            terminal=runner_protocol.ExecutionTerminal.COMPLETE,
            launched=True,
            exit_code=1,
            process_group_settled=True,
            process_tree_settled=False,
            streams=(
                runner_protocol.StreamSettlement(
                    role=runner_protocol.StreamRole.STDIN,
                    terminal=runner_protocol.StreamTerminal.COMPLETE,
                    observed_bytes=0,
                    retained_bytes=0,
                    observed_sha256=empty_digest,
                    retained_sha256=None,
                ),
                *(
                    runner_protocol.StreamSettlement(
                        role=role,
                        terminal=runner_protocol.StreamTerminal.EOF,
                        observed_bytes=0,
                        retained_bytes=0,
                        observed_sha256=empty_digest,
                        retained_sha256=None,
                    )
                    for role in (
                        runner_protocol.StreamRole.STDOUT,
                        runner_protocol.StreamRole.STDERR,
                    )
                ),
            ),
            worker_pid=51231,
            tool_pid=51232,
        )
        execution = runner_supervisor.ExecutionOutcome(
            reason=runner_supervisor.ExecutionReason.COMPLETE,
            request_id=request_id,
            worker_pid=51231,
            settlement=settlement,
            validated=runner_protocol.ValidatedSettlement(
                worker=settlement,
                mechanically_settled=True,
                containment_assurance=runner_protocol.ContainmentAssurance.COOPERATIVE_SCOPE,
                escape_protected=False,
                tree_proven=False,
                clean_eligible=True,
                capture_complete=True,
                _authority=runner_protocol._VALIDATION_AUTHORITY,
            ),
            worker_returncode=0,
            worker_spawned=True,
            worker_reaped=True,
            control_eof=True,
            go_command_sent=True,
            parent_pipes_closed=True,
            containment_settled=True,
            stages_settled=True,
            _authority=runner_supervisor._EXECUTION_OUTCOME_AUTHORITY,
        )
    else:
        execution = runner_supervisor.ExecutionOutcome(
            reason=runner_supervisor.ExecutionReason.INCOMPLETE,
            request_id=request_id,
            stages_settled=True,
            _authority=runner_supervisor._EXECUTION_OUTCOME_AUTHORITY,
        )
    return runner_repository.RepositoryExecutionOutcome(
        execution=execution,
        publication=runner_repository.RepositoryPublication.NOT_REQUESTED,
        requested_roles=(),
        discarded_roles=(
            runner_protocol.StreamRole.STDOUT,
            runner_protocol.StreamRole.STDERR,
        ),
    )


class _PreparedLaunch:
    def __init__(self, argv):
        self.argv = tuple(argv)
        self.environment = {"PREPARED": "yes"}
        self.record = {"identity": "prepared"}
        self.redactions = ()
        self.source_argv_indexes = tuple(range(len(argv)))
        self.closed = False

    def close(self):
        self.closed = True


class _PolicyInvocation:
    def __init__(self):
        self.attached = None
        self.settlements = []

    def attach(self, environment):
        self.attached = dict(environment)
        attached = dict(environment)
        attached[network_policy.PRIVATE_POLICY_ENV] = "broker-policy"
        return attached

    def settle(self, **kwargs):
        self.settlements.append(kwargs)


class _PolicyScope:
    def __init__(self):
        self.invocation = _PolicyInvocation()
        self.prepared = None

    def prepare_invocation(self, **kwargs):
        self.prepared = kwargs
        return self.invocation


def _install_bound_policy(monkeypatch, run, scope):
    monkeypatch.setattr(network_policy, "scope_for", lambda repository: scope if repository is run else None)
    monkeypatch.setattr(
        network_policy, "transport_door",
        lambda _source_id, *, argv: SimpleNamespace(
            supported=True, broker_required=True, profile="fixture",
        ),
    )
    monkeypatch.setattr(runner, "have", lambda _name: True)
    prepared = _PreparedLaunch(("fixture", "--exact"))
    monkeypatch.setattr(runtime_identity, "prepare_launch", lambda *_args, **_kwargs: prepared)
    monkeypatch.setattr(runtime_identity, "revalidate_launch", lambda _prepared: None)
    monkeypatch.setattr(runtime_identity, "publish_launch_identity", lambda *_args: "identity")
    return prepared


def test_bound_repository_requires_source_id_before_prepare_launch(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for",
                        lambda repository: object() if repository is run else None)
    _forbid_launch(monkeypatch)

    result = _managed_call(run, ["subfinder", "-duc"])

    assert result.status is Status.FAILED
    assert result.started is False
    assert "source_id" in result.note


def test_bound_repository_refuses_mismatched_transport_door_before_launch(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    observed = {}
    monkeypatch.setattr(network_policy, "scope_for",
                        lambda repository: object() if repository is run else None)

    def refuse(source_id, *, argv):
        observed.update(source_id=source_id, argv=list(argv))
        return None

    monkeypatch.setattr(network_policy, "transport_door", refuse)
    _forbid_launch(monkeypatch)

    result = _managed_call(run, ["subfinder", "-duc"], source_id="vertical.subfinder")

    assert result.status is Status.FAILED
    assert result.started is False
    assert observed == {"source_id": "vertical.subfinder", "argv": ["subfinder", "-duc"]}


def test_bound_chunks_bwrap_is_prepared_and_supervised_without_outer_broker(tmp_path, monkeypatch):
    run = _running_run(tmp_path)

    class NoBrokerScope:
        def prepare_invocation(self, **_kwargs):
            pytest.fail("self-contained bwrap launcher installed an outer broker")

    scope = NoBrokerScope()
    command = _chunks_bwrap_command(tmp_path, monkeypatch, artifact_root=run.dir)
    prepared = _PreparedLaunch(tuple(command))
    monkeypatch.setattr(network_policy, "scope_for", lambda repository: scope if repository is run else None)
    monkeypatch.setattr(runner, "have", lambda _name: True)
    monkeypatch.setattr(runtime_identity, "prepare_launch", lambda *_args, **_kwargs: prepared)
    monkeypatch.setattr(runtime_identity, "revalidate_launch", lambda _prepared: None)
    monkeypatch.setattr(runtime_identity, "publish_launch_identity", lambda *_args: "identity")
    observed = {}
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: (
            observed.update(environment=invocation.worker.environment)
            or _authenticated_outcome(invocation.worker.request_id, clean=True)
        ),
    )

    result = _managed_call(
        run, command,
        source_id="crawl.jxscout_chunks",
    )

    assert result.started is True
    assert prepared.closed
    assert network_policy.PRIVATE_POLICY_ENV not in observed["environment"]


@pytest.mark.parametrize("mutation", [
    "missing-unshare", "valued-unshare", "valued-clearenv", "share-net",
    "host-root-bind", "secret-bind", "cap-add", "options-after-command",
    "foreign-bundle", "foreign-engine", "nonprivate-scratch",
])
def test_bound_chunks_refuses_missing_or_forged_bwrap_network_deny_flags_before_launch(
        tmp_path, monkeypatch, mutation):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for", lambda repository: object() if repository is run else None)
    _forbid_launch(monkeypatch)

    command = _chunks_bwrap_command(tmp_path, monkeypatch, artifact_root=run.dir)
    if mutation == "missing-unshare":
        command.remove("--unshare-all")
    elif mutation == "valued-unshare":
        command[command.index("--unshare-all")] = "--unshare-all=1"
    elif mutation == "valued-clearenv":
        command[command.index("--clearenv")] = "--clearenv=1"
    elif mutation == "share-net":
        command.insert(command.index("sh"), "--share-net")
    elif mutation == "host-root-bind":
        command[command.index("sh"):command.index("sh")] = ["--bind", "/", "/"]
    elif mutation == "secret-bind":
        command[command.index("sh"):command.index("sh")] = ["--ro-bind", "/home/operator/.ssh", "/secret"]
    elif mutation == "cap-add":
        command[command.index("sh"):command.index("sh")] = ["--cap-add", "ALL"]
    elif mutation == "options-after-command":
        for option in ("--unshare-all", "--die-with-parent", "--clearenv"):
            command.remove(option)
            command.append(option)
    elif mutation == "foreign-bundle":
        foreign = tmp_path / "outside.js"
        foreign.write_text("secret")
        command[46] = command[47] = str(foreign)
        inner = shlex.split(command[62])
        inner[8] = str(foreign)
        command[62] = shlex.join(inner)
    elif mutation == "foreign-engine":
        (tmp_path / "attacker").mkdir()
        foreign = tmp_path / "attacker" / "jxscout-chunks"
        foreign.write_text("#!/bin/sh\nexit 0\n")
        foreign.chmod(0o755)
        command[40] = command[41] = str(foreign)
        inner = shlex.split(command[62])
        inner[7] = str(foreign)
        command[62] = shlex.join(inner)
    else:
        foreign = tmp_path / "quarry-jxscout-foreign"
        foreign.mkdir(mode=0o700)
        command[49] = command[50] = str(foreign)
        inner = shlex.split(command[62])
        inner[11] = str(foreign / "out.txt")
        inner[13] = str(foreign / "err.txt")
        command[62] = shlex.join(inner)

    result = _managed_call(run, command, source_id="crawl.jxscout_chunks")

    assert result.status is Status.FAILED
    assert result.started is False
    assert "exact transport door" in result.note


@pytest.mark.parametrize("source_id, command", [
    ("horizontal.csp", ("bwrap", "--unshare-all", "--die-with-parent", "--clearenv")),
    ("crawl.jxscout_ast", ("systemd-run", "--user", "--scope")),
])
def test_bound_broker_free_or_unsupported_doors_do_not_gain_chunks_exception(
        tmp_path, monkeypatch, source_id, command):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for", lambda repository: object() if repository is run else None)
    _forbid_launch(monkeypatch)

    result = _managed_call(run, list(command), source_id=source_id)

    assert result.status is Status.FAILED
    assert result.started is False
    assert "exact transport door" in result.note


def test_run_contract_passes_literal_source_id(monkeypatch, tmp_path):
    events.configure(tmp_path)
    captured = {}

    def fake_run(tool, cmd, **kwargs):
        captured.update(kwargs)
        return runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.0, None, 0)

    monkeypatch.setattr(contract, "_run", fake_run)
    try:
        contract.run_contract(
            "vertical.subfinder", ["subfinder", "-duc"],
            approved_peers=("8.8.8.8",),
        )
    finally:
        events.reset()

    assert captured["source_id"] == "vertical.subfinder"
    assert captured["approved_peers"] == ("8.8.8.8",)


def test_run_contract_forwards_network_hosts(monkeypatch, tmp_path):
    events.configure(tmp_path)
    captured = {}

    def fake_run(tool, cmd, **kwargs):
        captured.update(kwargs)
        return runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.0, None, 0)

    monkeypatch.setattr(contract, "_run", fake_run)
    try:
        contract.run_contract(
            "vertical.subfinder", ["subfinder", "-duc"],
            network_hosts=("Example.TEST.",),
        )
    finally:
        events.reset()

    assert captured["network_hosts"] == ("Example.TEST.",)


def test_unbound_repository_keeps_optional_source_id_compatibility(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for", lambda _repository: None)
    monkeypatch.setattr(runner, "have", lambda _name: False)

    result = _managed_call(run, ["subfinder", "-duc"])

    assert result.status is Status.SKIPPED
    assert result.started is False


def test_bound_policy_payload_is_attached_before_supervise_and_settles_allow(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    prepared = _install_bound_policy(monkeypatch, run, scope)
    observed = {}

    def supervise(_repository, invocation, **_kwargs):
        observed["environment"] = invocation.worker.environment
        return _authenticated_outcome(invocation.worker.request_id, clean=True)

    monkeypatch.setattr(runner_repository, "supervise_repository_execution", supervise)

    _managed_call(run, ["fixture", "--exact"], source_id="fixture.source")

    assert scope.prepared == {
        "request_id": ANY,
        "source_id": "fixture.source",
        "tool": "fixture",
        "argv": ["fixture", "--exact"],
        "environment": prepared.environment,
        "runtime_identity": prepared.record,
        "approved_peers": (),
    }
    assert dict(observed["environment"])[network_policy.PRIVATE_POLICY_ENV] == "broker-policy"
    assert scope.invocation.settlements == [{
        "decision": "allow",
        "reason": "repository supervisor returned an authenticated outcome",
        "summary": {"runner": "repository"},
    }]


def test_bound_policy_forwards_caller_owned_approved_peers(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id, clean=True,
        ),
    )

    _managed_call(
        run, ["fixture", "--exact"], source_id="fixture.source",
        approved_peers=("8.8.8.8", "2001:4860:4860::8888"),
    )

    assert scope.prepared["approved_peers"] == (
        "8.8.8.8", "2001:4860:4860::8888",
    )


@pytest.mark.parametrize("profile", ("target-http-exact", "nuclei-authorized-http"))
def test_host_bound_profile_cannot_bypass_authority_with_peer_ips(
        tmp_path, monkeypatch, profile):
    run = _running_run(tmp_path)
    monkeypatch.setattr(network_policy, "scope_for", lambda repository: object())
    monkeypatch.setattr(
        network_policy, "transport_door",
        lambda _source_id, *, argv: SimpleNamespace(
            supported=True, broker_required=True, profile=profile,
        ),
    )
    _forbid_launch(monkeypatch)

    result = _managed_call(
        run, ["httpx", "-duc", "-follow-host-redirects"],
        source_id="probe.httpx", approved_peers=("8.8.8.8",),
    )

    assert result.status is Status.FAILED
    assert result.started is False
    assert "network hosts" in result.note


def test_bound_policy_resolves_network_hosts_before_forwarding(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    observed = {}
    monkeypatch.setattr(
        runner, "_resolve_network_hosts",
        lambda current, **kwargs: (
            observed.update(scope=current, **kwargs) or ("8.8.8.8",)
        ),
    )
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id, clean=True,
        ),
    )

    _managed_call(
        run, ["fixture", "--exact"], source_id="fixture.source",
        network_hosts=("example.test",),
    )

    assert observed["scope"] is scope
    assert observed["network_hosts"] == ("example.test",)
    assert scope.prepared["approved_peers"] == ("8.8.8.8",)


def _network_host_scope():
    return network_policy.NetworkPolicyScope(
        block_private_targets=False,
        own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
        requested_cidrs=("8.8.8.0/24",),
        apex_domains=("example.test",),
    )


def test_network_hosts_use_validating_dns_and_canonical_union(monkeypatch):
    scope = _network_host_scope()
    traces = []
    monkeypatch.setattr(scope, "_trace", lambda row: traces.append(row))
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("ambient resolver was reached"),
    )
    seen = []

    def resolve(policy, host, *, on_event, effect_fence, **_kwargs):
        assert policy.source_id == "probe.tlsx_certs"
        assert policy.tool == "native-dns"
        assert effect_fence is scope.effect_fence
        seen.append(host)
        on_event("dns-planned", "1.1.1.1", 53, "allow", "planned")
        on_event("dns-settled", "1.1.1.1", 53, "allow", "settled")
        return (("8.8.4.4",) if host == "a.example.test" else ("8.8.8.8",)), "ok"

    monkeypatch.setattr(network_dns, "resolve", resolve)
    assert runner._canonical_network_hosts(
        ("B.EXAMPLE.TEST.", "a.example.test"),
    ) == ("a.example.test", "b.example.test")
    peers = runner._resolve_network_hosts(
        scope, request_id="a" * 32, source_id="probe.tlsx_certs",
        network_hosts=("a.example.test", "b.example.test"),
    )

    assert seen == ["a.example.test", "b.example.test"]
    assert peers == ("8.8.4.4", "8.8.8.8")
    assert [row["record_type"] for row in traces] == [
        "planned", "planned", "settlement", "settlement",
        "planned", "planned", "settlement", "settlement",
    ]
    assert all(row["tool"] == "native-dns" for row in traces)


@pytest.mark.parametrize("answers,state", [
    (("8.8.8.8", "127.0.0.1"), "ok"),
    (("127.0.0.1",), "ok"),
    ((), "indeterminate"),
])
def test_network_hosts_refuse_mixed_protected_and_indeterminate_answers(
        monkeypatch, answers, state):
    scope = _network_host_scope()
    monkeypatch.setattr(scope, "_trace", lambda _row: None)
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(
        network_dns, "resolve", lambda *_args, **_kwargs: (answers, state),
    )

    with pytest.raises(network_policy.NetworkPolicyError):
        runner._resolve_network_hosts(
            scope, request_id="b" * 32, source_id="probe.tlsx_certs",
            network_hosts=("example.test",),
        )


def test_network_host_literal_is_classified_without_dns(monkeypatch):
    scope = _network_host_scope()
    monkeypatch.setattr(scope, "_trace", lambda _row: None)
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(
        network_dns, "resolve",
        lambda *_args, **_kwargs: pytest.fail("literal reached DNS"),
    )

    assert runner._resolve_network_hosts(
        scope, request_id="c" * 32, source_id="probe.tlsx_certs",
        network_hosts=("8.8.8.8",),
    ) == ("8.8.8.8",)


def test_network_host_authority_fault_settles_its_outer_plan(monkeypatch):
    scope = _network_host_scope()
    traces = []
    monkeypatch.setattr(scope, "_trace", lambda row: traces.append(row))

    def authority_fault(*_args, **_kwargs):
        raise OSError("authority snapshot failed")

    monkeypatch.setattr(scope, "host_allowed", authority_fault)

    with pytest.raises(OSError):
        runner._resolve_network_hosts(
            scope, request_id="d" * 32, source_id="probe.tlsx_certs",
            network_hosts=("example.test",),
        )

    assert [row["record_type"] for row in traces] == ["planned", "settlement"]
    assert traces[-1]["decision"] == "deny"


def test_network_host_corpus_deadline_refuses_before_dns(monkeypatch):
    scope = _network_host_scope()
    traces = []
    monkeypatch.setattr(scope, "_trace", lambda row: traces.append(row))
    monkeypatch.setattr(resource_contract, "MAX_RESOLVER_CORPUS_DEADLINE_SECONDS", 0.0)
    monkeypatch.setattr(
        network_dns, "resolve", lambda *_args, **_kwargs: pytest.fail("DNS exceeded corpus deadline"),
    )

    with pytest.raises(network_policy.NetworkPolicyError):
        runner._resolve_network_hosts(
            scope, request_id="e" * 32, source_id="probe.tlsx_certs",
            network_hosts=("example.test",),
        )

    assert [row["record_type"] for row in traces] == ["planned", "settlement"]
    assert traces[-1]["decision"] == "deny"


def test_network_host_resolver_plan_is_deny_settled_on_failure(monkeypatch):
    scope = _network_host_scope()
    traces = []
    monkeypatch.setattr(scope, "_trace", lambda row: traces.append(row))

    def failed_resolve(_policy, _host, *, on_event, **_kwargs):
        on_event("dns-planned", "1.1.1.1", 53, "allow", "planned")
        raise OSError("resolver failed after plan")

    monkeypatch.setattr(network_dns, "resolve", failed_resolve)
    with pytest.raises(OSError):
        runner._resolve_network_hosts(
            scope, request_id="f" * 32, source_id="probe.tlsx_certs",
            network_hosts=("example.test",),
        )

    assert [row["record_type"] for row in traces] == [
        "planned", "planned", "settlement", "settlement",
    ]
    assert [row["decision"] for row in traces[-2:]] == ["deny", "deny"]


def test_network_host_final_trace_failure_gets_best_effort_deny(monkeypatch):
    scope = _network_host_scope()
    traces = []

    def fail_allow_settlement(row):
        if row["record_type"] == "settlement" and row["decision"] == "allow":
            raise OSError("final trace write failed")
        traces.append(row)

    monkeypatch.setattr(scope, "_trace", fail_allow_settlement)
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    with pytest.raises(OSError):
        runner._resolve_network_hosts(
            scope, request_id="0" * 32, source_id="probe.tlsx_certs",
            network_hosts=("8.8.8.8",),
        )

    assert [row["record_type"] for row in traces] == ["planned", "settlement"]
    assert traces[-1]["decision"] == "deny"


@pytest.mark.parametrize("failure", ("normalize", "supervisor"))
def test_bound_policy_settles_deny_on_admission_or_supervisor_failure(tmp_path, monkeypatch, failure):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    if failure == "normalize":
        monkeypatch.setattr(runner_protocol, "normalize_invocation", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError()))
    else:
        monkeypatch.setattr(
            runner_repository, "supervise_repository_execution",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError()),
        )

    result = _managed_call(run, ["fixture", "--exact"], source_id="fixture.source")

    assert result.status is Status.FAILED
    assert [item["decision"] for item in scope.invocation.settlements] == ["deny"]


def test_bound_policy_denies_matching_incomplete_supervisor_outcome(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id,
        ),
    )

    result = _managed_call(run, ["fixture", "--exact"], source_id="fixture.source")

    assert result.status is Status.FAILED
    assert [item["decision"] for item in scope.invocation.settlements] == ["deny"]


def test_bound_policy_native_cleanup_does_not_settle_twice(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    scope = _PolicyScope()
    _install_bound_policy(monkeypatch, run, scope)
    final = run.dir / "raw" / "probe" / "fixture" / "native.txt"
    command = [sys.executable, "-c", "pass", str(final)]
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "fixture", "native.txt")
    monkeypatch.setattr(
        runtime_identity, "prepare_launch",
        lambda *_args, **_kwargs: _PreparedLaunch(command),
    )
    monkeypatch.setattr(
        runner_repository, "supervise_repository_execution",
        lambda _repository, invocation, **_kwargs: _authenticated_outcome(
            invocation.worker.request_id,
            clean=True,
        ),
    )
    monkeypatch.setattr(
        runner, "_repository_run_result",
        lambda tool, cmd, *_args, **_kwargs: runner.RunResult(
            tool, cmd, Status.EMPTY, 0, 0.0, None, 0,
            meta={"started": True, "repository_ownership_settled": True},
        ),
    )

    _managed_call(
        run, command, source_id="fixture.source", native_outputs=(policy,),
    )

    assert [item["decision"] for item in scope.invocation.settlements] == ["allow"]
