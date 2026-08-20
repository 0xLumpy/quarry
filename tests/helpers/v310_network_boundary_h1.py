#!/usr/bin/env python3
"""Root-netns H1 witness for the V310-07 broker and pinned proxy boundary."""
from __future__ import annotations

import errno
import json
import os
import pathlib
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time

import v310_network_h1 as fixture
from quarry_recon import network_proxy
from quarry_recon.network_broker import (
    BrokerPolicy,
    NetworkBrokerSession,
    NetworkEffectFence,
    acknowledge_listener,
    acquire_worker_subreaper,
    reap_adopted_descendants,
    seal_worker_identity,
)


_TOOL_IP = fixture._TOOL_IP
_FIXTURE_IP = fixture._FIXTURE_IP
_HTTP_PORT = fixture._HTTP_PORT
_CONTROL_IP = "10.203.0.99"
_METADATA_IP = "169.254.169.254"
_IDNA_HOST = "xn--bcher-kva.fixture.test"
_FIXTURE_DNS_RESPONSE = fixture._dns_response


def _policy() -> BrokerPolicy:
    return BrokerPolicy(
        request_id="f" * 32,
        source_id="h1.network-boundary", tool="python",
        block_private_targets=False,
        control_plane_cidrs=(f"{_CONTROL_IP}/32",),
        initial_own_ips=(_TOOL_IP,), resolver_ips=(_FIXTURE_IP,),
        apex_domains=("fixture.test",), oos_patterns=(r"^oos\.",),
        effective_cidrs=("10.203.0.0/24",), approved_peers=(_FIXTURE_IP,),
    )


def _invoking_identity() -> tuple[int, int]:
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("H1 helper needs sudo's invoking uid and gid") from exc
    if uid <= 0 or gid <= 0:
        raise RuntimeError("H1 helper invoking identity is invalid")
    return uid, gid


def _drop_to(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def _tracee_program() -> str:
    return '''import errno, json, socket
targets = {
    "approved": ("10.203.0.1", 8080),
    "direct_ip": ("8.8.4.4", 80),
    "scanner_self": ("10.203.0.2", 8080),
    "metadata": ("169.254.169.254", 80),
    "control_plane": ("10.203.0.99", 80),
}
results = {}
for name, endpoint in targets.items():
    handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    handle.settimeout(2)
    try:
        handle.connect(endpoint)
    except OSError as exc:
        results[name] = exc.errno
    else:
        results[name] = 0
    finally:
        handle.close()
datagrams = {
    "sendto_allowed": ("sendto", ("10.203.0.1", 8080)),
    "sendto_metadata": ("sendto", ("169.254.169.254", 8080)),
    "sendmsg_allowed": ("sendmsg", ("10.203.0.1", 8080)),
    "sendmsg_control": ("sendmsg", ("10.203.0.99", 8080)),
}
for name, (operation, endpoint) in datagrams.items():
    handle = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if operation == "sendto":
            results[name] = handle.sendto(b"x", endpoint)
        else:
            results[name] = handle.sendmsg([b"x"], [], 0, endpoint)
    except OSError as exc:
        results[name] = exc.errno
    finally:
        handle.close()
print(json.dumps(results, sort_keys=True), flush=True)
'''


def _boundary_dns_response(query: bytes, counters: dict[str, int], lock,
                           log_path: pathlib.Path) -> bytes:
    """Add one IDNA fixture answer without changing the browser H1 fixture."""
    if len(query) < 17:
        return b""
    name, end = fixture._dns_name(query, 12)
    kind, qclass = struct.unpack_from("!HH", query, end)
    if name != _IDNA_HOST:
        return _FIXTURE_DNS_RESPONSE(query, counters, lock, log_path)
    with lock:
        counters[name] = counters.get(name, 0) + 1
        count = counters[name]
        with open(log_path, "a", encoding="ascii") as handle:
            handle.write(json.dumps({"dns": name, "kind": kind, "count": count},
                                    sort_keys=True) + "\n")
    answers = ()
    if kind == 1 and qclass == 1:
        answers = (
            b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 10, 4)
            + socket.inet_aton(_FIXTURE_IP),
        )
    return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, 0)
            + query[12:end + 4] + b"".join(answers))


def _proxy(policy: BrokerPolicy, deadline: float):
    proxy = object.__new__(network_proxy.PinnedBrowserProxy)
    proxy._policy = policy
    proxy._deadline = deadline
    proxy._stop = threading.Event()
    proxy._effect_fence = NetworkEffectFence()
    proxy._lock = threading.Lock()
    proxy._records = []
    proxy._open_plans = {}
    proxy._record_bytes = 0
    proxy._dropped = 0
    proxy._fatal = None
    proxy._sockets = set()
    proxy._threads = set()
    proxy._listener = None
    proxy._registration = None
    proxy._accept_thread = None
    return proxy


def _request(proxy, host: str, path: str) -> bytes:
    upstream = proxy._dial("GET", host, _HTTP_PORT)
    try:
        upstream.settimeout(2)
        upstream.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{_HTTP_PORT}\r\n"
            "Connection: close\r\n\r\n".encode("ascii"),
        )
        body = bytearray()
        while True:
            block = upstream.recv(65536)
            if not block:
                return bytes(body)
            body.extend(block)
    finally:
        proxy._close_tracked(upstream)


def _refused(proxy, host: str) -> bool:
    try:
        upstream = proxy._dial("GET", host, _HTTP_PORT)
    except network_proxy.BrowserProxyRefused:
        return True
    else:
        proxy._close_tracked(upstream)
        return False


def _read_tracee(output: pathlib.Path) -> dict[str, int]:
    lines = output.read_text("utf-8", errors="replace").splitlines()
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (type(value) is dict and set(value) == {
                "approved", "direct_ip", "scanner_self", "metadata", "control_plane",
                "sendto_allowed", "sendto_metadata", "sendmsg_allowed", "sendmsg_control"}
                and all(type(item) is int for item in value.values())):
            return value
    raise RuntimeError("broker tracee did not emit its bounded result")


def _reap_child(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            observed, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if observed == pid:
            return True
        time.sleep(0.01)
    return False


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("V310-07 boundary H1 requires root network-namespace authority")
    uid, gid = _invoking_identity()
    root = pathlib.Path(tempfile.mkdtemp(prefix="quarry-v310-boundary-h1-"))
    os.chown(root, uid, gid)
    os.chmod(root, 0o700)
    deadline = time.monotonic() + 30
    fixture_pid = tracee_pid = -1
    stop_w = -1
    browser_proxy = None
    session = None
    handoff = None
    acceptance_errors = []
    document = {}
    try:
        os.unshare(os.CLONE_NEWNET)
        fixture._run("/usr/sbin/ip", "link", "set", "lo", "up")
        fixture._run(
            "/usr/sbin/ip", "link", "add", "qh1t", "type", "veth",
            "peer", "name", "qh1s",
        )
        config_r, config_w = os.pipe()
        ready_r, ready_w = os.pipe()
        stop_r, stop_w = os.pipe()
        acquire_worker_subreaper()
        fixture._dns_response = _boundary_dns_response
        fixture._drop = lambda: _drop_to(uid, gid)
        fixture_parent_pid = os.getpid()
        fixture_pid = os.fork()
        if fixture_pid == 0:
            os.close(config_w)
            os.close(ready_r)
            os.close(stop_w)
            try:
                fixture._pdeathsig()
                if os.getppid() != fixture_parent_pid:
                    os._exit(127)
                fixture._fixture(
                    config_r, ready_w, stop_r, root,
                    tls=False, exercise_invalid=False, crashpad_upload=False,
                )
            except BaseException:
                os._exit(127)
        os.close(config_r)
        os.close(ready_w)
        os.close(stop_r)
        if fixture._read_exact(ready_r, 1) != b"U":
            raise RuntimeError("fixture namespace setup failed")
        fixture._run(
            "/usr/sbin/ip", "link", "set", "qh1s", "netns", str(fixture_pid),
        )
        fixture._run("/usr/sbin/ip", "addr", "add", f"{_TOOL_IP}/24", "dev", "qh1t")
        fixture._run("/usr/sbin/ip", "link", "set", "qh1t", "up")
        fixture._write_all(config_w, b"C")
        os.close(config_w)
        if fixture._read_exact(ready_r, 1) != b"R":
            raise RuntimeError("fixture services setup failed")
        os.close(ready_r)
        _drop_to(uid, gid)
        fixture._dumpable()
        tracee_output = root / "tracee.jsonl"
        tracee_pid, tracee_ack, tracee_command, handoff = fixture._launcher(
            "standard", tracee_output, deadline_monotonic=deadline,
        )
        seal_worker_identity()
        policy = _policy()
        session = NetworkBrokerSession(
            handoff, policy, expected_profile="standard",
            deadline_monotonic=deadline,
        )
        session.start()
        acknowledge_listener(
            tracee_ack, child_pidfd=handoff.child_pidfd,
            deadline_monotonic=deadline,
        )
        fixture._command(
            tracee_command, [sys.executable, "-c", _tracee_program()],
            {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"},
        )
        tracee_rc = fixture._wait(tracee_pid, deadline)
        while not session.summary()["listener_hup"] and time.monotonic() < deadline:
            time.sleep(0.01)
        session.settle_after_tasks(deadline_monotonic=min(deadline, time.monotonic() + 2))
        tracee_results = _read_tracee(tracee_output)
        if tracee_rc != 0:
            acceptance_errors.append("tracee_exit")
        if tracee_results != {
                "approved": 0, "direct_ip": errno.EPERM,
                "scanner_self": errno.EPERM, "metadata": errno.EPERM,
                "control_plane": errno.EPERM,
                "sendto_allowed": 1, "sendto_metadata": errno.EPERM,
                "sendmsg_allowed": 1, "sendmsg_control": errno.EPERM}:
            acceptance_errors.append("broker_direct_effects")
        summary = session.summary()
        if summary.get("complete") is not True:
            acceptance_errors.append("broker_settlement")
        direct_records = {
            (record["peer"], record["decision"])
            for record in summary["records"]
            if record["syscall"] == "connect"
        }
        if not {
                (_FIXTURE_IP, "allow"), ("8.8.4.4", "deny"),
                (_TOOL_IP, "deny"), (_METADATA_IP, "deny"),
                (_CONTROL_IP, "deny"),
        } <= direct_records:
            acceptance_errors.append("broker_direct_records")
        datagram_records = {
            (record["syscall"], record["peer"], record["decision"],
             record["stage"], record["result"])
            for record in summary["records"]
            if record["syscall"] in {"sendto", "sendmsg"}
        }
        if not {
                ("sendto", _FIXTURE_IP, "allow", "settled", "1"),
                ("sendto", _METADATA_IP, "deny", "settled", None),
                ("sendmsg", _FIXTURE_IP, "allow", "settled", "1"),
                ("sendmsg", _CONTROL_IP, "deny", "settled", None),
        } <= datagram_records:
            acceptance_errors.append("broker_datagram_records")

        browser_proxy = _proxy(policy, deadline)
        start = _request(browser_proxy, "fixture.test", "/start")
        redirect = _request(browser_proxy, "redirect.fixture.test", "/final")
        idna = _request(browser_proxy, "xn--bcher-kva.fixture.test", "/idna")
        cidr = _request(browser_proxy, _FIXTURE_IP, "/cidr")
        rebind_first = _request(browser_proxy, "rebind.fixture.test", "/rebind")
        refused = {
            "unicode_idna": _refused(browser_proxy, "bücher.fixture.test"),
            "scope": _refused(browser_proxy, "oos.fixture.test"),
            "direct_ip": _refused(browser_proxy, "8.8.4.4"),
            "mixed": _refused(browser_proxy, "mixed.fixture.test"),
            "protected": _refused(browser_proxy, "protected.fixture.test"),
            "rebind": _refused(browser_proxy, "rebind.fixture.test"),
        }
        if (not start.startswith(b"HTTP/1.1 302")
                or b"Location: http://redirect.fixture.test:8080/final\r\n" not in start
                or not redirect.startswith(b"HTTP/1.1 200")
                or not idna.startswith(b"HTTP/1.1 404")
                or not cidr.startswith(b"HTTP/1.1 404")
                or not rebind_first.startswith(b"HTTP/1.1 404")):
            acceptance_errors.append("proxy_effects")
        if not all(refused.values()):
            acceptance_errors.append("proxy_refusals")
        proxy_summary = browser_proxy.summary()
        if proxy_summary.get("complete") is not True:
            acceptance_errors.append("proxy_settlement")
        dns_records = [json.loads(line) for line in (root / "dns.jsonl").read_text("ascii").splitlines()]
        http_records = [json.loads(line) for line in (root / "http.jsonl").read_text("ascii").splitlines()]
        expected_dns = {
            "fixture.test", "redirect.fixture.test", "xn--bcher-kva.fixture.test",
            "rebind.fixture.test", "mixed.fixture.test", "protected.fixture.test",
        }
        if {record["dns"] for record in dns_records} != expected_dns:
            acceptance_errors.append("dns_effect_set")
        contacts = {(record["host"], record["path"]) for record in http_records}
        expected_contacts = {
            (f"fixture.test:{_HTTP_PORT}", "/start"),
            (f"redirect.fixture.test:{_HTTP_PORT}", "/final"),
            (f"xn--bcher-kva.fixture.test:{_HTTP_PORT}", "/idna"),
            (f"{_FIXTURE_IP}:{_HTTP_PORT}", "/cidr"),
            (f"rebind.fixture.test:{_HTTP_PORT}", "/rebind"),
        }
        if contacts != expected_contacts:
            acceptance_errors.append("http_effect_set")
        document = {
            "schema_version": "quarry.network-boundary-h1.v1",
            "broker": summary,
            "proxy": proxy_summary,
            "tracee_results": tracee_results,
            "dns_records": dns_records,
            "http_records": http_records,
            "refused": refused,
            "acceptance_errors": acceptance_errors,
        }
    except BaseException as exc:
        acceptance_errors.append(f"harness:{type(exc).__name__}:{exc}")
        document = {"schema_version": "quarry.network-boundary-h1.v1",
                    "acceptance_errors": acceptance_errors}
    finally:
        if tracee_pid > 0:
            fixture._pidfd_kill(tracee_pid)
            if not _reap_child(tracee_pid, timeout=2):
                acceptance_errors.append("tracee_reap")
        if session is not None:
            try:
                session.settle_after_tasks(
                    deadline_monotonic=time.monotonic() + 2,
                )
            except BaseException:
                acceptance_errors.append("broker_cleanup")
        if handoff is not None:
            try:
                os.close(handoff.child_pidfd)
            except OSError:
                pass
        if browser_proxy is not None:
            try:
                for handle in tuple(browser_proxy._sockets):
                    browser_proxy._close_tracked(handle)
            except BaseException:
                acceptance_errors.append("proxy_cleanup")
        if stop_w >= 0:
            try:
                fixture._write_all(stop_w, b"S")
                os.close(stop_w)
            except OSError:
                pass
        if fixture_pid > 0:
            if not _reap_child(fixture_pid, timeout=2):
                fixture._pidfd_kill(fixture_pid)
                if not _reap_child(fixture_pid, timeout=2):
                    acceptance_errors.append("fixture_reap")
        try:
            reaped = reap_adopted_descendants(
                launcher_reaped=True, deadline_monotonic=time.monotonic() + 2,
            )
        except BaseException:
            reaped = ()
        document["reaped"] = [list(value) for value in reaped]
        try:
            shutil.rmtree(root)
        except OSError:
            acceptance_errors.append("workspace_cleanup")
        document["acceptance_errors"] = acceptance_errors
        print(json.dumps(document, sort_keys=True), flush=True)
    return 0 if not acceptance_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
