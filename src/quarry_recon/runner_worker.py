"""Fixed bootstrap and parked pre-exec launcher owner.

The module is intentionally executable only through ``python -m`` with a private
request/command channel on stdin and a worker-control channel on stdout.  The
legacy path creates no child.  The additive parked path forks a fixed launcher
before decoding target material, proves it stopped as a session/group leader, and
accepts only a PREPARED-digest-bound abort.  This slice never releases or executes
the target.
"""
from __future__ import annotations

import ctypes
import dataclasses
import hashlib
import json
import os
import select
import signal
import shutil
import stat
import struct
import sys
import tempfile
import time

from . import runner_ipc
from .runner_protocol import (
    MAX_FRAME_BYTES,
    MAX_PID,
    MAX_STDIN_DATA_BYTES,
    ContainmentKind,
    ExecutionTerminal,
    PreparedFrame,
    ReadyFrame,
    StdinMode,
    StreamRole,
    StreamSettlement,
    StreamTerminal,
    StartedFrame,
    WorkerRequest,
    WorkerCommandKind,
    WorkerSettlement,
    decode_command,
    decode_request,
    encode_request,
    encode_prepared,
    encode_ready,
    encode_started,
    encode_settlement,
    prepared_digest,
    request_digest,
)
from .runner_containment import (
    capture_parked_process_identity,
    capture_process_identity,
)
from .runner_streams import _run_stream_engine
from .network_broker import (
    BrokerPolicy,
    ControlEndpointRegistry,
    ListenerHandoff,
    NetworkBrokerRefused,
    NetworkBrokerSession,
    NetworkEffectFence,
    acquire_worker_subreaper,
    acknowledge_listener,
    attest_exec_fds,
    child_install_and_report,
    duplicate_reported_listener,
    seal_worker_identity,
    verify_listener_bootstrap,
    reap_adopted_descendants,
)
from .network_cdp import PinnedCDPBridge
from .network_proxy import PinnedBrowserProxy
from .network_dns import TargetDNSMediator
from .network_policy import PRIVATE_POLICY_ENV


EXPECTED_PARENT_PID_ENV = "QUARRY_RUNNER_EXPECTED_PARENT_PID"
PREPARED_ABORT_ENV = "QUARRY_RUNNER_PREPARED_ABORT"
EXECUTION_ENV = "QUARRY_RUNNER_EXECUTION"
STDOUT_FD_ENV = "QUARRY_RUNNER_STDOUT_FD"
STDERR_FD_ENV = "QUARRY_RUNNER_STDERR_FD"
STDIN_FD_ENV = "QUARRY_RUNNER_STDIN_FD"
PRIVATE_REDACTIONS_ENV = "QUARRY_RUNNER_PRIVATE_REDACTIONS"
_PRIVATE_BROWSER_LAUNCH_ENV = "QUARRY_RUNNER_BROWSER_LAUNCH"
_PR_SET_PDEATHSIG = 1
_EXIT_BOOTSTRAP_INVALID = 64
_EXIT_CONTROL_FAILED = 65
_BROKER_BOOTSTRAP_SECONDS = 5.0
_RUNNER_PROXY_FLAGS = frozenset({
    "-proxy", "--proxy", "-http-proxy", "--http-proxy",
    "-socks5", "--socks5", "-socks-proxy", "--socks-proxy",
    "-chrome-proxy", "--chrome-proxy",
    "-p", "-pi", "-proxy-internal", "--proxy-internal",
})
_DNS_RESOLVER_FLAGS = frozenset({
    "-r", "--resolver", "-resolver", "--resolvers", "-resolvers",
    "--resolvers-trusted", "-system-resolvers", "--system-resolvers",
})
_GOWITNESS_WSS_FLAGS = frozenset({"--chrome-wss-url"})


def _gowitness_browser_path(argv: tuple[str, ...]) -> tuple[tuple[str, ...], str]:
    """Consume the one runner-admitted Chromium path from Gowitness' argv."""
    result = [argv[0]]
    browser_path = None
    cursor = 1
    while cursor < len(argv):
        value = argv[cursor]
        name = value.split("=", 1)[0]
        if name in _GOWITNESS_WSS_FLAGS:
            raise RuntimeError("network_cdp_caller_argument_forbidden")
        if name == "--chrome-path":
            if browser_path is not None:
                raise RuntimeError("network_browser_path_invalid")
            if value == "--chrome-path":
                if cursor + 1 >= len(argv) or not argv[cursor + 1]:
                    raise RuntimeError("network_browser_path_invalid")
                browser_path = argv[cursor + 1]
                cursor += 2
            else:
                browser_path = value.partition("=")[2]
                cursor += 1
            continue
        result.append(value)
        cursor += 1
    if (type(browser_path) is not str or not browser_path.startswith("/")
            or "\x00" in browser_path):
        raise RuntimeError("network_browser_path_invalid")
    return tuple(result), browser_path


def _browser_argv(browser_path: str, profile: str,
                  proxy_endpoint: tuple[str, int]) -> tuple[str, ...]:
    host, port = proxy_endpoint
    if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError("network_proxy_endpoint_invalid")
    return (
        browser_path, "--headless=new", "--disable-gpu", "--no-first-run",
        "--no-default-browser-check", "--disable-background-networking",
        "--disable-component-update", "--disable-default-apps",
        "--disable-domain-reliability", "--disable-extensions", "--disable-sync",
        "--metrics-recording-only", "--disable-quic", "--disable-http2",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=AsyncDns,DnsOverHttps,UseDnsHttpsSvcbAlpn,WebRtcHideLocalIpsWithMdns",
        f"--proxy-server=http://127.0.0.1:{port}",
        "--proxy-bypass-list=<-loopback>",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        f"--user-data-dir={profile}", "--remote-debugging-pipe", "about:blank",
    )


def _strip_dns_resolver_overrides(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Remove known resolver selections so policy values are the only ones used."""
    result = [argv[0]]
    cursor = 1
    valueless = {"-system-resolvers", "--system-resolvers"}
    while cursor < len(argv):
        value = argv[cursor]
        if value in _DNS_RESOLVER_FLAGS:
            if value in valueless:
                cursor += 1
                continue
            if cursor + 1 >= len(argv) or not argv[cursor + 1]:
                raise RuntimeError("network_dns_caller_resolver_invalid")
            cursor += 2
            continue
        if any(value.startswith(flag + "=") for flag in _DNS_RESOLVER_FLAGS):
            cursor += 1
            continue
        result.append(value)
        cursor += 1
    return tuple(result)


def _strip_puredns_bin_override(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Keep puredns' delegated resolver binary worker-selected and attested."""
    result = [argv[0]]
    cursor = 1
    while cursor < len(argv):
        value = argv[cursor]
        if value in {"-b", "--bin"}:
            if cursor + 1 >= len(argv) or not argv[cursor + 1]:
                raise RuntimeError("network_dns_caller_massdns_invalid")
            cursor += 2
            continue
        if value.startswith("--bin=") or value.startswith("-b="):
            cursor += 1
            continue
        result.append(value)
        cursor += 1
    return tuple(result)


def _attested_massdns_path(request: WorkerRequest) -> str:
    """Return the private runtime anchor which prepared puredns may execute."""
    path = shutil.which("massdns", path=dict(request.environment).get("PATH"))
    if not path or not os.path.isabs(path):
        raise RuntimeError("network_dns_massdns_unavailable")
    try:
        observed = os.stat(path)
    except OSError as exc:
        raise RuntimeError("network_dns_massdns_unavailable") from exc
    if not stat.S_ISREG(observed.st_mode) or not observed.st_mode & stat.S_IXUSR:
        raise RuntimeError("network_dns_massdns_unavailable")
    return path


def _write_pinned_resolver_file(resolvers: tuple[str, ...]) -> tuple[str, str]:
    """Create a bounded private puredns resolver file owned by this worker."""
    if (not resolvers or len(resolvers) > 16
            or any(type(value) is not str or not value.isascii() for value in resolvers)):
        raise RuntimeError("network_dns_resolver_set_invalid")
    body = ("\n".join(resolvers) + "\n").encode("ascii")
    if not 1 <= len(body) <= 4096:
        raise RuntimeError("network_dns_resolver_file_invalid")
    directory = tempfile.mkdtemp(prefix="quarry-resolvers-")
    path = os.path.join(directory, "resolvers.txt")
    descriptor = -1
    try:
        os.chmod(directory, 0o700)
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        pending = memoryview(body)
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:
                raise RuntimeError("network_dns_resolver_file_invalid")
            pending = pending[written:]
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if observed.st_size != len(body) or observed.st_mode & 0o077:
            raise RuntimeError("network_dns_resolver_file_invalid")
    except BaseException:
        _close_quietly(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        try:
            os.rmdir(directory)
        except OSError:
            pass
        raise
    _close_quietly(descriptor)
    return directory, path


def _configure_target_dns_resolvers(request: WorkerRequest, policy: BrokerPolicy,
                                    launcher, endpoint: tuple[str, int]) -> WorkerRequest:
    """Replace ambient resolver configuration with the held local mediator."""
    argv = _strip_dns_resolver_overrides(request.argv)
    tool = os.path.basename(argv[0])
    host, port = endpoint
    if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError("network_dns_mediator_endpoint_invalid")
    resolver = f"{host}:{port}"
    if tool == "dnsx":
        return dataclasses.replace(request, argv=argv + ("-r", resolver))
    if tool == "dig":
        # OSINT owns one fixed DMARC lookup.  Reject a widened dig grammar,
        # then force one literal resolver and a wire shape the broker parses:
        # no search/config expansion, EDNS option channel, AD bit, or TCP
        # retry on truncation.
        if (len(argv) != 4 or argv[1:3] != ("+short", "TXT")
                or not argv[3].startswith("_dmarc.")
                or any(value.startswith("@") for value in argv)):
            raise RuntimeError("network_dns_dig_argv_invalid")
        return dataclasses.replace(
            request,
            argv=argv + (
                "@" + host, "-p", str(port), "+noedns", "+noadflag", "+ignore", "-r",
            ),
        )
    if tool != "puredns":
        raise RuntimeError("network_dns_tool_invalid")
    argv = _strip_puredns_bin_override(argv)
    massdns = _attested_massdns_path(request)
    directory, path = _write_pinned_resolver_file((resolver,))
    launcher._network_resolver_directory = directory
    launcher._network_resolver_path = path
    # puredns delegates its first pass to the pinned massdns binary and then
    # performs trusted validation itself.  Pin both files so neither path can
    # silently fall back to puredns' user configuration.
    return dataclasses.replace(
        request,
        argv=argv + (
            "--bin", massdns, "--resolvers", path, "--resolvers-trusted", path,
        ),
    )


def _cleanup_target_dns_resolvers(launcher) -> None:
    path = getattr(launcher, "_network_resolver_path", None)
    directory = getattr(launcher, "_network_resolver_directory", None)
    fault = None
    if path is not None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            launcher._network_resolver_path = None
        except OSError as exc:
            fault = exc
        else:
            launcher._network_resolver_path = None
    if directory is not None:
        try:
            os.rmdir(directory)
        except FileNotFoundError:
            launcher._network_resolver_directory = None
        except OSError as exc:
            fault = fault or exc
        else:
            launcher._network_resolver_directory = None
    if fault is not None:
        raise RuntimeError("network_dns_resolver_cleanup_failed") from fault


def _stop_target_dns_mediator(launcher) -> dict | None:
    mediator = getattr(launcher, "_network_dns_mediator", None)
    if mediator is not None:
        mediator.stop()
        summary = mediator.summary()
        if type(summary) is not dict or summary.get("complete") is not True:
            raise NetworkBrokerRefused("network_dns_mediator_settlement_incomplete")
        launcher._network_dns_mediator = None
        return summary
    return None


def _expected_parent_pid() -> int:
    raw = os.environ.get(EXPECTED_PARENT_PID_ENV)
    if raw is None or not raw.isascii() or not raw.isdecimal():
        raise RuntimeError("worker_parent_invalid")
    value = int(raw)
    if not 1 <= value <= (1 << 31) - 1:
        raise RuntimeError("worker_parent_invalid")
    return value


def _arm_parent_death(expected_parent_pid: int) -> None:
    """Arm Linux parent-death SIGKILL and close the install race."""
    if sys.platform != "linux":
        raise RuntimeError("worker_platform_unsupported")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        raise RuntimeError("worker_pdeathsig_unavailable")
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise RuntimeError("worker_pdeathsig_failed")
    if os.getppid() != expected_parent_pid:
        raise RuntimeError("worker_parent_changed")


def _metadata_failure() -> RuntimeError:
    return RuntimeError("worker_metadata_invalid")


def _parse_output_fd(raw: str | None) -> int | None:
    if raw is None:
        return None
    if (type(raw) is not str or not raw or not raw.isascii()
            or not raw.isdecimal() or (len(raw) > 1 and raw[0] == "0")):
        raise _metadata_failure()
    value = int(raw)
    if not 3 <= value <= MAX_PID:
        raise _metadata_failure()
    return value


def _pop_output_fd_metadata() -> tuple[int | None, int | None]:
    """Remove both private keys even when either value is malformed."""
    stdout_raw = os.environ.pop(STDOUT_FD_ENV, None)
    stderr_raw = os.environ.pop(STDERR_FD_ENV, None)
    return _parse_output_fd(stdout_raw), _parse_output_fd(stderr_raw)


def _pop_input_fd_metadata() -> int | None:
    return _parse_output_fd(os.environ.pop(STDIN_FD_ENV, None))


def _pop_prepared_abort_mode() -> bool:
    raw = os.environ.pop(PREPARED_ABORT_ENV, None)
    if raw is None:
        return False
    if raw != "1":
        raise _metadata_failure()
    return True


def _pop_execution_mode() -> bool:
    raw = os.environ.pop(EXECUTION_ENV, None)
    if raw is None:
        return False
    if raw != "1":
        raise _metadata_failure()
    return True


def _validate_output_fds(
    request,
    stdout_fd: int | None,
    stderr_fd: int | None,
    *,
    request_fd: int,
    control_fd: int,
) -> tuple[int | None, int | None]:
    expected_stdout = request.claim_for(StreamRole.STDOUT) is not None
    expected_stderr = request.claim_for(StreamRole.STDERR) is not None
    if (request.stdin_mode is StdinMode.FILE
            or expected_stdout != (stdout_fd is not None)
            or expected_stderr != (stderr_fd is not None)):
        raise _metadata_failure()
    values = tuple(fd for fd in (stdout_fd, stderr_fd) if fd is not None)
    if (any(type(fd) is not int or not 3 <= fd <= MAX_PID for fd in values)
            or len(values) != len(set(values))
            or any(fd in (request_fd, control_fd, 0, 1, 2) for fd in values)):
        raise _metadata_failure()
    return stdout_fd, stderr_fd


def _validate_execution_fds(
    request,
    stdout_fd: int | None,
    stderr_fd: int | None,
    stdin_file_fd: int | None,
    *,
    request_fd: int,
    control_fd: int,
) -> tuple[int | None, int | None, int | None]:
    expected_stdout = request.claim_for(StreamRole.STDOUT) is not None
    expected_stderr = request.claim_for(StreamRole.STDERR) is not None
    expected_stdin = request.stdin_mode is StdinMode.FILE
    if (expected_stdout != (stdout_fd is not None)
            or expected_stderr != (stderr_fd is not None)
            or expected_stdin != (stdin_file_fd is not None)):
        raise _metadata_failure()
    values = tuple(
        fd for fd in (stdin_file_fd, stdout_fd, stderr_fd) if fd is not None
    )
    if (any(type(fd) is not int or not 3 <= fd <= MAX_PID for fd in values)
            or len(values) != len(set(values))
            or any(fd in (request_fd, control_fd, 0, 1, 2) for fd in values)):
        raise _metadata_failure()
    return stdout_fd, stderr_fd, stdin_file_fd


def _fd_identity(fd: int) -> tuple[int, int]:
    observed = os.fstat(fd)
    return observed.st_dev, observed.st_ino


def _validate_spawn_fds(
    stdout_fd: int | None,
    stderr_fd: int | None,
    inherited_fds: tuple[int, ...],
) -> None:
    """Authenticate all numeric inputs before pipe allocation can reuse a hole."""
    if (type(inherited_fds) is not tuple or len(inherited_fds) != 2
            or any(type(fd) is not int or fd < 0 for fd in inherited_fds)):
        raise RuntimeError("launcher_metadata_invalid")
    outputs = tuple(fd for fd in (stdout_fd, stderr_fd) if fd is not None)
    values = outputs + inherited_fds
    if (any(type(fd) is not int or fd < 0 for fd in outputs)
            or len(values) != len(set(values))):
        raise RuntimeError("launcher_metadata_invalid")
    try:
        identities = tuple(_fd_identity(fd) for fd in values)
    except OSError:
        raise RuntimeError("launcher_metadata_invalid") from None
    if len(identities) != len(set(identities)):
        raise RuntimeError("launcher_metadata_invalid")


def _consume_output_fd_metadata(
    request,
    *,
    request_fd: int,
    control_fd: int,
) -> tuple[int | None, int | None]:
    """Consume numeric environment metadata and bind it to request claims."""
    stdout_fd, stderr_fd = _pop_output_fd_metadata()
    return _validate_output_fds(
        request, stdout_fd, stderr_fd,
        request_fd=request_fd, control_fd=control_fd,
    )


def _close_quietly(fd: int) -> None:
    if type(fd) is not int or fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _close_child_fds_except(keep: set[int]) -> None:
    """Close the fork snapshot, including aliases unknown to the worker owner."""
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        # Linux procfs is part of this launcher's identity-proof prerequisite.  A
        # missing view is a setup failure rather than permission to retain ambient
        # descriptors.
        raise RuntimeError("launcher_proc_unavailable") from None
    for name in names:
        if not name.isascii() or not name.isdecimal():
            continue
        fd = int(name)
        if fd not in keep:
            _close_quietly(fd)


def _isolate_browser_stdio() -> None:
    """Keep the sidecar from retaining the controller stream pipes."""
    null_fd = os.open(
        "/dev/null", os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for fd in (0, 1, 2):
            os.dup2(null_fd, fd, inheritable=True)
    finally:
        if null_fd not in {0, 1, 2}:
            _close_quietly(null_fd)


def _launcher_child(
    *,
    worker_pid: int,
    release_read: int,
    release_write: int,
    stdout_fd: int | None,
    stderr_fd: int | None,
    inherited_fds: tuple[int, ...],
) -> None:
    """Become a release-gated child without ever decoding or executing a target."""
    try:
        _close_quietly(release_write)
        _arm_parent_death(worker_pid)
        os.setsid()
        if os.getpid() != os.getpgrp() or os.getpid() != os.getsid(0):
            raise RuntimeError("launcher_identity_invalid")

        if stdout_fd is None:
            _close_quietly(1)
        elif stdout_fd != 1:
            os.dup2(stdout_fd, 1, inheritable=False)
        if stderr_fd is None:
            _close_quietly(2)
        elif stderr_fd != 2:
            os.dup2(stderr_fd, 2, inheritable=False)

        keep = {
            release_read,
            1 if stdout_fd is not None else -1,
            2 if stderr_fd is not None else -1,
        }
        _close_child_fds_except(keep)

        os.kill(os.getpid(), signal.SIGSTOP)
        # SIGCONT is merely scheduling.  No release token is ever written in this
        # slice; EOF or a stray byte both terminate without exec.
        while True:
            try:
                os.read(release_read, 1)
                break
            except InterruptedError:
                continue
        _close_quietly(release_read)
    except BaseException:
        pass
    os._exit(0)


def _execution_launcher_child(
    *,
    worker_pid: int,
    release_read: int,
    release_write: int,
    stdin_read: int,
    stdin_write: int,
    stdout_read: int,
    stdout_write: int,
    stderr_read: int,
    stderr_write: int,
    exec_status_read: int,
    exec_status_write: int,
    broker_report_read: int,
    broker_report_write: int,
    broker_ack_read: int,
    broker_ack_write: int,
    chrome_input_read: int,
    bridge_input_write: int,
    bridge_output_read: int,
    chrome_output_write: int,
    browser_exec_status_read: int,
    browser_exec_status_write: int,
    browser_report_read: int,
    browser_report_write: int,
    browser_ack_read: int,
    browser_ack_write: int,
    browser_pid_read: int,
    browser_pid_write: int,
    inherited_fds: tuple[int, ...],
) -> None:
    """Park without target material, then exec one exact private request.

    The worker is the only process with the release writer.  SIGCONT is merely a
    scheduling event: until a complete canonical request arrives and the release
    channel reaches EOF, this child cannot reach ``execve``.  The status writer is
    close-on-exec, so EOF on the worker's status reader is positive kernel evidence
    that the image transition completed.
    """
    try:
        for fd in (release_write, stdin_write, stdout_read, stderr_read,
                   exec_status_read, broker_report_read, broker_ack_write,
                   bridge_input_write, bridge_output_read,
                   browser_exec_status_read, browser_report_read,
                   browser_ack_write, browser_pid_read):
            _close_quietly(fd)
        _arm_parent_death(worker_pid)
        os.setsid()
        if os.getpid() != os.getpgrp() or os.getpid() != os.getsid(0):
            raise RuntimeError("launcher_identity_invalid")

        keep = {
            release_read, stdin_read, stdout_write, stderr_write,
            exec_status_write, broker_report_write, broker_ack_read,
            chrome_input_read, chrome_output_write,
            browser_exec_status_write, browser_report_write,
            browser_ack_read, browser_pid_write,
        }
        _close_child_fds_except(keep)
        os.kill(os.getpid(), signal.SIGSTOP)

        release_wire = runner_ipc.read_frame(
            release_read, max_frame_bytes=MAX_FRAME_BYTES,
        )
        runner_ipc.require_eof(release_read)
        request = decode_request(release_wire)
        _close_quietly(release_read)

        if stdin_read != 0:
            os.dup2(stdin_read, 0, inheritable=True)
        if stdout_write != 1:
            os.dup2(stdout_write, 1, inheritable=True)
        if stderr_write != 2:
            os.dup2(stderr_write, 2, inheritable=True)
        for fd in (stdin_read, stdout_write, stderr_write):
            if fd not in (0, 1, 2):
                _close_quietly(fd)
        environment = {key: value for key, value in request.environment}
        policy_raw = environment.pop(PRIVATE_POLICY_ENV, None)
        browser_raw = environment.pop(_PRIVATE_BROWSER_LAUNCH_ENV, None)
        environment.pop(PRIVATE_REDACTIONS_ENV, None)
        if browser_raw is None:
            for fd in (
                chrome_input_read, chrome_output_write,
                browser_exec_status_write, browser_report_write,
                browser_ack_read, browser_pid_write,
            ):
                _close_quietly(fd)
        else:
            if policy_raw is None or request.tool != "gowitness":
                raise RuntimeError("network_browser_launch_invalid")
            try:
                browser_document = json.loads(browser_raw)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("network_browser_launch_invalid") from exc
            if (type(browser_document) is not dict
                    or set(browser_document) != {"argv", "environment"}
                    or type(browser_document["argv"]) is not list
                    or not browser_document["argv"]
                    or any(type(value) is not str or "\x00" in value
                           for value in browser_document["argv"])
                    or type(browser_document["environment"]) is not dict
                    or any(type(key) is not str or type(value) is not str
                           or not key or "=" in key or "\x00" in key or "\x00" in value
                           for key, value in browser_document["environment"].items())):
                raise RuntimeError("network_browser_launch_invalid")
            browser_argv = tuple(browser_document["argv"])
            browser_environment = dict(browser_document["environment"])
            parent_pid = os.getpid()
            browser_pid = os.fork()
            if browser_pid == 0:
                try:
                    for fd in (
                        exec_status_write, broker_report_write, broker_ack_read,
                    ):
                        _close_quietly(fd)
                    os.setpgid(0, 0)
                    if os.getpgrp() != os.getpid() or os.getsid(0) != parent_pid:
                        raise RuntimeError("network_browser_identity_invalid")
                    runner_ipc.write_all(
                        browser_pid_write, struct.pack("!I", os.getpid()),
                    )
                    _close_quietly(browser_pid_write)
                    keep = {
                        0, 1, 2, chrome_input_read, chrome_output_write,
                        browser_exec_status_write, browser_report_write,
                        browser_ack_read,
                    }
                    _close_child_fds_except(keep)
                    _isolate_browser_stdio()
                    child_install_and_report(
                        browser_report_write, browser_ack_read, profile="browser",
                        control_fds=(browser_exec_status_write,
                                     chrome_input_read, chrome_output_write),
                        deadline_monotonic=(
                            time.monotonic() + _BROKER_BOOTSTRAP_SECONDS
                        ),
                    )
                    read_identity = os.fstat(chrome_input_read)
                    write_identity = os.fstat(chrome_output_write)
                    os.dup2(chrome_input_read, 3, inheritable=True)
                    os.dup2(chrome_output_write, 4, inheritable=True)
                    for fd in (chrome_input_read, chrome_output_write):
                        if fd not in {3, 4}:
                            _close_quietly(fd)
                    attest_exec_fds(pipe_controls=(
                        (3, "read", read_identity.st_dev, read_identity.st_ino),
                        (4, "write", write_identity.st_dev, write_identity.st_ino),
                    ), status_fd=browser_exec_status_write)
                    os.execve(
                        browser_argv[0], list(browser_argv), browser_environment,
                    )
                except BaseException:
                    try:
                        os.write(browser_exec_status_write, b"\x01")
                    except BaseException:
                        pass
                os._exit(127)
            for fd in (
                chrome_input_read, chrome_output_write,
                browser_exec_status_write, browser_report_write,
                browser_ack_read, browser_pid_write,
            ):
                _close_quietly(fd)
        if policy_raw is None:
            _close_quietly(broker_report_write)
            _close_quietly(broker_ack_read)
        else:
            # The only profile admitted by this first runner integration is the
            # fixed standard filter.  The trusted worker authenticates the
            # listener and starts its broker before it releases this ACK.
            child_install_and_report(
                broker_report_write, broker_ack_read, profile="standard",
                control_fds=(exec_status_write,),
                deadline_monotonic=time.monotonic() + _BROKER_BOOTSTRAP_SECONDS,
            )
        if request.cwd is not None:
            os.chdir(request.cwd)
        os.execvpe(request.argv[0], list(request.argv), environment)
    except BaseException:
        try:
            os.write(exec_status_write, b"\x01")
        except BaseException:
            pass
    os._exit(127)


class _ParkedLauncher:
    """Exclusive status/release authority for one exact forked child."""

    def __init__(
        self,
        pid: int,
        release_write: int,
        *,
        stdin_write: int = -1,
        stdout_read: int = -1,
        stderr_read: int = -1,
        exec_status_read: int = -1,
        broker_report_read: int = -1,
        broker_ack_write: int = -1,
    ) -> None:
        self.pid = pid
        self.pgid = pid
        self.start_time_ticks: int | None = None
        self.returncode: int | None = None
        self._release_write = release_write
        self._release_close_attempted = False
        self.stdin_write_fd = stdin_write
        self.stdout_read_fd = stdout_read
        self.stderr_read_fd = stderr_read
        self._exec_status_read = exec_status_read
        self._broker_report_read = broker_report_read
        self._broker_ack_write = broker_ack_write
        self._release_callback = None
        self._network_broker_session = None
        self._network_browser_broker_session = None
        self._network_proxy = None
        self._network_cdp_bridge = None
        self._network_control_registry = None
        self._network_effect_fence = None
        self._browser_pid = None
        self._browser_pidfd = -1
        self._browser_preexec_identity_verified = False
        self._released = False
        self._reaped = False
        self._stop_wait_state = "not_started"
        self._stop_wait_result: tuple[int, int] | None = None
        self._wait_state = "not_started"
        self._wait_result: tuple[int, int] | None = None

    def close_inherited_before_stop(self) -> None:
        """Compatibility seam; real child setup closes inherited descriptors."""

    def prove_stopped(self) -> bool:
        if self._reaped:
            return False
        if self._stop_wait_state == "complete":
            if self._stop_wait_result is None:
                raise RuntimeError("launcher_wait_invalid")
            waited_pid, status = self._stop_wait_result
            return self._finish_stop_observation(waited_pid, status)
        if self._stop_wait_state == "ambiguous":
            # The prior wait may have consumed the stop notification.  A fresh
            # parent/start/session/group/stopped proof is stronger than replaying
            # that notification and cannot reap the child.
            try:
                worker = capture_process_identity(os.getpid())
                proof = capture_parked_process_identity(self.pid, worker)
            except Exception:
                self._stop_wait_state = "not_started"
            else:
                self.start_time_ticks = proof.process.start_time_ticks
                self._stop_wait_state = "proved_after_ambiguity"
                return True
        while True:
            try:
                self._stop_wait_state = "attempting"; self._stop_wait_result = os.waitpid(self.pid, os.WUNTRACED); self._stop_wait_state = "complete"
                break
            except InterruptedError:
                self._stop_wait_state = "not_started"
                continue
            except BaseException:
                self._stop_wait_state = "ambiguous"
                raise
        if self._stop_wait_result is None:
            raise RuntimeError("launcher_wait_invalid")
        waited_pid, status = self._stop_wait_result
        return self._finish_stop_observation(waited_pid, status)

    def _finish_stop_observation(self, waited_pid: int, status: int) -> bool:
        if waited_pid != self.pid:
            raise RuntimeError("launcher_wait_invalid")
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self.returncode = os.waitstatus_to_exitcode(status)
            self._reaped = True
            self._wait_state = "terminal"
            return False
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            return False
        worker = capture_process_identity(os.getpid())
        proof = capture_parked_process_identity(self.pid, worker)
        if (proof.process.pid != self.pid or proof.parent.pid != os.getpid()
                or proof.state not in ("T", "t")):
            raise RuntimeError("launcher_identity_invalid")
        self.start_time_ticks = proof.process.start_time_ticks
        return True

    def _finish_wait_result(self, waited_pid: int, status: int) -> int:
        if waited_pid != self.pid:
            raise RuntimeError("launcher_wait_invalid")
        self.returncode = os.waitstatus_to_exitcode(status)
        self._reaped = True
        self._wait_state = "terminal"
        return self.returncode

    def _reconcile_ambiguous_wait(self) -> int | None:
        try:
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            # This object is the exclusive reaper for the direct child.  ECHILD
            # after an ambiguous wait means that invocation consumed the status.
            self._reaped = True
            self._wait_state = "terminal"
            return self.returncode
        if waited_pid == 0:
            self._wait_state = "not_started"
            return None
        return self._finish_wait_result(waited_pid, status)

    def release_for_exec(
        self,
        request: WorkerRequest,
        *,
        deadline: float | None = None,
        clock=time.monotonic,
    ) -> bool:
        """Release one exact request and prove its successful image transition."""
        if (type(request) is not WorkerRequest or self._reaped or self._released
                or self._release_write < 0 or self._exec_status_read < 0
                or not callable(clock)):
            return False
        if deadline is not None and (
                type(deadline) not in (int, float) or type(deadline) is bool):
            return False
        wire = encode_request(request)
        try:
            # Waking the child is not authority: it still blocks on the complete
            # framed release plus EOF.  Wake before the potentially pipe-sized
            # write so a large, still-bounded request cannot deadlock on capacity.
            os.kill(self.pid, signal.SIGCONT)
            runner_ipc.write_all(self._release_write, wire)
            os.close(self._release_write)
            self._release_write = -1
            self._release_close_attempted = True
            callback = self._release_callback
            if callback is not None:
                callback(deadline=deadline, clock=clock)
            else:
                self._close_broker_bootstrap_fds()
            while True:
                timeout = None
                if deadline is not None:
                    timeout = max(0.0, float(deadline) - float(clock()))
                    if timeout <= 0:
                        return False
                readable, _, _ = select.select(
                    (self._exec_status_read,), (), (), timeout,
                )
                if not readable:
                    return False
                try:
                    status = os.read(self._exec_status_read, 1)
                except InterruptedError:
                    continue
                break
        except BaseException:
            raise
        finally:
            if self._exec_status_read >= 0:
                _close_quietly(self._exec_status_read)
                self._exec_status_read = -1
            self._close_broker_bootstrap_fds()
        if status:
            return False
        self._released = True
        return True

    def _close_broker_bootstrap_fds(self) -> None:
        for attribute in (
            "_broker_report_read", "_broker_ack_write",
            "_browser_bridge_input_write", "_browser_bridge_output_read",
            "_browser_exec_status_read", "_browser_report_read",
            "_browser_ack_write", "_browser_pid_read",
        ):
            fd = getattr(self, attribute, -1)
            if fd >= 0:
                _close_quietly(fd)
                setattr(self, attribute, -1)

    def abort_and_reap(self) -> int:
        if self._reaped:
            return 0 if self.returncode is None else self.returncode
        if self._wait_state == "complete":
            if self._wait_result is None:
                raise RuntimeError("launcher_wait_invalid")
            return self._finish_wait_result(*self._wait_result)
        if self._wait_state == "ambiguous":
            reconciled = self._reconcile_ambiguous_wait()
            if self._reaped:
                return 0 if reconciled is None else reconciled
        if self._stop_wait_state == "complete":
            if self._stop_wait_result is None:
                raise RuntimeError("launcher_wait_invalid")
            waited_pid, status = self._stop_wait_result
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                return self._finish_wait_result(waited_pid, status)

        if self._stop_wait_state == "ambiguous":
            # A failed stop wait may have reaped an early-exiting child.  Reconcile
            # child status before any numeric signal can target a reused identity.
            reconciled = self._reconcile_ambiguous_wait()
            if self._reaped:
                return 0 if reconciled is None else reconciled

        for attribute in (
            "stdin_write_fd", "stdout_read_fd", "stderr_read_fd",
            "_exec_status_read",
            "_broker_report_read", "_broker_ack_write",
            "_browser_bridge_input_write", "_browser_bridge_output_read",
            "_browser_exec_status_read", "_browser_report_read",
            "_browser_ack_write", "_browser_pid_read",
        ):
            fd = getattr(self, attribute, -1)
            if fd >= 0:
                _close_quietly(fd)
                setattr(self, attribute, -1)

        if self._release_write >= 0 and not self._release_close_attempted:
            release_write = self._release_write
            try:
                os.close(release_write)
            except OSError:
                self._release_close_attempted = True
                self._release_write = -1
            except BaseException:
                # The raw close may or may not have completed.  Never retry a
                # numeric FD that could now be reused; process exit closes any
                # surviving private writer after child reconciliation.
                self._release_close_attempted = True
                self._release_write = -1
                raise
            else:
                self._release_close_attempted = True
                self._release_write = -1
        # Retrying SIGKILL before wait is safe: the exact direct child remains
        # unreaped, so its PID/PGID cannot have been reused.
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                self._wait_state = "attempting"; self._wait_result = os.waitpid(self.pid, 0); self._wait_state = "complete"
                break
            except InterruptedError:
                self._wait_state = "not_started"
                continue
            except BaseException:
                self._wait_state = "ambiguous"
                raise
        if self._wait_result is None:
            raise RuntimeError("launcher_wait_invalid")
        return self._finish_wait_result(*self._wait_result)

    def send_deadline_sigint(self) -> None:
        """Request the private graceful deadline disposition without reaping.

        The stream owner remains the exclusive reaper and keeps draining until
        its fixed outer settlement deadline.  That owner falls back to
        ``abort_and_reap`` if this request does not settle the launcher.
        """
        if self._reaped:
            return
        try:
            os.killpg(self.pgid, signal.SIGINT)
        except ProcessLookupError:
            # A concurrent leader exit is reconciled by the stream owner.  Do
            # not retry a numeric identity after its process group is gone.
            pass
        except OSError:
            # Delivery is ambiguous for every other failure.  Let the stream
            # owner take its exception path, SIGKILL, and exactly reap.
            raise


class _PreparedAbortOwner:
    """Stable cleanup root spanning allocation, fork and transaction return."""

    def __init__(self) -> None:
        self.release_read = -1
        self.release_write = -1
        self.pid = -1
        self.launcher = None


class _ExecutionLauncherOwner:
    """Stable allocation graph for one release-gated execution launcher."""

    def __init__(self) -> None:
        self.release_read = -1
        self.release_write = -1
        self.stdin_read = -1
        self.stdin_write = -1
        self.stdout_read = -1
        self.stdout_write = -1
        self.stderr_read = -1
        self.stderr_write = -1
        self.exec_status_read = -1
        self.exec_status_write = -1
        self.broker_report_read = -1
        self.broker_report_write = -1
        self.broker_ack_read = -1
        self.broker_ack_write = -1
        self.chrome_input_read = -1
        self.bridge_input_write = -1
        self.bridge_output_read = -1
        self.chrome_output_write = -1
        self.browser_exec_status_read = -1
        self.browser_exec_status_write = -1
        self.browser_report_read = -1
        self.browser_report_write = -1
        self.browser_ack_read = -1
        self.browser_ack_write = -1
        self.browser_pid_read = -1
        self.browser_pid_write = -1
        self.pid = -1
        self.launcher = None


def _close_execution_child_ends(owner: _ExecutionLauncherOwner) -> None:
    for attribute in (
        "release_read", "stdin_read", "stdout_write", "stderr_write",
        "exec_status_write", "broker_report_write", "broker_ack_read",
        "chrome_input_read", "chrome_output_write",
        "browser_exec_status_write", "browser_report_write",
        "browser_ack_read", "browser_pid_write",
    ):
        fd = getattr(owner, attribute)
        if fd >= 0:
            _close_quietly(fd)
            setattr(owner, attribute, -1)


def _adopt_execution_launcher(owner: _ExecutionLauncherOwner) -> _ParkedLauncher | None:
    if owner.launcher is None and owner.pid > 0:
        owner.launcher = _ParkedLauncher(
            owner.pid,
            owner.release_write,
            stdin_write=owner.stdin_write,
            stdout_read=owner.stdout_read,
            stderr_read=owner.stderr_read,
            exec_status_read=owner.exec_status_read,
            broker_report_read=owner.broker_report_read,
            broker_ack_write=owner.broker_ack_write,
        )
        owner.launcher._browser_bridge_input_write = owner.bridge_input_write
        owner.launcher._browser_bridge_output_read = owner.bridge_output_read
        owner.launcher._browser_exec_status_read = owner.browser_exec_status_read
        owner.launcher._browser_report_read = owner.browser_report_read
        owner.launcher._browser_ack_write = owner.browser_ack_write
        owner.launcher._browser_pid_read = owner.browser_pid_read
    launcher = owner.launcher
    if launcher is not None:
        owner.release_write = -1
        owner.stdin_write = -1
        owner.stdout_read = -1
        owner.stderr_read = -1
        owner.exec_status_read = -1
        owner.broker_report_read = -1
        owner.broker_ack_write = -1
        owner.bridge_input_write = -1
        owner.bridge_output_read = -1
        owner.browser_exec_status_read = -1
        owner.browser_report_read = -1
        owner.browser_ack_write = -1
        owner.browser_pid_read = -1
    _close_execution_child_ends(owner)
    return launcher


def _close_execution_owner_fds(owner: _ExecutionLauncherOwner) -> None:
    for attribute in (
        "release_read", "release_write", "stdin_read", "stdin_write",
        "stdout_read", "stdout_write", "stderr_read", "stderr_write",
        "exec_status_read", "exec_status_write",
        "broker_report_read", "broker_report_write",
        "broker_ack_read", "broker_ack_write",
        "chrome_input_read", "bridge_input_write", "bridge_output_read",
        "chrome_output_write", "browser_exec_status_read",
        "browser_exec_status_write", "browser_report_read",
        "browser_report_write", "browser_ack_read", "browser_ack_write",
        "browser_pid_read", "browser_pid_write",
    ):
        fd = getattr(owner, attribute)
        if fd >= 0:
            _close_quietly(fd)
            setattr(owner, attribute, -1)


class _ExecutionLauncherFence:
    """Cleanup layer shared by launcher allocation and execution ownership."""

    def __init__(self, owner: _ExecutionLauncherOwner) -> None:
        self._owner = owner

    def __enter__(self) -> _ExecutionLauncherFence:
        return self

    def __exit__(self, _kind, primary, _traceback) -> bool:
        if primary is None:
            return False
        owner = self._owner
        launcher = _adopt_execution_launcher(owner)
        if launcher is not None and not _launcher_terminal(launcher):
            try:
                _settle_launcher(launcher)
            except BaseException as cleanup:
                if not isinstance(primary, Exception):
                    raise primary
                raise cleanup
        else:
            _close_execution_owner_fds(owner)
        if not isinstance(primary, Exception):
            raise primary
        return False


class _PreparedAbortFence:
    """One active cleanup layer over a shared launcher authority.

    Two layers are installed before the fork.  If the sole cooperative
    cancellation lands in the inner layer's handler or settlement call, the
    outer layer observes the same durable PID/launcher facts and finishes the
    reap before preserving that cancellation.
    """

    def __init__(self, owner: _PreparedAbortOwner) -> None:
        self._owner = owner

    def __enter__(self) -> _PreparedAbortFence:
        return self

    def __exit__(self, _kind, primary, _traceback) -> bool:
        owner = self._owner
        if owner.launcher is None and owner.pid > 0:
            owner.launcher = _ParkedLauncher(owner.pid, owner.release_write)
        launcher = owner.launcher
        if launcher is not None and not _launcher_terminal(launcher):
            try:
                _settle_launcher(launcher)
            except BaseException as cleanup:
                if primary is not None and not isinstance(primary, Exception):
                    raise primary
                raise cleanup
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        return False


def _spawn_parked_launcher(
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
    inherited_fds: tuple[int, ...],
    _owner: _PreparedAbortOwner | None = None,
) -> _ParkedLauncher:
    """Fork a metadata-only launcher before target request decoding."""
    _validate_spawn_fds(stdout_fd, stderr_fd, inherited_fds)
    owner = _PreparedAbortOwner() if _owner is None else _owner
    if (type(owner) is not _PreparedAbortOwner or owner.pid != -1
            or owner.release_read != -1 or owner.release_write != -1
            or owner.launcher is not None):
        raise RuntimeError("launcher_owner_invalid")
    try:
        owner.release_read, owner.release_write = os.pipe()
        worker_pid = os.getpid()
        owner.pid = os.fork()
        if owner.pid == 0:  # pragma: no cover - covered by Linux integration tests
            _launcher_child(
                worker_pid=worker_pid,
                release_read=owner.release_read,
                release_write=owner.release_write,
                stdout_fd=stdout_fd,
                stderr_fd=stderr_fd,
                inherited_fds=inherited_fds,
            )
        owner.launcher = _ParkedLauncher(owner.pid, owner.release_write)
        _close_quietly(owner.release_read)
        owner.release_read = -1
        for fd in {fd for fd in (stdout_fd, stderr_fd) if fd is not None}:
            _close_quietly(fd)
        return owner.launcher
    except BaseException as primary:
        if owner.pid == 0:
            os._exit(_EXIT_BOOTSTRAP_INVALID)
        _close_quietly(owner.release_read)
        owner.release_read = -1
        if owner.pid > 0:
            if owner.launcher is None:
                owner.launcher = _ParkedLauncher(
                    owner.pid, owner.release_write,
                )
            _settle_launcher(owner.launcher)
        else:
            _close_quietly(owner.release_write)
            owner.release_write = -1
        for fd in {fd for fd in (stdout_fd, stderr_fd) if fd is not None}:
            _close_quietly(fd)
        raise primary


def _spawn_execution_launcher(
    *,
    inherited_fds: tuple[int, ...],
    _owner: _ExecutionLauncherOwner | None = None,
) -> _ParkedLauncher:
    """Fork one target-blind launcher whose tool pipes remain worker-owned."""
    if (type(inherited_fds) is not tuple or len(inherited_fds) != 2
            or any(type(fd) is not int or fd < 0 for fd in inherited_fds)
            or len(set(inherited_fds)) != 2):
        raise RuntimeError("launcher_metadata_invalid")
    try:
        identities = tuple(_fd_identity(fd) for fd in inherited_fds)
    except OSError:
        raise RuntimeError("launcher_metadata_invalid") from None
    if len(set(identities)) != len(identities):
        raise RuntimeError("launcher_metadata_invalid")

    owner = _ExecutionLauncherOwner() if _owner is None else _owner
    if (type(owner) is not _ExecutionLauncherOwner or owner.pid != -1
            or owner.launcher is not None):
        raise RuntimeError("launcher_owner_invalid")
    with _ExecutionLauncherFence(owner):
        with _ExecutionLauncherFence(owner):
            owner.release_read, owner.release_write = os.pipe()
            owner.stdin_read, owner.stdin_write = os.pipe()
            owner.stdout_read, owner.stdout_write = os.pipe()
            owner.stderr_read, owner.stderr_write = os.pipe()
            owner.exec_status_read, owner.exec_status_write = os.pipe()
            owner.broker_report_read, owner.broker_report_write = os.pipe()
            owner.broker_ack_read, owner.broker_ack_write = os.pipe()
            owner.chrome_input_read, owner.bridge_input_write = os.pipe()
            owner.bridge_output_read, owner.chrome_output_write = os.pipe()
            owner.browser_exec_status_read, owner.browser_exec_status_write = os.pipe()
            owner.browser_report_read, owner.browser_report_write = os.pipe()
            owner.browser_ack_read, owner.browser_ack_write = os.pipe()
            owner.browser_pid_read, owner.browser_pid_write = os.pipe()
            os.set_inheritable(owner.exec_status_write, False)
            os.set_inheritable(owner.browser_exec_status_write, False)
            worker_pid = os.getpid()
            owner.pid = os.fork()
            if owner.pid == 0:  # pragma: no cover - Linux integration exercises this
                _execution_launcher_child(
                    worker_pid=worker_pid,
                    release_read=owner.release_read,
                    release_write=owner.release_write,
                    stdin_read=owner.stdin_read,
                    stdin_write=owner.stdin_write,
                    stdout_read=owner.stdout_read,
                    stdout_write=owner.stdout_write,
                    stderr_read=owner.stderr_read,
                    stderr_write=owner.stderr_write,
                    exec_status_read=owner.exec_status_read,
                    exec_status_write=owner.exec_status_write,
                    broker_report_read=owner.broker_report_read,
                    broker_report_write=owner.broker_report_write,
                    broker_ack_read=owner.broker_ack_read,
                    broker_ack_write=owner.broker_ack_write,
                    chrome_input_read=owner.chrome_input_read,
                    bridge_input_write=owner.bridge_input_write,
                    bridge_output_read=owner.bridge_output_read,
                    chrome_output_write=owner.chrome_output_write,
                    browser_exec_status_read=owner.browser_exec_status_read,
                    browser_exec_status_write=owner.browser_exec_status_write,
                    browser_report_read=owner.browser_report_read,
                    browser_report_write=owner.browser_report_write,
                    browser_ack_read=owner.browser_ack_read,
                    browser_ack_write=owner.browser_ack_write,
                    browser_pid_read=owner.browser_pid_read,
                    browser_pid_write=owner.browser_pid_write,
                    inherited_fds=inherited_fds,
                )
            launcher = _adopt_execution_launcher(owner)
            if launcher is None:
                raise RuntimeError("launcher_owner_invalid")
            return launcher


def _not_started_streams() -> tuple[StreamSettlement, ...]:
    return tuple(
        StreamSettlement(
            role=role,
            terminal=StreamTerminal.NOT_STARTED,
            observed_bytes=0,
            retained_bytes=0,
            observed_sha256=None,
            retained_sha256=None,
            claim_id=None,
            lines=0,
            detail=None,
        )
        for role in StreamRole
    )


def _negative_settlement(
    *, request_id: str, worker_pid: int, terminal: ExecutionTerminal, detail: str,
    process_group_settled: bool = False,
) -> WorkerSettlement:
    return WorkerSettlement(
        request_id=request_id,
        terminal=terminal,
        launched=False,
        exit_code=None,
        process_group_settled=process_group_settled,
        process_tree_settled=False,
        streams=_not_started_streams(),
        worker_pid=worker_pid,
        tool_pid=None,
        detail=detail,
    )


def _write_settlement(control_fd: int, settlement: WorkerSettlement) -> None:
    runner_ipc.write_all(control_fd, encode_settlement(settlement))


def _launcher_terminal(launcher) -> bool:
    return (
        getattr(launcher, "_reaped", False) is True
        or getattr(launcher, "returncode", None) is not None
    )


def _settle_launcher(launcher) -> bool:
    """Kill/reap once; retry only after a failed cooperative cleanup boundary."""
    first: BaseException | None = None
    try:
        launcher.abort_and_reap()
        return True
    except BaseException as exc:
        first = exc
    if _launcher_terminal(launcher):
        if first is not None and not isinstance(first, Exception):
            raise first
        return True
    try:
        launcher.abort_and_reap()
        settled = True
    except BaseException as retry:
        if first is not None and not isinstance(first, Exception):
            raise first
        if not isinstance(retry, Exception):
            raise retry
        settled = False
    if first is not None and not isinstance(first, Exception):
        raise first
    return settled


def _settle_after_boundary(launcher, primary: BaseException) -> bool:
    """Reconcile child authority, then preserve cooperative cancellation."""
    try:
        settled = _settle_launcher(launcher)
    except BaseException as cleanup:
        if not isinstance(primary, Exception):
            raise primary
        raise cleanup
    if not isinstance(primary, Exception):
        raise primary
    return settled


def _close_listener_handoff(handoff: ListenerHandoff | None) -> None:
    if handoff is None:
        return
    for fd in (handoff.listener_fd, handoff.child_pidfd):
        _close_quietly(fd)


def _read_exact_until(fd: int, size: int, deadline: float) -> bytes:
    body = bytearray()
    while len(body) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("network_browser_bootstrap_timeout")
        readable, _, _ = select.select((fd,), (), (), remaining)
        if not readable:
            raise RuntimeError("network_browser_bootstrap_timeout")
        try:
            block = os.read(fd, size - len(body))
        except InterruptedError:
            continue
        if not block:
            raise RuntimeError("network_browser_bootstrap_truncated")
        body.extend(block)
    return bytes(body)


def _require_exec_eof_until(fd: int, deadline: float) -> None:
    readable, _, _ = select.select((fd,), (), (), max(0.0, deadline - time.monotonic()))
    if not readable:
        raise RuntimeError("network_browser_exec_timeout")
    if os.read(fd, 1):
        raise RuntimeError("network_browser_exec_failed")


def _require_eof_until(fd: int, deadline: float) -> None:
    readable, _, _ = select.select((fd,), (), (), max(0.0, deadline - time.monotonic()))
    if not readable or os.read(fd, 1):
        raise RuntimeError("network_browser_bootstrap_trailing_data")


def _verify_browser_descendant(browser_pid: int, launcher_pid: int) -> None:
    try:
        with open(f"/proc/{browser_pid}/stat", "rb", buffering=0) as handle:
            stat_body = handle.read(4096)
        close = stat_body.rfind(b")")
        fields = stat_body[close + 2:].split()
        parent_pid, process_group, session = map(int, fields[1:4])
        with open(f"/proc/{browser_pid}/cgroup", "rb", buffering=0) as handle:
            browser_cgroup = handle.read(65537)
        with open(f"/proc/{launcher_pid}/cgroup", "rb", buffering=0) as handle:
            launcher_cgroup = handle.read(65537)
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeError("network_browser_identity_invalid") from exc
    if (close < 1 or len(fields) < 4 or parent_pid != launcher_pid
            or process_group != browser_pid or session != launcher_pid
            or not browser_cgroup or len(browser_cgroup) > 65536
            or browser_cgroup != launcher_cgroup):
        raise RuntimeError("network_browser_identity_invalid")


def _configure_network_broker(
    request: WorkerRequest, launcher, *, settlement_deadline: float | None,
) -> WorkerRequest:
    """Prepare optional policy-owned transport before the launcher release.

    Policy parsing and any worker-owned proxy happen only after the authenticated
    GO, but before ``release_for_exec`` receives the derived child request.  The
    callback then starts the kernel broker while the child is blocked in its
    private listener-report/ACK handshake.
    """
    request_environment = dict(request.environment)
    if _PRIVATE_BROWSER_LAUNCH_ENV in request_environment:
        raise RuntimeError("network_browser_launch_environment_forbidden")
    policy_raw = request_environment.get(PRIVATE_POLICY_ENV)
    if policy_raw is None:
        return request

    if type(settlement_deadline) not in {int, float, type(None)}:
        raise RuntimeError("network_broker_settlement_deadline_invalid")
    network_deadline = (
        float((1 << 53) - 1)
        if settlement_deadline is None else float(settlement_deadline)
    )
    if network_deadline <= time.monotonic():
        raise RuntimeError("network_broker_settlement_deadline_invalid")

    policy = BrokerPolicy.from_json(policy_raw)
    if (policy.request_id != request.request_id
            or policy.tool != request.tool):
        raise RuntimeError("network_broker_policy_request_mismatch")

    # GO is already authenticated, but the parked launcher has not received its
    # release frame.  Fix orphan ownership and seal the broker before that child
    # can fork the browser sidecar.
    acquire_worker_subreaper()
    seal_worker_identity()

    registry = ControlEndpointRegistry()
    effect_fence = NetworkEffectFence()
    launcher._network_control_registry = registry
    launcher._network_effect_fence = effect_fence
    child_request = request
    # Kept only in this worker's mediator/session objects.  In particular it
    # is never added to the policy JSON or derived child environment.
    dns_mediator_authentication = None
    if policy.transport_profile == "target-dns":
        dns_mediator_authentication = os.urandom(32)
        mediator = TargetDNSMediator(
            policy, authentication=dns_mediator_authentication,
            deadline_monotonic=network_deadline, effect_fence=effect_fence,
        )
        try:
            mediator.start()
            launcher._network_dns_mediator = mediator
            policy = dataclasses.replace(
                policy, dns_mediator_endpoint=mediator.endpoint,
            )
            child_request = _configure_target_dns_resolvers(
                child_request, policy, launcher, mediator.endpoint,
            )
        except BaseException:
            try:
                mediator.stop()
            finally:
                launcher._network_dns_mediator = None
                _cleanup_target_dns_resolvers(launcher)
            raise
    proxy_flags = None
    proxy_environment = False
    gowitness_browser = False
    if (policy.source_id == "crawl.katana_standard"
            and policy.transport_profile == "target-http-proxy"):
        proxy_flags = ("-proxy",)
    elif (policy.source_id in {"probe.gowitness", "enrich.gowitness"}
          and policy.transport_profile == "browser-pipe-proxy"):
        gowitness_browser = True
    elif policy.transport_profile == "nuclei-authorized-http":
        # Nuclei's AliveSocksProxy is also retryabledns' transport: with this
        # scheme it forces DNS-over-TCP. The pinned proxy owns both the
        # DNS and raw-TCP lanes, so the tracee has no direct resolver door.
        proxy_flags = ("-p", "-pi")
    elif (policy.source_id == "params.oob_control"
          and policy.transport_profile == "oob-control-proxy"):
        proxy_environment = True
    if proxy_flags is not None or proxy_environment or gowitness_browser:
        if any(value.split("=", 1)[0] in _RUNNER_PROXY_FLAGS
               for value in request.argv):
            raise RuntimeError("network_proxy_caller_argument_forbidden")
        if (gowitness_browser
                and any(value.split("=", 1)[0] in _GOWITNESS_WSS_FLAGS
                        for value in request.argv)):
            raise RuntimeError("network_cdp_caller_argument_forbidden")
        if (proxy_environment
                and {"HTTP_PROXY", "HTTPS_PROXY"}.intersection(
                    dict(request.environment),
                )):
            raise RuntimeError("network_proxy_caller_environment_forbidden")
        browser_directories = None
        if gowitness_browser:
            if len(policy.control_helpers) != 1 or len(policy.control_clients) != 1:
                raise RuntimeError("network_browser_control_identity_invalid")
            prepared_home = dict(request.environment).get("HOME")
            if (type(prepared_home) is not str or not os.path.isabs(prepared_home)
                    or not os.path.isdir(prepared_home)):
                raise RuntimeError("network_browser_home_invalid")
            root = tempfile.mkdtemp(prefix=".quarry-chromium-", dir=prepared_home)
            os.chmod(root, 0o700)
            browser_directories = {
                "root": root,
                "home": os.path.join(root, "home"),
                "profile": os.path.join(root, "profile"),
                "tmp": os.path.join(root, "tmp"),
            }
            for path in browser_directories.values():
                if path != root:
                    os.mkdir(path, 0o700)
            policy = dataclasses.replace(
                policy,
                private_unix_roots=tuple(sorted({
                    *policy.private_unix_roots, browser_directories["tmp"],
                })),
            )
        proxy = PinnedBrowserProxy(
            policy, registry, deadline_monotonic=network_deadline,
            effect_fence=effect_fence,
        )
        launcher._network_proxy = proxy
        proxy.start()
        host, port = proxy.endpoint
        if host != "127.0.0.1":
            raise RuntimeError("network_proxy_endpoint_invalid")
        endpoint = f"http://127.0.0.1:{port}"
        if gowitness_browser:
            controller_argv, browser_path = _gowitness_browser_path(request.argv)
            if browser_directories is None:
                raise RuntimeError("network_browser_launch_invalid")
            bridge = PinnedCDPBridge(
                policy, registry,
                chrome_output_fd=launcher._browser_bridge_output_read,
                chrome_input_fd=launcher._browser_bridge_input_write,
                adapter="gowitness", controller_identity=policy.control_clients[0],
                expected_controller_tgid=launcher.pid,
                deadline_monotonic=network_deadline, effect_fence=effect_fence,
            )
            launcher._network_cdp_bridge = bridge
            for attribute in (
                "_browser_bridge_output_read", "_browser_bridge_input_write",
            ):
                fd = getattr(launcher, attribute)
                _close_quietly(fd)
                setattr(launcher, attribute, -1)
            bridge.start()
            browser_document = json.dumps(
                {
                    "argv": list(_browser_argv(
                        browser_path, browser_directories["profile"], proxy.endpoint,
                    )),
                    "environment": {
                        "HOME": browser_directories["home"],
                        "TMPDIR": browser_directories["tmp"],
                        "XDG_CACHE_HOME": os.path.join(browser_directories["home"], ".cache"),
                        "XDG_CONFIG_HOME": os.path.join(browser_directories["home"], ".config"),
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                    },
                },
                ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            )
            environment = dict(request.environment)
            environment[_PRIVATE_BROWSER_LAUNCH_ENV] = browser_document
            child_request = dataclasses.replace(
                request,
                argv=controller_argv + ("--chrome-wss-url", bridge.websocket_url),
                environment=tuple(sorted(environment.items())),
            )
        elif proxy_environment:
            environment = dict(request.environment)
            environment.update({"HTTP_PROXY": endpoint, "HTTPS_PROXY": endpoint})
            child_request = dataclasses.replace(
                request, environment=tuple(sorted(environment.items())),
            )
        else:
            child_request = dataclasses.replace(
                request,
                argv=request.argv + (
                    proxy_flags[0], f"socks5://127.0.0.1:{port}"
                    if policy.transport_profile == "nuclei-authorized-http"
                    else endpoint,
                    *proxy_flags[1:],
                ),
            )

    def bootstrap(*, deadline, clock) -> None:
        now = float(clock())
        handoff = None
        browser_handoff = None
        session = None
        browser_session = None
        try:
            if (type(deadline) not in {int, float}
                    or float(deadline) <= now):
                raise RuntimeError("network_broker_bootstrap_deadline_invalid")
            # These process-wide facts must be fixed before any untrusted
            # descendant can exec.  The launcher is already parked and cannot
            # fork a grandchild before this callback ACKs its listener.
            if gowitness_browser:
                browser_pid = struct.unpack(
                    "!I", _read_exact_until(
                        launcher._browser_pid_read, 4, float(deadline),
                    ),
                )[0]
                if not 1 <= browser_pid < MAX_PID:
                    raise RuntimeError("network_browser_pid_invalid")
                _require_eof_until(launcher._browser_pid_read, float(deadline))
                launcher._browser_pid = browser_pid
                _verify_browser_descendant(browser_pid, launcher.pid)
                launcher._browser_preexec_identity_verified = True
                launcher._browser_pidfd = os.pidfd_open(browser_pid, 0)
                browser_handoff = duplicate_reported_listener(
                    browser_pid, launcher._browser_report_read,
                    expected_profile="browser", deadline_monotonic=float(deadline),
                    abort_child_on_failure=False,
                )
                try:
                    verify_listener_bootstrap(
                        browser_handoff, launcher._browser_report_read,
                        deadline_monotonic=float(deadline),
                        abort_child_on_failure=False,
                    )
                except BaseException:
                    browser_handoff = None
                    raise
            handoff = duplicate_reported_listener(
                launcher.pid, launcher._broker_report_read,
                expected_profile="standard", deadline_monotonic=float(deadline),
                abort_child_on_failure=False,
            )
            try:
                verify_listener_bootstrap(
                    handoff, launcher._broker_report_read,
                    deadline_monotonic=float(deadline),
                    abort_child_on_failure=False,
                )
            except BaseException:
                # verify_listener_bootstrap consumes/settles both handoff FDs
                # on failure; do not retry their numeric values in finally.
                handoff = None
                raise
            session = NetworkBrokerSession(
                handoff, policy, expected_profile="standard",
                deadline_monotonic=network_deadline,
                control_registry=registry,
                effect_fence=effect_fence,
                dns_mediator_authentication=dns_mediator_authentication,
            )
            if gowitness_browser:
                browser_session = NetworkBrokerSession(
                    browser_handoff, policy, expected_profile="browser",
                    deadline_monotonic=network_deadline,
                    control_registry=registry, effect_fence=effect_fence,
                )
                browser_session.start()
            session.start()
            if browser_session is not None:
                browser_pidfd = browser_handoff.child_pidfd
                launcher._network_browser_broker_session = browser_session
                browser_handoff = None
                acknowledge_listener(
                    launcher._browser_ack_write,
                    child_pidfd=browser_pidfd,
                    deadline_monotonic=float(deadline),
                )
                launcher._browser_ack_write = -1
                _require_exec_eof_until(
                    launcher._browser_exec_status_read, float(deadline),
                )
                _close_quietly(launcher._browser_exec_status_read)
                launcher._browser_exec_status_read = -1
                browser_session = None
            child_pidfd = handoff.child_pidfd
            launcher._network_broker_session = session
            handoff = None
            acknowledge_listener(
                launcher._broker_ack_write,
                child_pidfd=child_pidfd,
                deadline_monotonic=float(deadline),
            )
            launcher._broker_ack_write = -1
            session = None  # launcher now owns listener and pidfd settlement.
        except BaseException:
            effect_fence.cancel()
            raise
        finally:
            # The report pipe is no longer useful after its exact EOF proof;
            # acknowledge_listener owns and closes the ACK writer on success.
            if launcher._broker_report_read >= 0:
                _close_quietly(launcher._broker_report_read)
                launcher._broker_report_read = -1
            if getattr(launcher, "_browser_report_read", -1) >= 0:
                _close_quietly(launcher._browser_report_read)
                launcher._browser_report_read = -1
            if getattr(launcher, "_browser_pid_read", -1) >= 0:
                _close_quietly(launcher._browser_pid_read)
                launcher._browser_pid_read = -1
            if session is not None:
                session.stop()
                if launcher._network_broker_session is session:
                    launcher._network_broker_session = None
            if browser_session is not None:
                browser_session.stop()
                if launcher._network_browser_broker_session is browser_session:
                    launcher._network_browser_broker_session = None
            if handoff is not None:
                _close_listener_handoff(handoff)
            if browser_handoff is not None:
                _close_listener_handoff(browser_handoff)

    launcher._release_callback = bootstrap
    return child_request


def _settle_network_broker(launcher, *, deadline_monotonic: float | None = None) -> dict | None:
    """Settle proxy and listener only after the direct launcher is terminal."""
    browser_session = getattr(launcher, "_network_browser_broker_session", None)
    bridge = getattr(launcher, "_network_cdp_bridge", None)
    gowitness_state = getattr(launcher, "_network_gowitness_state", None)
    if browser_session is not None or bridge is not None or gowitness_state is not None:
        return _settle_gowitness_network(
            launcher, deadline_monotonic=deadline_monotonic,
        )
    proxy = getattr(launcher, "_network_proxy", None)
    session = getattr(launcher, "_network_broker_session", None)
    launcher._network_proxy = None
    launcher._network_broker_session = None
    proxy_fault = None
    mediator_fault = None
    mediator_summary = None
    try:
        mediator_summary = _stop_target_dns_mediator(launcher)
    except BaseException as exc:
        mediator_fault = exc
        fence = getattr(launcher, "_network_effect_fence", None)
        if fence is not None:
            try:
                fence.cancel()
            except BaseException as cancel_fault:
                if isinstance(mediator_fault, Exception) \
                        and not isinstance(cancel_fault, Exception):
                    mediator_fault = cancel_fault
    if proxy is not None:
        try:
            proxy.stop()
            proxy_summary = proxy.summary()
            if (type(proxy_summary) is not dict
                    or proxy_summary.get("complete") is not True):
                raise NetworkBrokerRefused(
                    "network_proxy_settlement_incomplete",
                )
        except BaseException as exc:
            proxy_fault = exc
            fence = getattr(launcher, "_network_effect_fence", None)
            if fence is not None:
                try:
                    fence.cancel()
                except BaseException as cancel_fault:
                    if isinstance(proxy_fault, Exception) \
                            and not isinstance(cancel_fault, Exception):
                        proxy_fault = cancel_fault
    if session is None:
        if proxy_fault is not None:
            _cleanup_target_dns_resolvers(launcher)
            raise proxy_fault
        if mediator_fault is not None:
            _cleanup_target_dns_resolvers(launcher)
            raise mediator_fault
        _cleanup_target_dns_resolvers(launcher)
        return None if mediator_summary is None else {"dns_mediator": mediator_summary}
    try:
        session.settle_after_tasks(
            deadline_monotonic=(
                float((1 << 53) - 1)
                if deadline_monotonic is None else float(deadline_monotonic)
            ),
        )
        summary = session.summary()
        if type(summary) is not dict or summary.get("complete") is not True:
            raise NetworkBrokerRefused("network_broker_settlement_incomplete")
        if proxy_fault is not None:
            raise proxy_fault
        if mediator_fault is not None:
            raise mediator_fault
        if mediator_summary is not None:
            summary["dns_mediator"] = mediator_summary
        _cleanup_target_dns_resolvers(launcher)
        return summary
    except BaseException as primary:
        fence = getattr(launcher, "_network_effect_fence", None)
        cancel_fault = None
        if fence is not None:
            try:
                fence.cancel()
            except BaseException as exc:
                cancel_fault = exc
        session.stop()
        _cleanup_target_dns_resolvers(launcher)
        if (cancel_fault is not None and isinstance(primary, Exception)
                and not isinstance(cancel_fault, Exception)):
            raise cancel_fault
        raise


def _settle_gowitness_network(launcher, *, deadline_monotonic: float | None) -> dict:
    """Settle controller, CDP, and the separately grouped browser in order."""
    deadline = (
        float((1 << 53) - 1)
        if deadline_monotonic is None else float(deadline_monotonic)
    )
    state = getattr(launcher, "_network_gowitness_state", None)
    if state is None:
        state = {
            "controller_summary": None, "controller_eof": False,
            "browser_killed": False,
            "adopted_killed": False, "browser_summary": None,
            "bridge_summary": None, "proxy_summary": None,
            "reaped": None, "fence_cancelled": False,
            "stopped": set(), "cleanup_required": False,
            "cleanup_complete": False, "complete_summary": None,
        }
        launcher._network_gowitness_state = state
    if state["complete_summary"] is not None:
        return state["complete_summary"]
    if state["cleanup_complete"]:
        return {"complete": False, "cleanup_complete": True}
    controller = launcher._network_broker_session
    browser = launcher._network_browser_broker_session
    bridge = launcher._network_cdp_bridge
    proxy = launcher._network_proxy
    fence = launcher._network_effect_fence
    try:
        if state["cleanup_required"]:
            _cleanup_gowitness_network(launcher, state, deadline)
            return {"complete": False, "cleanup_complete": True}
        if any(value is None for value in (controller, browser, bridge, proxy, fence)):
            raise NetworkBrokerRefused("network_browser_settlement_authority_invalid")
        if state["controller_summary"] is None:
            controller.settle_after_tasks(deadline_monotonic=deadline)
            observed = controller.summary()
            if observed.get("complete") is not True:
                raise NetworkBrokerRefused("network_broker_settlement_incomplete")
            state["controller_summary"] = observed
        if not state["controller_eof"]:
            while time.monotonic() < deadline:
                cdp_live = bridge.summary()
                if (cdp_live.get("settled_connections") == 1
                        and cdp_live.get("active_client") is False):
                    state["controller_eof"] = True
                    break
                time.sleep(0.01)
            if not state["controller_eof"]:
                raise NetworkBrokerRefused("network_cdp_controller_eof_unproved")
        _kill_browser_authority(launcher, state)
        if not state["adopted_killed"]:
            _kill_adopted_browser_descendants(browser, deadline)
            state["adopted_killed"] = True
        if state["browser_summary"] is None:
            browser.settle_after_tasks(deadline_monotonic=deadline)
            observed = browser.summary()
            if observed.get("complete") is not True:
                raise NetworkBrokerRefused("network_browser_settlement_incomplete")
            state["browser_summary"] = observed
        if state["bridge_summary"] is None:
            bridge.stop()
            observed = bridge.summary()
            if observed.get("complete") is not True:
                raise NetworkBrokerRefused("network_cdp_settlement_incomplete")
            state["bridge_summary"] = observed
        if state["proxy_summary"] is None:
            proxy.stop()
            observed = proxy.summary()
            if observed.get("complete") is not True:
                raise NetworkBrokerRefused("network_proxy_settlement_incomplete")
            state["proxy_summary"] = observed
        if state["reaped"] is None:
            state["reaped"] = reap_adopted_descendants(
                launcher_reaped=True, deadline_monotonic=deadline,
            )
        summary = dict(state["controller_summary"])
        summary.update({
            "browser_broker": state["browser_summary"],
            "cdp_bridge": state["bridge_summary"],
            "browser_proxy": state["proxy_summary"],
            "adopted_descendants": len(state["reaped"]),
        })
        launcher._network_broker_session = None
        launcher._network_browser_broker_session = None
        launcher._network_cdp_bridge = None
        launcher._network_proxy = None
        state["complete_summary"] = summary
        return summary
    except BaseException as exc:
        primary = exc
        state["cleanup_required"] = True
        try:
            _cleanup_gowitness_network(launcher, state, deadline)
        except BaseException as cleanup_fault:
            if not isinstance(primary, Exception):
                raise primary
            if not isinstance(cleanup_fault, Exception):
                raise cleanup_fault
            raise cleanup_fault
        raise primary


def _kill_browser_authority(launcher, state: dict) -> None:
    """Kill the exact browser group, then retire its pidfd without stale reuse."""
    if state["browser_killed"]:
        return
    browser_pid = getattr(launcher, "_browser_pid", None)
    browser_pidfd = getattr(launcher, "_browser_pidfd", -1)
    if browser_pid is None and browser_pidfd < 0:
        state["browser_killed"] = True
        return
    if type(browser_pid) is not int or not 1 <= browser_pid < MAX_PID:
        raise NetworkBrokerRefused("network_browser_identity_invalid")
    if type(browser_pidfd) is not int or browser_pidfd < 0:
        # The browser reports its PID and creates its own PGID before waiting
        # for the listener ACK.  Its exact PPid/session/PGID/cgroup identity is
        # durably recorded before pidfd_open, so failure of that open can still
        # retire the verified pre-exec PGID after bootstrap FDs are closed.
        if getattr(launcher, "_browser_preexec_identity_verified", False) is not True:
            raise NetworkBrokerRefused("network_browser_identity_invalid")
        try:
            os.killpg(browser_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        state["browser_killed"] = True
        return
    try:
        signal.pidfd_send_signal(browser_pidfd, 0)
    except ProcessLookupError:
        pass
    else:
        try:
            os.killpg(browser_pid, signal.SIGKILL)
        except ProcessLookupError:
            signal.pidfd_send_signal(browser_pidfd, signal.SIGKILL)
    state["browser_killed"] = True
    # Commit retirement before close: cancellation may make close ambiguous,
    # but no retry may ever target a subsequently reused numeric descriptor.
    launcher._browser_pidfd = -1
    os.close(browser_pidfd)


def _cleanup_gowitness_network(launcher, state: dict, deadline: float) -> None:
    """Monotonically finish a failed or cancelled sidecar transaction."""
    fence = getattr(launcher, "_network_effect_fence", None)
    if fence is not None and not state["fence_cancelled"]:
        fence.cancel()
        state["fence_cancelled"] = True
    _kill_browser_authority(launcher, state)
    browser = getattr(launcher, "_network_browser_broker_session", None)
    if state["reaped"] is None:
        state["reaped"] = _kill_and_reap_adopted_children(deadline)
        state["adopted_killed"] = True
    for name, component in (
        ("controller", getattr(launcher, "_network_broker_session", None)),
        ("browser", browser),
        ("bridge", getattr(launcher, "_network_cdp_bridge", None)),
        ("proxy", getattr(launcher, "_network_proxy", None)),
    ):
        if component is not None and name not in state["stopped"]:
            component.stop()
            state["stopped"].add(name)
    launcher._network_broker_session = None
    launcher._network_browser_broker_session = None
    launcher._network_cdp_bridge = None
    launcher._network_proxy = None
    state["cleanup_complete"] = True


def _kill_and_reap_adopted_children(deadline: float) -> tuple[tuple[int, int], ...]:
    """Pidfd-kill every current direct child, then prove subreaper emptiness."""
    reaped: list[tuple[int, int]] = []
    first_sweep = True
    while first_sweep or time.monotonic() < deadline:
        first_sweep = False
        try:
            with open(
                    f"/proc/{os.getpid()}/task/{os.getpid()}/children",
                    "r", encoding="ascii") as handle:
                body = handle.read(65537)
        except (OSError, UnicodeError) as exc:
            raise NetworkBrokerRefused(
                "network_browser_descendant_snapshot_failed",
            ) from exc
        if len(body) > 65536:
            raise NetworkBrokerRefused("network_browser_descendant_snapshot_failed")
        values = body.split()
        if len(values) > 512 or any(not value.isdecimal() for value in values):
            raise NetworkBrokerRefused("network_browser_descendant_snapshot_failed")
        for value in values:
            pidfd = -1
            try:
                pidfd = os.pidfd_open(int(value), 0)
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                if pidfd >= 0:
                    os.close(pidfd)
        while len(reaped) <= 512:
            try:
                waited_pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return tuple(reaped)
            if waited_pid == 0:
                break
            reaped.append((waited_pid, status))
        if len(reaped) > 512:
            raise NetworkBrokerRefused("network_browser_descendant_settlement_incomplete")
        time.sleep(0.01)
    raise NetworkBrokerRefused("network_browser_descendant_settlement_incomplete")


def _kill_adopted_browser_descendants(browser_session, deadline: float) -> None:
    """Kill exact subreaper-owned Chrome descendants until listener HUP."""
    while time.monotonic() < deadline:
        if browser_session.summary().get("listener_hup") is True:
            return
        try:
            with open(
                    f"/proc/{os.getpid()}/task/{os.getpid()}/children",
                    "r", encoding="ascii") as handle:
                body = handle.read(65537)
        except (OSError, UnicodeError) as exc:
            raise NetworkBrokerRefused(
                "network_browser_descendant_snapshot_failed",
            ) from exc
        if len(body) > 65536:
            raise NetworkBrokerRefused("network_browser_descendant_snapshot_failed")
        values = body.split()
        if len(values) > 512 or any(not value.isdecimal() for value in values):
            raise NetworkBrokerRefused("network_browser_descendant_snapshot_failed")
        for value in values:
            pidfd = -1
            try:
                pidfd = os.pidfd_open(int(value), 0)
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                if pidfd >= 0:
                    os.close(pidfd)
        time.sleep(0.01)
    raise NetworkBrokerRefused("network_browser_descendant_settlement_incomplete")


def _command_matches_prepared(command, request, prepared: PreparedFrame) -> bool:
    return (
        command.request_id == request.request_id
        and command.request_sha256 == request_digest(request)
        and command.worker_pid == prepared.worker_pid
        and command.prepared_sha256 == prepared_digest(prepared)
    )


def _write_parked_failure(
    control_fd: int,
    *,
    request_id: str,
    worker_pid: int,
    detail: str,
    settled: bool,
) -> bool:
    try:
        _write_settlement(control_fd, _negative_settlement(
            request_id=request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.WORKER_FAILED,
            detail=detail,
            process_group_settled=settled,
        ))
        return True
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return False


def _run_prepared_abort_transaction(
    request_fd: int,
    control_fd: int,
    worker_pid: int,
    owner: _PreparedAbortOwner,
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
) -> int:
    launcher = None
    request = None
    try:
        # No target request has been read or decoded at this boundary.  The forked
        # child receives only fixed descriptor metadata.
        launcher = _spawn_parked_launcher(
            stdout_fd=stdout_fd,
            stderr_fd=stderr_fd,
            inherited_fds=(request_fd, control_fd),
            _owner=owner,
        )
        launcher.close_inherited_before_stop()
    except BaseException as primary:
        if launcher is not None:
            _settle_after_boundary(launcher, primary)
        if not isinstance(primary, Exception):
            raise
        return _EXIT_BOOTSTRAP_INVALID

    try:
        request = decode_request(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        # The fixed supervisor uses explicit stage-free PREPARED mode only to
        # prove and abort the launcher, so request claims need no dummy writer.
        # Once any private writer is supplied, however, its roles must match the
        # request exactly before the transaction can testify PREPARED.
        if stdout_fd is not None or stderr_fd is not None:
            _validate_output_fds(
                request, stdout_fd, stderr_fd,
                request_fd=request_fd, control_fd=control_fd,
            )
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_BOOTSTRAP_INVALID

    digest = request_digest(request)
    try:
        runner_ipc.write_all(control_fd, encode_ready(ReadyFrame(
            request_id=request.request_id,
            worker_pid=worker_pid,
            request_sha256=digest,
        )))
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_CONTROL_FAILED

    proof_error: BaseException | None = None
    try:
        stopped = launcher.prove_stopped()
    except BaseException as primary:
        proof_error = primary
        stopped = False
    if not stopped:
        settled = (
            _settle_after_boundary(launcher, proof_error)
            if proof_error is not None else _settle_launcher(launcher)
        )
        _write_parked_failure(
            control_fd,
            request_id=request.request_id,
            worker_pid=worker_pid,
            detail="launcher_not_parked",
            settled=settled,
        )
        return _EXIT_CONTROL_FAILED

    prepared = PreparedFrame(
        request_id=request.request_id,
        worker_pid=worker_pid,
        launcher_pid=launcher.pid,
        launcher_pgid=launcher.pgid,
        containment_kind=ContainmentKind.CGROUP_V2,
        containment_id=f"direct/quarry-{request.request_id}",
    )
    try:
        runner_ipc.write_all(control_fd, encode_prepared(prepared))
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_CONTROL_FAILED

    command_error: BaseException | None = None
    try:
        command = decode_command(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        runner_ipc.require_eof(request_fd)
        command_valid = _command_matches_prepared(command, request, prepared)
    except BaseException as primary:
        command_error = primary
        command = None
        command_valid = False
        command_invalid = True
    else:
        command_invalid = False

    settled = (
        _settle_after_boundary(launcher, command_error)
        if command_error is not None else _settle_launcher(launcher)
    )
    if not settled:
        detail = "launcher_settlement_failed"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = _EXIT_CONTROL_FAILED
    elif command_invalid:
        detail = "command_invalid"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = _EXIT_CONTROL_FAILED
    elif not command_valid:
        detail = "command_mismatch"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = 0
    elif command.command is WorkerCommandKind.GO:
        detail = "go_refused"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = 0
    else:
        detail = "parent_abort"
        terminal = ExecutionTerminal.CANCELLED
        returncode = 0
    try:
        _write_settlement(control_fd, _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=terminal,
            detail=detail,
            process_group_settled=settled,
        ))
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return _EXIT_CONTROL_FAILED
    return returncode


def _run_prepared_abort_worker(
    request_fd: int,
    control_fd: int,
    worker_pid: int,
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
) -> int:
    owner = _PreparedAbortOwner()
    with _PreparedAbortFence(owner):
        with _PreparedAbortFence(owner):
            return _run_prepared_abort_transaction(
                request_fd, control_fd, worker_pid, owner,
                stdout_fd=stdout_fd, stderr_fd=stderr_fd,
            )


def _stdin_payload_valid(request: WorkerRequest, stdin_data, stdin_file_fd) -> bool:
    if request.stdin_mode is StdinMode.NULL:
        return stdin_data is None and stdin_file_fd is None
    if request.stdin_mode is StdinMode.DATA:
        return (
            type(stdin_data) is bytes
            and stdin_file_fd is None
            and len(stdin_data) == request.stdin_bytes
            and hashlib.sha256(stdin_data).hexdigest() == request.stdin_sha256
        )
    return (
        stdin_data is None
        and type(stdin_file_fd) is int
        and stdin_file_fd >= 3
    )


def _run_execution_transaction(
    request_fd: int,
    control_fd: int,
    worker_pid: int,
    owner: _ExecutionLauncherOwner,
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
    stdin_data: bytes | None,
    stdin_file_fd: int | None,
) -> int:
    launcher = None
    request = None
    try:
        launcher = _spawn_execution_launcher(
            inherited_fds=(request_fd, control_fd),
            _owner=owner,
        )
        launcher.close_inherited_before_stop()
    except BaseException as primary:
        if launcher is not None:
            _settle_after_boundary(launcher, primary)
        if not isinstance(primary, Exception):
            raise
        return _EXIT_BOOTSTRAP_INVALID

    try:
        request = decode_request(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        _validate_execution_fds(
            request, stdout_fd, stderr_fd, stdin_file_fd,
            request_fd=request_fd, control_fd=control_fd,
        )
        if request.stdin_mode is StdinMode.DATA and stdin_data is None:
            stdin_data = runner_ipc.read_payload(
                request_fd, request.stdin_bytes,
                max_payload_bytes=MAX_STDIN_DATA_BYTES,
            )
        if not _stdin_payload_valid(request, stdin_data, stdin_file_fd):
            raise _metadata_failure()
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_BOOTSTRAP_INVALID

    digest = request_digest(request)
    try:
        runner_ipc.write_all(control_fd, encode_ready(ReadyFrame(
            request_id=request.request_id,
            worker_pid=worker_pid,
            request_sha256=digest,
        )))
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_CONTROL_FAILED

    try:
        stopped = launcher.prove_stopped()
    except BaseException as primary:
        settled = _settle_after_boundary(launcher, primary)
        _write_parked_failure(
            control_fd, request_id=request.request_id, worker_pid=worker_pid,
            detail="launcher_not_parked", settled=settled,
        )
        return _EXIT_CONTROL_FAILED
    if not stopped:
        settled = _settle_launcher(launcher)
        _write_parked_failure(
            control_fd, request_id=request.request_id, worker_pid=worker_pid,
            detail="launcher_not_parked", settled=settled,
        )
        return _EXIT_CONTROL_FAILED

    prepared = PreparedFrame(
        request_id=request.request_id,
        worker_pid=worker_pid,
        launcher_pid=launcher.pid,
        launcher_pgid=launcher.pgid,
        containment_kind=ContainmentKind.CGROUP_V2,
        containment_id=f"direct/quarry-{request.request_id}",
    )
    try:
        runner_ipc.write_all(control_fd, encode_prepared(prepared))
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_CONTROL_FAILED

    command_error = None
    try:
        command = decode_command(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        command_valid = _command_matches_prepared(command, request, prepared)
    except BaseException as primary:
        command_error = primary
        command = None
        command_valid = False

    if command_error is not None or not command_valid \
            or command.command is not WorkerCommandKind.GO:
        try:
            # Only a fully correlated GO defers EOF until the post-STARTED
            # parent observation barrier.  Malformed, negative and mismatched
            # commands remain pre-launch transactions and reject every trailing
            # byte, including after a frame-decoding refusal.
            runner_ipc.require_eof(request_fd)
        except BaseException as eof_error:
            if (command_error is None
                    or (isinstance(command_error, Exception)
                        and not isinstance(eof_error, Exception))):
                command_error = eof_error
        settled = (
            _settle_after_boundary(launcher, command_error)
            if command_error is not None else _settle_launcher(launcher)
        )
        if command_error is not None:
            terminal = ExecutionTerminal.WORKER_FAILED
            detail = "command_invalid"
            returncode = _EXIT_CONTROL_FAILED
        elif not command_valid:
            terminal = ExecutionTerminal.WORKER_FAILED
            detail = "command_mismatch"
            returncode = 0
        else:
            terminal = ExecutionTerminal.CANCELLED
            detail = "parent_abort"
            returncode = 0
        _write_settlement(control_fd, _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=terminal,
            detail=detail,
            process_group_settled=settled,
        ))
        return returncode

    started = StartedFrame(
        request_id=request.request_id,
        worker_pid=worker_pid,
        tool_pid=launcher.pid,
        tool_pgid=launcher.pgid,
        containment_kind=prepared.containment_kind,
        containment_id=prepared.containment_id,
    )

    def _write_started() -> None:
        runner_ipc.write_all(control_fd, encode_started(started))
        # The exact parent keeps this private command channel open after GO while
        # it independently authenticates STARTED identity and containment.
        # Waiting for EOF before the stream engine can reap keeps even an already-
        # exited launcher as an inspectable zombie.  Successful authentication
        # closes the barrier immediately; failure settlement also closes it before
        # kill/reap.  In either case trailing bytes are rejected.
        runner_ipc.require_eof(request_fd)

    now = time.monotonic()
    execution_deadline = None if request.timeout == 0 else now + float(request.timeout)
    # Timeout zero leaves execution unbounded.  The stream owner still bounds
    # release and starts a fixed drain grace after natural leader exit; finite
    # executions retain one absolute execution-plus-settlement budget.
    settlement_deadline = (
        None if execution_deadline is None else execution_deadline + 5.0
    )
    network_settlement_complete = False
    try:
        child_request = _configure_network_broker(
            request, launcher, settlement_deadline=settlement_deadline,
        )
        settlement = _run_stream_engine(
            child_request,
            launcher,
            stdin_data=stdin_data,
            stdin_file_fd=stdin_file_fd,
            stdout_stage_fd=stdout_fd,
            stderr_stage_fd=stderr_fd,
            execution_deadline=execution_deadline,
            settlement_deadline=settlement_deadline,
            clock=time.monotonic,
            on_started=_write_started,
        )
        _settle_network_broker(
            launcher, deadline_monotonic=settlement_deadline,
        )
        network_settlement_complete = True
        _write_settlement(control_fd, settlement)
    except BaseException as primary:
        if not _launcher_terminal(launcher):
            _settle_after_boundary(launcher, primary)
        if not network_settlement_complete:
            try:
                _settle_network_broker(
                    launcher, deadline_monotonic=settlement_deadline,
                )
            except BaseException as cleanup_fault:
                if not isinstance(primary, Exception):
                    raise primary
                raise cleanup_fault
        if not isinstance(primary, Exception):
            raise
        return _EXIT_CONTROL_FAILED
    return 0


def _run_execution_worker(
    request_fd: int,
    control_fd: int,
    worker_pid: int,
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
    stdin_data: bytes | None,
    stdin_file_fd: int | None,
) -> int:
    owner = _ExecutionLauncherOwner()
    with _ExecutionLauncherFence(owner):
        with _ExecutionLauncherFence(owner):
            return _run_execution_transaction(
                request_fd, control_fd, worker_pid, owner,
                stdout_fd=stdout_fd, stderr_fd=stderr_fd,
                stdin_data=stdin_data, stdin_file_fd=stdin_file_fd,
            )


def _run_worker(
    request_fd: int,
    control_fd: int,
    expected_parent_pid: int,
    *,
    stdout_fd: int | None = None,
    stderr_fd: int | None = None,
    prepared_abort: bool = False,
    execution: bool = False,
    stdin_data: bytes | None = None,
    stdin_file_fd: int | None = None,
) -> int:
    """Run one legacy or parked transaction over blocking descriptors."""
    _arm_parent_death(expected_parent_pid)
    worker_pid = os.getpid()
    if (type(prepared_abort) is not bool or type(execution) is not bool
            or (prepared_abort and execution)):
        raise _metadata_failure()
    if execution:
        return _run_execution_worker(
            request_fd, control_fd, worker_pid,
            stdout_fd=stdout_fd, stderr_fd=stderr_fd,
            stdin_data=stdin_data, stdin_file_fd=stdin_file_fd,
        )
    if prepared_abort or stdout_fd is not None or stderr_fd is not None:
        return _run_prepared_abort_worker(
            request_fd, control_fd, worker_pid,
            stdout_fd=stdout_fd, stderr_fd=stderr_fd,
        )
    try:
        request = decode_request(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
    except BaseException:
        return _EXIT_BOOTSTRAP_INVALID

    digest = request_digest(request)
    try:
        runner_ipc.write_all(control_fd, encode_ready(ReadyFrame(
            request_id=request.request_id,
            worker_pid=worker_pid,
            request_sha256=digest,
        )))
    except BaseException:
        return _EXIT_CONTROL_FAILED

    try:
        command = decode_command(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        runner_ipc.require_eof(request_fd)
    except BaseException:
        try:
            _write_settlement(control_fd, _negative_settlement(
                request_id=request.request_id,
                worker_pid=worker_pid,
                terminal=ExecutionTerminal.WORKER_FAILED,
                detail="command_invalid",
            ))
        except BaseException:
            return _EXIT_CONTROL_FAILED
        return _EXIT_CONTROL_FAILED

    correlation_ok = (
        command.request_id == request.request_id
        and command.request_sha256 == digest
        and command.worker_pid == worker_pid
        and command.prepared_sha256 is None
    )
    if not correlation_ok:
        settlement = _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.WORKER_FAILED,
            detail="command_mismatch",
        )
    elif command.command is WorkerCommandKind.GO:
        settlement = _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.WORKER_FAILED,
            detail="go_before_prepared",
        )
    else:
        settlement = _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.CANCELLED,
            detail="parent_abort",
        )
    try:
        _write_settlement(control_fd, settlement)
    except BaseException:
        return _EXIT_CONTROL_FAILED
    return 0


def main() -> int:
    """Process entry point; never render private failures to stderr."""
    try:
        expected_parent_pid = _expected_parent_pid()
        prepared_abort = _pop_prepared_abort_mode()
        execution = _pop_execution_mode()
        stdout_fd, stderr_fd = _pop_output_fd_metadata()
        stdin_file_fd = _pop_input_fd_metadata()
        # The bootstrap environment contains only fixed numeric metadata.  Remove
        # even that value before accepting the target-effective request over IPC.
        os.environ.clear()
        return _run_worker(
            0, 1, expected_parent_pid,
            stdout_fd=stdout_fd, stderr_fd=stderr_fd,
            prepared_abort=prepared_abort,
            execution=execution,
            stdin_file_fd=stdin_file_fd,
        )
    except BaseException:
        return _EXIT_BOOTSTRAP_INVALID
    finally:
        try:
            os.close(1)
        except OSError:
            pass


if __name__ == "__main__":  # pragma: no cover - exercised by integration tests
    raise SystemExit(main())
