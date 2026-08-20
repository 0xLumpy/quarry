#!/usr/bin/env python3
"""Isolated diagnostic harness for the V310-07 real browser doors.

This helper is invoked only by an H1 test under sudo.  It builds two network
namespaces joined by one veth, gives the tool side no default route, and runs a
literal DNS/HTTP fixture on the other side.  It emits JSON diagnostics; it is
not release evidence by itself.
"""
from __future__ import annotations

import ctypes
import dataclasses
import errno
import fcntl
import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

from quarry_recon import netguard, network_broker
from quarry_recon.network_broker import (
    BrokerPolicy,
    ControlEndpointRegistry,
    NetworkEffectFence,
    NetworkBrokerSession,
    acknowledge_listener,
    acquire_worker_subreaper,
    attest_exec_fds,
    child_install_and_report,
    duplicate_reported_listener,
    reap_adopted_descendants,
    seal_worker_identity,
    verify_listener_bootstrap,
)
from quarry_recon.network_cdp import PinnedCDPBridge, pipe_exec_identity
from quarry_recon.network_proxy import PinnedBrowserProxy


_TOOL_IP = "10.203.0.2"
_FIXTURE_IP = "10.203.0.1"
_DNS_PORT = 53
_HTTP_PORT = 8080
_HTTPS_PORT = 8443
_INVALID_HTTPS_PORT = 8444
_CRASHPAD_UPLOAD_PORT = 9090
_MAX_COMMAND_BYTES = 64 * 1024


def _run(*argv: str) -> None:
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _drop() -> None:
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)


def _write_all(fd: int, body: bytes) -> None:
    while body:
        written = os.write(fd, body)
        if written <= 0:
            raise RuntimeError("pipe write failed")
        body = body[written:]


def _read_exact(fd: int, size: int) -> bytes:
    body = bytearray()
    while len(body) < size:
        block = os.read(fd, size - len(body))
        if not block:
            raise RuntimeError("pipe truncated")
        body.extend(block)
    return bytes(body)


def _close_except(keep: set[int]) -> None:
    for name in os.listdir("/proc/self/fd"):
        if not name.isascii() or not name.isdecimal():
            continue
        fd = int(name)
        if fd in keep:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _pdeathsig() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise RuntimeError("PDEATHSIG failed")


def _dumpable() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(4, 1, 0, 0, 0) != 0:
        raise RuntimeError("PR_SET_DUMPABLE failed")


def _identity(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
    return digest.hexdigest(), total


def _high_fd(fd: int) -> int:
    duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 32)
    os.close(fd)
    return duplicate


def _command(fd: int, argv: list[str], environment: dict[str, str]) -> None:
    body = json.dumps(
        {"argv": argv, "environment": environment}, ensure_ascii=True,
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    if len(body) > _MAX_COMMAND_BYTES:
        raise RuntimeError("command oversized")
    _write_all(fd, struct.pack("!I", len(body)) + body)
    os.close(fd)


def _launcher(profile: str, output: pathlib.Path, *,
              deadline_monotonic: float, exec_pipe_fds=()):
    exec_pipe_fds = tuple(exec_pipe_fds)
    if exec_pipe_fds and len(exec_pipe_fds) != 2:
        raise RuntimeError("exec pipe set invalid")
    report_r, report_w = os.pipe()
    ack_r, ack_w = os.pipe()
    command_r, command_w = os.pipe()
    output_fd = os.open(
        output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600,
    )
    pid = os.fork()
    if pid == 0:
        try:
            os.close(report_r)
            os.close(ack_w)
            os.close(command_w)
            os.setpgid(0, 0)
            _pdeathsig()
            os.dup2(output_fd, 1)
            os.dup2(output_fd, 2)
            keep = {0, 1, 2, report_w, ack_r, command_r, *exec_pipe_fds}
            _close_except(keep)
            child_install_and_report(
                report_w, ack_r, profile=profile,
                control_fds=(command_r, *exec_pipe_fds),
                deadline_monotonic=deadline_monotonic,
            )
            length = struct.unpack("!I", _read_exact(command_r, 4))[0]
            if not 1 <= length <= _MAX_COMMAND_BYTES:
                raise RuntimeError("command frame invalid")
            document = json.loads(_read_exact(command_r, length))
            os.close(command_r)
            if (type(document) is not dict
                    or set(document) != {"argv", "environment"}
                    or type(document["argv"]) is not list
                    or not document["argv"]
                    or any(type(value) is not str or "\x00" in value
                           for value in document["argv"])
                    or type(document["environment"]) is not dict
                    or any(type(key) is not str or type(value) is not str
                           for key, value in document["environment"].items())):
                raise RuntimeError("command invalid")
            pipe_controls = ()
            if exec_pipe_fds:
                read_fd, write_fd = exec_pipe_fds
                read_identity = os.fstat(read_fd)
                write_identity = os.fstat(write_fd)
                os.dup2(read_fd, 3, inheritable=True)
                os.dup2(write_fd, 4, inheritable=True)
                for fd in exec_pipe_fds:
                    if fd not in {3, 4}:
                        os.close(fd)
                pipe_controls = (
                    (3, "read", read_identity.st_dev, read_identity.st_ino),
                    (4, "write", write_identity.st_dev, write_identity.st_ino),
                )
            attest_exec_fds(pipe_controls=pipe_controls)
            os.execve(document["argv"][0], document["argv"], document["environment"])
        except BaseException as exc:
            try:
                os.write(2, ("launcher: " + repr(exc) + "\n").encode())
            except BaseException:
                pass
            os._exit(127)
    os.close(report_w)
    os.close(ack_r)
    os.close(command_r)
    os.close(output_fd)
    for fd in exec_pipe_fds:
        os.close(fd)
    handoff = duplicate_reported_listener(
        pid, report_r, expected_profile=profile,
        deadline_monotonic=deadline_monotonic,
    )
    verify_listener_bootstrap(
        handoff, report_r, deadline_monotonic=deadline_monotonic,
    )
    os.close(report_r)
    return pid, ack_w, command_w, handoff


class _FixtureHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "quarry-h1"

    def do_GET(self):
        record = {"host": self.headers.get("Host"), "path": self.path}
        if isinstance(self.connection, ssl.SSLSocket):
            record["alpn"] = self.connection.selected_alpn_protocol()
        with self.server.record_lock:
            with open(self.server.record_path, "a", encoding="ascii") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        if self.path == "/start":
            body = b""
            self.send_response(302)
            self.send_header(
                "Location",
                f"{self.server.redirect_scheme}://redirect.fixture.test:"
                f"{self.server.redirect_port}/final",
            )
        elif self.path == "/final":
            body = b"<!doctype html><title>quarry-h1-final</title><p>ok</p>"
            if self.server.invalid_image_url:
                body += (
                    b'<img src="' + self.server.invalid_image_url.encode("ascii")
                    + b'">'
                )
            if self.server.oos_image_url:
                body += (
                    b'<img src="' + self.server.oos_image_url.encode("ascii")
                    + b'">'
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            if self.server.alt_svc:
                self.send_header("Alt-Svc", self.server.alt_svc)
        else:
            body = b"missing"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = message[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        labels.append(message[offset:offset + length].decode("ascii").lower())
        offset += length


def _dns_response(query: bytes, counters: dict[str, int], lock: threading.Lock,
                  log_path: pathlib.Path) -> bytes:
    if len(query) < 17:
        return b""
    name, end = _dns_name(query, 12)
    if end + 4 != len(query):
        return b""
    kind, qclass = struct.unpack_from("!HH", query, end)
    with lock:
        counters[name] = counters.get(name, 0) + 1
        count = counters[name]
        with open(log_path, "a", encoding="ascii") as handle:
            handle.write(json.dumps({"dns": name, "kind": kind, "count": count},
                                    sort_keys=True) + "\n")
    answers = []
    if kind == 1 and qclass == 1:
        values = {
            "fixture.test": (_FIXTURE_IP,),
            "redirect.fixture.test": (_FIXTURE_IP,),
            "mixed.fixture.test": (_FIXTURE_IP, "169.254.169.254"),
            "protected.fixture.test": ("169.254.169.254",),
            "invalid.fixture.test": (_FIXTURE_IP,),
            "rebind.fixture.test": (
                (_FIXTURE_IP,) if count <= 1 else ("169.254.169.254",)
            ),
        }.get(name, ())
        for value in values:
            answers.append(
                b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 10, 4)
                + socket.inet_aton(value)
            )
    flags = 0x8180 if name.endswith("fixture.test") or name == "fixture.test" else 0x8183
    return (
        query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
        + query[12:end + 4] + b"".join(answers)
    )


def _fixture(config_r: int, ready_w: int, stop_r: int,
             root: pathlib.Path, *, tls: bool, exercise_invalid: bool,
             crashpad_upload: bool) -> None:
    os.unshare(os.CLONE_NEWNET)
    _write_all(ready_w, b"U")
    if _read_exact(config_r, 1) != b"C":
        os._exit(91)
    os.close(config_r)
    _run("/usr/sbin/ip", "link", "set", "lo", "up")
    _run("/usr/sbin/ip", "addr", "add", f"{_FIXTURE_IP}/24", "dev", "qh1s")
    _run("/usr/sbin/ip", "link", "set", "qh1s", "up")
    dns_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_udp.bind((_FIXTURE_IP, _DNS_PORT))
    dns_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dns_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_tcp.bind((_FIXTURE_IP, _DNS_PORT))
    dns_tcp.listen(8)
    httpd = http.server.ThreadingHTTPServer((_FIXTURE_IP, _HTTP_PORT), _FixtureHTTP)
    httpd.record_path = root / "http.jsonl"
    httpd.record_lock = threading.Lock()
    httpd.redirect_scheme = "http"
    httpd.redirect_port = _HTTP_PORT
    httpd.invalid_image_url = ""
    httpd.oos_image_url = ""
    httpd.alt_svc = ""
    httpsd = invalid_httpsd = None
    upload_listener = None
    if crashpad_upload:
        upload_listener = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        )
        upload_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        upload_listener.bind((_FIXTURE_IP, _CRASHPAD_UPLOAD_PORT))
        upload_listener.listen(8)
    tls_lock = threading.Lock()
    if tls:
        def context(cert: str, key: str, label: str):
            value = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            value.minimum_version = ssl.TLSVersion.TLSv1_2
            value.set_alpn_protocols(["h2", "http/1.1"])
            value.load_cert_chain(root / cert, root / key)

            def sni(_handle, server_name, _context):
                with tls_lock:
                    with open(root / "tls.jsonl", "a", encoding="ascii") as output:
                        output.write(json.dumps({
                            "listener": label, "sni": server_name,
                        }, sort_keys=True) + "\n")

            value.set_servername_callback(sni)
            return value

        httpsd = http.server.ThreadingHTTPServer(
            (_FIXTURE_IP, _HTTPS_PORT), _FixtureHTTP,
        )
        httpsd.record_path = root / "https.jsonl"
        httpsd.record_lock = threading.Lock()
        httpsd.redirect_scheme = "https"
        httpsd.redirect_port = _HTTPS_PORT
        httpsd.invalid_image_url = (
            f"https://invalid.fixture.test:{_INVALID_HTTPS_PORT}/bad"
            if exercise_invalid else ""
        )
        httpsd.oos_image_url = (
            f"https://oos.fixture.test:{_HTTPS_PORT}/oos"
            if exercise_invalid else ""
        )
        httpsd.alt_svc = (
            'h2="oos.fixture.test:9443"; ma=3600' if exercise_invalid else ""
        )
        httpsd.socket = context(
            "valid.crt", "valid.key", "valid",
        ).wrap_socket(httpsd.socket, server_side=True)
        invalid_httpsd = http.server.ThreadingHTTPServer(
            (_FIXTURE_IP, _INVALID_HTTPS_PORT), _FixtureHTTP,
        )
        invalid_httpsd.record_path = root / "invalid-https.jsonl"
        invalid_httpsd.record_lock = threading.Lock()
        invalid_httpsd.redirect_scheme = "https"
        invalid_httpsd.redirect_port = _INVALID_HTTPS_PORT
        invalid_httpsd.invalid_image_url = ""
        invalid_httpsd.oos_image_url = ""
        invalid_httpsd.alt_svc = ""
        invalid_httpsd.socket = context(
            "invalid.crt", "invalid.key", "invalid",
        ).wrap_socket(invalid_httpsd.socket, server_side=True)
    counters: dict[str, int] = {}
    dns_lock = threading.Lock()
    stop = threading.Event()
    _drop()

    def udp_loop():
        dns_udp.settimeout(0.1)
        while not stop.is_set():
            try:
                query, peer = dns_udp.recvfrom(65535)
            except socket.timeout:
                continue
            response = _dns_response(query, counters, dns_lock, root / "dns.jsonl")
            if response:
                dns_udp.sendto(response, peer)

    def tcp_loop():
        dns_tcp.settimeout(0.1)
        while not stop.is_set():
            try:
                client, _peer = dns_tcp.accept()
            except socket.timeout:
                continue
            try:
                length = struct.unpack("!H", _read_exact(client.fileno(), 2))[0]
                query = _read_exact(client.fileno(), length)
                response = _dns_response(query, counters, dns_lock, root / "dns.jsonl")
                _write_all(client.fileno(), struct.pack("!H", len(response)) + response)
            finally:
                client.close()

    def upload_loop():
        assert upload_listener is not None
        upload_listener.settimeout(0.1)
        while not stop.is_set():
            try:
                client, peer = upload_listener.accept()
            except socket.timeout:
                continue
            client.settimeout(0.25)
            received = bytearray()
            try:
                while len(received) <= 1024 * 1024:
                    block = client.recv(min(64 * 1024, 1024 * 1024 + 1 - len(received)))
                    if not block:
                        break
                    received.extend(block)
            except (TimeoutError, socket.timeout):
                pass
            finally:
                client.close()
            with open(root / "crashpad-upload.jsonl", "a", encoding="ascii") as output:
                output.write(json.dumps({
                    "peer": [str(peer[0]), int(peer[1])],
                    "bytes": len(received),
                    "prefix": bytes(received[:64]).hex(),
                }, sort_keys=True) + "\n")

    threads = [
        threading.Thread(target=udp_loop), threading.Thread(target=tcp_loop),
        threading.Thread(target=httpd.serve_forever),
    ]
    if httpsd is not None and invalid_httpsd is not None:
        threads.extend((
            threading.Thread(target=httpsd.serve_forever),
            threading.Thread(target=invalid_httpsd.serve_forever),
        ))
    if upload_listener is not None:
        threads.append(threading.Thread(target=upload_loop))
    for thread in threads:
        thread.start()
    _write_all(ready_w, b"R")
    os.close(ready_w)
    os.read(stop_r, 1)
    stop.set()
    httpd.shutdown()
    if httpsd is not None:
        httpsd.shutdown()
    if invalid_httpsd is not None:
        invalid_httpsd.shutdown()
    dns_udp.close()
    dns_tcp.close()
    if upload_listener is not None:
        upload_listener.close()
    for thread in threads:
        thread.join(timeout=2)
    os._exit(0)


def _environment(home: pathlib.Path) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "TMPDIR": str(home / "tmp"),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
    }
    for value in environment.values():
        if value.startswith("/") and value not in {"/usr/bin:/bin"}:
            pathlib.Path(value).mkdir(parents=True, exist_ok=True)
    return environment


def _generate_tls_material(root: pathlib.Path) -> None:
    commands = (
        ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-days", "1", "-subj", "/CN=Quarry H1 Root", "-keyout",
         str(root / "ca.key"), "-out", str(root / "ca.crt")),
        ("req", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj",
         "/CN=fixture.test", "-keyout", str(root / "valid.key"), "-out",
         str(root / "valid.csr")),
        ("x509", "-req", "-sha256", "-days", "1", "-in",
         str(root / "valid.csr"), "-CA", str(root / "ca.crt"), "-CAkey",
         str(root / "ca.key"), "-CAcreateserial", "-out", str(root / "valid.crt"),
         "-extfile", str(root / "valid.ext")),
        ("req", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj",
         "/CN=mismatch.fixture.test", "-keyout", str(root / "invalid.key"),
         "-out", str(root / "invalid.csr")),
        ("x509", "-req", "-sha256", "-days", "1", "-in",
         str(root / "invalid.csr"), "-CA", str(root / "ca.crt"), "-CAkey",
         str(root / "ca.key"), "-CAserial", str(root / "ca.srl"), "-out",
         str(root / "invalid.crt"), "-extfile", str(root / "invalid.ext")),
    )
    (root / "valid.ext").write_text(
        "subjectAltName=DNS:fixture.test,DNS:redirect.fixture.test,DNS:oos.fixture.test\n"
        "extendedKeyUsage=serverAuth\n", encoding="ascii",
    )
    (root / "invalid.ext").write_text(
        "subjectAltName=DNS:mismatch.fixture.test\n"
        "extendedKeyUsage=serverAuth\n", encoding="ascii",
    )
    for arguments in commands:
        subprocess.run(
            ("/usr/bin/openssl", *arguments), check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    for path in root.glob("*.crt"):
        os.chown(path, 1000, 1000)
        os.chmod(path, 0o644)
    for path in root.glob("*.key"):
        os.chown(path, 1000, 1000)
        os.chmod(path, 0o600)


def _tls_material_attestation(root: pathlib.Path) -> dict:
    valid = subprocess.run(
        ("/usr/bin/openssl", "verify", "-CAfile", str(root / "ca.crt"),
         "-verify_hostname", "fixture.test", str(root / "valid.crt")),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    mismatch = subprocess.run(
        ("/usr/bin/openssl", "verify", "-CAfile", str(root / "ca.crt"),
         "-verify_hostname", "invalid.fixture.test", str(root / "invalid.crt")),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode != 0
    return {
        "valid_hostname_chain": valid,
        "invalid_hostname_refused": mismatch,
        "ca_sha256": hashlib.sha256((root / "ca.crt").read_bytes()).hexdigest(),
        "valid_leaf_sha256": hashlib.sha256((root / "valid.crt").read_bytes()).hexdigest(),
        "invalid_leaf_sha256": hashlib.sha256((root / "invalid.crt").read_bytes()).hexdigest(),
    }


def _install_browser_test_ca(browser_home: pathlib.Path, ca: pathlib.Path) -> str:
    certutil = os.environ.get("QUARRY_CERTUTIL") or shutil.which("certutil")
    if not certutil or not pathlib.Path(certutil).is_file():
        raise RuntimeError("TLS H1 requires an attested certutil executable")
    nssdb = browser_home / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)
    database = "sql:" + str(nssdb)
    subprocess.run(
        (certutil, "-N", "--empty-password", "-d", database), check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        (certutil, "-A", "-d", database, "-n", "Quarry H1 Root",
         "-t", "C,,", "-i", str(ca)), check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return "sha256:" + hashlib.sha256(pathlib.Path(certutil).read_bytes()).hexdigest()


def _wait(pid: int, deadline: float) -> int:
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.05)
    return 124


def _pidfd_kill(pid: int) -> None:
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError:
        return
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(pidfd)


def _direct_children() -> tuple[int, ...]:
    try:
        body = pathlib.Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children").read_text()
    except OSError:
        return ()
    return tuple(int(value) for value in body.split() if value.isdecimal())


def _browser_process_snapshot(root_pid: int, *, argument_marker: bytes | None = None,
                              ) -> list[dict]:
    """Return a bounded, secret-free identity/FD snapshot of Chrome's tree.

    This is diagnostic H1 material, not an authority decision.  In particular,
    an unreadable non-dumpable Crashpad process is recorded as unreadable rather
    than being inferred safe from its name.
    """
    socket_kinds: dict[str, str] = {}
    for name in ("tcp", "tcp6", "udp", "udp6", "unix"):
        try:
            lines = pathlib.Path(f"/proc/net/{name}").read_text(
                "ascii", errors="strict",
            ).splitlines()[1:]
        except (OSError, UnicodeError):
            continue
        for line in lines:
            fields = line.split()
            try:
                inode = fields[6] if name == "unix" else fields[9]
            except IndexError:
                continue
            if inode.isdecimal():
                socket_kinds[inode] = name
    processes: dict[int, tuple[int, dict[str, str]]] = {}
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            fields = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in (entry / "status").read_text(
                    "ascii", errors="strict",
                ).splitlines()
                if ":" in line
            }
            parent = int(fields["PPid"])
        except (OSError, KeyError, ValueError, UnicodeError):
            continue
        processes[pid] = (parent, fields)
    descendants = {root_pid}
    changed = True
    while changed and len(descendants) <= 512:
        changed = False
        for pid, (parent, _fields) in processes.items():
            if parent in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    # Crashpad deliberately daemonizes and is adopted by the worker subreaper,
    # so it may no longer be a descendant of the browser leader by PPid.  Pin
    # only the exact PID Chromium advertises in its own process title; never
    # sweep unrelated same-UID processes by name.
    referenced_handlers = set()
    for pid in tuple(descendants):
        try:
            command = (pathlib.Path("/proc") / str(pid) / "cmdline").read_bytes()
        except OSError:
            continue
        for match in re.finditer(rb"(?:^|[ \x00])--crashpad-handler-pid=([0-9]+)", command):
            referenced_handlers.add(int(match.group(1)))
    descendants.update(
        pid for pid in referenced_handlers if pid in processes
    )
    if argument_marker is not None:
        if not argument_marker or b"\x00" in argument_marker:
            raise RuntimeError("process snapshot marker is invalid")
        for pid in processes:
            try:
                command = (
                    pathlib.Path("/proc") / str(pid) / "cmdline"
                ).read_bytes()
            except OSError:
                continue
            if argument_marker in command:
                descendants.add(pid)
    result = []
    for pid in sorted(descendants)[:512]:
        entry = pathlib.Path("/proc") / str(pid)
        parent, fields = processes.get(pid, (-1, {}))
        record = {
            "pid": pid,
            "ppid": parent,
            "tgid": fields.get("Tgid"),
            "name": fields.get("Name"),
            "cap_inh": fields.get("CapInh"),
            "cap_eff": fields.get("CapEff"),
            "cap_prm": fields.get("CapPrm"),
            "cap_amb": fields.get("CapAmb"),
            "cap_bnd": fields.get("CapBnd"),
            "no_new_privs": fields.get("NoNewPrivs"),
            "seccomp": fields.get("Seccomp"),
            "seccomp_filters": fields.get("Seccomp_filters"),
        }
        try:
            record["exe"] = os.readlink(entry / "exe")
        except OSError as exc:
            record["exe_error"] = int(exc.errno)
        try:
            raw = (entry / "cmdline").read_bytes()
            if len(raw) > _MAX_COMMAND_BYTES:
                raise RuntimeError("process command oversized")
            record["argv"] = [
                value.decode("utf-8", errors="replace")
                for value in raw.rstrip(b"\x00").split(b"\x00") if value
            ]
        except OSError as exc:
            record["argv_error"] = int(exc.errno)
        descriptors = []
        try:
            names = sorted(
                (value for value in (entry / "fd").iterdir()
                 if value.name.isdecimal()),
                key=lambda value: int(value.name),
            )
            if len(names) > 4096:
                raise RuntimeError("process descriptor inventory oversized")
            for value in names:
                try:
                    target = os.readlink(value)
                except OSError as exc:
                    target = f"<unreadable:{exc.errno}>"
                match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
                descriptors.append([
                    int(value.name), target,
                    (socket_kinds.get(match.group(1), "unknown-socket")
                     if match is not None else None),
                ])
        except OSError as exc:
            record["fd_error"] = int(exc.errno)
        record["fds"] = descriptors
        result.append(record)
    return result


def _dumpability_witness() -> dict[str, int]:
    """A parent attacker proves PR_SET_DUMPABLE=0, independent of Yama=1."""
    ready_r, ready_w = os.pipe()
    stop_r, stop_w = os.pipe()
    victim = os.fork()
    if victim == 0:
        os.close(ready_r)
        os.close(stop_w)
        sensitive = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        seal_worker_identity()
        _write_all(ready_w, struct.pack("!I", sensitive))
        os.close(ready_w)
        os.read(stop_r, 1)
        os.close(stop_r)
        os.close(sensitive)
        os._exit(0)
    os.close(ready_w)
    os.close(stop_r)
    sensitive_fd = struct.unpack("!I", _read_exact(ready_r, 4))[0]
    os.close(ready_r)
    results = {}
    for name, path in {
        "mem_errno": f"/proc/{victim}/mem",
        "fd_errno": f"/proc/{victim}/fd/{sensitive_fd}",
    }.items():
        try:
            observed = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        except OSError as exc:
            results[name] = int(exc.errno)
        else:
            os.close(observed)
            results[name] = 0
    _write_all(stop_w, b"S")
    os.close(stop_w)
    observed, status = os.waitpid(victim, 0)
    if observed != victim or os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError("dumpability witness did not settle")
    return results


def _filter_digest(profile: str) -> str:
    array, _program = network_broker._filter_program(
        network_broker._architecture(), profile=profile,
    )
    return "sha256:" + hashlib.sha256(bytes(array)).hexdigest()


def _run_crashpad_adversary(root: pathlib.Path, policy: BrokerPolicy,
                            registry: ControlEndpointRegistry, launch,
                            *, deadline_monotonic: float) -> dict:
    """Run the exact handler with an explicit pending upload under the filter."""
    wrapper = pathlib.Path(__file__).with_name(
        "v310_crashpad_h1_wrapper.py",
    ).resolve()
    if not wrapper.is_file():
        raise RuntimeError("Crashpad H1 wrapper is missing")
    database = root / "crashpad-adversary-db"
    deadline = min(deadline_monotonic, time.monotonic() + 10.0)
    cancellation = threading.Event()
    fence = NetworkEffectFence(cancellation)
    pid, ack, command, handoff = launch
    adversary_policy = dataclasses.replace(
        policy, request_id="e" * 32, source_id="h1.crashpad-upload",
        tool="chrome_crashpad_handler", approved_peers=(),
        control_helpers=(), control_clients=(), private_unix_roots=(),
    )
    session = NetworkBrokerSession(
        handoff, adversary_policy, control_registry=registry,
        expected_profile="browser", deadline_monotonic=deadline,
        cancellation_event=cancellation, effect_fence=fence,
    )
    session.start()
    acknowledge_listener(
        ack, child_pidfd=handoff.child_pidfd,
        deadline_monotonic=deadline, cancellation=cancellation,
    )
    _command(
        command, [str(wrapper), "--standalone", str(database)],
        _environment(root / "crashpad-adversary-home"),
    )
    processes = []
    observed_handler = False
    observed_upload_attempt = False
    while time.monotonic() < deadline:
        candidate = _browser_process_snapshot(
            pid, argument_marker=str(database).encode("utf-8"),
        )
        if any(record.get("exe") == "/usr/lib/chromium/chrome_crashpad_handler"
               for record in candidate):
            processes = candidate
            observed_handler = True
        summary = session.summary()
        observed_upload_attempt = any(
            record.get("syscall") == "connect"
            and record.get("peer") == _FIXTURE_IP
            and record.get("port") == _CRASHPAD_UPLOAD_PORT
            for record in summary.get("records", ())
        )
        if (observed_upload_attempt or summary.get("fatal")
                or summary.get("listener_hup")):
            break
        time.sleep(0.02)
    synthetic_pids = {int(record["pid"]) for record in processes}
    for child in synthetic_pids:
        _pidfd_kill(child)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    launcher_status = None
    try:
        observed, status = os.waitpid(pid, 0)
        if observed == pid:
            launcher_status = os.waitstatus_to_exitcode(status)
    except ChildProcessError:
        pass
    reap_deadline = time.monotonic() + 2.0
    while time.monotonic() < reap_deadline:
        live = False
        for child in synthetic_pids - {pid}:
            try:
                observed, _status = os.waitpid(child, os.WNOHANG)
            except ChildProcessError:
                continue
            if observed == 0:
                live = True
        if not live:
            break
        time.sleep(0.01)
    session.settle_after_tasks(deadline_monotonic=time.monotonic() + 2.0)
    return {
        "classification": "synthetic-pending-report-exact-handler-adversary",
        "wrapper_identity": _identity(str(wrapper)),
        "handler_identity": _identity(
            "/usr/lib/chromium/chrome_crashpad_handler",
        ),
        "database": str(database),
        "observed_handler": observed_handler,
        "observed_upload_attempt": observed_upload_attempt,
        "processes": processes,
        "summary": session.summary(),
        "launcher_status": launcher_status,
        "survivors": sorted(
            pid for pid in synthetic_pids
            if pathlib.Path(f"/proc/{pid}").exists()
        ),
    }


def _run_nondumpable_adversary(root: pathlib.Path, policy: BrokerPolicy,
                               registry: ControlEndpointRegistry, launch,
                               *, deadline_monotonic: float) -> dict:
    helper = pathlib.Path(__file__).with_name(
        "v310_nondumpable_connect_h1.py",
    ).resolve()
    if not helper.is_file():
        raise RuntimeError("nondumpable H1 helper is missing")
    output = root / "nondumpable-adversary.log"
    pid, ack, command, handoff = launch
    deadline = min(deadline_monotonic, time.monotonic() + 5.0)
    cancellation = threading.Event()
    fence = NetworkEffectFence(cancellation)
    adversary_policy = dataclasses.replace(
        policy, request_id="f" * 32, source_id="h1.nondumpable",
        tool="nondumpable-connect", approved_peers=(_FIXTURE_IP,),
        control_helpers=(), control_clients=(), private_unix_roots=(),
    )
    session = NetworkBrokerSession(
        handoff, adversary_policy, control_registry=registry,
        expected_profile="standard", deadline_monotonic=deadline,
        cancellation_event=cancellation, effect_fence=fence,
    )
    session.start()
    acknowledge_listener(
        ack, child_pidfd=handoff.child_pidfd,
        deadline_monotonic=deadline, cancellation=cancellation,
    )
    _command(
        command, [str(helper)], _environment(root / "nondumpable-home"),
    )
    status = _wait(pid, deadline)
    if status == 124:
        _pidfd_kill(pid)
        try:
            observed, raw_status = os.waitpid(pid, 0)
            if observed == pid:
                status = os.waitstatus_to_exitcode(raw_status)
        except ChildProcessError:
            pass
    session.settle_after_tasks(deadline_monotonic=time.monotonic() + 2.0)
    lines = output.read_text("utf-8", errors="replace").splitlines()
    reports = []
    for line in lines:
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if type(document) is dict and set(document) == {"connect_errno"}:
            reports.append(document)
    return {
        "classification": "nondumpable-mediator-loss-adversary",
        "helper_identity": _identity(str(helper)),
        "launcher_status": status,
        "reports": reports,
        "summary": session.summary(),
        "survivors": [pid] if pathlib.Path(f"/proc/{pid}").exists() else [],
    }


def main() -> int:
    modes = {
        "katana", "gowitness", "katana-tls", "gowitness-tls",
        "gowitness-crashpad",
    }
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in modes:
        raise SystemExit("run as root with katana|gowitness[-tls]|gowitness-crashpad")
    mode = sys.argv[1]
    crashpad_adversary = mode == "gowitness-crashpad"
    tls = mode.endswith("-tls")
    tool = "gowitness" if crashpad_adversary else mode.removesuffix("-tls")
    exercise_invalid = tls and tool == "gowitness"
    root = pathlib.Path(tempfile.mkdtemp(prefix="quarry-v310-h1-"))
    os.chown(root, 1000, 1000)
    os.chmod(root, 0o700)
    for name in ("browser", "controller"):
        path = root / name
        path.mkdir()
        os.chown(path, 1000, 1000)
        os.chmod(path, 0o700)
    tls_material = None
    if tls:
        _generate_tls_material(root)
        tls_material = _tls_material_attestation(root)
    os.unshare(os.CLONE_NEWNET)
    _run("/usr/sbin/ip", "link", "set", "lo", "up")
    _run("/usr/sbin/ip", "link", "add", "qh1t", "type", "veth", "peer", "name", "qh1s")
    config_r, config_w = os.pipe()
    ready_r, ready_w = os.pipe()
    stop_r, stop_w = os.pipe()
    acquire_worker_subreaper()
    fixture_pid = os.fork()
    if fixture_pid == 0:
        os.close(config_w)
        os.close(ready_r)
        os.close(stop_w)
        _fixture(
            config_r, ready_w, stop_r, root,
            tls=tls, exercise_invalid=exercise_invalid,
            crashpad_upload=crashpad_adversary,
        )
    os.close(config_r)
    os.close(ready_w)
    os.close(stop_r)
    if _read_exact(ready_r, 1) != b"U":
        raise RuntimeError("fixture namespace failed")
    _run("/usr/sbin/ip", "link", "set", "qh1s", "netns", str(fixture_pid))
    _run("/usr/sbin/ip", "addr", "add", f"{_TOOL_IP}/24", "dev", "qh1t")
    _run("/usr/sbin/ip", "link", "set", "qh1t", "up")
    _write_all(config_w, b"C")
    os.close(config_w)
    if _read_exact(ready_r, 1) != b"R":
        raise RuntimeError("fixture services failed")
    os.close(ready_r)
    for path in root.iterdir():
        if path.is_dir():
            for child in path.iterdir():
                os.chown(child, 1000, 1000)
    _drop()
    _dumpable()
    capability_lines = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in pathlib.Path("/proc/self/status").read_text().splitlines()
        if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"))
    }
    browser_home = root / "browser"
    controller_home = root / "controller"
    browser_env = _environment(browser_home)
    controller_env = _environment(controller_home)
    certutil_identity = (
        _install_browser_test_ca(browser_home, root / "ca.crt") if tls else None
    )
    chromium = "/usr/lib/chromium/chromium"
    controller = shutil.which(tool) or str(pathlib.Path("/home/kali/go/bin") / tool)
    if not pathlib.Path(controller).is_file():
        controller = None
    if controller is None:
        raise RuntimeError(f"{tool} not installed")
    helper_identity = _identity(chromium)
    controller_identity = _identity(controller)
    dumpability_witness = _dumpability_witness()
    own = netguard.own_ips()
    policy = BrokerPolicy(
        request_id=("a" if tool == "katana" else "b") * 32,
        source_id=f"h1.{tool}", tool=tool,
        block_private_targets=False, control_plane_cidrs=("10.203.0.99/32",),
        initial_own_ips=own, resolver_ips=(_FIXTURE_IP,),
        apex_domains=("fixture.test",), oos_patterns=(r"^oos\.",),
        effective_cidrs=(), approved_peers=(),
        control_helpers=(helper_identity,),
        control_clients=(controller_identity,),
        private_unix_roots=(str(browser_home / "tmp"),),
    )
    browser_output = root / "browser.log"
    controller_output = root / "controller.log"
    chrome_input_r, worker_input_w = os.pipe()
    worker_output_r, chrome_output_w = os.pipe()
    chrome_input_r = _high_fd(chrome_input_r)
    chrome_output_w = _high_fd(chrome_output_w)
    chrome_pipe_identity = pipe_exec_identity(chrome_input_r, chrome_output_w)
    deadline = time.monotonic() + 50
    cancellation = threading.Event()
    effect_fence = NetworkEffectFence(cancellation)
    browser_pid, browser_ack, browser_command, browser_handoff = _launcher(
        "browser", browser_output,
        deadline_monotonic=deadline,
        exec_pipe_fds=(chrome_input_r, chrome_output_w),
    )
    controller_pid, controller_ack, controller_command, controller_handoff = _launcher(
        "standard", controller_output,
        deadline_monotonic=deadline,
    )
    crashpad_launch = None
    nondumpable_launch = None
    if crashpad_adversary:
        crashpad_launch = _launcher(
            "browser", root / "crashpad-adversary.log",
            deadline_monotonic=deadline,
        )
        nondumpable_launch = _launcher(
            "standard", root / "nondumpable-adversary.log",
            deadline_monotonic=deadline,
        )
    # Launchers are still blocked on ACK.  Seal the worker before either can
    # exec untrusted code, closing same-UID /proc/<worker>/{mem,fd} access.
    seal_worker_identity()
    registry = ControlEndpointRegistry()
    browser_session = NetworkBrokerSession(
        browser_handoff, policy, control_registry=registry,
        expected_profile="browser",
        deadline_monotonic=deadline, cancellation_event=cancellation,
        effect_fence=effect_fence,
    )
    controller_session = NetworkBrokerSession(
        controller_handoff, policy, control_registry=registry,
        expected_profile="standard",
        deadline_monotonic=deadline, cancellation_event=cancellation,
        effect_fence=effect_fence,
    )
    browser_session.start()
    controller_session.start()
    prior_policy = dataclasses.replace(
        policy, request_id=("c" if tool == "katana" else "d") * 32,
    )
    prior_proxy = PinnedBrowserProxy(
        prior_policy, registry,
        deadline_monotonic=min(deadline, time.monotonic() + 5),
    )
    prior_proxy.start()
    prior_authentication = bytes(prior_proxy._authentication)
    prior_proxy.stop()
    proxy = PinnedBrowserProxy(
        policy, registry, deadline_monotonic=deadline,
        cancellation_event=cancellation,
        effect_fence=effect_fence,
    )
    proxy.start()
    replay = socket.create_connection(proxy.endpoint, timeout=1.0)
    replay.settimeout(1.0)
    try:
        replay.sendall(
            prior_authentication
            + b"GET http://fixture.test:8080/replay HTTP/1.1\r\n"
              b"Host: fixture.test:8080\r\nConnection: close\r\n\r\n"
        )
        replay_response = replay.recv(4096)
    finally:
        replay.close()
    prior_bridge = PinnedCDPBridge(
        prior_policy, registry, chrome_output_fd=worker_output_r,
        chrome_input_fd=worker_input_w,
        adapter=tool, controller_identity=controller_identity,
        expected_controller_tgid=controller_pid,
        deadline_monotonic=min(deadline, time.monotonic() + 5),
    )
    prior_bridge.start()
    prior_cdp_authentication = bytes(prior_bridge._authentication)
    prior_bridge.stop()
    bridge = PinnedCDPBridge(
        policy, registry, chrome_output_fd=worker_output_r,
        chrome_input_fd=worker_input_w, deadline_monotonic=deadline,
        adapter=tool, controller_identity=controller_identity,
        expected_controller_tgid=controller_pid,
        cancellation_event=cancellation,
        effect_fence=effect_fence,
    )
    os.close(worker_output_r)
    os.close(worker_input_w)
    bridge.start()
    replay_cdp = socket.create_connection(bridge.endpoint, timeout=1.0)
    replay_cdp.settimeout(1.0)
    try:
        replay_cdp.sendall(
            prior_cdp_authentication
            + b"GET /devtools/browser/replay HTTP/1.1\r\n"
              b"Host: 127.0.0.1\r\nConnection: Upgrade\r\n"
              b"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
              b"Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
        )
        try:
            replay_cdp_response = replay_cdp.recv(4096)
        except (ConnectionResetError, TimeoutError, socket.timeout):
            replay_cdp_response = b""
    finally:
        replay_cdp.close()
    acknowledge_listener(
        browser_ack, child_pidfd=browser_handoff.child_pidfd,
        deadline_monotonic=deadline, cancellation=cancellation,
    )
    acknowledge_listener(
        controller_ack, child_pidfd=controller_handoff.child_pidfd,
        deadline_monotonic=deadline, cancellation=cancellation,
    )
    proxy_host, proxy_port = proxy.endpoint
    chrome_argv = [
        chromium, "--headless=new", "--disable-gpu", "--no-first-run",
        "--no-default-browser-check", "--disable-background-networking",
        "--disable-component-update", "--disable-default-apps",
        "--disable-domain-reliability", "--disable-extensions", "--disable-sync",
        "--metrics-recording-only", "--disable-quic",
        "--disable-http2",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=AsyncDns,DnsOverHttps,UseDnsHttpsSvcbAlpn,WebRtcHideLocalIpsWithMdns",
        f"--proxy-server=http://{proxy_host}:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        f"--user-data-dir={browser_home / 'profile'}",
        "--remote-debugging-pipe",
        "about:blank",
    ]
    _command(browser_command, chrome_argv, browser_env)
    ws_url = bridge.websocket_url
    # An unfiltered same-UID process may discover the bridge port, but it has
    # neither a broker-minted one-shot tuple grant nor the injected preface.
    foreign_cdp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    foreign_cdp.settimeout(1.0)
    foreign_cdp_bytes = b""
    try:
        foreign_cdp.connect(bridge.endpoint)
        foreign_cdp.sendall(
            b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n"
        )
        try:
            foreign_cdp_bytes = foreign_cdp.recv(4096)
        except (ConnectionResetError, TimeoutError, socket.timeout):
            foreign_cdp_bytes = b""
    finally:
        foreign_cdp.close()
    target = (
        f"https://fixture.test:{_HTTPS_PORT}/start" if tls
        else f"http://fixture.test:{_HTTP_PORT}/start"
    )
    if tool == "katana":
        argv = [
            controller, "-u", target, "-headless", "-cwu", ws_url,
            "-d", "1", "-silent", "-timeout", "15", "-r", _FIXTURE_IP,
        ]
    else:
        argv = [
            controller, "scan", "single", "-u", target,
            "--chrome-wss-url", ws_url, "--write-stdout", "--write-none",
            "--screenshot-path", str(controller_home / "screenshots"),
            "--timeout", "15", "--delay", "0", "--threads", "1",
        ]
    _command(controller_command, argv, controller_env)
    controller_rc = _wait(controller_pid, deadline)
    if controller_rc == 124:
        _pidfd_kill(controller_pid)
    browser_processes = _browser_process_snapshot(browser_pid)
    crashpad_result = (
        _run_crashpad_adversary(
            root, policy, registry, crashpad_launch,
            deadline_monotonic=deadline,
        )
        if crashpad_adversary else None
    )
    nondumpable_result = (
        _run_nondumpable_adversary(
            root, policy, registry, nondumpable_launch,
            deadline_monotonic=deadline,
        )
        if crashpad_adversary else None
    )
    # Listener HUP authenticates that every filtered controller descendant has
    # exited; the broker then closes its retained connected OFDs so the bridge
    # observes controller EOF before Chromium is torn down.
    controller_hup_deadline = min(deadline, time.monotonic() + 2.0)
    while (not controller_session.summary()["listener_hup"]
           and time.monotonic() < controller_hup_deadline):
        time.sleep(0.01)
    _pidfd_kill(browser_pid)
    _write_all(stop_w, b"S")
    os.close(stop_w)
    end_cleanup = time.monotonic() + 5
    while time.monotonic() < end_cleanup:
        children = _direct_children()
        if not children:
            break
        for child in children:
            _pidfd_kill(child)
        time.sleep(0.05)
        while True:
            try:
                observed, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if observed == 0:
                break
    reaped = reap_adopted_descendants(
        launcher_reaped=True, deadline_monotonic=time.monotonic() + 2,
    )
    browser_session.settle_after_tasks(deadline_monotonic=time.monotonic() + 2)
    controller_session.settle_after_tasks(deadline_monotonic=time.monotonic() + 2)
    bridge.stop()
    proxy.stop()
    contact_log = root / ("https.jsonl" if tls else "http.jsonl")
    http_records = (
        contact_log.read_text("ascii").splitlines() if contact_log.exists() else []
    )
    invalid_http_records = (
        (root / "invalid-https.jsonl").read_text("ascii").splitlines()
        if (root / "invalid-https.jsonl").exists() else []
    )
    tls_records = (
        (root / "tls.jsonl").read_text("ascii").splitlines()
        if (root / "tls.jsonl").exists() else []
    )
    dns_records = (
        (root / "dns.jsonl").read_text("ascii").splitlines()
        if (root / "dns.jsonl").exists() else []
    )
    crashpad_upload_records = (
        (root / "crashpad-upload.jsonl").read_text("ascii").splitlines()
        if (root / "crashpad-upload.jsonl").exists() else []
    )
    browser_summary = browser_session.summary()
    controller_summary = controller_session.summary()
    proxy_summary = proxy.summary()
    cdp_summary = bridge.summary()
    parsed_http = [json.loads(value) for value in http_records]
    parsed_dns = [json.loads(value) for value in dns_records]
    acceptance_errors = []
    if controller_rc != 0:
        acceptance_errors.append("controller_exit")
    active_port = _HTTPS_PORT if tls else _HTTP_PORT
    required_http = {
        (f"fixture.test:{active_port}", "/start"),
        (f"redirect.fixture.test:{active_port}", "/final"),
    }
    observed_http = {(value.get("host"), value.get("path")) for value in parsed_http}
    if not required_http <= observed_http:
        acceptance_errors.append("target_redirect_witness")
    expected_dns = {"fixture.test", "redirect.fixture.test"}
    if exercise_invalid:
        expected_dns.add("invalid.fixture.test")
    if any(value.get("dns") not in expected_dns
           for value in parsed_dns):
        acceptance_errors.append("unexpected_dns_witness")
    parsed_tls = [json.loads(value) for value in tls_records]
    if tls:
        observed_sni = {(value.get("listener"), value.get("sni")) for value in parsed_tls}
        required_sni = {
                ("valid", "fixture.test"),
                ("valid", "redirect.fixture.test"),
        }
        if exercise_invalid:
            required_sni.add(("invalid", "invalid.fixture.test"))
        if not required_sni <= observed_sni:
            acceptance_errors.append("tls_sni_witness")
        if (tls_material is None
                or tls_material.get("valid_hostname_chain") is not True
                or tls_material.get("invalid_hostname_refused") is not True):
            acceptance_errors.append("tls_chain_fixture")
        if any(value.get("alpn") != "http/1.1" for value in parsed_http):
            acceptance_errors.append("tls_alpn_not_http1")
        if exercise_invalid and invalid_http_records:
            acceptance_errors.append("invalid_certificate_application_contact")
        if exercise_invalid:
            if any(
                    json.loads(value).get("host", "").startswith("oos.fixture.test")
                    for value in http_records):
                acceptance_errors.append("tls_origin_coalescing_contact")
            if not any(
                    record.get("host") == "oos.fixture.test"
                    and record.get("decision") == "deny"
                    for record in proxy_summary.get("records", ())):
                acceptance_errors.append("tls_oos_proxy_refusal_witness")
    for name, summary in (
            ("browser", browser_summary), ("controller", controller_summary),
            ("proxy", proxy_summary), ("cdp", cdp_summary)):
        if summary.get("complete") is not True:
            acceptance_errors.append(f"{name}_settlement")
    if foreign_cdp_bytes or replay_cdp_response:
        acceptance_errors.append("cdp_foreign_or_replay")
    if not replay_response.startswith(b"HTTP/1.1 400"):
        acceptance_errors.append("proxy_replay")
    if any(
            record.get("decision") == "allow"
            and record.get("peer") == _FIXTURE_IP
            for record in controller_summary["records"]):
        acceptance_errors.append("controller_direct_target")
    # An ordinary unprivileged process retains an inert capability bounding
    # set.  The executable authority sets must be empty; CapBnd is retained in
    # the report as an environmental fact, not misreported as active authority.
    if any(int(capability_lines[name], 16) != 0
           for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")):
        acceptance_errors.append("worker_capabilities")
    if any(value not in {errno.EACCES, errno.EPERM}
           for value in dumpability_witness.values()):
        acceptance_errors.append("worker_dumpability")
    if any(line.split()[1] == "00000000" for line in
           pathlib.Path("/proc/net/route").read_text("ascii").splitlines()[1:]
           if len(line.split()) > 1):
        acceptance_errors.append("tool_default_route")
    if network_broker.complete_backend() is not True:
        acceptance_errors.append("backend_incomplete_after_freeze")
    if crashpad_adversary:
        result = crashpad_result or {}
        handler_processes = [
            record for record in result.get("processes", ())
            if record.get("exe") == "/usr/lib/chromium/chrome_crashpad_handler"
        ]
        if not result.get("observed_handler") or not handler_processes:
            acceptance_errors.append("crashpad_exact_handler_identity")
        if not result.get("observed_upload_attempt"):
            acceptance_errors.append("crashpad_active_upload_attempt")
        if crashpad_upload_records:
            acceptance_errors.append("crashpad_upload_contact")
        if result.get("survivors"):
            acceptance_errors.append("crashpad_survivors")
        synthetic_summary = result.get("summary", {})
        if synthetic_summary.get("complete") is not True:
            acceptance_errors.append("crashpad_broker_settlement")
        if not any(
                record.get("decision") == "deny"
                and record.get("peer") == _FIXTURE_IP
                and record.get("port") == _CRASHPAD_UPLOAD_PORT
                for record in synthetic_summary.get("records", ())):
            acceptance_errors.append("crashpad_explicit_deny")
        for record in handler_processes:
            if any(record.get(name) != "0000000000000000"
                   for name in ("cap_inh", "cap_eff", "cap_prm", "cap_amb")):
                acceptance_errors.append("crashpad_capabilities")
            if record.get("no_new_privs") != "1" or record.get("seccomp") != "2":
                acceptance_errors.append("crashpad_filter_identity")
            if any(item[2] in {"tcp", "tcp6", "udp", "udp6"}
                   for item in record.get("fds", ())):
                acceptance_errors.append("crashpad_inherited_inet_fd")
            initial_fds = [
                value.split("=", 1)[1]
                for value in record.get("argv", ())
                if value.startswith("--initial-client-fd=")
            ]
            if (len(initial_fds) != 1 or not initial_fds[0].isdecimal()
                    or not any(
                        item[0] == int(initial_fds[0]) and item[2] == "unix"
                        for item in record.get("fds", ())
                    )):
                acceptance_errors.append("crashpad_initial_client_fd")
        inaccessible = nondumpable_result or {}
        if (inaccessible.get("launcher_status") != 0
                or inaccessible.get("reports") != [{"connect_errno": errno.EPERM}]):
            acceptance_errors.append("nondumpable_explicit_eperm")
        inaccessible_summary = inaccessible.get("summary", {})
        if (inaccessible_summary.get("fatal")
                != "network_broker_tracee_memory_read_failed"
                or inaccessible_summary.get("listener_hup") is not True
                or inaccessible_summary.get("complete") is not False
                or inaccessible_summary.get("records") != []):
            acceptance_errors.append("nondumpable_machinery_truth")
        if inaccessible.get("survivors"):
            acceptance_errors.append("nondumpable_survivors")
    survivors = _direct_children()
    if survivors:
        acceptance_errors.append("surviving_descendants")
    document = {
        "tool": tool,
        "controller_rc": controller_rc,
        "controller_output": controller_output.read_text("utf-8", errors="replace")[-16384:],
        "browser_output": browser_output.read_text("utf-8", errors="replace")[-16384:],
        "http_records": http_records,
        "invalid_http_records": invalid_http_records,
        "tls_records": tls_records,
        "dns_records": dns_records,
        "browser_summary": browser_summary,
        "controller_summary": controller_summary,
        "proxy_summary": proxy_summary,
        "cdp_summary": cdp_summary,
        "capabilities": capability_lines,
        "dumpability_witness": dumpability_witness,
        "routes": pathlib.Path("/proc/net/route").read_text("ascii").splitlines(),
        "own_ips": own,
        "identities": {
            "chromium": helper_identity, tool: controller_identity,
            "certutil": certutil_identity,
        },
        "commands": {
            "chromium": chrome_argv,
            "controller": argv,
        },
        "browser_processes": browser_processes,
        "crashpad_adversary": {
            "enabled": crashpad_adversary,
            "upload_records": crashpad_upload_records,
            "result": crashpad_result,
        },
        "nondumpable_adversary": nondumpable_result,
        "tls_material": tls_material,
        "filter_digests": {
            "browser": _filter_digest("browser"),
            "standard": _filter_digest("standard"),
        },
        "foreign_cdp_bytes": foreign_cdp_bytes.hex(),
        "replayed_cdp_response_prefix": replay_cdp_response[:32].hex(),
        "replayed_proxy_response_prefix": replay_response[:32].hex(),
        "chrome_pipe_identity": [list(value) for value in chrome_pipe_identity],
        "reaped": reaped,
        "surviving_descendants": survivors,
        "acceptance_errors": acceptance_errors,
        "backend_complete": network_broker.complete_backend(),
    }
    print(json.dumps(document, sort_keys=True))
    return 0 if not acceptance_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
