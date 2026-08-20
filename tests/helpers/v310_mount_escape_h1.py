#!/usr/bin/env python3
"""Diagnostic H1 for the proposed read-only mount/cgroup escape boundary.

This is deliberately not production wiring and never enables the V310-07
backend.  The supervisor runs as root only to create and kill one exact cgroup;
the sandboxed payload has a private user/mount/PID/cgroup namespace, private
proc, no capabilities, and only one explicit writable bind.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import pathlib
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


_BWRAP = "/usr/bin/bwrap"
_MAX_OUTPUT = 256 * 1024
_CLONE_NEWNS = 0x00020000
_CLONE_NEWCGROUP = 0x02000000
_CLONE_NEWUSER = 0x10000000
_CLONE_INTO_CGROUP = 1 << 33
_SYS_CLONE3 = 435
_SYS_OPENAT2 = 437
_PR_GET_SECUREBITS = 27
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_RAISE = 2


def _digest(path: pathlib.Path) -> dict:
    body = path.read_bytes()
    st = path.stat()
    return {
        "path": str(path), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
        "mode": st.st_mode & 0o7777,
    }


def _attempt(callable_):
    try:
        value = callable_()
    except OSError as exc:
        return {"ok": False, "errno": int(exc.errno or 0), "error": type(exc).__name__}
    except BaseException as exc:
        return {"ok": False, "errno": None, "error": type(exc).__name__}
    return {"ok": True, "result": value}


def _write_pid(path: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.write(fd, b"0\n")
    finally:
        os.close(fd)


def _status() -> dict:
    wanted = {
        "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs",
        "Seccomp", "Seccomp_filters",
    }
    fields = {}
    for line in pathlib.Path("/proc/self/status").read_text().splitlines():
        name, separator, value = line.partition(":")
        if separator and name in wanted:
            fields[name] = value.strip()
    return fields


def _write_cgroup(path: str):
    return pathlib.Path(path).write_text("0\n", encoding="ascii")


def _openat2_symlink(path: str):
    class OpenHow(ctypes.Structure):
        _fields_ = (("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                    ("resolve", ctypes.c_uint64))

    library = ctypes.CDLL(None, use_errno=True)
    how = OpenHow(os.O_WRONLY | os.O_CLOEXEC, 0, 0)
    ctypes.set_errno(0)
    result = library.syscall(
        _SYS_OPENAT2, -100, os.fsencode(path), ctypes.byref(how), ctypes.sizeof(how),
    )
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    os.close(result)
    return result


def _unshare(flags: int):
    library = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = library.unshare(ctypes.c_int(flags))
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _mount_cgroup():
    target = pathlib.Path("/mnt/new-cgroup")
    target.mkdir(exist_ok=True)
    library = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = library.mount(
        ctypes.c_char_p(b"none"), ctypes.c_char_p(os.fsencode(target)),
        ctypes.c_char_p(b"cgroup2"), ctypes.c_ulong(0), ctypes.c_void_p(),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _ambient_cap_raise():
    library = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = library.prctl(
        _PR_CAP_AMBIENT, _PR_CAP_AMBIENT_RAISE, 21, 0, 0,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _clone3(flags: int, cgroup_fd: int = 0):
    class CloneArgs(ctypes.Structure):
        _fields_ = tuple((name, ctypes.c_uint64) for name in (
            "flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack",
            "stack_size", "tls", "set_tid", "set_tid_size", "cgroup",
        ))

    args = CloneArgs()
    args.flags = flags
    args.exit_signal = signal.SIGCHLD
    args.cgroup = cgroup_fd
    library = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = library.syscall(_SYS_CLONE3, ctypes.byref(args), ctypes.sizeof(args))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if result == 0:
        os._exit(97)
    os.kill(result, signal.SIGKILL)
    os.waitpid(result, 0)
    return result


def _canaries(*, outer_pid: int, outer_cgroup: str, worker_fd: int) -> dict:
    pathlib.Path("/mnt/direct-link").unlink(missing_ok=True)
    pathlib.Path("/mnt/proc-link").unlink(missing_ok=True)
    pathlib.Path("/mnt/direct-link").symlink_to("/sys/fs/cgroup/cgroup.procs")
    pathlib.Path("/mnt/proc-link").symlink_to(
        f"/proc/{outer_pid}/root{outer_cgroup}/cgroup.procs",
    )
    current_cgroup_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return {
            "direct": _attempt(lambda: _write_cgroup("/sys/fs/cgroup/cgroup.procs")),
            "outer_named": _attempt(lambda: _write_cgroup(f"{outer_cgroup}/cgroup.procs")),
            "outer_proc_root": _attempt(lambda: _write_cgroup(
                f"/proc/{outer_pid}/root{outer_cgroup}/cgroup.procs",
            )),
            "outer_proc_fd": _attempt(lambda: _write_cgroup(
                f"/proc/{outer_pid}/fd/{worker_fd}/cgroup.procs",
            )),
            "writable_symlink": _attempt(lambda: _write_cgroup("/mnt/direct-link")),
            "proc_symlink": _attempt(lambda: _write_cgroup("/mnt/proc-link")),
            "openat2_symlink": _attempt(lambda: _openat2_symlink("/mnt/direct-link")),
            "unshare_user": _attempt(lambda: _unshare(_CLONE_NEWUSER)),
            "unshare_mount": _attempt(lambda: _unshare(_CLONE_NEWNS)),
            "unshare_cgroup": _attempt(lambda: _unshare(_CLONE_NEWCGROUP)),
            "mount_cgroup2": _attempt(_mount_cgroup),
            "clone3_newuser": _attempt(lambda: _clone3(_CLONE_NEWUSER)),
            "clone3_into_cgroup": _attempt(lambda: _clone3(
                _CLONE_INTO_CGROUP, current_cgroup_fd,
            )),
            "ambient_cap_raise": _attempt(_ambient_cap_raise),
        }
    finally:
        os.close(current_cgroup_fd)


def _child(options) -> int:
    mountinfo = pathlib.Path("/proc/self/mountinfo").read_text()
    before = _canaries(
        outer_pid=options.outer_pid, outer_cgroup=options.outer_cgroup,
        worker_fd=options.worker_fd,
    )
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        result = _canaries(
            outer_pid=options.outer_pid, outer_cgroup=options.outer_cgroup,
            worker_fd=options.worker_fd,
        )
        os.write(write_fd, json.dumps(result, sort_keys=True).encode("ascii"))
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    fork_body = os.read(read_fd, _MAX_OUTPUT + 1)
    os.close(read_fd)
    os.waitpid(pid, 0)
    if len(fork_body) > _MAX_OUTPUT:
        raise RuntimeError("fork canary report overflow")
    fork_result = json.loads(fork_body)
    connection = socket.create_connection(("127.0.0.1", options.port), timeout=3)
    after = _canaries(
        outer_pid=options.outer_pid, outer_cgroup=options.outer_cgroup,
        worker_fd=options.worker_fd,
    )
    library = ctypes.CDLL(None, use_errno=True)
    securebits = int(library.prctl(_PR_GET_SECUREBITS, 0, 0, 0, 0))
    fds = {}
    for item in pathlib.Path("/proc/self/fd").iterdir():
        try:
            fds[item.name] = os.readlink(item)
        except OSError:
            pass
    report = {
        "schema_version": "quarry.v310-mount-escape-h1-child.v1",
        "pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
        "status": _status(), "securebits": securebits,
        "mountinfo": mountinfo.splitlines(), "fds": fds,
        "dbus_environment": {
            key: os.environ.get(key) for key in (
                "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
            )
        },
        "dbus_path_exists": pathlib.Path("/run/user/1000/bus").exists(),
        "before_connect": before, "fork_before_connect": fork_result,
        "after_connect": after,
    }
    print(json.dumps(report, sort_keys=True), flush=True)
    payload = b"x" * 4096
    try:
        while True:
            connection.sendall(payload)
    except OSError:
        pass
    return 0


class _Counter:
    def __init__(self, listener: socket.socket):
        self.listener = listener
        self.accepted = threading.Event()
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.bytes = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            connection, _peer = self.listener.accept()
            self.accepted.set()
            connection.settimeout(0.1)
            with connection:
                while not self.stopped.is_set():
                    try:
                        body = connection.recv(65536)
                    except socket.timeout:
                        continue
                    if not body:
                        break
                    with self.lock:
                        self.bytes += len(body)
        finally:
            self.stopped.set()

    def value(self):
        with self.lock:
            return self.bytes


def _events(path: pathlib.Path) -> dict[str, str]:
    return dict(
        line.split(None, 1) for line in path.read_text(encoding="ascii").splitlines()
        if line.strip()
    )


def _supervisor() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("mount escape H1 supervisor requires root")
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))
    from quarry_recon import runtime_identity

    root = pathlib.Path(tempfile.mkdtemp(prefix="quarry-v310-mount-h1-"))
    writable = root / "writable"
    writable.mkdir(mode=0o777)
    os.chmod(writable, 0o777)
    cgroup = pathlib.Path("/sys/fs/cgroup") / f"quarry-v310-mount-h1-{os.getpid()}"
    cgroup.mkdir(mode=0o755)
    cgroup_fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    counter = _Counter(listener)
    counter.thread.start()
    helper = pathlib.Path(__file__).resolve()
    helper_copy = writable / "v310_mount_escape_h1.py"
    shutil.copyfile(helper, helper_copy)
    os.chmod(helper_copy, 0o555)
    command = [
        _BWRAP, "--unshare-all", "--unshare-user", "--share-net",
        "--die-with-parent", "--new-session", "--ro-bind", "/", "/",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--tmpfs", "/run", "--bind", str(writable), "/mnt", "--chdir", "/mnt",
        "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LC_ALL", "C.UTF-8",
        "--uid", "1000", "--gid", "1000", "--cap-drop", "ALL",
        "--disable-userns", "/usr/bin/python3", "/mnt/v310_mount_escape_h1.py", "--child",
        "--outer-pid", str(os.getpid()), "--outer-cgroup", str(cgroup),
        "--worker-fd", str(cgroup_fd), "--port", str(listener.getsockname()[1]),
    ]
    prepared = runtime_identity.prepare_launch("bwrap", command)
    proc = None
    report = None
    faults = []
    before_ack = after_ack = 0
    try:
        identity = prepared.record["identities"][0]
        if (identity.get("attestation") != "host-digest"
                or identity.get("executable", {}).get("path") != _BWRAP
                or identity.get("closure") is not None):
            raise RuntimeError("bwrap host-digest prerequisite identity is invalid")
        version = subprocess.run(
            [prepared.argv[0], "--version"], env=prepared.environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5, check=True,
        ).stdout
        help_body = subprocess.run(
            [prepared.argv[0], "--help"], env=prepared.environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5, check=True,
        ).stdout
        if (len(version) > 4096 or len(help_body) > _MAX_OUTPUT
                or not all(flag.encode("ascii") in help_body for flag in (
                    "--unshare-all", "--share-net", "--disable-userns", "--cap-drop",
                    "--proc", "--ro-bind",
                ))):
            raise RuntimeError("bwrap prerequisite semantics are unavailable")

        def place_child():
            _write_pid(str(cgroup / "cgroup.procs"))

        proc = subprocess.Popen(
            prepared.argv, env=prepared.environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            close_fds=True, preexec_fn=place_child,
        )
        line = proc.stdout.readline(_MAX_OUTPUT + 1)
        if not line or len(line.encode("utf-8")) > _MAX_OUTPUT:
            proc.wait(timeout=3)
            detail = proc.stderr.read(_MAX_OUTPUT + 1)
            raise RuntimeError(
                "sandbox canary report missing or oversized: " + detail[:2000],
            )
        report = json.loads(line)
        if not counter.accepted.wait(3):
            raise RuntimeError("sandbox streaming connection was not established")
        deadline = time.monotonic() + 3
        while counter.value() < 65536 and time.monotonic() < deadline:
            time.sleep(0.01)
        if counter.value() < 65536:
            raise RuntimeError("sandbox streaming witness received no useful prefix")
        (cgroup / "cgroup.kill").write_text("1\n", encoding="ascii")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if _events(cgroup / "cgroup.events").get("populated") == "0":
                break
            time.sleep(0.01)
        else:
            raise RuntimeError("outer cgroup did not become empty")
        before_ack = counter.value()
        time.sleep(0.3)
        after_ack = counter.value()
        proc.wait(timeout=3)
        stderr = proc.stderr.read(_MAX_OUTPUT + 1)
        if len(stderr.encode("utf-8")) > _MAX_OUTPUT:
            raise RuntimeError("sandbox stderr overflow")
        if after_ack != before_ack:
            raise RuntimeError("bytes arrived after cancellation acknowledgement")
        statuses = (report["before_connect"], report["fork_before_connect"],
                    report["after_connect"])
        if any(value.get("ok") for rows in statuses for value in rows.values()):
            raise RuntimeError("one cgroup/namespace/capability escape canary succeeded")
        caps = report["status"]
        if any(caps.get(name) != "0000000000000000" for name in (
                "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
            raise RuntimeError("sandbox capability set was not empty")
        if caps.get("NoNewPrivs") != "1":
            raise RuntimeError("sandbox no-new-privileges invariant is absent")
        if report["dbus_path_exists"] or any(report["dbus_environment"].values()):
            raise RuntimeError("sandbox retained a user-manager control route")
        mount_points = [line.split()[4:6] for line in report["mountinfo"]]
        cgroup_rows = [line for line in report["mountinfo"] if " - cgroup2 " in line]
        if (not cgroup_rows or any(" rw," in line.split(" - ", 1)[0] for line in cgroup_rows)
                or [row for row in mount_points if row[0] == "/mnt"] != [["/mnt", "rw,nosuid,nodev,relatime"]]):
            raise RuntimeError("sandbox mount roster is not exact/read-only")
        output = {
            "schema_version": "quarry.v310-mount-escape-h1.v1",
            "classification": "diagnostic-not-release-evidence",
            "backend_complete": False,
            "bwrap_identity": identity,
            "bwrap_anchor": prepared.record["selected_executable"],
            "bwrap_version": version.decode("utf-8", "strict").strip(),
            "bwrap_help_sha256": hashlib.sha256(help_body).hexdigest(),
            "helper_identity": _digest(helper),
            "helper_sandbox_copy": _digest(helper_copy),
            "child": report,
            "outer_cgroup": str(cgroup),
            "outer_cgroup_populated": _events(cgroup / "cgroup.events").get("populated"),
            "bytes_before_cancel_ack": before_ack,
            "bytes_after_cancel_ack": after_ack,
            "process_returncode": proc.returncode,
            "acceptance_errors": faults,
        }
        print(json.dumps(output, sort_keys=True))
    finally:
        counter.stopped.set()
        listener.close()
        counter.thread.join(timeout=1)
        if proc is not None and proc.poll() is None:
            try:
                (cgroup / "cgroup.kill").write_text("1\n", encoding="ascii")
            except OSError:
                proc.kill()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        os.close(cgroup_fd)
        try:
            cgroup.rmdir()
        except OSError:
            pass
        prepared.close()
        shutil.rmtree(root)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--outer-pid", type=int)
    parser.add_argument("--outer-cgroup")
    parser.add_argument("--worker-fd", type=int)
    parser.add_argument("--port", type=int)
    options = parser.parse_args()
    if options.child:
        if (not options.outer_pid or not options.outer_cgroup
                or options.worker_fd is None or not options.port):
            raise RuntimeError("child canary inputs are incomplete")
        return _child(options)
    return _supervisor()


if __name__ == "__main__":
    raise SystemExit(main())
