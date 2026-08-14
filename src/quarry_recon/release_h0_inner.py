"""Minimal candidate-bound launcher for the development H0 collection diagnostic.

The outer runner invokes this file by its absolute path inside the read-only
candidate mount.  This module deliberately uses only the standard library until
it has written and closed the dedicated isolation-report pipe.  Pytest and all
candidate test code are imported only after that descriptor is gone.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import sys
from pathlib import Path

_CANDIDATE_ROOT = "/candidate"
_WORK_ROOT = "/work"
_LAUNCHER = "/candidate/src/quarry_recon/release_h0_inner.py"
_TAXONOMY_OUTPUT = "/work/taxonomy.json"
_EXPECTED_ENVIRONMENT = {
    "HOME": "/work/home",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "QUARRY_OFFLINE_CI": "1",
    "TMPDIR": "/work/tmp",
    "XDG_CACHE_HOME": "/work/xdg-cache",
    "XDG_CONFIG_HOME": "/work/xdg-config",
    "XDG_DATA_HOME": "/work/xdg-data",
}
_NAMESPACES = ("cgroup", "ipc", "mnt", "net", "pid", "user", "uts")
_PYTEST_ARGUMENTS = (
    "-p",
    "no:cacheprovider",
    "--collect-only",
    "-q",
    "-m",
    "offline",
    "--strict-markers",
    "--quarry-taxonomy-manifest",
    _TAXONOMY_OUTPUT,
    "/candidate/tests",
)


def _canonical_json_line(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _write_all(descriptor: int, body: bytes) -> None:
    offset = 0
    while offset < len(body):
        written = os.write(descriptor, body[offset:])
        if written <= 0:
            raise OSError("short isolation-report pipe write")
        offset += written


def _read_effective_capabilities() -> str:
    with open("/proc/self/status", encoding="ascii", errors="strict") as stream:
        for line in stream:
            if line.startswith("CapEff:\t"):
                return line.split("\t", 1)[1].strip()
    return "missing"


def _mount_record(path: str) -> dict:
    filesystem = os.statvfs(path)
    value = os.stat(path, follow_symlinks=False)
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "path": path,
        "read_only": bool(filesystem.f_flag & os.ST_RDONLY),
    }


def _open_descriptors() -> list[int]:
    descriptors = []
    for name in os.listdir("/proc/self/fd"):
        try:
            descriptor = int(name, 10)
            os.fstat(descriptor)
        except (OSError, ValueError):
            continue
        descriptors.append(descriptor)
    return sorted(descriptors)


def _runtime_module_is_under_usr(module: object) -> bool:
    path = getattr(module, "__file__", None)
    if type(path) is not str:
        return False
    try:
        return Path(path).resolve(strict=True).is_relative_to(Path("/usr").resolve(strict=True))
    except OSError:
        return False


def _isolation_report(descriptor: int) -> tuple[dict, bool]:
    descriptor_stat = os.fstat(descriptor)
    environment = [
        {"name": name, "value": value}
        for name, value in sorted(os.environ.items())
    ]
    report = {
        "checks": {
            "candidate_read_only": bool(os.statvfs(_CANDIDATE_ROOT).f_flag & os.ST_RDONLY),
            "candidate_source_exact": os.path.realpath(__file__) == _LAUNCHER,
            "cwd_exact": os.getcwd() == _CANDIDATE_ROOT,
            "dev_isolated": os.path.ismount("/dev"),
            "effective_capabilities_empty": _read_effective_capabilities() == "0000000000000000",
            "environment_exact": os.environ == _EXPECTED_ENVIRONMENT,
            "fd_inventory_exact": _open_descriptors() == [0, 1, 2, descriptor],
            "forbidden_roots_absent": all(
                not os.path.lexists(path) for path in ("/etc", "/home", "/host", "/sys", "/tmp")
            ),
            "hostname_exact": socket.gethostname() == "quarry-h0-development",
            "no_git_visible": not os.path.lexists("/candidate/.git"),
            "proc_read_only": bool(os.statvfs("/proc").f_flag & os.ST_RDONLY),
            "report_fd_is_pipe": stat.S_ISFIFO(descriptor_stat.st_mode),
            "runtime_read_only": bool(os.statvfs("/usr").f_flag & os.ST_RDONLY),
            "work_read_write": not bool(os.statvfs(_WORK_ROOT).f_flag & os.ST_RDONLY),
        },
        "effective_capabilities": _read_effective_capabilities(),
        "environment": environment,
        "gid": os.getgid(),
        "hostname": socket.gethostname(),
        "mounts": [_mount_record(path) for path in ("/candidate", "/dev", "/proc", "/usr", "/work")],
        "namespaces": [
            {"name": name, "value": os.readlink(f"/proc/self/ns/{name}")}
            for name in _NAMESPACES
        ],
        "open_descriptors": _open_descriptors(),
        "root_entries": sorted(os.listdir("/")),
        "schema_version": "quarry.h0-isolation-report.v1",
        "uid": os.getuid(),
    }
    return report, all(report["checks"].values())


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "--isolation-fd":
        return 64
    try:
        isolation_fd = int(sys.argv[2], 10)
    except ValueError:
        return 64
    if isolation_fd <= 2 or str(isolation_fd) != sys.argv[2]:
        return 64

    report_ok = False
    primary: BaseException | None = None
    try:
        report, report_ok = _isolation_report(isolation_fd)
        _write_all(isolation_fd, _canonical_json_line(report))
    except BaseException as exc:
        primary = exc
    close_fault: BaseException | None = None
    try:
        os.close(isolation_fd)
    except BaseException as exc:
        close_fault = exc
    if primary is not None:
        if type(primary) in {KeyboardInterrupt, SystemExit}:
            raise primary
        return 70
    if close_fault is not None:
        if type(close_fault) in {KeyboardInterrupt, SystemExit}:
            raise close_fault
        return 71
    if not report_ok:
        return 72
    if _open_descriptors() != [0, 1, 2]:
        return 75

    # Import the attested collector while -I still exposes only the /usr
    # runtime.  Candidate source is added afterward, so src/pytest.py cannot
    # shadow the collector recorded by the outer runtime probe.
    try:
        import pytest
    except ImportError:
        return 73
    if not _runtime_module_is_under_usr(pytest):
        return 76

    # Candidate source authority is explicit.  Isolated mode omits the script
    # directory and ambient editable/user paths; only this exact mount is added.
    sys.path.insert(0, "/candidate/src")
    os.chdir(_CANDIDATE_ROOT)
    try:
        import quarry_recon
    except ImportError:
        return 73
    initializer = Path(quarry_recon.__file__).resolve(strict=True)
    if not initializer.is_relative_to(Path("/candidate/src").resolve(strict=True)):
        return 74
    return int(pytest.main(list(_PYTEST_ARGUMENTS)))


if __name__ == "__main__":
    raise SystemExit(main())
