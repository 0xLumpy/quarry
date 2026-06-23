"""Tool registry — load tool definitions, audit installs, drive install/update/doctor.

No tool is "production ready" until it has a registry entry (design §2). The registry
is data (data/tools.yaml); this module is the behavior around it.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# version token, not part of a longer dotted number (excludes IPs like 127.0.0.1)
_VER_RE = re.compile(r"(?<![\w.])v?\d+\.\d+(?:\.\d+)?(?![\w.])")

import yaml


@dataclass
class Tool:
    bin: str
    phase: str
    role: str
    install: str | None = None
    update: str | None = None
    version_cmd: str | None = None
    doc: str | None = None
    keys: str | None = None
    optional: bool = False
    notes: str | None = None
    runtime: str = "go"            # go | pipx | source | binary — toolchain it needs
    deps: list[str] | None = None  # extra apt packages this specific tool needs
    needs_chromium: bool = False   # runtime needs a chromium browser

    @property
    def installed(self) -> bool:
        return shutil.which(self.bin) is not None

    @property
    def path(self) -> str | None:
        return shutil.which(self.bin)

    def version(self) -> str:
        """A clean version string ('v2.14.0', '2.2.4') — never the tool's ASCII banner.
        Extracts the first version-like token from the output; 'installed' if none found."""
        if not self.installed or not self.version_cmd:
            return ""
        try:
            p = subprocess.run(self.version_cmd.split(), capture_output=True,
                               text=True, timeout=15)
        except (subprocess.SubprocessError, OSError):
            return ""
        text = _ANSI_RE.sub("", p.stdout + p.stderr)
        for line in text.splitlines():          # prefer a line that names a version
            if "version" in line.lower():
                m = _VER_RE.search(line)
                if m:
                    return m.group(0)
        m = _VER_RE.search(text)
        return m.group(0) if m else "installed"


def load_tools() -> list[Tool]:
    data = yaml.safe_load(resources.files("quarry_recon.data").joinpath("tools.yaml").read_text())
    tools = []
    for t in data.get("tools", []):
        tools.append(Tool(
            bin=t["bin"], phase=t.get("phase", "?"), role=t.get("role", ""),
            install=t.get("install"), update=t.get("update"),
            version_cmd=t.get("version_cmd"), doc=t.get("doc"),
            keys=t.get("keys"), optional=bool(t.get("optional", False)),
            notes=t.get("notes"), runtime=t.get("runtime", "go"),
            deps=t.get("deps") or [], needs_chromium=bool(t.get("needs_chromium", False)),
        ))
    return tools


def tools_by_phase(phase: str) -> list[Tool]:
    return [t for t in load_tools() if t.phase == phase]


def run_shell(cmd: str, dry_run: bool) -> tuple[int, str]:
    """Run an install/update shell command. Returns (exit_code, short_output)."""
    if dry_run:
        return 0, "(dry-run)"
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
        tail = "\n".join((p.stdout + p.stderr).strip().splitlines()[-4:])
        return p.returncode, tail
    except subprocess.SubprocessError as e:
        return 1, str(e)
