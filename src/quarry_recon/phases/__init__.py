"""Methodology phases. Each is an independently rerunnable module (design §10)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..config import ScopeMatcher, TargetProfile
from ..store import Run


@dataclass
class PhaseContext:
    run: Run
    profile: TargetProfile
    scope: ScopeMatcher
    workdir: Path                 # scratch dir for inter-phase input files
    echo: callable = print
    http_timeout: int = 1800

    def tmp(self, name: str) -> Path:
        self.workdir.mkdir(parents=True, exist_ok=True)
        return self.workdir / name

    def write_list(self, name: str, items) -> Path:
        p = self.tmp(name)
        uniq = sorted(set(i.strip() for i in items if i and i.strip()))
        p.write_text("\n".join(uniq) + ("\n" if uniq else ""))
        return p


# phase name -> (callable, human label, requires_active)
# OSINT is NOT here — it's a separate pre-flight command (`quarry osint`). The recon run acts
# only on the human-confirmed scope in target.yaml.
from . import horizontal, vertical, probe, crawl, enrich, content, params  # noqa: E402

# needs_active=True => whole phase skipped in passive mode. Phases with passive value
# (crawl: gau/waymore-U; params: gf over corpus) self-gate instead.
REGISTRY = {
    "horizontal": (horizontal.run, "Horizontal discovery (ASN/CIDR/cert/SAN)", False),
    "vertical": (vertical.run, "Vertical subdomain discovery", False),
    "probe": (probe.run, "Probe / fingerprint / screenshots / ports", True),
    "crawl": (crawl.run, "Crawl + URL/archive + JS mining", False),
    "enrich": (enrich.run, "Enrich late-discovered hosts (resolve/takeover/probe)", True),
    "content": (content.run, "Content discovery (candidate-driven ffuf; off by default)", True),
    "params": (params.run, "Params + lightweight scanning (nuclei OOB)", False),
}

ORDER = ["horizontal", "vertical", "probe", "crawl", "enrich", "content", "params"]
