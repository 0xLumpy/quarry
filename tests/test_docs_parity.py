"""Documentation parity: the operator docs must stay in step with the shipped templates and code.

These tests pin *coverage*, not prose — every knob/field/mode/block/kind must be documented somewhere,
every relative doc link must resolve, and every fenced YAML example must parse. They do not pin wording.
As batch-2 pages land, remove them from ``_PENDING`` and add their coverage/command/entity checks.
"""
import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.offline

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
DATA = ROOT / "src" / "quarry_recon" / "data"

#: batch-2 pages not written yet — links to them are allowed to dangle until they land.
_PENDING = {
    "installation.md", "quickstart.md", "running.md", "running-campaigns.md",
    "campaigns.md", "outputs-and-coverage.md", "oob.md", "errors-and-recovery.md",
    "architecture.md", "tuning.md",
}


def _read(name: str) -> str:
    return (DOCS / name).read_text()


def test_every_config_key_is_documented():
    tmpl = yaml.safe_load((DATA / "config.template.yaml").read_text())
    keys = list(tmpl.get("PERFORMANCE", {}).keys()) + ["openintel"]
    page = _read("configuration.md")
    missing = [k for k in keys if k not in page]
    assert not missing, f"configuration.md is missing config keys: {missing}"


def test_every_target_field_and_mode_is_documented():
    tmpl = yaml.safe_load((DATA / "target.template.yaml").read_text())
    fields = [k for k in tmpl if k != "MODES"]
    modes = list((tmpl.get("MODES") or {}).keys())
    page = _read("target-reference.md")
    missing = [k for k in fields + modes if k not in page]
    assert not missing, f"target-reference.md is missing target fields/modes: {missing}"


def test_every_secret_block_is_documented():
    # source of truth = the blocks secrets.py reads; openintel is documented in external-integrations.
    blocks = ["github", "shodan", "whoxy", "projectdiscovery", "certspotter",
              "censys", "oob", "notify", "openintel", "ai"]
    secrets_page = _read("secrets.md")
    ext_page = _read("external-integrations.md")
    for b in blocks:
        assert b in secrets_page or b in ext_page, f"secret block `{b}` documented nowhere"


def test_all_relative_doc_links_resolve():
    bad = []
    for md in DOCS.glob("*.md"):
        for target in re.findall(r"\]\(([^)]+\.md)\)", md.read_text()):
            if target.startswith("http") or "/" in target:
                continue
            if target in _PENDING:
                continue
            if not (DOCS / target).exists():
                bad.append(f"{md.name} -> {target}")
    assert not bad, f"broken doc links: {bad}"


def test_all_fenced_yaml_examples_parse():
    bad = []
    for md in DOCS.glob("*.md"):
        for block in re.findall(r"```yaml\n(.*?)```", md.read_text(), re.DOTALL):
            try:
                yaml.safe_load(block)
            except yaml.YAMLError as e:
                bad.append(f"{md.name}: {e}")
    assert not bad, f"unparseable YAML examples: {bad}"
