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

#: batch-2 pages not written yet — links to them are allowed to dangle until they land. All landed.
_PENDING: set[str] = set()


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
        for target in re.findall(r"\]\((?!https?:|mailto:|#)([^)]+)\)", md.read_text()):
            target = target.split("#", 1)[0]          # drop an #anchor; resolve the path part
            if not target or target in _PENDING:
                continue
            # resolve relative to the linking file's dir — covers .md, directory links (design/), and ../
            if not (md.parent / target).resolve().exists():
                bad.append(f"{md.name} -> {target}")
    assert not bad, f"broken doc links: {bad}"


def test_every_command_is_documented_somewhere():
    from quarry_recon.cli import cli

    corpus = "\n".join(md.read_text() for md in DOCS.glob("*.md"))
    # require the actual invocation `quarry <cmd>`, not just the word — a bare "run"/"set" is ordinary prose.
    missing = [c for c in cli.commands if f"quarry {c}" not in corpus]
    assert not missing, f"commands never shown as `quarry <cmd>`: {missing}"
    oob = cli.commands.get("oob")
    sub_missing = [n for n in getattr(oob, "commands", {}) if f"quarry oob {n}" not in corpus]
    assert not sub_missing, f"oob subcommands never shown as `quarry oob <cmd>`: {sub_missing}"


def test_every_entity_is_documented():
    from quarry_recon import store

    page = _read("outputs-and-coverage.md")
    missing = [e for e in store.ENTITY_KEYS if f"`{e}`" not in page]
    assert not missing, f"outputs-and-coverage.md is missing entities: {missing}"


def test_every_coverage_kind_is_documented_with_its_class():
    from quarry_recon import events

    page = _read("outputs-and-coverage.md")
    soft = [events.COVERAGE_SAMPLE, events.COVERAGE_PROVIDER]
    gaps = [events.COVERAGE_CAP, events.COVERAGE_TIMEOUT, events.COVERAGE_TOOL_OMISSION,
            events.COVERAGE_OWNERSHIP, events.COVERAGE_UNKNOWN]
    # pin the classification, not just the name: each kind must sit in a row with its soft-limit/gap class.
    bad = [k for k in soft if f"`{k}` | soft limit" not in page]
    bad += [k for k in gaps if f"`{k}` | gap" not in page]
    assert not bad, f"outputs-and-coverage.md miscategorises or omits coverage kinds: {bad}"


def test_all_fenced_yaml_examples_parse():
    bad = []
    for md in DOCS.glob("*.md"):
        for block in re.findall(r"```yaml\n(.*?)```", md.read_text(), re.DOTALL):
            try:
                yaml.safe_load(block)
            except yaml.YAMLError as e:
                bad.append(f"{md.name}: {e}")
    assert not bad, f"unparseable YAML examples: {bad}"
