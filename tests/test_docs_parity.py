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


def test_readme_states_the_current_source_count():
    from quarry_recon import sources

    assert len(sources.all_sources()) == 67
    assert "67 sources" in (ROOT / "README.md").read_text()


def test_source_registry_has_exact_ownership_and_transport_references():
    from quarry_recon import network_policy, policy, sources

    registered = set(sources.all_source_contracts())
    assert sources.validate() == []
    assert set(policy.SOURCE_OWNERSHIP) == registered
    assert set(network_policy.REGISTERED_TRANSPORT_DOORS) == set(sources.all_sources())
    assert set(network_policy.AUXILIARY_TRANSPORT_DOORS) == registered - {"evidence.ownership"} - set(sources.all_sources())


def test_auxiliary_source_contracts_are_complete_without_expanding_phase_plans():
    from quarry_recon import sources

    auxiliary = sources.auxiliary_sources()
    assert sources.get("osint.whoxy") is None
    assert sources.get_any("osint.whoxy") == auxiliary["osint.whoxy"]
    assert {"osint.whoxy", "osint.asrank", "osint.azmap", "osint.rdap", "osint.rdap_resolve",
            "osint.asnmap", "osint.porch_pirate", "osint.whois", "osint.dmarc", "probe.cdncheck",
            "params.oob_control"} <= set(auxiliary)
    for contract in auxiliary.values():
        assert set(sources.FULL_CONTRACT_FIELDS) <= set(contract)


def test_tier_and_class_queries_remain_phase_only_unless_auxiliary_is_requested():
    from quarry_recon import sources

    planned = set(sources.all_sources())
    optional = set(sources.by_tier("optional"))
    passive = set(sources.by_class("passive"))
    assert optional <= planned and passive <= planned
    assert "osint.whoxy" not in optional and "osint.whoxy" not in passive
    assert "osint.whoxy" in sources.by_tier("optional", include_auxiliary=True)
    assert "osint.whoxy" in sources.by_class("passive", include_auxiliary=True)


def test_nuclei_policy_label_is_exact_in_registry_and_generated_docs():
    from quarry_recon import nuclei_policy, sources

    tools = yaml.safe_load((DATA / "tools.yaml").read_text())["tools"]
    nuclei = next(tool for tool in tools if tool["bin"] == "nuclei")
    label = "broad active vulnerability verification"
    assert nuclei["role"].startswith(label)
    assert f"| `nuclei` | {label.capitalize()}" in _read("tools.md")
    assert nuclei_policy.OWNER_DESCRIPTIONS == {
        "probe.nuclei_waf": "WAF fingerprinting",
        "enrich.nuclei_waf": "WAF fingerprinting",
        "params.nuclei_takeover": "subdomain takeover verification",
        "params.nuclei_scan": label,
    }
    assert tuple(nuclei_policy.OWNER_DESCRIPTIONS) == nuclei_policy.OWNERS
    assert set(nuclei_policy.OWNERS) <= {
        source_id for source_id, source in sources.all_sources().items()
        if source["tool"] == "nuclei"
    }


def test_private_reach_default_and_protected_exclusions_are_documented():
    from quarry_recon.config import TargetProfile
    from quarry_recon import netguard

    target = yaml.safe_load((DATA / "target.template.yaml").read_text())
    profile = TargetProfile("docs-policy", [], [], [], [], {}, [], {}, [])
    assert target["MODES"]["BLOCK_PRIVATE_TARGETS"] is False
    assert profile.block_private_targets is False
    assert netguard.is_contactable_ip("10.0.0.1")
    for protected in ("127.0.0.1", "169.254.169.254"):
        assert not netguard.is_contactable_ip(protected)
    page = _read("target-reference.md")
    assert "`BLOCK_PRIVATE_TARGETS` | `false`" in page
    for exclusion in ("Scanner-self", "loopback", "link-local", "metadata"):
        assert exclusion in page


def test_oob_public_self_hosted_and_off_transport_are_documented():
    from quarry_recon.config import TargetProfile
    from quarry_recon import nuclei_policy

    oob = _read("oob.md")
    readme = (ROOT / "README.md").read_text()
    target = yaml.safe_load((DATA / "target.template.yaml").read_text())
    profile = TargetProfile("docs-policy", [], [], [], [], {}, [], {}, [])
    plan = nuclei_policy.default_plan_summary()
    assert "public" in oob and "self-hosted" in oob
    assert "ephemeral owner-only `0600` config file" in oob
    assert "`-config`" in oob and "`--config`" in oob
    assert "`-token`" not in oob and "`-itoken`" not in oob
    assert target["MODES"]["OOB_ENABLED"] is True
    assert profile.oob_enabled is True
    assert plan["modes"] == {
        "oob_backend": "public-interactsh", "oob_enabled": True,
        "block_private_targets": False,
    }
    assert plan["channels"] == [
        {"owner": "params.oob_probe", "enabled": True, "oob_backend": "public-interactsh"},
        {"owner": "quarry.oob_poll", "enabled": True, "oob_backend": "public-interactsh"},
        {"owner": "params.dalfox_blind_oob", "enabled": False, "oob_backend": "off"},
        {"owner": "quarry.oob_import", "enabled": True, "oob_backend": "local-only"},
    ]
    assert "Set `MODES.OOB_ENABLED: false`" in readme
