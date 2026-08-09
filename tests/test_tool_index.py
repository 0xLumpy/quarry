"""The generated tool index must match the registry — regenerate with `scripts/gen_tool_index.py --write`."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "scripts" / "gen_tool_index.py"
PAGE = ROOT / "docs" / "tools.md"

pytestmark = pytest.mark.offline


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_tool_index", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_tools_md_is_up_to_date():
    gen = _load_generator()
    assert PAGE.read_text() == gen.render(), (
        "docs/tools.md is stale — run `python scripts/gen_tool_index.py --write`"
    )


def test_every_registered_actionable_tool_appears_and_is_credited():
    """Independent of the generator's `_actionable` predicate: the expected set is the registry minus
    `dependency: true` minus the explicit `massdns` backend. Every such tool must appear on the page with
    an upstream link — so a predicate bug can't silently drop a tool and still pass."""
    gen = _load_generator()
    import yaml

    tools = yaml.safe_load(gen.REGISTRY.read_text())["tools"]
    expected = [t for t in tools if not t.get("dependency") and t["bin"] != "massdns"]
    page = PAGE.read_text()
    for t in expected:
        assert t.get("doc"), f"{t['bin']}: actionable tool has no `doc:` upstream link to credit"
        assert f"`{t['bin']}` |" in page, f"{t['bin']} missing from docs/tools.md"
        assert f"]({t['doc']})" in page, f"{t['bin']} missing its upstream link in docs/tools.md"
    # and nothing extra: excluded tools must NOT appear as rows
    for t in tools:
        if t.get("dependency") or t["bin"] == "massdns":
            assert f"`{t['bin']}` |" not in page, f"{t['bin']} is a runtime/dependency and must be excluded"
