"""QR39-010 — selectors are validated before any side effect.

`--phases typo` must produce NO run and a nonzero (invalid-selector) exit; duplicate/empty tokens likewise;
an unknown doctor/install selector must not silently select zero work and return success.
"""
import json
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from quarry_recon.cli import _select_phases, cli

pytestmark = pytest.mark.offline


def _profile(tmp_path: Path) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text("TARGET: t\nAPEX_DOMAINS:\n  - example.com\n")
    return p


def _no_run_created(tmp_path: Path) -> bool:
    return not list((tmp_path / "recon").glob("*/manifest.json"))


# ── _select_phases unit contract ───────────────────────────────────────────────
def test_select_phases_full_set_when_omitted():
    from quarry_recon.phases import ORDER
    assert _select_phases(None) == list(ORDER)


def test_select_phases_canonicalizes_order():
    # an out-of-order selector is returned in canonical ORDER so a dependent lane is never starved
    assert _select_phases("vertical,horizontal") == ["horizontal", "vertical"]


@pytest.mark.parametrize("bad", ["", "typo", "horizontal,typo", "horizontal,horizontal", "horizontal,", ",",
                                 "horizontal, ,vertical"])
def test_select_phases_rejects_bad_selectors(bad):
    # an explicitly-empty selector ("") is INVALID — only an omitted flag (None) means "all phases"
    with pytest.raises(click.UsageError):
        _select_phases(bad)


def test_run_empty_phases_exits_two_and_creates_no_run(tmp_path):
    res = CliRunner().invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", ""])
    assert res.exit_code == 2, res.output
    assert _no_run_created(tmp_path)


# ── run: invalid --phases -> exit 2, no run ────────────────────────────────────
@pytest.mark.parametrize("phases", ["typo-phase", "horizontal,horizontal", "horizontal,"])
def test_run_invalid_phases_exits_two_and_creates_no_run(tmp_path, phases):
    res = CliRunner().invoke(cli, ["run", "-t", str(_profile(tmp_path)), "--phases", phases])
    assert res.exit_code == 2, res.output
    assert _no_run_created(tmp_path)


# ── doctor / install selectors ─────────────────────────────────────────────────
def test_doctor_unknown_phase_exits_two(tmp_path):
    res = CliRunner().invoke(cli, ["doctor", "--phase", "nope"])
    assert res.exit_code == 2, res.output


def test_install_unknown_only_exits_two_without_installing(tmp_path, monkeypatch):
    monkeypatch.setattr("quarry_recon.cli.install_one",
                        lambda *a, **k: pytest.fail("installed under an invalid selector"))
    res = CliRunner().invoke(cli, ["install", "--only", "does-not-exist"])
    assert res.exit_code == 2, res.output


def test_install_unknown_phase_exits_two(tmp_path):
    res = CliRunner().invoke(cli, ["install", "--phase", "nope"])
    assert res.exit_code == 2, res.output


def test_install_empty_only_exits_two_without_installing(tmp_path, monkeypatch):
    monkeypatch.setattr("quarry_recon.cli.install_one",
                        lambda *a, **k: pytest.fail("installed under an explicitly-empty --only"))
    res = CliRunner().invoke(cli, ["install", "--only", ""])
    assert res.exit_code == 2, res.output


def test_install_empty_phase_exits_two_without_installing(tmp_path, monkeypatch):
    monkeypatch.setattr("quarry_recon.cli.install_one",
                        lambda *a, **k: pytest.fail("installed under an explicitly-empty --phase"))
    res = CliRunner().invoke(cli, ["install", "--phase", ""])
    assert res.exit_code == 2, res.output
