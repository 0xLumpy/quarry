"""C08.1 — the compatibility-lock schema + version capture / drift detection.

The lock makes installs reproducible: each tool carries a PINNED version (`pin`), a download `sha256`, and a
post-install `capability` smoke test. `quarry lock` captures the installed versions on a validated host; `drift`
flags an installed version that no longer matches the pin (a reproducibility break).
"""
from dataclasses import replace

import pytest

from quarry_recon import registry
from quarry_recon.registry import LockError, Tool, drift, version_eq, _validate_lock

pytestmark = pytest.mark.offline

_VALID_SHA = "a" * 64


def _tool(**kw):
    base = dict(bin="subfinder", phase="vertical", role="passive", runtime="go")
    base.update(kw)
    return Tool(**base)


class TestVersionEq:
    @pytest.mark.parametrize("a,b,eq", [
        ("v2.14.0", "2.14.0", True),          # leading-v tolerant
        ("2.14.0", "2.14.0", True),
        (" v2.14.0 ", "2.14.0", True),        # whitespace tolerant
        ("2.14.0", "2.14.1", False),
        (None, "2.14.0", False),              # unknown never matches
        ("", "2.14.0", False),
        ("2.14.0", None, False),
    ])
    def test_tolerant_compare(self, a, b, eq):
        assert version_eq(a, b) is eq


class TestDrift:
    def _patch_installed(self, monkeypatch, t, installed_version):
        # a tool is "installed" (which()) and its version() returns installed_version
        monkeypatch.setattr(type(t), "installed", property(lambda self: installed_version is not None))
        monkeypatch.setattr(type(t), "version", lambda self: installed_version or "")

    def test_not_installed(self, monkeypatch):
        t = _tool(pin="2.14.0")
        self._patch_installed(monkeypatch, t, None)
        assert drift(t) == "not-installed"

    def test_unpinned(self, monkeypatch):
        t = _tool(pin=None)
        self._patch_installed(monkeypatch, t, "2.14.0")
        assert drift(t) == "unpinned"

    def test_ok_when_installed_matches_pin(self, monkeypatch):
        t = _tool(pin="v2.14.0")
        self._patch_installed(monkeypatch, t, "2.14.0")   # leading-v tolerant
        assert drift(t) == "ok"

    def test_drift_when_installed_differs(self, monkeypatch):
        t = _tool(pin="2.14.0")
        self._patch_installed(monkeypatch, t, "2.15.0")
        assert drift(t) == "DRIFT"

    def test_version_unknown_is_not_capturable(self, monkeypatch):
        # review-C08.1#1: an installed tool whose version can't be parsed (version() == "") is UNCAPTURABLE —
        # never 'ok' and never a pin, even against a pin.
        t = _tool(pin="2.14.0")
        self._patch_installed(monkeypatch, t, "")            # installed but version unknown
        assert drift(t) == "version-unknown"

    def test_installed_sentinel_cannot_become_a_fake_pin(self):
        # the old 'installed' sentinel let version_eq('installed','installed') accept a fake pin — now "" wins
        assert version_eq("installed", "installed") is True   # (string equality — but version() never RETURNS it)
        assert version_eq("", "") is False                    # an unknown version is never a match


class TestCaptureLock:
    def test_capture_reports_installed_pin_and_drift(self, monkeypatch):
        fake = [_tool(bin="subfinder", pin="2.14.0"), _tool(bin="httpx", pin="1.6.0"),
                _tool(bin="gau", pin=None)]
        installed = {"subfinder": "2.14.0", "httpx": "1.7.0", "gau": "2.2.4"}   # httpx drifts, gau unpinned
        monkeypatch.setattr(registry, "load_tools", lambda: fake)
        monkeypatch.setattr(Tool, "installed", property(lambda self: self.bin in installed))
        monkeypatch.setattr(Tool, "version", lambda self: installed.get(self.bin, ""))
        rows = {r["bin"]: r for r in registry.capture_lock()}
        assert rows["subfinder"]["drift"] == "ok" and rows["subfinder"]["installed"] == "2.14.0"
        assert rows["httpx"]["drift"] == "DRIFT" and rows["httpx"]["installed"] == "1.7.0" and rows["httpx"]["pin"] == "1.6.0"
        assert rows["gau"]["drift"] == "unpinned"

    def test_version_probed_exactly_once_per_tool(self, monkeypatch):
        # review-C08.1#3: capture must not run each tool's version command twice
        calls = {}
        monkeypatch.setattr(registry, "load_tools", lambda: [_tool(bin="subfinder", pin="2.14.0")])
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(Tool, "version", lambda self: (calls.__setitem__(self.bin, calls.get(self.bin, 0) + 1), "2.14.0")[1])
        registry.capture_lock()
        assert calls["subfinder"] == 1                                # probed once, not twice


class TestSchema:
    def test_tool_carries_strategy_aware_lock_fields(self):
        t = _tool(pin="1.0.0", ref="deadbeef", policy="distro",
                  artifacts={"linux/amd64": {"url": "u", "sha256": _VALID_SHA}},
                  capability="subfinder -version")
        assert t.pin == "1.0.0" and t.ref == "deadbeef" and t.policy == "distro"
        assert t.artifacts["linux/amd64"]["sha256"] == _VALID_SHA and t.capability == "subfinder -version"

    def test_pin_field_does_not_shadow_installed_version_method(self):
        # `version()` (installed) and `pin` (locked) are DISTINCT — the field must not clobber the method
        t = replace(_tool(), pin="9.9.9")
        assert callable(t.version) and t.pin == "9.9.9"

    def test_real_registry_loads_lock_fields(self):
        tools = registry.load_tools()
        assert tools and all(hasattr(t, "pin") and hasattr(t, "artifacts") and hasattr(t, "ref")
                             and hasattr(t, "capability") for t in tools)


class TestLockValidation:
    @pytest.mark.parametrize("bad", [
        {"bin": "t", "version": 2.0},                                 # numeric version would crash .strip()
        {"bin": "t", "version": ""},                                  # empty
        {"bin": "t", "capability": ""},                               # empty capability
        {"bin": "t", "ref": 123},                                     # non-string ref
        {"bin": "t", "artifacts": {}},                                # empty artifacts
        {"bin": "t", "artifacts": {"amd64": {"url": "u", "sha256": _VALID_SHA}}},   # bad platform key (no os/arch)
        {"bin": "t", "artifacts": {"linux/amd64": {"url": "u", "sha256": "short"}}},  # bad hash
        {"bin": "t", "artifacts": {"linux/amd64": {"sha256": _VALID_SHA}}},          # missing url
    ])
    def test_malformed_lock_fails_loud(self, bad):
        with pytest.raises(LockError):
            _validate_lock(bad["bin"], bad)

    @pytest.mark.parametrize("ok", [
        {"bin": "t"},                                                 # all lock fields absent -> fine
        {"bin": "t", "version": "v2.14.0"},
        {"bin": "t", "artifacts": {"linux/amd64": {"url": "u", "sha256": _VALID_SHA},
                                   "linux/arm64": {"url": "u2", "sha256": "b" * 64}}},   # multi-arch
        {"bin": "t", "ref": "abc123", "policy": "distro"},
    ])
    def test_valid_lock_passes(self, ok):
        _validate_lock(ok["bin"], ok)                                 # no raise

    def test_real_tools_yaml_is_valid(self):
        registry.load_tools()                                         # loading validates every entry
