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
        # a tool is "installed" (which()) and its runtime IDENTITY is installed_version
        monkeypatch.setattr(type(t), "installed", property(lambda self: installed_version is not None))
        monkeypatch.setattr(registry, "installed_identity", lambda tool: installed_version or "")

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
        monkeypatch.setattr(registry, "installed_identity", lambda t: installed.get(t.bin, ""))
        rows = {r["bin"]: r for r in registry.capture_lock()}
        assert rows["subfinder"]["drift"] == "ok" and rows["subfinder"]["installed"] == "2.14.0"
        assert rows["httpx"]["drift"] == "DRIFT" and rows["httpx"]["installed"] == "1.7.0" and rows["httpx"]["pin"] == "1.6.0"
        assert rows["gau"]["drift"] == "unpinned"

    def test_identity_probed_exactly_once_per_tool(self, monkeypatch):
        # review-C08.1#3: capture must not probe each tool's identity twice
        calls = {}
        monkeypatch.setattr(registry, "load_tools", lambda: [_tool(bin="subfinder", pin="2.14.0")])
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry, "installed_identity",
                            lambda t: (calls.__setitem__(t.bin, calls.get(t.bin, 0) + 1), "2.14.0")[1])
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
        {"bin": "t", "ref": "main"},                                  # review-r4#6: floating sentinel ref
        {"bin": "t", "ref": "HEAD"},
        {"bin": "t", "cap_codes": [True]},                            # review-r4#6: bool is not a valid exit code
        {"bin": "t", "cap_codes": [0, True]},
        {"bin": "t", "version": "v1", "install": "curl -o t https://x/t"},  # review-r6#2: go pin, no parseable module
        {"bin": "t", "version": "v1"},                                # review-r6#2: go pin, no install at all
        {"bin": "t", "maintenance_state": "bogus"},                   # v0.3.9: not a known refresh class
        {"bin": "t", "maintenance_state": 3},                         # v0.3.9: non-string
        {"bin": "t", "release": ""},                                  # v0.3.9: empty release tag
        {"bin": "t", "release": 5},                                   # v0.3.9: non-string release
        {"bin": "t", "release": "latest", "ref": "abc123"},           # r13#2: release is a floating sentinel
        {"bin": "t", "release": "3.1.1"},                             # r13#2: release with no pin/ref to differ from
        {"bin": "t", "release": "v2.14.0", "version": "v2.14.0", "install": "go install x/cmd/x@latest"},  # ==pin
        {"bin": "t", "maintenance_state": "distro"},                  # r13#2: distro state without policy: distro
        {"bin": "t", "policy": "distro", "maintenance_state": "active"},  # r13#2: policy distro but state != distro
        {"bin": "t", "policy": "distro"},                             # r14: policy distro with NO maintenance_state
    ])
    def test_malformed_lock_fails_loud(self, bad):
        with pytest.raises(LockError):
            _validate_lock(bad["bin"], bad)

    @pytest.mark.parametrize("ok", [
        {"bin": "t"},                                                 # all lock fields absent -> fine
        {"bin": "t", "version": "v2.14.0", "install": "go install ex.com/t/cmd/t@latest"},
        {"bin": "t", "version": "8.9", "runtime": "pipx", "install": "pipx install t"},   # pipx pin, no go install
        {"bin": "t", "artifacts": {"linux/amd64": {"url": "u", "sha256": _VALID_SHA},
                                   "linux/arm64": {"url": "u2", "sha256": "b" * 64}}},   # multi-arch
        {"bin": "t", "ref": "abc123", "policy": "distro", "maintenance_state": "distro"},   # distro agrees
        {"bin": "t", "maintenance_state": "active"},                  # v0.3.9: valid refresh classes
        {"bin": "t", "maintenance_state": "frozen", "release": "2.1",  # release DIFFERS from a pseudo-version pin
         "version": "v0.0.0-abc", "install": "go install x/cmd/x@latest"},
        {"bin": "t", "policy": "distro", "maintenance_state": "distro"},   # distro state + policy agree
    ])
    def test_valid_lock_passes(self, ok):
        _validate_lock(ok["bin"], ok)                                 # no raise

    def test_real_tools_yaml_is_valid(self):
        registry.load_tools()                                         # loading validates every entry

    @pytest.mark.parametrize("sentinel", ["latest", "installed", "main", "master", "HEAD"])
    def test_sentinel_pins_rejected(self, sentinel):
        with pytest.raises(LockError):
            _validate_lock("t", {"bin": "t", "version": sentinel})

    def test_binary_pin_requires_artifacts(self):
        with pytest.raises(LockError):
            _validate_lock("gitleaks", {"bin": "gitleaks", "runtime": "binary", "version": "8.30.1"})
        _validate_lock("gitleaks", {"bin": "gitleaks", "runtime": "binary", "version": "8.30.1",
                                    "artifacts": {"linux/amd64": {"url": "u", "sha256": _VALID_SHA}}})  # ok

    @pytest.mark.parametrize("bad", [[], [0, 0], ["x"], [256], [-1], "notlist"])
    def test_bad_cap_codes_rejected(self, bad):
        with pytest.raises(LockError):
            _validate_lock("t", {"bin": "t", "cap_codes": bad})

    def test_valid_cap_codes_pass(self):
        _validate_lock("t", {"bin": "t", "cap_codes": [0, 1]})
        _validate_lock("t", {"bin": "t", "cap_codes": [0]})


class TestPinnedInstall:
    def test_go_at_latest_becomes_pinned(self):
        t = _tool(runtime="go", install="go install example.com/x/cmd/x@latest", pin="v1.2.3")
        assert registry.pinned_install(t) == "go install example.com/x/cmd/x@v1.2.3"

    def test_pipx_uses_force_to_apply_the_pin(self):
        # review-C08.2r2#1: `pipx install pkg==ver` leaves an existing env unchanged — must use --force
        t = _tool(runtime="pipx", install="pipx install waymore", pin="8.9")
        assert registry.pinned_install(t) == 'pipx install --force "waymore==8.9"'

    def test_unpinned_returns_unchanged(self):
        t = _tool(runtime="binary", install="curl ... | sh", pin=None)
        assert registry.pinned_install(t) == "curl ... | sh"        # binary/source pending C08.2b

    def test_real_go_and_pipx_tools_are_pinned(self):
        ts = {t.bin: t for t in registry.load_tools()}
        assert registry.pinned_install(ts["subfinder"]).endswith("@v2.14.0")
        assert registry.pinned_install(ts["arjun"]) == 'pipx install --force "arjun==2.2.7"'
        assert "@latest" not in registry.pinned_install(ts["nuclei"])   # no floating ref in a pinned install


class TestRealPins:
    def test_version_pinned_tools_have_no_sentinels(self):
        # 31 go/pipx + gitleaks + trufflehog = 33 carry an exact `version:` pin (massdns uses ref; nmap distro)
        pinned = [t for t in registry.load_tools() if t.pin]
        assert len(pinned) == 33
        assert all(t.pin.lower() not in registry._SENTINEL_PINS for t in pinned)

    def test_nmap_is_distro_policy_not_pinned(self):
        nmap = next(t for t in registry.load_tools() if t.bin == "nmap")
        assert nmap.policy == "distro" and nmap.pin is None

    def test_binary_tools_pinned_with_artifacts(self):
        ts = {t.bin: t for t in registry.load_tools()}
        for b in ("gitleaks", "trufflehog"):
            t = ts[b]
            assert t.pin and t.repo and t.runtime == "binary"
            assert set(t.artifacts) >= {"linux/amd64", "linux/arm64"}
            for a in t.artifacts.values():
                assert a["url"].startswith("https://") and len(a["sha256"]) == 64

    def test_massdns_pinned_to_exact_commit(self):
        m = next(t for t in registry.load_tools() if t.bin == "massdns")
        assert m.runtime == "source" and m.ref == "6bfa47197d78e68b79041d494e280174cb2d6ae1" and m.repo

    def test_every_tool_has_a_lock_strategy(self):
        # C08.2 complete: every tool is pinned (version/ref) OR distro-managed — none floats on latest
        for t in registry.load_tools():
            assert t.pin or t.ref or t.policy == "distro", f"{t.bin} has no lock strategy"

    def test_no_pinned_install_uses_a_floating_ref(self):
        for t in registry.load_tools():
            cmd = registry.pinned_install(t) or ""
            assert "@latest" not in cmd and "releases/latest" not in cmd, f"{t.bin} still floats"


class TestBinarySourceInstall:
    def test_binary_install_fills_platform_artifact_and_verifies(self, monkeypatch):
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/amd64")
        t = _tool(bin="gitleaks", runtime="binary", pin="v8.30.1",
                  artifacts={"linux/amd64": {"url": "https://ex/gl_amd64.tgz", "sha256": _VALID_SHA},
                             "linux/arm64": {"url": "https://ex/gl_arm64.tgz", "sha256": "b" * 64}},
                  install='curl -fsSL {url} -o /tmp/{bin}.tgz && echo "{sha256}  /tmp/{bin}.tgz" | sha256sum -c -')
        cmd = registry.pinned_install(t)
        assert "gl_amd64.tgz" in cmd and _VALID_SHA in cmd and "sha256sum -c" in cmd
        assert "gl_arm64.tgz" not in cmd                      # only THIS platform's artifact

    def test_binary_missing_platform_returns_none(self, monkeypatch):
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/riscv64")
        t = _tool(bin="gitleaks", runtime="binary", pin="v1",
                  artifacts={"linux/amd64": {"url": "u", "sha256": _VALID_SHA}}, install="curl {url}")
        assert registry.pinned_install(t) is None             # uninstallable here -> caller reports

    def test_source_install_fills_ref(self):
        t = _tool(bin="massdns", runtime="source", ref="deadbeefcafe",
                  install="git clone x && git checkout {ref} && make && cp bin/{bin} ~/.local/bin/")
        cmd = registry.pinned_install(t)
        assert "checkout deadbeefcafe" in cmd and "bin/massdns" in cmd


class TestInstalledIdentity:
    def test_go_uses_module_metadata_not_cli_banner(self, monkeypatch):
        # review-C08.2#3: identity from `go version -m`, NOT the tool's -version (which lagged for dnsx/ffuf/…)
        t = _tool(bin="ffuf", runtime="go", install="go install github.com/ffuf/ffuf/v2@latest")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/bin/ffuf")
        monkeypatch.setattr(registry, "_go_mod_and_version", lambda p: ("github.com/ffuf/ffuf/v2", "v2.2.1"))
        assert registry.installed_identity(t) == "v2.2.1"                    # module metadata wins

    def test_go_wrong_module_is_unproven(self, monkeypatch):
        # review-C08.2r4#4: a same-named binary from a DIFFERENT module is not the intended tool -> unproven
        t = _tool(bin="ffuf", runtime="go", install="go install github.com/ffuf/ffuf/v2@latest")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/bin/ffuf")
        monkeypatch.setattr(registry, "_go_mod_and_version", lambda p: ("github.com/evil/ffuf", "v2.2.1"))
        assert registry.installed_identity(t) == ""

    def test_go_not_on_path_is_unproven(self, monkeypatch):
        # review-C08.2r4#4: identity is of the PATH-resolved executable; not resolving -> unproven
        t = _tool(bin="ffuf", runtime="go", install="go install github.com/ffuf/ffuf/v2@latest")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: None)
        assert registry.installed_identity(t) == ""

    def test_distro_identity_and_drift(self, monkeypatch):
        t = _tool(bin="nmap", runtime="binary", policy="distro")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        assert registry.installed_identity(t) == "distro" and registry.drift(t) == "distro"

    def test_source_identity_verifies_ref_and_binary_sha(self, monkeypatch, tmp_path):
        import hashlib
        monkeypatch.setenv("HOME", str(tmp_path))
        binp = tmp_path / ".local" / "bin" / "massdns"
        binp.parent.mkdir(parents=True, exist_ok=True); binp.write_bytes(b"MASSDNS-BUILD")
        sha = hashlib.sha256(b"MASSDNS-BUILD").hexdigest()
        (tmp_path / ".local" / "bin" / ".massdns.lock").write_text(f'{{"ident":"6bfa4719","sha256":"{sha}"}}')
        t = _tool(bin="massdns", runtime="source", ref="6bfa4719")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(Tool, "path", property(lambda self: str(binp)))
        monkeypatch.setattr(registry.shutil, "which", lambda b: None)
        assert registry.installed_identity(t) == "6bfa4719" and registry.drift(t) == "ok"

    def test_source_drift_when_binary_replaced_but_receipt_stale(self, monkeypatch, tmp_path):
        # review-C08.2r3#2: binary swapped out-of-band, receipt kept -> sha mismatch -> DRIFT (not stale 'ok')
        import hashlib
        monkeypatch.setenv("HOME", str(tmp_path))
        binp = tmp_path / ".local" / "bin" / "massdns"
        binp.parent.mkdir(parents=True, exist_ok=True); binp.write_bytes(b"REPLACED-BINARY")
        old_sha = hashlib.sha256(b"ORIGINAL-BUILD").hexdigest()
        (tmp_path / ".local" / "bin" / ".massdns.lock").write_text(f'{{"ident":"6bfa4719","sha256":"{old_sha}"}}')
        t = _tool(bin="massdns", runtime="source", ref="6bfa4719")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(Tool, "path", property(lambda self: str(binp)))
        monkeypatch.setattr(registry.shutil, "which", lambda b: None)
        assert registry.installed_identity(t) == "" and registry.drift(t) == "version-unknown"


class TestInstallOne:
    def _go(self, **kw):
        base = dict(bin="subfinder", runtime="go", pin="v2.14.0",
                    install="go install x/cmd/x@latest", version_cmd="subfinder -version")
        base.update(kw)
        return _tool(**base)

    def _patch_go(self, monkeypatch, *, drift="ok", cap=(0, "v2.14.0"), cmds=None):
        monkeypatch.setattr(registry, "run_shell", lambda c, d: (cmds.append(c) if cmds is not None else None, (0, ""))[1])
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: cap)
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry, "installed_identity", lambda t: "v2.14.0")
        monkeypatch.setattr(registry, "drift", lambda t: drift)

    def test_go_pinned_success_never_uses_latest(self, monkeypatch):
        cmds = []
        self._patch_go(monkeypatch, cmds=cmds)
        assert registry.install_one(self._go(), lambda m: None) is True
        assert any("@v2.14.0" in c for c in cmds) and not any("@latest" in c for c in cmds)

    def test_identity_mismatch_is_failure_not_ok(self, monkeypatch):
        self._patch_go(monkeypatch, drift="DRIFT")
        assert registry.install_one(self._go(), lambda m: None) is False     # review#4

    def test_version_unknown_locked_is_failure(self, monkeypatch):
        # review-C08.2r2#3: a locked tool that can't verify its identity must FAIL (not silently pass)
        self._patch_go(monkeypatch, drift="version-unknown")
        assert registry.install_one(self._go(), lambda m: None) is False

    def test_capability_nonzero_is_failure(self, monkeypatch):
        # review-C08.2r2#2: rc 1 (an ordinary error / traceback) is NOT success — default accepts only 0
        self._patch_go(monkeypatch, cap=(1, "boom"))
        assert registry.install_one(self._go(), lambda m: None) is False

    def test_capability_accepts_declared_cap_codes(self, monkeypatch):
        # a help-probe tool that exits 1 legitimately declares cap_codes [0,1]
        self._patch_go(monkeypatch, cap=(1, "usage"))
        assert registry.install_one(self._go(cap_codes=[0, 1]), lambda m: None) is True

    def test_timeout_probe_fails_even_with_cap_codes_0_1(self, monkeypatch):
        # review-C08.2r3#1: a TIMED-OUT / not-executed probe (_PROBE_NOT_RUN) is NOT accepted, even by [0,1]
        self._patch_go(monkeypatch, cap=(registry._PROBE_NOT_RUN, ""))
        assert registry.install_one(self._go(cap_codes=[0, 1]), lambda m: None) is False

    def test_shadowed_managed_binary_fails(self, monkeypatch, tmp_path):
        # review-C08.2r3#2: after activation, an older PATH copy that shadows the managed binary is a failure
        t, stage, dest = self._binary(monkeypatch, tmp_path)
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/usr/local/bin/gitleaks")   # shadow
        monkeypatch.setattr(registry, "_go_bin_dir", lambda: None)   # non-go shadow -> not reclaimable
        assert registry.install_one(t, lambda m: None) is False

    def test_unsupported_platform_returns_false_not_crash(self, monkeypatch):
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/riscv64")
        t = _tool(bin="gitleaks", runtime="binary", pin="v1", install="curl {url}",
                  artifacts={"linux/amd64": {"url": "u", "sha256": _VALID_SHA}})
        assert registry.install_one(t, lambda m: None) is False              # review#6 (no crash)

    def _binary(self, monkeypatch, tmp_path, *, stage_content="NEW", probe=(0, "v8.30.1"), old="OLD"):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/amd64")
        stage = tmp_path / ".local" / "bin" / ".stage" / "gitleaks"
        dest = tmp_path / ".local" / "bin" / "gitleaks"
        dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text(old)

        def rs(c, d):
            if "curl" in c:
                stage.parent.mkdir(parents=True, exist_ok=True); stage.write_text(stage_content)
            return (0, "")
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: probe)   # capability rc + version text
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))     # managed dest resolves (no shadow)
        t = _tool(bin="gitleaks", runtime="binary", pin="v8.30.1", version_cmd="gitleaks version",
                  artifacts={"linux/amd64": {"url": "https://x/g.tgz", "sha256": _VALID_SHA}},
                  install="curl {url} ... ~/.local/bin/.stage {bin}")
        return t, stage, dest

    def test_binary_stages_verifies_then_atomically_activates(self, monkeypatch, tmp_path):
        t, stage, dest = self._binary(monkeypatch, tmp_path)
        assert registry.install_one(t, lambda m: None) is True
        assert dest.read_text() == "NEW" and not stage.exists()             # atomically activated

    def test_binary_capability_failure_keeps_old_binary(self, monkeypatch, tmp_path):
        t, stage, dest = self._binary(monkeypatch, tmp_path, stage_content="BROKEN", probe=(127, ""), old="OLD-WORKING")
        assert registry.install_one(t, lambda m: None) is False             # review#5
        assert dest.read_text() == "OLD-WORKING" and not stage.exists()     # existing binary NOT destroyed

    def test_binary_wrong_release_version_is_rejected(self, monkeypatch, tmp_path):
        # review-C08.2r2#4: a WORKING binary from the WRONG release (version != pin) must not activate
        t, stage, dest = self._binary(monkeypatch, tmp_path, probe=(0, "v1.2.3"), old="OLD-WORKING")
        assert registry.install_one(t, lambda m: None) is False
        assert dest.read_text() == "OLD-WORKING" and not stage.exists()

    def test_source_receipt_write_failure_fails_verification(self, monkeypatch, tmp_path):
        # review-C08.2r2#4/r4#2: a receipt-write failure (after activation) must FAIL verification, not report
        # success — the binary is active but unverifiable, so `install` reinstalls next time (recoverable).
        monkeypatch.setenv("HOME", str(tmp_path))
        stage = tmp_path / ".local" / "bin" / ".stage" / "massdns"
        dest = tmp_path / ".local" / "bin" / "massdns"
        dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text("OLD")

        def rs(c, d):
            if "git" in c:
                stage.parent.mkdir(parents=True, exist_ok=True); stage.write_text("NEW")
            return (0, "")
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, ""))
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))    # resolves to managed dest (no shadow)
        monkeypatch.setattr(registry, "_write_receipt",
                            lambda b, ref, sha: (_ for _ in ()).throw(OSError("receipt unwritable")))
        t = _tool(bin="massdns", runtime="source", ref="deadbeef", version_cmd="massdns --help", cap_codes=[0, 1],
                  install="git clone x && git checkout {ref} && cp bin/{bin} ~/.local/bin/.stage/{bin}")
        assert registry.install_one(t, lambda m: None) is False              # verification failed
        assert dest.read_text() == "NEW"                                     # activated; receipt gap -> reinstall recovers


class TestCliNoFloat:
    def _run(self, monkeypatch, tmp_path, argv):
        import re as _re
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod, bootstrap
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".local" / "bin").mkdir(parents=True, exist_ok=True)
        cmds = []

        def rs(c, d):
            cmds.append(c)
            m = _re.search(r"\.stage/(\S+)", c)                            # a binary/source STAGE command
            if m:
                sp = tmp_path / ".local" / "bin" / ".stage" / m.group(1)
                sp.parent.mkdir(parents=True, exist_ok=True); sp.write_text("bin")
            return (0, "")
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, ""))   # capability rc 0; version via version_eq
        monkeypatch.setattr(registry, "version_eq", lambda a, b: True)           # staged version matches (not the focus)
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(tmp_path / ".local" / "bin" / b))  # no shadow
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry, "installed_identity", lambda t: t.pin or t.ref or "installed")
        monkeypatch.setattr(registry, "drift", lambda t: "ok")
        for fn in ("install_data_files", "run_extras", "cleanup"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: None)
        return CliRunner().invoke(cli_mod.cli, argv), cmds

    def test_update_never_runs_latest_or_pipx_upgrade(self, monkeypatch, tmp_path):
        res, cmds = self._run(monkeypatch, tmp_path, ["update"])   # update now covers ALL installed tools
        assert res.exit_code == 0, res.output
        joined = "\n".join(cmds)
        assert "@latest" not in joined and "pipx upgrade" not in joined and "releases/latest" not in joined
        assert any("@v2.14.0" in c for c in cmds)                           # pins used instead

    def test_update_covers_installed_optional_tools(self, monkeypatch, tmp_path):
        # js-beautify drift fix: `update` must sync an INSTALLED optional tool (was skipped) — and use the
        # shared one-line `↻ tool ✓` output
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod, bootstrap
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))   # everything installed
        updated = []
        monkeypatch.setattr(cli_mod, "install_one",
                            lambda t, echo, dry_run=False: (updated.append(t.bin), True)[1])
        for fn in ("install_data_files", "run_extras", "cleanup"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: None)
        res = CliRunner().invoke(cli_mod.cli, ["update"])
        assert res.exit_code == 0
        assert "js-beautify" in updated and "↻ js-beautify ✓" in res.output   # optional+installed synced, 1 line

    def test_install_failure_exits_nonzero(self, monkeypatch, tmp_path):
        # a failing tool must propagate a non-zero exit (review-C08.2#6)
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod, bootstrap
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(registry, "run_shell", lambda c, d: (1, "boom"))   # every install fails
        monkeypatch.setattr(Tool, "installed", property(lambda self: False))
        for fn in ("install_data_files", "run_extras", "cleanup", "install_system_packages"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: True)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--only", "subfinder", "--yes"])
        assert res.exit_code != 0

    def _full_bootstrap_env(self, monkeypatch, tmp_path):
        from quarry_recon import cli as cli_mod, bootstrap
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(Tool, "installed", property(lambda self: False))
        monkeypatch.setattr(bootstrap, "system_report", lambda who: {"level": "ok"})
        monkeypatch.setattr(cli_mod, "_echo_syscheck", lambda rep: None)
        for fn in ("install_system_packages", "ensure_golang", "install_data_files", "run_extras", "cleanup"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: True)
        # install_one: REQUIRED tools succeed, OPTIONAL tools fail
        monkeypatch.setattr(cli_mod, "install_one", lambda t, echo, dry_run=False: not t.optional)
        return cli_mod

    def test_optional_failure_nonfatal_in_full_bootstrap(self, monkeypatch, tmp_path):
        # fresh-install#1: in the FULL bootstrap (--include-optional, no narrowing) an optional tool failing is
        # best-effort — exit 0 so install.sh can persist PATH.
        from click.testing import CliRunner
        cli_mod = self._full_bootstrap_env(monkeypatch, tmp_path)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--include-optional", "--yes"])
        assert res.exit_code == 0 and "optional tool failed" in res.output

    def test_targeted_only_failure_is_fatal_even_if_optional(self, monkeypatch, tmp_path):
        # fresh-install#1: a NARROWED retry (`quarry install --only dnsgen`) must exit NON-zero when it fails —
        # it must not report success while the requested tool is still broken.
        from click.testing import CliRunner
        cli_mod = self._full_bootstrap_env(monkeypatch, tmp_path)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--only", "dnsgen", "--yes"])
        assert res.exit_code != 0


class TestGoArchiveChecksum:
    def _bs(self, sha):
        return {"golang": {"min_version": "1.25", "version": "1.26.4",
                           "url": "https://dl.google.com/go/{version}.{os}-{arch}.tar.gz",
                           "sha256": {"linux/amd64": sha, "linux/arm64": sha}}}

    def test_refuses_unverified_go_archive(self, monkeypatch):
        # review-C08.2r3#3: a blank host (no go) must NOT replace /usr/local/go from an unchecked archive
        from quarry_recon import bootstrap
        monkeypatch.setattr(bootstrap.shutil, "which", lambda b: None)          # no existing go
        monkeypatch.setattr(bootstrap, "load_bootstrap", lambda: self._bs("PENDING"))
        monkeypatch.setattr(bootstrap.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(bootstrap.platform, "system", lambda: "Linux")
        msgs = []
        assert bootstrap.ensure_golang(msgs.append, dry=False) is False
        assert any("not pinned" in m or "UNVERIFIED" in m for m in msgs)

    def test_verified_go_archive_runs_sha_check(self, monkeypatch):
        from quarry_recon import bootstrap
        cmds = []
        monkeypatch.setattr(bootstrap.shutil, "which", lambda b: None)
        monkeypatch.setattr(bootstrap, "load_bootstrap", lambda: self._bs("a" * 64))
        monkeypatch.setattr(bootstrap.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(bootstrap.platform, "system", lambda: "Linux")
        monkeypatch.setattr(bootstrap, "_sh", lambda cmd, dry, to: (cmds.append(cmd), (0, ""))[1])
        assert bootstrap.ensure_golang(lambda m: None, dry=False) is True
        assert "sha256sum -c" in cmds[0] and ("a" * 64) in cmds[0]              # the archive is checksum-verified


def _health_env(monkeypatch, *, installed=True, identity="v1", cap_rc=0):
    # the REAL health seams (identity probed once + capability probe) — not the drift() wrapper
    monkeypatch.setattr(Tool, "installed", property(lambda self: installed))
    monkeypatch.setattr(registry, "installed_identity", lambda t: identity)
    monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (cap_rc, ""))


class TestVerifyInstalled:
    def test_ok_tool_with_passing_capability_verifies(self, monkeypatch):
        _health_env(monkeypatch, identity="v1")
        assert registry.verify_installed(_tool(pin="v1", version_cmd="x -version")) is True

    @pytest.mark.parametrize("identity", ["v2", ""])            # DRIFT (v2!=v1) · version-unknown ("")
    def test_bad_identity_fails_verification(self, monkeypatch, identity):
        # review-C08.2r4#1: a present tool with unverified identity is NOT healthy (would be reinstalled)
        _health_env(monkeypatch, identity=identity)
        assert registry.verify_installed(_tool(pin="v1", version_cmd="x -version")) is False

    def test_not_installed_fails_verification(self, monkeypatch):
        _health_env(monkeypatch, installed=False)
        assert registry.verify_installed(_tool(pin="v1", version_cmd="x -version")) is False

    def test_capability_failure_fails_verification(self, monkeypatch):
        _health_env(monkeypatch, identity="v1", cap_rc=127)
        assert registry.verify_installed(_tool(pin="v1", version_cmd="x -version")) is False


class TestHealth:
    def test_ok_snapshot(self, monkeypatch):
        _health_env(monkeypatch, identity="v1")
        h = registry.health(_tool(pin="v1", version_cmd="x -version"))
        assert h["ok"] and h["drift"] == "ok" and h["identity"] == "v1" and h["capability"] is True

    def test_drift_is_not_ok(self, monkeypatch):
        _health_env(monkeypatch, identity="v2")
        h = registry.health(_tool(pin="v1", version_cmd="x -version"))
        assert not h["ok"] and h["drift"] == "DRIFT" and h["identity"] == "v2"

    def test_identity_unknown_is_not_ok(self, monkeypatch):
        _health_env(monkeypatch, identity="")
        h = registry.health(_tool(pin="v1", version_cmd="x -version"))
        assert not h["ok"] and h["drift"] == "version-unknown"

    def test_capability_failure_is_not_ok_even_when_drift_ok(self, monkeypatch):
        _health_env(monkeypatch, identity="v1", cap_rc=127)
        h = registry.health(_tool(pin="v1", version_cmd="x -version"))
        assert not h["ok"] and h["drift"] == "ok" and h["capability"] is False

    def test_no_probe_capability_is_none(self, monkeypatch):
        _health_env(monkeypatch, identity="v1")
        h = registry.health(_tool(pin="v1"))                   # no version_cmd/capability
        assert h["ok"] and h["capability"] is None

    def test_probes_identity_exactly_once(self, monkeypatch):
        calls = {"n": 0}
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry, "installed_identity",
                            lambda t: (calls.__setitem__("n", calls["n"] + 1), "v1")[1])
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, ""))
        registry.health(_tool(pin="v1", version_cmd="x -version"))
        assert calls["n"] == 1                                 # NOT re-probed for display + verdict


class TestShapeGuards:
    def test_pipx_version_tolerates_non_dict_json(self, monkeypatch):
        import json
        monkeypatch.setattr(registry.subprocess, "run",
                            lambda *a, **k: type("P", (), {"stdout": json.dumps({"venvs": [1, 2]})})())
        assert registry._pipx_meta("arjun") == ("", [])          # list venvs -> empty, not a crash

    def test_read_receipt_rejects_non_object(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        rp = tmp_path / ".local" / "bin" / ".massdns.lock"
        rp.parent.mkdir(parents=True, exist_ok=True); rp.write_text("[1, 2, 3]")   # a list, not an object
        assert registry._read_receipt("massdns") == {}           # not a crash on rec.get()


class TestBinaryPathResolution:
    def test_activated_binary_must_resolve_on_path(self, monkeypatch, tmp_path):
        # review-C08.2r4#4: which(...) is None (not on PATH) must FAIL, not pass
        from test_lock import TestInstallOne
        t, stage, dest = TestInstallOne()._binary(monkeypatch, tmp_path)
        monkeypatch.setattr(registry.shutil, "which", lambda b: None)
        assert registry.install_one(t, lambda m: None) is False


class TestDriftOnlyExit:
    def test_drift_only_exits_nonzero_on_any_violation(self, monkeypatch):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(cli_mod, "load_tools", lambda: [_tool(bin="subfinder", pin="v2.14.0")])
        import quarry_recon.registry as reg
        monkeypatch.setattr(reg, "load_tools", lambda: [_tool(bin="subfinder", pin="v2.14.0")])
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(reg, "installed_identity", lambda t: "")          # version-unknown violation
        res = CliRunner().invoke(cli_mod.cli, ["lock", "--drift-only"])
        assert res.exit_code == 1 and "version-unknown" in res.output

    def test_drift_only_green_when_all_ok(self, monkeypatch):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        import quarry_recon.registry as reg
        monkeypatch.setattr(reg, "load_tools", lambda: [_tool(bin="subfinder", pin="v2.14.0")])
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(reg, "installed_identity", lambda t: "v2.14.0")
        res = CliRunner().invoke(cli_mod.cli, ["lock", "--drift-only"])
        assert res.exit_code == 0


class TestIdentityR5:
    def test_pipx_shadow_binary_rejected(self, monkeypatch):
        # review-C08.2r5#1: a /usr/local/bin shadow must not borrow the pipx env version
        t = _tool(bin="arjun", runtime="pipx", install="pipx install arjun")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/usr/local/bin/arjun")
        monkeypatch.setattr(registry, "_pipx_meta",
                            lambda pkg: ("2.2.7", ["/home/u/.local/pipx/venvs/arjun/bin/arjun"]))
        assert registry.installed_identity(t) == ""

    def test_pipx_resolved_to_app_path_ok(self, monkeypatch):
        t = _tool(bin="arjun", runtime="pipx", install="pipx install arjun")
        app = "/home/u/.local/pipx/venvs/arjun/bin/arjun"
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: app)
        monkeypatch.setattr(registry, "_pipx_meta", lambda pkg: ("2.2.7", [app]))
        assert registry.installed_identity(t) == "2.2.7"

    def test_go_parent_module_rejected(self, monkeypatch):
        # review-C08.2r5#3: the parent module must NOT satisfy the expected module (exact match required)
        t = _tool(bin="subfinder", runtime="go",
                  install="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/bin/subfinder")
        monkeypatch.setattr(registry, "_go_mod_and_version",
                            lambda p: ("github.com/projectdiscovery/subfinder", "v2.14.0"))   # PARENT of /v2
        assert registry.installed_identity(t) == ""

    def _binary_env(self, monkeypatch, tmp_path, receipt=None):
        import hashlib
        monkeypatch.setenv("HOME", str(tmp_path))
        binp = tmp_path / ".local" / "bin" / "gitleaks"
        binp.parent.mkdir(parents=True, exist_ok=True); binp.write_bytes(b"GITLEAKS-8.30.1")
        if receipt is not None:
            (tmp_path / ".local" / "bin" / ".gitleaks.lock").write_text(receipt)
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(binp))
        return _tool(bin="gitleaks", runtime="binary", pin="v8.30.1"), binp, hashlib.sha256(b"GITLEAKS-8.30.1").hexdigest()

    def test_binary_without_receipt_is_unverified(self, monkeypatch, tmp_path):
        # review-C08.2r5#2: a pre-C08 binary (no receipt) is unverified -> reinstall (checksum download runs)
        t, binp, sha = self._binary_env(monkeypatch, tmp_path, receipt=None)
        assert registry.installed_identity(t) == "" and registry.drift(t) == "version-unknown"

    def test_binary_receipt_match_ok(self, monkeypatch, tmp_path):
        t, binp, sha = self._binary_env(monkeypatch, tmp_path, receipt=None)
        (tmp_path / ".local" / "bin" / ".gitleaks.lock").write_text(f'{{"ident":"v8.30.1","sha256":"{sha}"}}')
        assert registry.installed_identity(t) == "v8.30.1" and registry.drift(t) == "ok"

    def test_binary_receipt_sha_mismatch_is_drift(self, monkeypatch, tmp_path):
        t, binp, sha = self._binary_env(monkeypatch, tmp_path,
                                        receipt='{"ident":"v8.30.1","sha256":"' + ("d" * 64) + '"}')
        assert registry.installed_identity(t) == "" and registry.drift(t) == "version-unknown"


class TestIdentityR6:
    def test_pipx_empty_app_paths_fails_closed(self, monkeypatch):
        # review-C08.2r6#1: an EMPTY app_paths list proves nothing -> must NOT verify a shadow
        t = _tool(bin="arjun", runtime="pipx", install="pipx install arjun")
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/usr/local/bin/arjun")
        monkeypatch.setattr(registry, "_pipx_meta", lambda pkg: ("2.2.7", []))   # no recorded paths
        assert registry.installed_identity(t) == ""

    def test_go_unparseable_module_fails_closed(self, monkeypatch):
        # review-C08.2r6#2: if the expected module can't be parsed, ANY embedded module must be rejected
        t = _tool(bin="x", runtime="go", install="curl -o x https://x/x")   # no 'go install <mod>@'
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry.shutil, "which", lambda b: "/bin/x")
        monkeypatch.setattr(registry, "_go_mod_and_version", lambda p: ("whatever.com/x", "v9"))
        assert registry.installed_identity(t) == ""

    def test_install_fails_when_binary_unhashable(self, monkeypatch, tmp_path):
        # review-C08.2r6#3: a "" digest (read failure) must NOT be written as a receipt / reported as success
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/amd64")
        stage = tmp_path / ".local" / "bin" / ".stage" / "gitleaks"
        dest = tmp_path / ".local" / "bin" / "gitleaks"
        dest.parent.mkdir(parents=True, exist_ok=True)

        def rs(c, d):
            if "curl" in c:
                stage.parent.mkdir(parents=True, exist_ok=True); stage.write_text("NEW")
            return (0, "")
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, "v8.30.1"))
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(dest))
        monkeypatch.setattr(registry, "_file_sha256", lambda p: "")            # binary unhashable
        t = _tool(bin="gitleaks", runtime="binary", pin="v8.30.1", version_cmd="gitleaks version",
                  artifacts={"linux/amd64": {"url": "https://x/g.tgz", "sha256": _VALID_SHA}},
                  install="curl {url} ... ~/.local/bin/.stage {bin}")
        msgs = []
        assert registry.install_one(t, msgs.append) is False
        assert not (tmp_path / ".local" / "bin" / ".gitleaks.lock").exists()   # no receipt written
        assert any("hash" in m for m in msgs)


class TestDoctorVersion:
    def _v(self, monkeypatch, ident, banner=""):
        from quarry_recon import cli
        monkeypatch.setattr(Tool, "version", lambda self: banner)
        return cli._doctor_version(_tool(bin="x", runtime="go"), ident)

    def test_identity_shown_when_present(self, monkeypatch):
        assert self._v(monkeypatch, "v2.14.0") == "v2.14.0"        # agrees with install source

    def test_empty_identity_falls_back_to_banner(self, monkeypatch):
        assert self._v(monkeypatch, "", banner="v9.9.9") == "v9.9.9"

    def test_empty_identity_no_banner_is_unknown(self, monkeypatch):
        assert "version unknown" in self._v(monkeypatch, "", banner="")

    def test_distro_prefers_banner(self, monkeypatch):
        assert self._v(monkeypatch, "distro", banner="7.94") == "7.94"

    def test_distro_without_banner_shows_distro(self, monkeypatch):
        assert "distro" in self._v(monkeypatch, "distro", banner="")

    def test_long_source_ref_is_shortened(self, monkeypatch):
        ref = "6bfa47197d78e68b79041d494e280174cb2d6ae1"           # 40-hex commit
        assert self._v(monkeypatch, ref) == ref[:12]

    def test_pseudo_version_not_treated_as_hex(self, monkeypatch):
        pv = "v0.0.0-20260422172756-4f562901bc23"                  # has non-hex chars -> shown whole
        assert self._v(monkeypatch, pv) == pv


class TestDoctorRender:
    # Codex P1: a present-but-unverified tool must render ⚠ unverified (+reason), never ✓ — even with a banner.
    def test_reason_drift(self):
        from quarry_recon import cli
        r = cli._health_reason({"drift": "DRIFT", "identity": "v2", "capability": None}, _tool(pin="v1"))
        assert "drift" in r and "v2" in r and "v1" in r

    def test_reason_identity_unknown(self):
        from quarry_recon import cli
        r = cli._health_reason({"drift": "version-unknown", "identity": "", "capability": None}, _tool(pin="v1"))
        assert "identity unproven" in r

    def test_reason_capability(self):
        from quarry_recon import cli
        r = cli._health_reason({"drift": "ok", "identity": "v1", "capability": False}, _tool(pin="v1"))
        assert "capability" in r

    def test_identity_unknown_with_valid_banner_still_unverified(self, monkeypatch):
        # the shadowed/unproven case: version() has a banner, but health.ok is False -> ⚠ not ✓
        from quarry_recon import cli
        _health_env(monkeypatch, identity="")                      # unproven identity
        t = _tool(pin="v1", version_cmd="x -version")
        monkeypatch.setattr(Tool, "version", lambda self: "v9.9.9")
        h = registry.health(t)
        assert h["ok"] is False                                    # verdict: unverified
        assert cli._doctor_version(t, h["identity"]) == "v9.9.9"   # banner still DISPLAYED (info only)


class TestGoBinaryMigration:
    # review-C08.2r7: a go->binary runtime migration (dalfox v2 go -> v3 binary) must reclaim a legacy
    # ~/go/bin copy that would shadow the newly-activated managed binary — else the upgrade silently keeps v2.
    def _setup(self, monkeypatch, tmp_path, *, stage_ok=True):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/amd64")
        gobin = tmp_path / "go" / "bin"; gobin.mkdir(parents=True)
        legacy = gobin / "dalfox"; legacy.write_text("V2-OLD")             # the shadowing go-install binary
        stage = tmp_path / ".local" / "bin" / ".stage" / "dalfox"
        dest = tmp_path / ".local" / "bin" / "dalfox"; dest.parent.mkdir(parents=True, exist_ok=True)

        def rs(c, d):
            if "curl" in c and stage_ok:
                stage.parent.mkdir(parents=True, exist_ok=True); stage.write_text("V3-NEW")
            return (0, "") if stage_ok else (1, "")
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, "v3.1.2"))
        monkeypatch.setattr(registry, "_go_bin_dir", lambda: gobin)
        # PATH resolves the legacy go copy FIRST while it exists; only after relocation does dest win
        monkeypatch.setattr(registry.shutil, "which",
                            lambda b: str(legacy) if legacy.exists() else (str(dest) if dest.exists() else None))
        t = _tool(bin="dalfox", runtime="binary", pin="v3.1.2", version_cmd="dalfox --version",
                  artifacts={"linux/amd64": {"url": "https://x/d.tgz", "sha256": _VALID_SHA}},
                  install="curl {url} ... {bin}")
        return t, legacy, dest, gobin

    def test_migration_reclaims_legacy_and_resolves_managed_v3(self, monkeypatch, tmp_path):
        t, legacy, dest, gobin = self._setup(monkeypatch, tmp_path)
        msgs = []
        assert registry.install_one(t, msgs.append) is True
        assert dest.read_text() == "V3-NEW"                                # managed v3 activated + resolves
        assert not legacy.exists()                                         # legacy no longer shadows
        baks = list(gobin.glob("dalfox.quarry-replaced-*"))
        assert baks and baks[0].read_text() == "V2-OLD"                    # relocated as ROLLBACK EVIDENCE, not deleted
        assert any("relocated legacy" in m for m in msgs)

    def test_failed_v3_install_leaves_v2_intact(self, monkeypatch, tmp_path):
        t, legacy, dest, gobin = self._setup(monkeypatch, tmp_path, stage_ok=False)
        assert registry.install_one(t, lambda m: None) is False
        assert legacy.read_text() == "V2-OLD"                              # staging failed BEFORE touching v2
        assert not dest.exists()                                           # nothing activated
        assert not list(gobin.glob("dalfox.quarry-replaced-*"))           # no relocation on a failed install

    def test_shadow_outside_go_bin_is_not_touched(self, monkeypatch, tmp_path):
        t, legacy, dest, gobin = self._setup(monkeypatch, tmp_path)
        sysdir = tmp_path / "usr" / "local" / "bin"; sysdir.mkdir(parents=True)
        sysshadow = sysdir / "dalfox"; sysshadow.write_text("SYS")         # a shadow we do NOT own
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(sysshadow))
        assert registry.install_one(t, lambda m: None) is False           # cannot reclaim a non-go shadow -> fail loud
        assert sysshadow.read_text() == "SYS"                             # untouched
        assert not list(gobin.glob("dalfox.quarry-replaced-*"))


class TestReclaimTransactional:
    # review-r8#3: the receipt is written BEFORE any legacy copy is touched, and a failed migration restores v2.
    def _mig(self, monkeypatch, tmp_path, *, which_after_reclaim="dest"):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/amd64")
        gobin = tmp_path / "go" / "bin"; gobin.mkdir(parents=True)
        legacy = gobin / "dalfox"; legacy.write_text("V2-OLD")
        stage = tmp_path / ".local" / "bin" / ".stage" / "dalfox"
        dest = tmp_path / ".local" / "bin" / "dalfox"; dest.parent.mkdir(parents=True, exist_ok=True)

        def rs(c, d):
            if "curl" in c:
                stage.parent.mkdir(parents=True, exist_ok=True); stage.write_text("V3-NEW")
            return (0, "")
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, "v3.1.2"))
        monkeypatch.setattr(registry, "_go_bin_dir", lambda: gobin)
        # while legacy exists it shadows; after reclaim, either dest resolves ("dest") or nothing does ("none")
        def which(b):
            if legacy.exists():
                return str(legacy)
            return str(dest) if (which_after_reclaim == "dest" and dest.exists()) else None
        monkeypatch.setattr(registry.shutil, "which", which)
        t = _tool(bin="dalfox", runtime="binary", pin="v3.1.2", version_cmd="dalfox --version",
                  artifacts={"linux/amd64": {"url": "https://x/d.tgz", "sha256": _VALID_SHA}},
                  install="curl {url} ... {bin}")
        return t, legacy, dest, gobin

    def test_hash_failure_leaves_legacy_intact(self, monkeypatch, tmp_path):
        t, legacy, dest, gobin = self._mig(monkeypatch, tmp_path)
        monkeypatch.setattr(registry, "_file_sha256", lambda p: "")     # unhashable -> fail BEFORE reclaim
        assert registry.install_one(t, lambda m: None) is False
        assert legacy.read_text() == "V2-OLD"                           # legacy untouched (transactional)
        assert not list(gobin.glob("dalfox.quarry-replaced-*"))

    def test_receipt_failure_leaves_legacy_intact(self, monkeypatch, tmp_path):
        t, legacy, dest, gobin = self._mig(monkeypatch, tmp_path)
        def boom(*a, **k):
            raise OSError("receipt write denied")
        monkeypatch.setattr(registry, "_write_receipt", boom)           # fail BEFORE reclaim
        assert registry.install_one(t, lambda m: None) is False
        assert legacy.read_text() == "V2-OLD"
        assert not list(gobin.glob("dalfox.quarry-replaced-*"))

    def test_unresolvable_dest_after_reclaim_restores_legacy(self, monkeypatch, tmp_path):
        # reclaim succeeds but the managed binary still doesn't resolve (~/.local/bin not on PATH) -> restore v2
        t, legacy, dest, gobin = self._mig(monkeypatch, tmp_path, which_after_reclaim="none")
        assert registry.install_one(t, lambda m: None) is False
        assert legacy.exists() and legacy.read_text() == "V2-OLD"       # legacy RESTORED (host keeps a working tool)
        assert not list(gobin.glob("dalfox.quarry-replaced-*"))         # relocation reverted


class TestMaintenanceSchema:
    def test_tool_carries_refresh_metadata(self):
        t = _tool(maintenance_state="frozen", release="2.1")
        assert t.maintenance_state == "frozen" and t.release == "2.1"

    def test_every_registry_tool_has_a_valid_maintenance_state(self):
        # v0.3.9: the snapshot is COMPLETE — every tool is classified into a known refresh class
        states = registry._MAINTENANCE_STATES
        missing = [t.bin for t in registry.load_tools() if t.maintenance_state not in states]
        assert not missing, f"tools with no/invalid maintenance_state: {missing}"

    def test_release_recorded_only_when_it_differs_from_a_pseudo_pin(self):
        # a `release` is meaningful only where the pin is a pseudo-version/commit (its human tag differs)
        for t in registry.load_tools():
            if t.release:
                assert t.release != (t.pin or t.ref), f"{t.bin}: release == pin (redundant)"

    def test_capture_lock_exposes_maintenance_and_release(self, monkeypatch):
        fake = [_tool(bin="gowitness", pin="v0.0.0-abc", maintenance_state="active", release="3.1.1"),
                _tool(bin="subfinder", pin="v2.14.0", maintenance_state="active")]
        monkeypatch.setattr(registry, "load_tools", lambda: fake)
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(registry, "installed_identity", lambda t: "x")
        rows = {r["bin"]: r for r in registry.capture_lock()}
        assert rows["gowitness"]["maintenance"] == "active" and rows["gowitness"]["release"] == "3.1.1"
        assert rows["subfinder"]["release"] == "v2.14.0"   # falls back to the pin when no distinct release


class TestMaintenanceView:
    def test_maintenance_view_never_probes_installed_tools(self, monkeypatch):
        # review-r13#1: the planning view reads the static registry; it must NOT probe (no installed_identity)
        from click.testing import CliRunner
        from quarry_recon.cli import cli
        probed = []
        monkeypatch.setattr(registry, "installed_identity", lambda t: probed.append(t.bin) or "")
        monkeypatch.setattr(registry, "capture_lock", lambda: (_ for _ in ()).throw(AssertionError("must not capture")))
        r = CliRunner().invoke(cli, ["lock", "--maintenance"])
        assert r.exit_code == 0 and not probed and "refresh-policy view" in r.output


class TestInstallOutput:
    def _full_env(self, monkeypatch, tmp_path):
        from quarry_recon import cli as cli_mod, bootstrap
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(Tool, "installed", property(lambda self: False))
        monkeypatch.setattr(bootstrap, "system_report", lambda w: {"level": "ok"})
        monkeypatch.setattr(cli_mod, "_echo_syscheck", lambda r: None)
        for fn in ("install_system_packages", "ensure_golang", "install_data_files", "run_extras", "cleanup"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: True)
        return cli_mod

    def test_success_is_one_clean_line_diagnostics_suppressed(self, monkeypatch, tmp_path):
        # collapse: a clean install is a NAME-only `→ tool ✓` (no version) — install_one's progress is buffered
        from click.testing import CliRunner
        cli_mod = self._full_env(monkeypatch, tmp_path)
        monkeypatch.setattr(cli_mod, "install_one",
                            lambda t, echo, dry_run=False: (echo(f"{t.bin}: ok (noise)"), True)[1])
        res = CliRunner().invoke(cli_mod.cli, ["install", "--include-optional", "--yes"])
        assert res.exit_code == 0
        assert "→ subfinder ✓" in res.output                     # NAME only — no version in install output
        assert "@ v2.14.0" not in res.output                     # version omitted (it lives in doctor/lock)
        assert "subfinder: ok (noise)" not in res.output         # buffered diagnostic suppressed on success

    def test_failure_shows_marker_and_buffered_diagnostics(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        cli_mod = self._full_env(monkeypatch, tmp_path)
        monkeypatch.setattr(cli_mod, "install_one",
                            lambda t, echo, dry_run=False: (echo("CAPABILITY FAILED"), False)[1])
        res = CliRunner().invoke(cli_mod.cli, ["install", "--only", "subfinder", "--yes"])
        # a FAILURE shows the attempted pin + diagnostics (unlike the name-only success line)
        assert res.exit_code != 0 and "✗" in res.output and "@ v2.14.0" in res.output and "CAPABILITY FAILED" in res.output

    def test_dry_run_marker_is_neutral_not_success(self, monkeypatch, tmp_path):
        # review polish-r2#1: install_one returns True in dry-run WITHOUT installing — must render (dry-run), not ✓
        from click.testing import CliRunner
        cli_mod = self._full_env(monkeypatch, tmp_path)
        monkeypatch.setattr(cli_mod, "install_one", lambda t, echo, dry_run=False: True)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--include-optional", "--dry-run"])
        assert res.exit_code == 0 and "(dry-run)" in res.output and "✓" not in res.output

    def test_success_keeps_exceptional_migration_note(self, monkeypatch, tmp_path):
        # review polish-r2#2: suppress only the routine "<bin>: ok" line; a legacy-relocation note stays
        from click.testing import CliRunner
        cli_mod = self._full_env(monkeypatch, tmp_path)
        def io(t, echo, dry_run=False):
            if t.bin == "dalfox":
                echo(f"{t.bin}: relocated legacy go binary /old -> /old.bak (runtime migration)")
            echo(f"{t.bin}: ok (x)")
            return True
        monkeypatch.setattr(cli_mod, "install_one", io)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--include-optional", "--yes"])
        assert res.exit_code == 0
        assert "relocated legacy go binary" in res.output   # exceptional note KEPT
        assert "dalfox: ok (x)" not in res.output            # routine ok line suppressed

    def test_dry_run_unavailable_shows_reason_not_false_success(self, monkeypatch, tmp_path):
        # review polish-r3: install_one can return False in dry-run (unsupported platform / manual-only) — that
        # must render an unavailable marker + the reason, NOT a misleading (dry-run)
        from click.testing import CliRunner
        cli_mod = self._full_env(monkeypatch, tmp_path)
        def io(t, echo, dry_run=False):
            if t.bin == "dalfox":
                echo("unsupported platform (linux/riscv64) — no dalfox artifact")
                return False
            return True
        monkeypatch.setattr(cli_mod, "install_one", io)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--include-optional", "--dry-run"])
        assert res.exit_code == 0
        assert "unsupported platform" in res.output and "⊘ unavailable" in res.output

    def test_distro_tool_not_labeled_unpinned_in_dry_run(self, monkeypatch, tmp_path):
        # review polish-r4: nmap is policy:distro — dry-run/failure must show (distro), never (unpinned) [P3]
        from click.testing import CliRunner
        cli_mod = self._full_env(monkeypatch, tmp_path)
        monkeypatch.setattr(cli_mod, "install_one", lambda t, echo, dry_run=False: True)
        res = CliRunner().invoke(cli_mod.cli, ["install", "--include-optional", "--dry-run"])
        nmap_line = next(l for l in res.output.splitlines() if l.strip().startswith("→ nmap"))
        assert "(distro)" in nmap_line and "(unpinned)" not in nmap_line


class TestOsintTimeout:
    def test_osint_rejects_zero_timeout(self):
        # review-r3#3: osint bounds each lookup with min(timeout, N); 0 would collapse every lookup to 0s. It has
        # no unbounded mode (unlike `run`), so 0/neg is rejected up front (before profile resolution).
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        res = CliRunner().invoke(cli_mod.cli, ["osint", "-t", "no-such-project-xyz", "--timeout", "0"])
        assert res.exit_code != 0 and "must be > 0" in res.output
