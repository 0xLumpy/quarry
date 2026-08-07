"""C08.1 — the compatibility-lock schema + version capture / drift detection.

The lock makes installs reproducible: each tool carries a PINNED version (`pin`), a download `sha256`, and a
post-install `capability` smoke test. `quarry lock` captures the installed versions on a validated host; `drift`
flags an installed version that no longer matches the pin (a reproducibility break).
"""
import pathlib
import re
from dataclasses import replace
from types import SimpleNamespace

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
        # 31 go/pipx + gitleaks + trufflehog + dalfox + bun = 34 carry an exact `version:` pin
        # (massdns uses ref; nmap is distro-managed)
        pinned = [t for t in registry.load_tools() if t.pin]
        assert len(pinned) == 34
        assert all(t.pin.lower() not in registry._SENTINEL_PINS for t in pinned)

    def test_nmap_is_distro_policy_not_pinned(self):
        nmap = next(t for t in registry.load_tools() if t.bin == "nmap")
        assert nmap.policy == "distro" and nmap.pin is None

    def test_the_artifact_URL_CARRIES_the_pin(self):
        """A half-done bump — `version:` moved, URLs left behind — installs the OLD release and then
        rejects it as drift. The pin and the bytes it names have to agree in the file itself."""
        for t in registry.load_tools():
            for plat, a in (t.artifacts or {}).items():
                assert t.pin, f"{t.bin} has artifacts but no pin"
                assert t.pin in a["url"], f"{t.bin} {plat}: pin {t.pin} not in {a['url']}"

    def test_binary_tools_pinned_with_artifacts(self):
        ts = {t.bin: t for t in registry.load_tools()}
        for b in ("gitleaks", "trufflehog", "dalfox"):
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

    def test_every_REAL_binary_install_verifies_its_digest_before_use(self):
        """What actually protects a MISTYPED sha256: nothing in this suite can know the true digest of a
        remote artifact, so the guarantee has to be that a wrong one FAILS CLOSED. Every real binary
        install pipes the pinned digest through `sha256sum -c -` before the tarball is opened, so a typo
        aborts the install instead of activating unverified bytes."""
        for t in registry.load_tools():
            if t.runtime != "binary":
                continue
            cmd = t.install or ""
            assert "{sha256}" in cmd and "sha256sum -c" in cmd, f"{t.bin} installs without checking a digest"
            # whichever unpacker it uses, verification comes FIRST
            unpack = next((u for u in ("tar -xzf", "unzip") if u in cmd), None)
            assert unpack, f"{t.bin} has no recognised unpack step to order against"
            assert cmd.index("sha256sum -c") < cmd.index(unpack), f"{t.bin} unpacks BEFORE verifying"

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
        # a LIST of results is consumed one per call, so a test can make the capability probe succeed and
        # the SECOND (version) invocation fail — they are separate process runs, not one fact.
        if isinstance(probe, list):
            seq = list(probe)
            monkeypatch.setattr(registry, "_probe",
                                lambda c, timeout=15: seq.pop(0) if seq else (127, ""))
        else:
            monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: probe)
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

    def test_a_FAILING_SECOND_probe_cannot_launder_a_scraped_token_into_the_pin(self, monkeypatch, tmp_path):
        """review#20 (Lumpy), and I had this wrong: I argued the capability probe already gated this,
        because it runs first with the same accepted set. It does not. It is a SEPARATE INVOCATION — and
        for the 5 tools with a distinct `capability` it is not even the same command. Capability can
        succeed and the version run that follows can fail, print help, and hand over a version-shaped
        token (`Mozilla/5.0`) that COINCIDES with the pin — activating a binary whose version command
        does not work."""
        t, stage, dest = self._binary(
            monkeypatch, tmp_path, old="OLD-WORKING",
            probe=[(0, "gitleaks v5.0"),                                  # capability: succeeds
                   (1, "Error: unknown flag\n --user-agent 'Mozilla/5.0'\n")])  # version: FAILS, scrapes 5.0
        assert registry.install_one(replace(t, pin="v5.0"), lambda m: None) is False
        assert dest.read_text() == "OLD-WORKING" and not stage.exists()

    def test_declaring_cap_codes_does_not_widen_the_STAGED_version_check(self, monkeypatch, tmp_path):
        """The install-side half of review#20's second point. A help-probe tool declares `cap_codes:
        [0, 1]`; if the staged version check reused that set, its failing version run would be accepted
        and the scraped `Mozilla/5.0` would satisfy a `v5.0` pin. `version_codes` is the axis, and it
        still defaults to {0} no matter what capability accepts."""
        t, stage, dest = self._binary(
            monkeypatch, tmp_path, old="OLD-WORKING",
            probe=[(1, "usage: gitleaks [command]"),                      # capability: DECLARED success
                   (1, "Error: unknown flag\n --user-agent 'Mozilla/5.0'\n")])   # version: failed
        t = replace(t, pin="v5.0", cap_codes=[0, 1])
        assert registry.install_one(t, lambda m: None) is False
        assert dest.read_text() == "OLD-WORKING" and not stage.exists()

    def test_declaring_version_codes_DOES_accept_that_exit_code(self, monkeypatch, tmp_path):
        """The other half, and the reason nothing declares it: `version_codes: [0, 1]` is an operator
        statement that THIS tool's version output is trustworthy on exit 1 — after which the scrape is
        accepted like any other version. The field is deliberately narrow, not a general loosening.
        (Fresh harness: the probe results are consumed one per call, so reusing an exhausted sequence
        would make a second install fail for an unrelated reason and pass this test by accident.)"""
        t, stage, dest = self._binary(
            monkeypatch, tmp_path,
            probe=[(1, "usage: gitleaks [command]"), (1, "gitleaks version v5.0")])
        assert registry.install_one(replace(t, pin="v5.0", cap_codes=[0, 1],
                                            version_codes=[0, 1]), lambda m: None) is True
        assert dest.read_text() == "NEW"

    def test_the_same_sequence_activates_once_the_version_probe_SUCCEEDS(self, monkeypatch, tmp_path):
        """The control: it is the failing exit code that stops it, not the help text or the pin value."""
        t, stage, dest = self._binary(monkeypatch, tmp_path,
                                      probe=[(0, "gitleaks v5.0"), (0, "gitleaks v5.0")])
        assert registry.install_one(replace(t, pin="v5.0"), lambda m: None) is True
        assert dest.read_text() == "NEW"

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


class TestAFailedProbeHasNoVersionToReport:
    """dalfox v2 answered `--version` with `Error: unknown flag: --version` and then its HELP text, whose
    first version-shaped token is the `Mozilla/5.0` in a default User-Agent. Quarry reported that tool as
    version "5.0" — a confident number scraped out of an error, which then hid the real defect (the wrong
    binary was on PATH). A probe that failed knows nothing about the version."""

    V2_HELP = ("Error: unknown flag: --version\n"
               "Usage:\n  dalfox [command]\n"
               "  --user-agent string   User-Agent (default \"Mozilla/5.0 (Windows NT 10.0)\")\n")

    def _probe(self, monkeypatch, rc, out):
        monkeypatch.setattr(registry, "_probe", lambda *a, **k: (rc, out))
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))

    def test_the_old_defect_verbatim(self, monkeypatch):
        assert registry._parse_version(self.V2_HELP) == "5.0", "fixture must reproduce the scrape"
        self._probe(monkeypatch, 1, self.V2_HELP)
        assert _tool(bin="dalfox", version_cmd="dalfox --version").version() == ""

    def test_a_successful_probe_still_reports(self, monkeypatch):
        self._probe(monkeypatch, 0, "dalfox 3.2.0\n")
        assert _tool(bin="dalfox", version_cmd="dalfox --version").version() == "3.2.0"

    def test_cap_codes_do_NOT_unlock_a_version(self, monkeypatch):
        """review#20 (Lumpy): `cap_codes: [0, 1]` — declared by 14 tools whose probe is a help screen —
        says the BINARY RUNS. It does not say a failed command's output carries a version. Two questions,
        two fields; overloading one of them is how a scraped token gets a second chance."""
        self._probe(monkeypatch, 1, "gau version 2.2.4\n")
        assert _tool(bin="gau", version_cmd="gau --version", cap_codes=[0, 1]).version() == ""
        assert _tool(bin="gau", version_cmd="gau --version",
                     version_codes=[0, 1]).version() == "2.2.4", "the version axis is the one that unlocks it"

    def test_nothing_declares_version_codes_yet_and_that_is_measured(self):
        """The field is an escape hatch, not a knob in use: 0 of 29 installed tools with a version probe
        exit non-zero (measured 2026-08-06). If the fresh-install box meets one, it is a yaml line."""
        assert [t.bin for t in registry.load_tools() if t.version_codes] == []

    def test_a_probe_that_never_RAN_is_uncapturable(self, monkeypatch):
        self._probe(monkeypatch, registry._PROBE_NOT_RUN, "")
        assert _tool(bin="x", version_cmd="x --version", version_codes=[0, 1]).version() == ""


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

    def test_run_rejects_negative_timeout_at_parse(self):
        # review-r3: `run --timeout -1` would reach communicate(timeout=-1) = instant timeout. IntRange(min=0)
        # rejects it at PARSE (exit 2) — before profile resolution or any run dir is created. 0 stays valid.
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        res = CliRunner().invoke(cli_mod.cli, ["run", "-t", "no-such-project-xyz", "--timeout", "-1"])
        assert res.exit_code == 2 and "timeout" in res.output.lower()   # click usage error, body never ran


class TestAnInstallFailureSAYSWhatHappened:
    """review#45 (Lumpy, from a real install on a fresh box): `jxscout-ast` exits with "needs bun (the
    analyzer fails under node)" and the operator was told "install/stage FAILED (checksum or build)" —
    the command's own output was discarded and the message guessed. Debugging the wrong thing is the
    cost of a message that does not know why it is printing."""

    def _binary(self, monkeypatch, tmp_path, *, code, out, stage=False):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(registry, "current_platform", lambda: "linux/amd64")
        stage_p = tmp_path / ".local" / "bin" / ".stage" / "gitleaks"

        def rs(c, d):
            if stage:
                stage_p.parent.mkdir(parents=True, exist_ok=True)
                stage_p.write_text("NEW")
            return (code, out)
        monkeypatch.setattr(registry, "run_shell", rs)
        monkeypatch.setattr(registry, "_probe", lambda c, timeout=15: (0, "v8.30.1"))
        monkeypatch.setattr(registry.shutil, "which", lambda b: str(tmp_path / ".local/bin/gitleaks"))
        t = _tool(bin="gitleaks", runtime="binary", pin="v8.30.1", version_cmd="gitleaks version",
                  artifacts={"linux/amd64": {"url": "https://x/g.tgz", "sha256": _VALID_SHA}},
                  install="curl {url} ... ~/.local/bin/.stage {bin}")
        msgs: list = []
        ok = registry.install_one(t, msgs.append)
        return ok, " ".join(msgs)

    def test_the_scripts_OWN_reason_reaches_the_operator(self, monkeypatch, tmp_path):
        ok, msg = self._binary(monkeypatch, tmp_path, code=1,
                               out="jxscout-ast needs bun (the analyzer fails under node): "
                                   "install bun first")
        assert ok is False
        assert "needs bun" in msg, msg
        assert "checksum or build" not in msg, "it no longer guesses"

    def test_the_EXIT_CODE_is_named(self, monkeypatch, tmp_path):
        _ok, msg = self._binary(monkeypatch, tmp_path, code=7, out="boom")
        assert "exit 7" in msg, msg

    def test_a_command_that_SUCCEEDS_but_stages_nothing_is_its_own_state(self, monkeypatch, tmp_path):
        """Both are failures; only one of them is the script's fault."""
        _ok, msg = self._binary(monkeypatch, tmp_path, code=0, out="all good!", stage=False)
        assert "exited 0 but staged no binary" in msg, msg
        assert "all good!" in msg, "…and it still shows what the command said"

    def test_a_SILENT_failure_says_that_rather_than_nothing(self, monkeypatch, tmp_path):
        _ok, msg = self._binary(monkeypatch, tmp_path, code=1, out="")
        assert "produced no output" in msg, msg

    def test_a_successful_install_is_unaffected(self, monkeypatch, tmp_path):
        ok, msg = self._binary(monkeypatch, tmp_path, code=0, out="", stage=True)
        assert ok is True and "FAILED" not in msg, msg


class TestBunIsProvisionedLikeAnyOtherTool:
    """Lumpy, 2026-08-07: `jxscout-ast` failed on every fresh box because bun was the ONE prerequisite
    the operator had to satisfy by hand — while Quarry bootstraps pipx and the Go toolchain and puts
    both on PATH itself. "The operator's decision" was an inconsistency, not a policy."""

    @staticmethod
    def _tools():
        return {t.bin: t for t in registry.load_tools()}

    def test_bun_is_in_the_registry_and_pinned(self):
        b = self._tools()["bun"]
        assert b.runtime == "binary" and b.pin == "v1.3.14" and b.repo == "oven-sh/bun"
        assert set(b.artifacts) >= {"linux/amd64", "linux/arm64"}
        for a in b.artifacts.values():
            assert a["url"].startswith("https://github.com/oven-sh/bun/releases/download/")
            assert len(a["sha256"]) == 64

    def test_it_installs_into_the_path_install_sh_already_persists(self):
        """No new PATH plumbing and nothing for the operator to source: `~/.local/bin` is exported by
        install.sh AND written to the rc file before tools are provisioned."""
        cmd = self._tools()["bun"].install
        assert "~/.local/bin/.stage/{bin}" in cmd
        rc = pathlib.Path("install.sh").read_text()
        assert '$HOME/.local/bin' in rc and '>>> quarry path >>>' in rc

    def test_it_is_installed_BEFORE_the_tool_that_needs_it(self):
        """The registry installs in file order, and `jxscout-ast` probes for `bun` on PATH."""
        names = [t.bin for t in registry.load_tools()]
        assert names.index("bun") < names.index("jxscout-ast")

    def test_the_x64_build_is_the_BASELINE_one(self):
        """The default x64 build requires AVX2 and a VPS CPU is not something an install script gets to
        assume. Measured: both run here; only baseline runs everywhere."""
        assert "baseline" in self._tools()["bun"].artifacts["linux/amd64"]["url"]

    def test_it_is_optional_like_the_lane_it_serves(self):
        """Nothing else needs a 90 MB JS runtime; a minimal install skips both, and install.sh passes
        --include-optional so a full bootstrap gets them."""
        t = self._tools()
        assert t["bun"].optional and t["jxscout-ast"].optional
        assert "--include-optional" in pathlib.Path("install.sh").read_text()

    def test_the_digest_is_verified_before_the_zip_is_opened(self):
        cmd = self._tools()["bun"].install
        assert cmd.index("sha256sum -c") < cmd.index("unzip")

    def test_the_binary_is_found_by_NAME_inside_the_zip(self):
        """The archive nests it under a build-named directory (`bun-linux-x64-baseline/bun`), which
        differs per artifact — assuming the path would break on the other platform."""
        cmd = self._tools()["bun"].install
        assert "-name bun" in cmd and "bun-linux-x64-baseline/bun" not in cmd

    def test_jxscout_ast_no_longer_needs_a_hand_installed_runtime(self):
        """Its guard stays — it just stops being the thing that fails a fresh install."""
        assert "command -v bun" in self._tools()["jxscout-ast"].install


class TestARuntimeDependencyIsNotAToolInTheOutput:
    """Lumpy, 2026-08-07, after the fresh proxmox install: "bun is now mentioned while installing in
    tools, and with doctor in crawl. as it is not a tool, but a dependency, it should not be listed
    there." It is provisioned by the SAME machinery (that part was the point) — only WHERE it is
    reported changes: with the toolchains, and with go/pipx/chromium."""

    @staticmethod
    def _tools():
        return {t.bin: t for t in registry.load_tools()}

    def test_bun_is_the_dependency_and_nothing_else_is(self):
        deps = [t.bin for t in registry.load_tools() if t.dependency]
        assert deps == ["bun"]

    def test_its_phase_still_names_the_tool_that_needs_it(self):
        """`phase` is not the display axis here — it is the dependency relation. Changing it would make
        `quarry install --phase crawl` stop provisioning the runtime jxscout-ast needs."""
        t = self._tools()
        assert t["bun"].phase == t["jxscout-ast"].phase == "crawl"

    # ── install ──────────────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _install(monkeypatch, tmp_path, argv):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod, bootstrap
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(Tool, "installed", property(lambda self: False))
        monkeypatch.setattr(bootstrap, "system_report", lambda who="install": {"level": "ok", "checks": []})
        monkeypatch.setattr(cli_mod, "_echo_syscheck", lambda rep: None)
        for fn in ("install_system_packages", "ensure_golang", "install_data_files", "run_extras", "cleanup"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: True)
        done = []
        monkeypatch.setattr(cli_mod, "install_one",
                            lambda t, echo, dry_run=False: (done.append(t.bin), True)[1])
        res = CliRunner().invoke(cli_mod.cli, ["install", "--yes", *argv])
        return res, done

    def test_a_full_install_provisions_it_with_the_TOOLCHAINS_not_the_tools(self, monkeypatch, tmp_path):
        res, done = self._install(monkeypatch, tmp_path, ["--include-optional"])
        assert res.exit_code == 0 and "bun" in done, res.output      # still installed
        head, _, tail = res.output.partition("[3/6] tools")
        assert "[2/6] runtimes" in head and "bun" in head, "reported in the toolchain step"
        assert "bun" not in tail.split("[4/6]")[0], "…and never in the tool list"

    def test_the_tool_count_counts_tools(self, monkeypatch, tmp_path):
        res, _ = self._install(monkeypatch, tmp_path, ["--include-optional"])
        listed = len([t for t in registry.load_tools() if not t.dependency])
        assert f"[3/6] tools ({listed})" in res.output, res.output

    def test_it_is_provisioned_BEFORE_the_tool_that_needs_it(self, monkeypatch, tmp_path):
        """Moving it out of the list must not move it out of the ORDER."""
        _, done = self._install(monkeypatch, tmp_path, ["--include-optional"])
        assert done.index("bun") < done.index("jxscout-ast")

    @pytest.mark.parametrize("argv", [["--phase", "crawl", "--include-optional"],
                                      ["--tools-only", "--include-optional"],
                                      ["--only", "bun"]])
    def test_a_NARROWED_run_still_installs_it(self, monkeypatch, tmp_path, argv):
        """A narrowed run has no toolchain step at all — there the dependency stays in the selection the
        operator asked for, or `quarry install --only bun` would print success and install nothing."""
        res, done = self._install(monkeypatch, tmp_path, argv)
        assert "bun" in done, (argv, res.output)

    # ── doctor ───────────────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _doctor(monkeypatch, installed=True, ok=True):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(Tool, "installed", property(lambda self: installed))
        monkeypatch.setattr(Tool, "version", lambda self: "1.2.3")
        monkeypatch.setattr(cli_mod, "health",
                            lambda t: {"ok": ok if t.dependency else True, "identity": "pin",
                                       "drift": "DRIFT", "capability": True})
        monkeypatch.setattr(cli_mod, "_chromium", lambda: True)
        return CliRunner().invoke(cli_mod.cli, ["doctor"]).output

    def test_it_is_reported_with_the_other_runtimes_not_under_crawl(self, monkeypatch):
        out = self._doctor(monkeypatch)
        crawl = out.split("[crawl]")[1].split("[")[0]
        assert "bun" not in crawl, crawl
        env = out.split("[environment]")[1].split("[system]")[0]
        assert "bun" in env and env.index("pipx") < env.index("bun"), env

    def test_the_header_and_the_verdict_quote_the_same_population(self, monkeypatch):
        out = self._doctor(monkeypatch)
        listed = len([t for t in registry.load_tools() if not t.dependency])
        assert f"— {listed} tools" in out, out
        assert f"{listed} tools installed + verified" in out, out

    def test_a_BROKEN_runtime_still_degrades_the_verdict(self, monkeypatch):
        """Not counting it as a tool is a display decision, not an amnesty: a runtime that does not
        verify is exactly why the lane that needs it will fail."""
        out = self._doctor(monkeypatch, ok=False)
        assert "DEGRADED" in out and "1 present but UNVERIFIED" in out, out


class TestTheChromiumLineSaysWhatTheLaneWillGet:
    """Lumpy, 2026-08-07: "check log (some libs optional)" told the operator neither what failed nor
    which log — and it appeared on a box where the only thing that happened was the EXPECTED rename
    fallback (libasound2 -> libasound2t64 on 24.04+; measured: the first apt attempt exits 100 there and
    the fallback succeeds). Exit codes describe the package manager. What matters is whether the
    screenshot lane will work, so chromium is asked."""

    @staticmethod
    def _state(monkeypatch, *, exe="/usr/bin/chromium", rc=0, stderr="", boom=None, cc=0, lc=100,
               tail="E: Package 'libasound2' has no installation candidate"):
        from quarry_recon import bootstrap
        monkeypatch.setattr(bootstrap.shutil, "which", lambda b: exe if b == "chromium" else None)

        def _run(cmd, **k):
            if boom:
                raise boom
            return SimpleNamespace(returncode=rc, stdout="", stderr=stderr)
        monkeypatch.setattr(bootstrap.subprocess, "run", _run)
        return bootstrap._chromium_state(False, cc, lc, tail)

    def test_a_working_headless_chromium_is_simply_ok(self, monkeypatch):
        """The rename fallback having fired is NOT a thing to report."""
        assert self._state(monkeypatch) == "ok"
        assert "check log" not in self._state(monkeypatch)

    def test_a_MISSING_chromium_says_what_it_costs_and_how_to_fix_it(self, monkeypatch):
        s = self._state(monkeypatch, exe=None, cc=100, tail="E: Unable to locate package chromium")
        assert "MISSING" in s and "screenshots" in s
        assert "Unable to locate package chromium" in s, "the package manager's own reason"
        assert "quarry install" in s

    def test_an_INSTALLED_but_broken_chromium_names_the_reason_it_gave(self, monkeypatch):
        """A missing .so lands here verbatim — the only thing an operator can act on."""
        s = self._state(monkeypatch, rc=127,
                        stderr="error while loading shared libraries: libnss3.so: cannot open "
                               "shared object file")
        assert "headless FAILED (exit 127)" in s and "libnss3.so" in s
        assert "screenshots will fail" in s

    def test_a_launch_that_RAISES_is_reported_not_swallowed(self, monkeypatch):
        s = self._state(monkeypatch, boom=OSError("Exec format error"))
        assert "WOULD NOT START" in s and "Exec format error" in s

    def test_a_dry_run_probes_nothing(self, monkeypatch):
        from quarry_recon import bootstrap
        monkeypatch.setattr(bootstrap.subprocess, "run",
                            lambda *a, **k: pytest.fail("a dry run must not launch chromium"))
        assert bootstrap._chromium_state(True, 0, 0, "") == "(dry-run)"

    def test_there_are_only_THREE_outcomes(self, monkeypatch):
        """ok / missing / present-but-broken. No fourth state that means "look somewhere else"."""
        outcomes = [self._state(monkeypatch),
                    self._state(monkeypatch, exe=None),
                    self._state(monkeypatch, rc=1)]
        assert outcomes[0] == "ok"
        assert all(o != "ok" and ("MISSING" in o or "FAILED" in o or "WOULD NOT START" in o)
                   for o in outcomes[1:])
        assert not any("check log" in o for o in outcomes)


class TestTheGoLineSaysOnlyWhatIsHappening:
    """Lumpy, 2026-08-07: "[declared version, sha256-verified; min 1.25]" restated guarantees that are
    unconditional in the code. An install line that recites its own invariants on every run is noise;
    the case an operator needs is the REFUSAL, which prints its own line."""

    @staticmethod
    def _run(monkeypatch, *, code=0, tail="", sha_ok=True):
        from quarry_recon import bootstrap
        msgs = []
        monkeypatch.setattr(bootstrap.shutil, "which", lambda b: None)     # nothing installed
        monkeypatch.setattr(bootstrap, "_sh", lambda *a, **k: (code, tail))
        if not sha_ok:
            real = bootstrap.load_bootstrap

            def _no_sha():
                bs = dict(real())
                bs["golang"] = dict(bs["golang"], sha256={})
                return bs
            monkeypatch.setattr(bootstrap, "load_bootstrap", _no_sha)
        ok = bootstrap.ensure_golang(msgs.append, dry=False)
        return ok, msgs

    def test_the_line_is_version_and_platform(self, monkeypatch):
        _ok, msgs = self._run(monkeypatch)
        line = next(m for m in msgs if "installing Go" in m)
        assert re.fullmatch(r"  installing Go \d+\.\d+(\.\d+)? \w+/\w+", line), line

    def test_the_recited_guarantees_are_gone(self, monkeypatch):
        _ok, msgs = self._run(monkeypatch)
        joined = " ".join(msgs)
        for noise in ("declared version", "sha256-verified", "min "):
            assert noise not in joined, joined

    def test_the_outcome_line_is_unchanged(self, monkeypatch):
        ok, msgs = self._run(monkeypatch)
        assert ok and "  go install: ok" in msgs

    def test_a_FAILURE_still_says_why(self, monkeypatch):
        ok, msgs = self._run(monkeypatch, code=1, tail="sha256sum: WARNING: 1 computed checksum did NOT match")
        assert ok is False
        assert any("go install: FAILED" in m and "did NOT match" in m for m in msgs), msgs

    def test_an_UNPINNED_archive_still_refuses_loudly(self, monkeypatch):
        """The guarantee is enforced by the code, not by the sentence — and when it bites, it speaks."""
        ok, msgs = self._run(monkeypatch, sha_ok=False)
        assert ok is False
        assert any("not pinned" in m and "UNVERIFIED" in m for m in msgs), msgs
        assert not any("installing Go" in m for m in msgs), "it must not claim to install anything"


class TestTheToolsSectionIsOneLinePerTool:
    """Lumpy, 2026-08-07: `nmap present + verified (distro) ✓` read as work happening twice — apt
    provisions it in [1/6], and the tools section then restated its own premise for every tool that was
    already there. The ✓ IS "present and verified"."""

    @staticmethod
    def _install(monkeypatch, verified=lambda t: True):
        from click.testing import CliRunner
        from quarry_recon import bootstrap, cli
        tools = [t for t in cli.load_tools() if t.bin in ("nmap", "dalfox")]
        monkeypatch.setattr(cli, "load_tools", lambda: tools)
        monkeypatch.setattr(cli, "verify_installed", verified)
        monkeypatch.setattr(Tool, "installed", property(lambda self: True))
        monkeypatch.setattr(cli, "_run_tool", lambda t, m, d: True)
        for fn in ("install_system_packages", "ensure_golang", "install_data_files", "run_extras",
                   "cleanup"):
            monkeypatch.setattr(bootstrap, fn, lambda *a, **k: True)
        monkeypatch.setattr(bootstrap, "system_report",
                            lambda ctx="install": {"level": "ok", "checks": []})
        return CliRunner().invoke(cli.install, ["--include-optional"]).output

    def test_a_present_tool_is_name_and_a_tick(self, monkeypatch):
        out = self._install(monkeypatch)
        assert "→ nmap ✓" in out and "→ dalfox ✓" in out, out
        assert "present + verified" not in out and "(distro)" not in out

    def test_a_tool_that_FAILS_verification_still_says_so(self, monkeypatch):
        """The quiet line is for the boring case only; the loud one is untouched."""
        out = self._install(monkeypatch, verified=lambda t: t.bin != "dalfox")
        assert "dalfox present but FAILED verification — reinstalling pin" in out, out
        assert "→ nmap ✓" in out

    def test_doctor_still_carries_the_detail(self, monkeypatch):
        """Lumpy: "in quarry doctor, we can keep the list as is" — the version and the distro tag live
        THERE, which is where an operator goes to ask what is installed. Asserted through the renderer
        doctor uses, not through the source of the command."""
        from quarry_recon import cli
        t = next(x for x in registry.load_tools() if x.bin == "nmap")
        monkeypatch.setattr(Tool, "version", lambda self: "")
        assert "distro" in cli._doctor_version(t, "distro")
        monkeypatch.setattr(Tool, "version", lambda self: "7.95")
        assert cli._doctor_version(t, "distro") == "7.95", "…and its real banner when it has one"


class TestTheSecretsBlockSaysTheKeysSTATE:
    """Lumpy, 2026-08-07: every key here is optional, so "(optional)" on every row said nothing — and
    certspotter carried a sentence about its free tier that belongs in the docs. A row now says one of
    three things: not set · set · malformed."""

    @staticmethod
    def _block(monkeypatch, **keys):
        from click.testing import CliRunner
        from quarry_recon import cli, secrets
        monkeypatch.setattr(secrets, "github_tokens", lambda: keys.get("github", []))
        for k in ("shodan", "whoxy", "chaos", "certspotter"):
            monkeypatch.setattr(secrets, k, lambda k=k: keys.get(k) or None)
        monkeypatch.setattr(cli, "load_tools", lambda *a, **k: [])
        monkeypatch.setattr(cli, "tools_by_phase", lambda *a, **k: [])
        out = CliRunner().invoke(cli.doctor, []).output
        return out[out.index("[secrets]"):out.index("[config]")]

    def test_the_optional_noise_is_gone(self, monkeypatch):
        blk = self._block(monkeypatch)
        assert "(optional)" not in blk and "free tier keyless" not in blk, blk
        assert "· shodan" in blk and "not set" in blk

    def test_a_well_shaped_key_is_a_tick_with_nothing_after_it(self, monkeypatch):
        blk = self._block(monkeypatch, shodan="Z" * 32)
        line = next(l for l in blk.splitlines() if "shodan" in l)
        assert line.strip().endswith("shodan"), line

    def test_github_still_counts_its_tokens(self, monkeypatch):
        blk = self._block(monkeypatch, github=["ghp_" + "a" * 36, "b" * 40])
        assert "2 token(s)" in blk, blk

    def test_a_MALFORMED_key_is_named_as_such(self, monkeypatch):
        """"wrong shape" already says it was not tested; the explanation was longer than the fact."""
        blk = self._block(monkeypatch, shodan="nope")
        line = next(l for l in blk.splitlines() if "shodan" in l)
        assert line.strip() == "✗ shodan                   wrong shape for this provider", repr(line)

    def test_one_bad_token_among_several_is_counted(self, monkeypatch):
        blk = self._block(monkeypatch, github=["ghp_" + "a" * 36, "not a token"])
        assert "1 of 2 wrong shape for this provider" in blk, blk

    def test_a_provider_whose_format_we_do_NOT_know_is_never_called_malformed(self, monkeypatch):
        """Inventing a shape would reject a perfectly good key. `whoxy` has no documented pattern here,
        so a set key is simply set."""
        blk = self._block(monkeypatch, whoxy="whatever-they-issue-42")
        assert "✓" in blk and "wrong shape" not in blk, blk

    def test_the_KEY_ITSELF_is_never_printed(self, monkeypatch):
        blk = self._block(monkeypatch, shodan="Z" * 32, whoxy="wx-SECRET-VALUE",
                          github=["ghp_" + "a" * 36])
        for v in ("Z" * 32, "wx-SECRET-VALUE", "ghp_" + "a" * 36):
            assert v not in blk, blk

    def test_the_check_is_LOCAL_and_never_a_request(self, monkeypatch):
        """"not by pinging, and accidentally create costs" — the whole point."""
        import inspect
        from quarry_recon import secrets
        src = inspect.getsource(secrets.key_shape) + inspect.getsource(secrets)[:0]
        assert "requests" not in src and "urlopen" not in src and "http" not in src.lower()


class TestTheLocalKeyShapeCheck:
    def test_documented_shapes_are_accepted(self):
        from quarry_recon.secrets import key_shape
        assert key_shape("shodan", "A" * 32) == "ok"
        assert key_shape("github", "ghp_" + "a" * 36) == "ok"
        assert key_shape("github", "github_pat_" + "a" * 30) == "ok"
        assert key_shape("github", "f" * 40) == "ok", "the pre-2021 40-hex tokens still exist"

    def test_a_wrong_shape_for_a_KNOWN_provider_is_malformed(self):
        from quarry_recon.secrets import key_shape
        assert key_shape("shodan", "A" * 31) == "malformed"
        assert key_shape("github", "ghp_short") == "malformed"

    def test_an_UNKNOWN_provider_never_gets_a_verdict_on_its_pattern(self):
        from quarry_recon.secrets import key_shape
        assert key_shape("whoxy", "anything-they-issue") == "unknown"
        assert key_shape("certspotter", "some_token_value") == "unknown"

    def test_placeholders_and_whitespace_are_malformed_for_EVERY_provider(self):
        """These are never a key, whatever the provider's format is."""
        from quarry_recon.secrets import key_shape
        for bad in ("<your-token>", "changeme", "xxx", "TODO", "has space", 'has"quote', " padded "):
            assert key_shape("whoxy", bad) == "malformed", bad

    def test_an_EMPTY_value_is_not_a_complaint(self):
        from quarry_recon.secrets import key_shape
        assert key_shape("shodan", "") == "unknown" and key_shape("shodan", None) == "unknown"
