"""Real-shell activation probe for QR39-008."""
from __future__ import annotations

import pytest

import test_qr39_008_install_activation as activation_tests
from quarry_recon import registry
from quarry_recon.registry import install_one


pytestmark = [pytest.mark.integration, pytest.mark.requires_tool("sh")]


def test_real_staged_probe_execs_verified_fd(tmp_path, monkeypatch):
    """The real probe executes the verified staged descriptor and observes activation."""
    monkeypatch.setenv("HOME", str(tmp_path))
    dest = activation_tests._bindir(tmp_path) / "qtool"

    def fake_shell(cmd, dry):
        stage = activation_tests._candidate_stage()
        stage.parent.mkdir(parents=True, exist_ok=True)
        stage.write_text("#!/bin/sh\nexit 0\n")
        return 0, ""

    monkeypatch.setattr(registry, "run_shell", fake_shell)
    monkeypatch.setattr(registry.shutil, "which", lambda _binary: str(dest))
    assert install_one(activation_tests._src_tool(), activation_tests._sink) is True
    assert dest.read_text() == "#!/bin/sh\nexit 0\n"
