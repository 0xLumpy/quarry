"""`secrets.oob()` must fail closed: an auth_token without a callback_server would be sent to the public
Interactsh backend, so it is dropped."""
import pytest

pytestmark = pytest.mark.offline


def test_auth_token_dropped_without_callback_server(monkeypatch):
    from quarry_recon import secrets
    monkeypatch.setattr(secrets, "load", lambda: {"oob": {"auth_token": "secret-token"}})
    assert secrets.oob() == {}, "auth_token must be dropped when no callback_server is configured"


def test_auth_token_kept_with_callback_server(monkeypatch):
    from quarry_recon import secrets
    cfg = {"callback_server": "oob.example.com", "auth_token": "secret-token"}
    monkeypatch.setattr(secrets, "load", lambda: {"oob": cfg})
    assert secrets.oob() == cfg, "auth_token must be kept when a server we control is configured"


@pytest.mark.parametrize("server", [" ", "https://", "://", ",", "  ,  ", ".", "...", "https://.", "https://./x"])
def test_auth_token_dropped_when_server_normalizes_to_no_host(monkeypatch, server):
    from quarry_recon import secrets
    monkeypatch.setattr(secrets, "load", lambda: {"oob": {"callback_server": server, "auth_token": "t"}})
    assert "auth_token" not in secrets.oob(), f"empty-host server {server!r} must still drop the token"


# --- resume_session must couple the CURRENT token to the SAVED session's server ---

def test_resume_public_saved_session_never_reuses_current_token():
    from quarry_recon.oob import _resume_token
    # saved session was public (no server); operator later set a private server+token.
    assert _resume_token(None, "oob.private.example", "PRIV") is None
    assert _resume_token("", "oob.private.example", "PRIV") is None
    assert _resume_token(".", "oob.private.example", "PRIV") is None   # saved normalizes to no host


def test_resume_selfhosted_reuses_token_only_on_matching_server():
    from quarry_recon.oob import _resume_token
    assert _resume_token("oob.example.com", "https://oob.example.com:443/x", "T") == "T"   # same host
    assert _resume_token("oob.example.com", "oob.OTHER.com", "T") is None                  # changed server
    assert _resume_token("oob.example.com", None, "T") is None                             # no current server
    assert _resume_token("oob.example.com", "oob.example.com", None) is None               # no token


def _resume_argv(monkeypatch, saved_server, current_server, token):
    """Build one managed resume window and return its secret-free argv."""
    from quarry_recon import oob
    from types import SimpleNamespace
    from pathlib import Path
    captured = {}

    def execute(_tool, cmd, **_kwargs):
        captured["cmd"] = list(cmd)
        return SimpleNamespace(
            status=oob.runner.Status.EMPTY,
            meta={"deadline_sigint": True},
        )

    monkeypatch.setattr(oob.runner, "run", execute)
    effective = oob._resume_token(saved_server, current_server, token)
    monkeypatch.setattr(oob.secrets, "values", lambda: [effective] if effective else [])
    result = oob._run_client_window(
        object(), log=Path("/tmp/i.jsonl"), session_file=Path("/tmp/s.session"),
        server=saved_server, token=effective, wait=0, seed_prior=True,
        managed_outputs=False,
    )
    assert result is not None
    return captured["cmd"]


def test_resume_session_argv_public_saved_sends_no_token(monkeypatch):
    cmd = _resume_argv(monkeypatch, saved_server=None, current_server="oob.private.example", token="PRIV")
    assert "-server" not in cmd and "-token" not in cmd and "PRIV" not in cmd


def test_resume_session_argv_matching_server_sends_both(monkeypatch):
    token = "PRIVATE-TOKEN"
    cmd = _resume_argv(
        monkeypatch, "oob.example.com", "https://oob.example.com/x", token,
    )
    assert "-server" in cmd and "oob.example.com" in cmd and "-config" in cmd
    assert "-token" not in cmd and token not in cmd


def test_resume_session_argv_changed_server_keeps_server_drops_token(monkeypatch):
    token = "PRIVATE-TOKEN"
    cmd = _resume_argv(monkeypatch, "oob.example.com", "oob.other.com", token)
    assert ("-server" in cmd and "oob.example.com" in cmd
            and "-token" not in cmd and token not in cmd)


def test_managed_window_refuses_an_unregistered_token_before_launch(monkeypatch):
    from pathlib import Path
    from quarry_recon import oob

    monkeypatch.setattr(oob.secrets, "values", lambda: [])
    monkeypatch.setattr(
        oob.runner, "run",
        lambda *_args, **_kwargs: pytest.fail("unregistered token reached the runner"),
    )
    with pytest.raises(oob.ContractError, match="active private credential"):
        oob._run_client_window(
            object(), log=Path("/tmp/log"), session_file=Path("/tmp/session"),
            server="oob.example.com", token="PRIVATE-TOKEN", wait=1,
            seed_prior=False, managed_outputs=False,
        )
