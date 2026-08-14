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
    """Drive resume_session() end-to-end with a mocked Popen and return the argv it built."""
    from quarry_recon import oob
    captured = {}

    class _FakeProc:
        stdout = None

    def _fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(oob.shutil, "which", lambda _b: "/usr/bin/interactsh-client")
    monkeypatch.setattr(
        oob, "_prepare_client_launch",
        lambda _run, command, **_kwargs: (list(command), {}),
    )
    monkeypatch.setattr(oob, "load_session", lambda _run: {
        "session_file": "/tmp/s.session", "log": "/tmp/i.jsonl", "server": saved_server, "domain": "D.oast.pro"})
    monkeypatch.setattr(oob.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(oob, "_await_register", lambda _p, _s, _w: ("D.oast.pro", "uid"))
    monkeypatch.setattr(oob.runner, "terminate_group", lambda _p: None)
    resumed = oob.resume_session(object(), token=token, server=current_server, wait=0)
    assert resumed is not None
    oob.close_session(resumed[1])
    return captured["cmd"]


def test_resume_session_argv_public_saved_sends_no_token(monkeypatch):
    cmd = _resume_argv(monkeypatch, saved_server=None, current_server="oob.private.example", token="PRIV")
    assert "-server" not in cmd and "-token" not in cmd and "PRIV" not in cmd


def test_resume_session_argv_matching_server_sends_both(monkeypatch):
    cmd = _resume_argv(monkeypatch, "oob.example.com", "https://oob.example.com/x", "T")
    assert "-server" in cmd and "oob.example.com" in cmd and "-config" in cmd
    assert "-token" not in cmd and "T" not in cmd


def test_resume_session_argv_changed_server_keeps_server_drops_token(monkeypatch):
    cmd = _resume_argv(monkeypatch, "oob.example.com", "oob.other.com", "T")
    assert "-server" in cmd and "oob.example.com" in cmd and "-token" not in cmd and "T" not in cmd
