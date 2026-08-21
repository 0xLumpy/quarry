"""Bounded local H1 witness for the production archive download path."""
from __future__ import annotations

import gzip
import hashlib
import http.server
import io
import stat
import tarfile
import threading

import pytest

from quarry_recon import bootstrap


pytestmark = [pytest.mark.integration, pytest.mark.requires_tool("curl")]


def _archive() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in (("go", None), ("go/bin", None), ("go/bin/go", b"fixture\n")):
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            if body is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
    return gzip.compress(stream.getvalue())


def test_local_redirect_download_verifies_and_extracts_the_same_archive(tmp_path):
    body = _archive()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler API
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/archive")
                self.end_headers()
                return
            if self.path == "/archive":
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404)

        def log_message(self, _format, *_args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        downloaded = tmp_path / "go.tgz"
        code, detail = bootstrap._download_atomic(
            f"http://127.0.0.1:{server.server_port}/start",
            downloaded,
            False,
            timeout=5,
        )
        assert (code, detail) == (0, "")
        assert downloaded.read_bytes() == body
        assert not list(tmp_path.glob(".go.tgz.*.tmp"))

        extracted = tmp_path / "root"
        bootstrap._verify_and_extract(downloaded, hashlib.sha256(body).hexdigest(), extracted)
        executable = extracted / "go" / "bin" / "go"
        assert executable.read_bytes() == b"fixture\n"
        assert stat.S_IMODE(executable.stat().st_mode) == 0o755
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
