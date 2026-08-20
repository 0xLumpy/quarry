"""Focused authenticated prior-byte seeding for file-native outputs."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from quarry_recon import store
from quarry_recon.runner_native import RepositoryNativeOutput, prepare_native_outputs


pytestmark = pytest.mark.offline


def _run(tmp_path: Path) -> store.Run:
    run = store.Run.create(tmp_path, "acme.example", run_id="native-file-prior")
    run.write_state("running")
    return run


def _command(path: Path) -> tuple[str, ...]:
    return ("fixture", "--output", "unused", str(path))


def test_file_seed_prior_copies_authenticated_committed_bytes_into_private_attempt(tmp_path):
    run = _run(tmp_path)
    components = ("raw", "oob", "interactsh-session.json")
    final = run.dir.joinpath(*components)
    initial = RepositoryNativeOutput.file(3, *components)

    first = prepare_native_outputs(run, _command(final), (initial,))
    Path(first.rewritten_cmd[3]).write_bytes(b'{"session":"prior"}\n')
    assert first.finish(clean=True).clean

    seeded = RepositoryNativeOutput.file(3, *components, seed_prior=True)
    second = prepare_native_outputs(run, _command(final), (seeded,))
    staged = Path(second.rewritten_cmd[3])
    expected = b'{"session":"prior"}\n'
    assert staged.read_bytes() == expected
    assert staged.parent != final.parent

    with staged.open("ab") as handle:
        handle.write(b'{"session":"current"}\n')
    receipt = second.finish(clean=True)

    expected += b'{"session":"current"}\n'
    assert receipt.clean
    assert final.read_bytes() == expected
    assert receipt.committed[0].sha256 == hashlib.sha256(expected).hexdigest()
