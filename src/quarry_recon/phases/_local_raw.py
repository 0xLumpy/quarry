"""Repository authority for in-process phase artifacts.

Native tools publish through the runner.  A few phase implementations build
raw evidence themselves, so they need the same long-lived claim while reading
local input or contacting a provider and a repository-owned publication step
afterward.  Compatibility fakes may still expose ``raw_path``; a path that is
actually owned by a real Run is never allowed through that ambient fallback.
"""
from __future__ import annotations

import contextlib
import os
from contextlib import contextmanager
from pathlib import Path

from .. import store
from ..state import ContractError


def _components(phase: str, tool: str, name: str) -> tuple[str, ...]:
    return ("raw", phase, tool, name)


def destination(run, phase: str, tool: str, name: str) -> Path:
    """Return the final identity without materializing a managed Run path."""
    components = _components(phase, tool, name)
    if type(run) is store.Run:
        return run.dir.joinpath(*components)
    path = Path(run.raw_path(phase, tool, name))
    if store.managed_run_for_artifact(path) is not None:
        raise ContractError(
            "managed raw evidence requires the exact repository Run authority",
        )
    return path


@contextmanager
def lifecycle(run):
    """Hold a durable base claim before a local scan or provider contact."""
    if type(run) is store.Run:
        with run.artifact_claim():
            yield
        return
    with contextlib.nullcontext():
        yield


def replace_text(run, phase: str, tool: str, name: str, text: str) -> Path:
    """Durably replace one completed text artifact under repository authority."""
    if type(run) is store.Run:
        with text_writer(run, phase, tool, name) as (path, writer):
            writer.write(text)
        return path
    path = destination(run, phase, tool, name)
    path.write_text(text, encoding="utf-8")
    return path


@contextmanager
def text_writer(run, phase: str, tool: str, name: str):
    """Yield ``(final_identity, writer)`` backed by an unpublished private stage.

    On a real Run, the final name is published only after the caller returns
    normally and the writer has closed.  Every exception, including
    ``KeyboardInterrupt`` and ``SystemExit``, leaves the prior final untouched
    and lets the artifact-claim context fence the private stage.
    """
    components = _components(phase, tool, name)
    path = destination(run, phase, tool, name)
    if type(run) is not store.Run:
        with path.open("w", encoding="utf-8") as writer:
            yield path, writer
        return

    with run.artifact_claim(*components) as claim:
        writer_fd = claim.open_writer()
        try:
            writer = os.fdopen(writer_fd, "w", encoding="utf-8")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(writer_fd)
            raise
        with writer:
            yield path, writer
        claim.publish()
