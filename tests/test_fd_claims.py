"""Focused contracts for the dependency-leaf descriptor claim machinery."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from quarry_recon import _fd_claims


pytestmark = pytest.mark.offline


class _InvalidClaim(Exception):
    pass


def _new_claim(*, fd: int = -1):
    return _fd_claims.new_claim(
        fd,
        (11, 13),
        "writer",
        ("secret-stage",),
        allowed_kinds=frozenset({"writer"}),
        invalid_error=_InvalidClaim,
    )


def test_fd_claims_remains_a_dependency_leaf():
    source = Path(_fd_claims.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module is not None
            imported_roots.add(node.module.partition(".")[0])

    assert imported_roots <= {"__future__", "collections", "errno", "threading"}


def test_claim_is_read_only_and_repr_discloses_no_authority():
    claim = _new_claim(fd=987654)

    rendered = repr(claim)
    assert rendered == "PrivateDescriptorClaim(kind='writer', disposition='pending')"
    assert "987654" not in rendered
    assert "secret-stage" not in rendered
    assert "11" not in rendered and "13" not in rendered
    with pytest.raises(AttributeError):
        claim._fd = 1
    with pytest.raises(AttributeError):
        del claim._fd


def test_populate_replay_rejects_before_allocation_without_mutating_claim():
    claim = _new_claim()
    observed = object()
    options = {
        "allow_unlinked": False,
        "fstat": lambda fd: observed,
        "identity_of": lambda value: (11, 13),
        "validate_metadata": lambda candidate, value, allow_unlinked: None,
        "make_identity_error": lambda components: AssertionError(components),
        "record_claim_error": _fd_claims.record_error,
        "invalid_error": _InvalidClaim,
    }
    _fd_claims.populate_claim(claim, lambda: 37, **options)
    before = tuple(
        object.__getattribute__(claim, field)
        for field in (
            "_fd", "_owned_identity", "_disposition", "_close_attempts",
            "_errors", "_dropped_error_count", "_metadata_fault",
        )
    )
    allocation_calls = []

    with pytest.raises(_InvalidClaim):
        _fd_claims.populate_claim(
            claim,
            lambda: allocation_calls.append(True) or 41,
            **options,
        )

    after = tuple(
        object.__getattribute__(claim, field)
        for field in (
            "_fd", "_owned_identity", "_disposition", "_close_attempts",
            "_errors", "_dropped_error_count", "_metadata_fault",
        )
    )
    assert allocation_calls == []
    assert after == before


def test_claim_error_journal_is_bounded_and_drop_count_saturates():
    claim = _new_claim(fd=43)
    faults = tuple(RuntimeError(f"fault-{index}") for index in range(6))

    for fault in faults:
        _fd_claims.record_error(claim, fault)

    assert claim.errors == faults[:_fd_claims.MAX_CLAIM_ERRORS]
    assert object.__getattribute__(claim, "_dropped_error_count") == 4
    object.__setattr__(
        claim, "_dropped_error_count", _fd_claims.MAX_DROPPED_ERRORS,
    )
    _fd_claims.record_error(claim, RuntimeError("beyond saturation"))
    assert (
        object.__getattribute__(claim, "_dropped_error_count")
        == _fd_claims.MAX_DROPPED_ERRORS
    )


def test_drain_never_exceeds_two_close_starts_over_claim_lifetime():
    claim = _new_claim(fd=47)
    observed = object()
    close_calls = []

    def close_stays_exact_live(fd):
        close_calls.append(fd)
        return OSError("close remained exact-live")

    options = {
        "allow_unlinked": True,
        "inspect": lambda candidate, *, allow_unlinked: observed,
        "close_owned": close_stays_exact_live,
        "fstat": lambda fd: observed,
        "identity_of": lambda value: (11, 13),
        "make_close_identity_error": lambda components: AssertionError(components),
        "record_claim_error": _fd_claims.record_error,
    }

    first_errors = _fd_claims.drain_claim(claim, **options)
    replay_errors = _fd_claims.drain_claim(claim, **options)

    assert close_calls == [47, 47]
    assert first_errors == claim.errors
    assert replay_errors == ()
    assert claim.fd == 47
    assert claim.disposition == "close_started"
    assert object.__getattribute__(claim, "_close_attempts") == 2
    assert claim.disposition not in _fd_claims.TERMINAL_DISPOSITIONS
