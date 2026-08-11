"""Opaque identities used as repository path segments.

Run and campaign identifiers are data, not paths.  Keep their grammar in one
module so every repository reader and writer makes the same containment
decision before joining an identifier to a managed root.
"""
from __future__ import annotations

import re
import unicodedata

from .state import ContractError


OPAQUE_ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
OPAQUE_ID_RULE = ("one ASCII segment of letters, digits, '.', '-' or '_' starting with a letter or "
                  "digit, at most 64 characters")
RUN_RESERVED_IDS = frozenset({"state", "campaigns"})

_OPAQUE_ID = re.compile(OPAQUE_ID_PATTERN, re.ASCII)


def _display(name) -> str:
    """Bounded diagnostic text without invoking hooks on a rejected object."""
    if type(name) is str:
        value = name if len(name) <= 96 else name[:93] + "..."
        return repr(value)
    return f"<{type(name).__name__}>"


class InvalidRepositoryId(ContractError):
    """An identifier cannot safely name one object below a repository root."""


class InvalidCampaignId(InvalidRepositoryId):
    """A campaign id is not one confined opaque path segment."""


class InvalidRunId(InvalidRepositoryId):
    """A run id is not one confined, non-reserved opaque path segment."""


class InvalidArtifactComponent(InvalidRepositoryId):
    """One artifact path component is unsafe or not portable within the repository."""


def valid_segment(name) -> bool:
    """Whether *name* obeys the shared opaque ASCII segment grammar."""
    # Exact built-in strings only: validation must not execute an untrusted
    # ``str`` subclass' equality/hash hooks when checking reserved names.
    return type(name) is str and _OPAQUE_ID.fullmatch(name) is not None


def valid_campaign_id(campaign_id) -> bool:
    return valid_segment(campaign_id) and campaign_id not in RUN_RESERVED_IDS


def valid_run_id(run_id) -> bool:
    return valid_segment(run_id) and run_id not in RUN_RESERVED_IDS


def validate_campaign_id(campaign_id: str) -> str:
    """Return a safe campaign id, or refuse before any path is constructed."""
    if not valid_campaign_id(campaign_id):
        reserved = (f"; reserved repository ids: {', '.join(sorted(RUN_RESERVED_IDS))}"
                    if type(campaign_id) is str and campaign_id in RUN_RESERVED_IDS else "")
        raise InvalidCampaignId(f"{_display(campaign_id)} is not a campaign id: {OPAQUE_ID_RULE}{reserved}")
    return campaign_id


def validate_run_id(run_id: str) -> str:
    """Return a safe run id, refusing repository namespaces as well as invalid segments."""
    if not valid_run_id(run_id):
        reserved = (f"; reserved run ids: {', '.join(sorted(RUN_RESERVED_IDS))}"
                    if type(run_id) is str and run_id in RUN_RESERVED_IDS else "")
        raise InvalidRunId(f"{_display(run_id)} is not a run id: {OPAQUE_ID_RULE}{reserved}")
    return run_id


def validate_artifact_component(value: str, label: str = "artifact component") -> str:
    """Return one safe filesystem component, refusing before it participates in a path.

    Artifact names need a wider vocabulary than opaque run IDs (IPv6 colons and human-readable spaces
    are legitimate), but never routes, controls, surrogate code points, or names beyond the portable
    single-component byte ceiling.
    """
    valid = type(value) is str and value not in ("", ".", "..") and "/" not in value and "\\" not in value
    if valid:
        valid = all(not unicodedata.category(char).startswith("C") for char in value)
    if valid:
        try:
            valid = len(value.encode("utf-8")) <= 255
        except UnicodeEncodeError:
            valid = False
    if not valid:
        raise InvalidArtifactComponent(
            f"{label} {_display(value)} must be one non-empty component without separators or controls "
            "and at most 255 UTF-8 bytes")
    return value
