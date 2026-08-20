"""A deliberately small, bounded out-of-scope hostname regex policy.

The engagement profile historically accepts regular expressions, while the
matched value is attacker-influenced DNS text.  CPython's backtracking engine
is safe here only after excluding grammar that can create an unbounded search
tree.  This module is the one acceptance point shared by profile matching, the
parent policy, and the serialized broker policy.

The admitted grammar is a sequence of literals, ``.``, character classes,
strict edge anchors, and at most one single-atom ``*``/``+``/``?`` repetition.
It covers Quarry's generated patterns and documented hostname exclusions while
excluding groups, alternation, lookaround, backreferences, counted/nested
repetition, and other constructs with surprising engine semantics.
"""
from __future__ import annotations

import functools
import re

from . import normalize


class OOSRegexError(ValueError):
    """An out-of-scope pattern is outside the bounded hostname grammar."""


_MAX_OOS_PATTERN_BYTES = 512
_allowed_escapes = frozenset(r".^$*+?{}[]()|\-" + "dDsSwW")


class BoundedOOSPattern:
    """Small Pattern-compatible wrapper that rejects oversized match input."""

    def __init__(self, pattern: str, compiled: re.Pattern[str]):
        self.pattern = pattern
        self.flags = compiled.flags
        self._compiled = compiled

    def search(self, host: str):
        # ScopeMatcher is fed discovered text from many passive parsers.  Do not
        # let an uncanonical/oversized value reach even the restricted engine.
        if (type(host) is not str or len(host) > 253 or not host.isascii()
                or normalize.canon_host_strict(host) != host):
            return None
        return self._compiled.search(host)


def _validate(pattern: str) -> None:
    if (type(pattern) is not str or not pattern or "\x00" in pattern
            or len(pattern.encode("ascii", "strict")) > _MAX_OOS_PATTERN_BYTES):
        raise OOSRegexError("out-of-scope pattern is outside its byte bound")

    repetitions = 0
    previous_atom = False
    index = 0
    while index < len(pattern):
        value = pattern[index]
        if value == "\\":
            index += 1
            if index >= len(pattern) or pattern[index] not in _allowed_escapes:
                raise OOSRegexError("out-of-scope pattern escape is not admitted")
            previous_atom = True
        elif value == "[":
            index += 1
            if index < len(pattern) and pattern[index] == "^":
                index += 1
            members = 0
            while index < len(pattern) and pattern[index] != "]":
                if pattern[index] == "\\":
                    index += 1
                    if index >= len(pattern) or pattern[index] not in _allowed_escapes:
                        raise OOSRegexError(
                            "out-of-scope character-class escape is not admitted",
                        )
                elif pattern[index] in "[\x00":
                    raise OOSRegexError("out-of-scope character class is invalid")
                members += 1
                index += 1
            if index >= len(pattern) or members == 0:
                raise OOSRegexError("out-of-scope character class is invalid")
            previous_atom = True
        elif value == "^":
            if index != 0:
                raise OOSRegexError("out-of-scope start anchor is not at the edge")
            previous_atom = False
        elif value == "$":
            if index != len(pattern) - 1:
                raise OOSRegexError("out-of-scope end anchor is not at the edge")
            previous_atom = False
        elif value in "*+?":
            if not previous_atom or repetitions:
                raise OOSRegexError("out-of-scope repetition is not linear")
            repetitions += 1
            previous_atom = False
        elif value in "(){}|":
            raise OOSRegexError("out-of-scope regex construct is not admitted")
        else:
            previous_atom = True
        index += 1


@functools.lru_cache(maxsize=2048)
def compile_oos(pattern: str) -> BoundedOOSPattern:
    """Validate and compile one bounded pattern with fixed case semantics."""
    try:
        _validate(pattern)
        compiled = re.compile(pattern, re.IGNORECASE | re.ASCII)
        return BoundedOOSPattern(pattern, compiled)
    except (UnicodeError, re.error) as exc:
        raise OOSRegexError("out-of-scope pattern is invalid") from exc


def oos_search(pattern: str, host: str) -> bool:
    """Search a canonical ASCII hostname using only the admitted grammar."""
    if (type(host) is not str or len(host) > 253 or not host.isascii()
            or normalize.canon_host_strict(host) != host):
        raise OOSRegexError("out-of-scope hostname is not canonical")
    return compile_oos(pattern).search(host) is not None


__all__ = (
    "BoundedOOSPattern", "OOSRegexError", "compile_oos", "oos_search",
)
