#!/usr/bin/env python3
"""Compare two candidate builds without hiding sdist timestamp metadata."""

from __future__ import annotations

import hashlib
import pathlib
import sys
import tarfile
from typing import Any


def _one(root: pathlib.Path, suffix: str) -> pathlib.Path:
    matches = sorted(root.glob(f"quarry_recon-*{suffix}"))
    if len(matches) != 1:
        raise ValueError(f"expected one {suffix} in {root}, found {len(matches)}")
    return matches[0]


def _digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _sdist_inventory(path: pathlib.Path) -> list[dict[str, Any]]:
    result = []
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"unsupported sdist member: {member.name}")
            body_digest = None
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"unreadable sdist member: {member.name}")
                body_digest = hashlib.sha256(extracted.read()).hexdigest()
            result.append({
                "digest": body_digest,
                "gid": member.gid,
                "gname": member.gname,
                "mode": member.mode,
                "name": member.name,
                "size": member.size,
                "type": "file" if member.isfile() else "directory",
                "uid": member.uid,
                "uname": member.uname,
            })
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: compare_builds.py DIST_A DIST_B", file=sys.stderr)
        return 2
    first, second = (pathlib.Path(value).resolve(strict=True) for value in argv[1:])
    wheel_a, wheel_b = _one(first, ".whl"), _one(second, ".whl")
    if _digest(wheel_a) != _digest(wheel_b):
        raise ValueError("fixed-epoch wheels are not byte-for-byte reproducible")
    sdist_a, sdist_b = _one(first, ".tar.gz"), _one(second, ".tar.gz")
    if _sdist_inventory(sdist_a) != _sdist_inventory(sdist_b):
        raise ValueError("sdist semantic inventories differ after ignoring mtimes")
    print("candidate builds agree: wheel bytes exact; sdist members exact except mtimes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
