"""Descriptor-based private filesystem helpers: dirs 0700, files 0600 at creation, every component opened
O_NOFOLLOW through a directory fd so no symlinked level can redirect a write outside the tree."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def _harden_fd(fd: int, *, is_dir: bool) -> bool:
    """True iff `fd` ends up owned by us with no group/other bits, tightening it if loose; else False."""
    try:
        st = os.fstat(fd)
    except OSError:
        return False
    if st.st_uid != os.geteuid():
        return False
    if stat.S_IMODE(st.st_mode) & 0o077:
        try:
            os.fchmod(fd, DIR_MODE if is_dir else FILE_MODE)
        except OSError:
            return False
        return not (stat.S_IMODE(os.fstat(fd).st_mode) & 0o077)
    return True


def _walk_dirfd(directory) -> int:
    """A fd for `directory`, creating missing levels 0700 and refusing a symlinked component (O_NOFOLLOW);
    an existing loose leaf is tightened, ancestors left alone. Caller owns the fd."""
    directory = Path(directory)
    parts = directory.parts
    if directory.is_absolute():
        dfd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        rest = parts[1:]
    else:
        dfd = os.open(os.getcwd(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        rest = parts
    try:
        created = True
        for comp in rest:
            try:
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                created = False
            except FileNotFoundError:
                try:
                    os.mkdir(comp, DIR_MODE, dir_fd=dfd)
                    created = True
                except FileExistsError:
                    created = False          # a concurrent walker made it; adopt and harden it below
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
            os.close(dfd)
            dfd = nfd
        if not created and not _harden_fd(dfd, is_dir=True):
            raise OSError(f"cannot make {directory} private (foreign owner or fchmod failed)")
        return dfd
    except BaseException:
        os.close(dfd)
        raise


def private_dir(path) -> Path:
    """Create `path` and missing parents 0700, refusing a symlinked component; tighten the leaf if loose."""
    os.close(_walk_dirfd(path))
    return Path(path)


def open_private(path, *, append: bool = False) -> int:
    """A 0600 write fd owned by us or it raises; O_NOFOLLOW/O_NONBLOCK in a symlink-safe 0700 parent, truncates
    unless `append`."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    try:
        # no O_TRUNC yet: validate the target before destroying any existing content
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_APPEND if append else 0)
        fd = os.open(path.name, flags, FILE_MODE, dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or not _harden_fd(fd, is_dir=False):
            raise OSError(f"refusing a non-regular or non-private target: {path}")
        if not append:
            os.ftruncate(fd, 0)          # truncate only after ownership/mode/type are verified
    except BaseException:
        os.close(fd)
        raise
    return fd


def write_private(path, text: str, *, encoding: str = "utf-8") -> None:
    """Atomically replace `path` with 0600 content via an exclusive random-named same-dir temp (O_EXCL|O_NOFOLLOW
    refuses a planted symlink, hard link or reused name), then rename inside the parent dir fd."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    tmp = f".{path.name}.{os.urandom(8).hex()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=dfd)
        try:
            with os.fdopen(fd, "w", encoding=encoding) as fh:
                fh.write(text)
            os.replace(tmp, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(dfd)


def append_private(path, text: str, *, encoding: str = "utf-8") -> None:
    """Append to `path`, creating it 0600 (and tightening an existing loose file) in a symlink-safe parent."""
    with os.fdopen(open_private(path, append=True), "a", encoding=encoding) as fh:
        fh.write(text)


def touch_private(path) -> Path:
    """Ensure `path` exists as a 0600 regular file owned by us in a 0700 parent, or raise. Tightens a
    pre-existing loose file; refuses a symlink, FIFO/device, or another user's file."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    try:
        try:
            os.close(os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=dfd))
        except FileExistsError:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode) or not _harden_fd(fd, is_dir=False):
                    raise OSError(f"refusing a non-regular or non-private target: {path}")
            finally:
                os.close(fd)
    finally:
        os.close(dfd)
    return path


def open_ro_private(path) -> int:
    """A read fd for a regular file owned by us, opened through a symlink-safe parent dir-fd walk (O_NOFOLLOW at
    every level) so no swapped component can redirect the read; raises otherwise. Caller owns the fd."""
    path = Path(path)
    dfd = _walk_dirfd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or not _harden_fd(fd, is_dir=False):
            raise OSError(f"refusing a non-regular or non-private file: {path}")   # never accept a loose file
    except BaseException:
        os.close(fd)
        raise
    return fd


def is_private(path) -> bool:
    """Whether `path` is a regular file or directory owned by us with no group/other bits (never a symlink,
    FIFO, socket or device)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return False
    return st.st_uid == os.geteuid() and not (stat.S_IMODE(st.st_mode) & 0o077)


def harden(path) -> bool:
    """Tighten an owned, too-loose regular file or directory to the private mode; refuse a symlink, another
    user's path, or a non-regular non-directory (FIFO/socket/device). Returns whether it ends up private."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if st.st_uid != os.geteuid() or stat.S_ISLNK(st.st_mode):
        return False
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return False
    if stat.S_IMODE(st.st_mode) & 0o077:
        try:
            os.chmod(path, DIR_MODE if stat.S_ISDIR(st.st_mode) else FILE_MODE, follow_symlinks=False)
        except OSError:
            return False
    return True


def write_json_private(path, obj, *, indent=None) -> None:
    write_private(path, json.dumps(obj, ensure_ascii=False, indent=indent))
