"""File helpers: atomic, reversible writes and safe output locations."""

from __future__ import annotations

import difflib
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from lambdatools.common.log import ToolError, log


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def data_dir() -> Path:
    """Per-user data directory (XDG on Unix, LOCALAPPDATA on Windows)."""
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "lambda-tools"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "lambda-tools"


def ensure_private_dir(path: Path) -> Path:
    """Create path; every directory created here (parents included) is 0700."""
    created, probe = [], path
    while not probe.exists():
        created.append(probe)
        probe = probe.parent
    for d in reversed(created):
        d.mkdir(mode=0o700, exist_ok=True)
        if sys.platform != "win32":
            os.chmod(d, 0o700)
    if sys.platform != "win32":
        os.chmod(path, 0o700)
    return path


def unified_diff(old: str, new: str, name: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )


def _backup_copy(real: Path) -> Path:
    dest_dir = ensure_private_dir(data_dir() / "file-backups" / utc_stamp())
    dest = dest_dir / real.name
    n = 1
    while dest.exists():
        dest = dest_dir / f"{real.name}.{n}"
        n += 1
    shutil.copy2(real, dest)
    return dest


def _umask() -> int:
    current = os.umask(0)
    os.umask(current)
    return current


def new_file_mode(mode: int) -> int:
    """`mode` as the process umask allows it, as open() would apply it."""
    return mode & ~_umask()


def atomic_write(path: Path, content: str | bytes, *, backup: bool = True, mode: int = 0o644) -> Path | None:
    """Write via temp file + rename in the same directory.

    Writes through symlinks, keeps an existing file's mode, and copies the old
    file to the per-user backup directory first. Returns the backup path.
    """
    real = Path(os.path.realpath(path))
    data = content.encode() if isinstance(content, str) else content
    backup_path = None
    mode = new_file_mode(mode)
    if real.exists():
        mode = real.stat().st_mode & 0o7777
        if backup:
            backup_path = _backup_copy(real)
            log.info("Backed up %s to %s (restore: cp '%s' '%s')", path, backup_path, backup_path, real)
    real.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=real.parent, prefix=f".{real.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, real)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return backup_path


def create_exclusive(path: Path, content: bytes, mode: int = 0o644) -> None:
    """Atomically create path; fail if it already exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, new_file_mode(mode))
        try:
            os.link(tmp, path)
        except FileExistsError:
            raise ToolError(f"{path} already exists; refusing to overwrite it") from None
    finally:
        Path(tmp).unlink(missing_ok=True)


def git_toplevel(path: Path) -> Path | None:
    probe = path if path.is_dir() else path.parent
    while not probe.exists():
        probe = probe.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return Path(out.stdout.strip()) if out.returncode == 0 else None


def refuse_if_tracked_location(path: Path, what: str) -> None:
    """Refuse to write sensitive output inside a git work tree unless ignored."""
    top = git_toplevel(path)
    if top is None:
        return
    result = subprocess.run(
        ["git", "-C", str(top), "check-ignore", "-q", "--no-index", str(path.resolve())],
        capture_output=True, timeout=30,
    )
    if result.returncode != 0:
        raise ToolError(
            f"{what} location {path} is inside git work tree {top} and is not ignored; "
            f"add it to .gitignore or choose a location outside the repository"
        )


def git_info(path: Path) -> dict | None:
    top = git_toplevel(path)
    if top is None:
        return None
    head = subprocess.run(["git", "-C", str(top), "rev-parse", "HEAD"], capture_output=True, text=True)
    if head.returncode != 0:
        return {"commit": None, "dirty": True}
    status = subprocess.run(
        ["git", "-C", str(top), "status", "--porcelain", "--", str(path.resolve())],
        capture_output=True, text=True,
    )
    return {"commit": head.stdout.strip(), "dirty": bool(status.stdout.strip())}
