"""Store secret values in the `pass` password store.

Values go to `pass` on stdin, never in argv. When `pass` is not installed or
its store is not initialized, callers redact. When it is set up but a write
fails, that is an error: values are never dropped silently.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from lambdatools.common.log import ToolError
from lambdatools.common.sanitize import path_part


def store_dir() -> Path:
    return Path(os.environ.get("PASSWORD_STORE_DIR") or Path.home() / ".password-store")


def availability() -> tuple[bool, str]:
    """(available, reason if not)."""
    if not shutil.which("pass"):
        return False, "`pass` is not installed"
    if not (store_dir() / ".gpg-id").exists():
        return False, f"password store at {store_dir()} is not initialized (`pass init <gpg-id>`)"
    return True, ""


def entry_path(*parts: str) -> str:
    return "/".join(path_part(p) for p in parts)


def insert(path: str, content: str) -> None:
    if (store_dir() / f"{path}.gpg").exists():
        raise ToolError(f"pass entry {path} already exists; refusing to overwrite it")
    try:
        result = subprocess.run(
            ["pass", "insert", "--multiline", path],
            input=content, capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ToolError(f"`pass insert {path}` failed: {e}") from None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["no output"]
        raise ToolError(f"`pass insert {path}` failed: {detail[0]}")
