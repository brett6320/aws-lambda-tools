"""Run child build tools with their output kept off stdout."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from lambdatools.common.log import ToolError, log


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 1800, capture: bool = False) -> str:
    """Run cmd; its stdout goes to our stderr unless captured. Raise on failure."""
    log.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd, cwd=cwd, timeout=timeout, text=True,
            stdout=subprocess.PIPE if capture else sys.stderr,
            stderr=sys.stderr,
        )
    except FileNotFoundError:
        raise ToolError(f"{cmd[0]} not found; install it and retry") from None
    except subprocess.TimeoutExpired:
        raise ToolError(f"{cmd[0]} timed out after {timeout}s") from None
    if result.returncode != 0:
        raise ToolError(f"{' '.join(cmd[:3])} … exited with status {result.returncode}; see output above")
    return result.stdout or ""
