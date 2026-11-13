"""Logging, deferred warnings, and the error type every command raises.

Stdout is data, stderr is people: all logging goes to stderr. Warnings that
matter after the run are collected and printed after the main output.
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict

log = logging.getLogger("lambdatools")

# Wire-level loggers can dump full API responses, which include Lambda
# environment variable values. They stay at WARNING even under -v.
_QUIET_LOGGERS = ("botocore", "boto3", "s3transfer", "urllib3")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class ToolError(Exception):
    """A failure with a message the user can act on."""

    def __init__(self, message: str, exit_code: int = EXIT_ERROR):
        super().__init__(message)
        self.exit_code = exit_code


class DeferredWarnings:
    """Warnings grouped per scope, printed after the main output."""

    def __init__(self) -> None:
        self._items: dict[str, list[str]] = defaultdict(list)

    def add(self, scope: str, message: str) -> None:
        if message not in self._items[scope]:
            self._items[scope].append(message)
        log.debug("warning [%s]: %s", scope, message)

    def __len__(self) -> int:
        return sum(len(v) for v in self._items.values())

    def flush(self, stream=None) -> None:
        stream = stream or sys.stderr
        for scope, messages in self._items.items():
            stream.write(f"\nWarnings for {scope} ({len(messages)}):\n")
            for message in messages:
                stream.write(f"  - {message}\n")
        self._items.clear()


WARNINGS = DeferredWarnings()


def setup(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def mode_prefix(execute: bool) -> str:
    return "[EXECUTE]" if execute else "[DRY-RUN]"
