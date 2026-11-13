"""Sanitize external values before they reach a terminal or a file."""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07?")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")

_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$", re.I)
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$")
_PATH_PART = re.compile(r"^[A-Za-z0-9._-]+$")


def clean(value: object, limit: int = 300) -> str:
    """Strip escape sequences and control characters; collapse to one line."""
    text = _ANSI.sub("", str(value))
    text = _CONTROL.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def valid_package_name(ecosystem: str, name: str) -> bool:
    pattern = _PYPI_NAME if ecosystem == "PyPI" else _NPM_NAME
    return bool(pattern.match(name)) and len(name) <= 214


def valid_version(version: str) -> bool:
    return bool(_VERSION.match(version))


def path_part(value: str) -> str:
    """Return value if it is safe as one path component, else raise."""
    if not _PATH_PART.match(value) or value in (".", ".."):
        raise ValueError(f"unsafe path component: {clean(value)!r}")
    return value
