"""Version parsing and ordering for PyPI (PEP 440) and npm (SemVer)."""

from __future__ import annotations

import re
from datetime import date
from functools import total_ordering

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class SemVer:
    def __init__(self, text: str):
        m = _SEMVER.match(text.strip())
        if not m:
            raise ValueError(f"invalid semver: {text!r}")
        self.text = text
        self.core = tuple(int(x) for x in m.group(1, 2, 3))
        pre = m.group(4)
        self.pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ()

    def _key(self):
        # A release sorts after any of its prereleases.
        return (self.core, 0 if self.pre else 1, self.pre)

    def __eq__(self, other):
        return isinstance(other, SemVer) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    def __str__(self):
        return self.text


def parse(ecosystem: str, text: str):
    """Return a comparable version, or None if text does not parse."""
    try:
        return Version(text) if ecosystem == "PyPI" else SemVer(text)
    except (InvalidVersion, ValueError):
        return None


def max_version(ecosystem: str, versions: list[str]) -> str | None:
    parsed = [(parse(ecosystem, v), v) for v in versions]
    parsed = [p for p in parsed if p[0] is not None]
    return max(parsed, key=lambda p: p[0])[1] if parsed else None


def bump(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"unknown bump part: {part}")


def release_greater(new: str, old: str) -> bool:
    return SemVer(new) > SemVer(old)


# Date versions: YYYY.MM.DD, plus .N for the Nth extra build on the same day.
DATE_RE = re.compile(r"^(20\d{2})\.(\d{2})\.(\d{2})(?:\.([1-9]\d*))?$")


def is_date_version(version: str) -> bool:
    m = DATE_RE.match(version)
    if not m:
        return False
    try:
        date(int(m[1]), int(m[2]), int(m[3]))
    except ValueError:
        return False
    return True


def numeric_key(version: str) -> tuple[int, ...]:
    """Order X.Y.Z and YYYY.MM.DD[.N] numerically, so moving from SemVer to dates sorts forward."""
    parts = [int(p) for p in version.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def next_date_version(current: str, today: date) -> str:
    """Today's date as YYYY.MM.DD, or YYYY.MM.DD.N when current is already from today."""
    base = today.strftime("%Y.%m.%d")
    if is_date_version(current) and current.split(".")[:3] == base.split("."):
        counter = int(current.split(".")[3]) if current.count(".") == 3 else 0
        return f"{base}.{counter + 1}"
    if numeric_key(current) >= numeric_key(base):
        raise ValueError(f"the current version {current} is not earlier than today's date {base} (UTC)")
    return base
