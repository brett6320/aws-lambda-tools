"""CHANGELOG.md maintenance (Keep a Changelog format).

The tool owns only the marked block inside [Unreleased]. On release, the
human-written Unreleased text and the tool block both move into the new
version section, and Unreleased starts empty again.
"""

from __future__ import annotations

import re

from lambdatools.common.log import ToolError

BEGIN = "<!-- BEGIN lambda-tools -->"
END = "<!-- END lambda-tools -->"
UNRELEASED_RE = re.compile(r"^## \[Unreleased\][^\n]*$", re.M)
SECTION_RE = re.compile(r"^## ", re.M)

SKELETON = f"""# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

{BEGIN}
{END}
"""


def _unreleased_bounds(text: str) -> tuple[int, int]:
    """Start (after heading line) and end offsets of the Unreleased body."""
    matches = list(UNRELEASED_RE.finditer(text))
    if len(matches) > 1:
        raise ToolError("CHANGELOG.md has more than one [Unreleased] heading; fix it by hand")
    if not matches:
        raise ToolError("CHANGELOG.md has no '## [Unreleased]' heading; add one")
    start = matches[0].end()
    nxt = SECTION_RE.search(text, start)
    return start, nxt.start() if nxt else len(text)


def _block(body: str) -> tuple[int, int] | None:
    """Offsets of the managed block (including markers) within body."""
    begins, ends = body.count(BEGIN), body.count(END)
    if begins == 0 and ends == 0:
        return None
    if begins != 1 or ends != 1 or body.index(BEGIN) > body.index(END):
        raise ToolError("CHANGELOG.md lambda-tools markers are unbalanced or duplicated; fix them by hand")
    return body.index(BEGIN), body.index(END) + len(END)


def _check_markers_outside(text: str, start: int, end: int) -> None:
    outside = text[:start] + text[end:]
    if BEGIN in outside or END in outside:
        raise ToolError("CHANGELOG.md has lambda-tools markers outside [Unreleased]; fix them by hand")


def add_unreleased(text: str | None, entries: list[str]) -> str:
    """Append bullet entries to the managed block in [Unreleased]."""
    text = text if text else SKELETON
    start, end = _unreleased_bounds(text)
    _check_markers_outside(text, start, end)
    body = text[start:end]
    bounds = _block(body)
    if bounds is None:
        body = body.rstrip("\n") + f"\n\n{BEGIN}\n{END}\n\n"
        bounds = _block(body)
    b0, b1 = bounds
    existing = [l for l in body[b0 + len(BEGIN):b1 - len(END)].splitlines() if l.strip()]
    for entry in entries:
        line = f"- {entry}"
        if line not in existing:
            existing.append(line)
    block = BEGIN + "\n" + "".join(l + "\n" for l in existing) + END
    return text[:start] + body[:b0] + block + body[b1:] + text[end:]


def has_version(text: str, version: str) -> bool:
    return re.search(rf"^## \[{re.escape(version)}\]", text, re.M) is not None


def release(text: str | None, version: str, day: str, sections: dict[str, list[str]]) -> str:
    """Move Unreleased content into a new version section.

    sections maps a heading (Security, Dependencies, Build) to bullet entries
    generated for this release; managed-block entries go under Security.
    """
    text = text if text else SKELETON
    if has_version(text, version):
        raise ToolError(f"CHANGELOG.md already has a section for {version}")
    start, end = _unreleased_bounds(text)
    _check_markers_outside(text, start, end)
    body = text[start:end]
    bounds = _block(body)
    managed: list[str] = []
    human = body
    if bounds:
        b0, b1 = bounds
        managed = [l[2:] for l in body[b0 + len(BEGIN):b1 - len(END)].splitlines() if l.startswith("- ")]
        human = body[:b0] + body[b1:]
    human = human.strip("\n")

    merged = {k: list(v) for k, v in sections.items()}
    merged["Security"] = managed + [e for e in merged.get("Security", []) if e not in managed]

    parts = [f"## [{version}] - {day}", ""]
    if human:
        parts += [human, ""]
    for heading in ("Security", "Dependencies", "Build"):
        items = merged.get(heading) or []
        if items:
            parts += [f"### {heading}", "", *[f"- {i}" for i in items], ""]
    new_section = "\n".join(parts)
    fresh_unreleased = f"\n\n{BEGIN}\n{END}\n\n"
    return text[:start] + fresh_unreleased + new_section + ("\n" if end < len(text) else "") + text[end:]
