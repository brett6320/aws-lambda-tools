"""Dependency inventory from a project directory or a deployment zip.

Zip contents are untrusted: they are read in memory, never extracted,
imported, or executed. Anything that cannot be inventoried is reported as a
coverage gap rather than treated as clean.
"""

from __future__ import annotations

import io
import json
import os
import posixpath
import re
import stat
import zipfile
from dataclasses import dataclass, field
from email.parser import HeaderParser
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from lambdatools.common.log import ToolError
from lambdatools.common.sanitize import clean, valid_package_name, valid_version

MAX_MEMBER_BYTES = 20 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED = 1024 * 1024 * 1024

SKIP_DIRS = {".git", ".venv", "venv", ".tox", "__pycache__", ".lambda-tools", "dist", ".pytest_cache"}

UNSUPPORTED_MANIFESTS = {
    "yarn.lock": "yarn.lock",
    "pnpm-lock.yaml": "pnpm-lock.yaml",
    "poetry.lock": "poetry.lock",
    "uv.lock": "uv.lock",
    "Pipfile.lock": "Pipfile.lock",
}


def normalize(ecosystem: str, name: str) -> str:
    return canonicalize_name(name) if ecosystem == "PyPI" else name.lower()


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    sources: list[str] = field(default_factory=list)
    direct: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, normalize(self.ecosystem, self.name), self.version)

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "direct": self.direct,
            "sources": self.sources,
        }


@dataclass
class Inventory:
    dependencies: dict[tuple, Dependency] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)
    label: str = ""

    def add(self, ecosystem: str, name: str, version: str, source: str, direct: bool = False) -> None:
        name, version = name.strip(), version.strip()
        if not valid_package_name(ecosystem, name) or not valid_version(version):
            self.gap(f"{source}: unparseable package entry {clean(name, 80)!r} {clean(version, 40)!r}")
            return
        dep = Dependency(ecosystem, name, version)
        existing = self.dependencies.setdefault(dep.key, dep)
        if source not in existing.sources:
            existing.sources.append(source)
        existing.direct = existing.direct or direct

    def gap(self, message: str) -> None:
        message = clean(message, 400)
        if message not in self.gaps:
            self.gaps.append(message)

    def merge(self, other: "Inventory") -> None:
        for dep in other.dependencies.values():
            for source in dep.sources:
                self.add(dep.ecosystem, dep.name, dep.version, source, dep.direct)
        for g in other.gaps:
            self.gap(g)

    def sorted(self) -> list[Dependency]:
        return sorted(self.dependencies.values(), key=lambda d: d.key)


class Tree:
    """Read-only view over a directory or a zip, with posix relative paths."""

    label: str

    def files(self) -> list[str]:
        raise NotImplementedError

    def read(self, name: str) -> bytes:
        raise NotImplementedError

    def text(self, name: str) -> str:
        return self.read(name).decode("utf-8", errors="replace")


class DirTree(Tree):
    def __init__(self, root: Path, skip_dirs: set[str] = SKIP_DIRS):
        self.root = root
        self.label = str(root)
        self._files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel_dir = Path(dirpath).relative_to(root)
            dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs or rel_dir.parts[:1] == ("node_modules",))
            for f in filenames:
                p = Path(dirpath) / f
                if p.is_symlink() or not p.is_file():
                    continue
                self._files.append((rel_dir / f).as_posix())
        self._files.sort()

    def files(self) -> list[str]:
        return self._files

    def read(self, name: str) -> bytes:
        path = self.root / name
        if path.stat().st_size > MAX_MEMBER_BYTES:
            raise ToolError(f"{path} is larger than {MAX_MEMBER_BYTES} bytes")
        return path.read_bytes()


class ZipTree(Tree):
    def __init__(self, data: bytes, label: str, max_total: int = MAX_ZIP_UNCOMPRESSED):
        self.label = label
        try:
            self._zip = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise ToolError(f"{label}: not a valid zip: {e}") from None
        total = 0
        self._infos: dict[str, zipfile.ZipInfo] = {}
        self.skipped: list[str] = []
        for info in self._zip.infolist():
            total += info.file_size
            if total > max_total:
                raise ToolError(f"{label}: uncompressed size exceeds {max_total} bytes; refusing to read")
            name = info.filename
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode):
                continue
            norm = posixpath.normpath(name)
            if name.startswith("/") or norm.startswith("..") or "\\" in name:
                self.skipped.append(name)
                continue
            self._infos[norm] = info

    def files(self) -> list[str]:
        return sorted(self._infos)

    def read(self, name: str) -> bytes:
        info = self._infos[name]
        if info.file_size > MAX_MEMBER_BYTES:
            raise ToolError(f"{self.label}:{name} is larger than {MAX_MEMBER_BYTES} bytes")
        with self._zip.open(info) as fh:
            return fh.read(MAX_MEMBER_BYTES + 1)[:MAX_MEMBER_BYTES]


def open_path(path: Path) -> Tree:
    if path.is_dir():
        return DirTree(path)
    if path.is_file():
        return ZipTree(path.read_bytes(), str(path))
    raise ToolError(f"{path} is neither a directory nor a zip file")


# --- Python -----------------------------------------------------------------

_PIN_OPS = ("==", "===")


def _python_metadata(tree: Tree, inv: Inventory, files: list[str]) -> set[str]:
    found: set[str] = set()
    for name in files:
        parent = posixpath.dirname(name)
        base = posixpath.basename(name)
        if not ((parent.endswith(".dist-info") and base == "METADATA") or (parent.endswith(".egg-info") and base == "PKG-INFO")):
            continue
        headers = HeaderParser().parsestr(tree.text(name))
        pkg, version = headers.get("Name"), headers.get("Version")
        source = f"{tree.label}:{name}"
        if not pkg or not version:
            inv.gap(f"{source}: missing Name or Version")
            continue
        inv.add("PyPI", pkg, version, source)
        found.add(canonicalize_name(pkg))
    return found


def _logical_lines(text: str) -> list[str]:
    lines, buf = [], ""
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        lines.append(buf + raw)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def parse_requirement_line(line: str) -> Requirement | None | str:
    """Return a Requirement, None for blank/comment lines, or an option string."""
    stripped = re.sub(r"(^|\s)#.*$", "", line).strip()
    if not stripped:
        return None
    if stripped.startswith("-"):
        return stripped
    stripped = re.sub(r"\s--hash[= ]\S+", "", stripped).strip()
    return Requirement(stripped)


def pinned_version(req: Requirement) -> str | None:
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in _PIN_OPS and "*" not in specs[0].version:
        return specs[0].version
    return None


def _requirements(tree: Tree, inv: Inventory, name: str, installed: set[str], seen: set[str]) -> None:
    if name in seen:
        return
    seen.add(name)
    source = f"{tree.label}:{name}"
    for line in _logical_lines(tree.text(name)):
        try:
            parsed = parse_requirement_line(line)
        except InvalidRequirement:
            inv.gap(f"{source}: cannot parse {clean(line, 80)!r}")
            continue
        if parsed is None:
            continue
        if isinstance(parsed, str):
            m = re.match(r"^(-r|--requirement)[= ]\s*(\S+)", parsed)
            if m:
                include = posixpath.normpath(posixpath.join(posixpath.dirname(name), m.group(2)))
                if include in tree.files():
                    _requirements(tree, inv, include, installed, seen)
                else:
                    inv.gap(f"{source}: included file {clean(m.group(2))} not found")
            elif re.match(r"^(-c|--constraint|-i|--index-url|--extra-index-url|--no-binary|--only-binary|--prefer-binary|--pre|--find-links|-f)\b", parsed):
                continue
            else:
                inv.gap(f"{source}: unsupported option {clean(parsed, 80)!r}")
            continue
        if parsed.url:
            inv.gap(f"{source}: {parsed.name} installed from URL; not scanned")
            continue
        version = pinned_version(parsed)
        if version:
            inv.add("PyPI", parsed.name, version, source, direct=True)
        elif canonicalize_name(parsed.name) not in installed:
            inv.gap(f"{source}: {parsed.name} is not pinned with ==; resolved version unknown")


def _is_requirements_file(name: str) -> bool:
    base = posixpath.basename(name)
    return base.endswith(".txt") and base.startswith("requirements") and "/" not in name.strip("/")


# --- Node.js ------------------------------------------------------------------

_NM_PACKAGE = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@][^/]*)/package\.json$")


def _package_lock(tree: Tree, inv: Inventory, name: str, include_dev: bool) -> None:
    source = f"{tree.label}:{name}"
    try:
        lock = json.loads(tree.text(name))
    except json.JSONDecodeError as e:
        inv.gap(f"{source}: invalid JSON ({e})")
        return
    if not isinstance(lock, dict) or not isinstance(lock.get("packages"), dict):
        inv.gap(f"{source}: lockfileVersion {lock.get('lockfileVersion') if isinstance(lock, dict) else '?'} is not supported; regenerate with npm 7 or newer")
        return
    packages = lock["packages"]
    root = packages.get("", {})
    direct = set(root.get("dependencies", {})) | set(root.get("optionalDependencies", {}))
    for path, meta in packages.items():
        if not path or not isinstance(meta, dict) or meta.get("link"):
            continue
        if (meta.get("dev") or meta.get("devOptional")) and not include_dev:
            continue
        if "node_modules/" not in path:
            continue  # workspace member, not an installed package
        pkg = meta.get("name") or path.rsplit("node_modules/", 1)[1]
        version = meta.get("version")
        if not isinstance(version, str):
            inv.gap(f"{source}: {clean(pkg, 80)} has no version")
            continue
        top_level = path.startswith("node_modules/") and path.count("node_modules/") == 1
        inv.add("npm", pkg, version, source, direct=top_level and pkg in direct)


def _node_modules(tree: Tree, inv: Inventory, files: list[str], covered_roots: set[str]) -> None:
    for name in files:
        m = _NM_PACKAGE.search(name)
        if not m:
            continue
        root = name[: name.index("node_modules/")]
        if root.rstrip("/") in covered_roots:
            continue
        source = f"{tree.label}:{name}"
        try:
            meta = json.loads(tree.text(name))
        except json.JSONDecodeError:
            inv.gap(f"{source}: invalid JSON")
            continue
        if not isinstance(meta, dict):
            continue
        pkg, version = meta.get("name"), meta.get("version")
        if not isinstance(pkg, str) or not isinstance(version, str):
            continue  # nested package.json files without identity are not packages
        inv.add("npm", pkg, version, source)


CODE_SUFFIXES = (".py", ".js", ".mjs", ".cjs")


def build_inventory(tree: Tree, include_dev: bool = False, installed: bool | None = None) -> Inventory:
    """Inventory a tree.

    installed=True (default for zips) treats node_modules as the truth: what
    is deployed is scanned even when a lockfile disagrees with it.
    """
    if installed is None:
        installed = isinstance(tree, ZipTree)
    inv = Inventory(label=tree.label)
    files = tree.files()
    for name in getattr(tree, "skipped", [])[:20]:
        inv.gap(f"{tree.label}: entry {name!r} has an unsafe path; not scanned")
    installed_py = _python_metadata(tree, inv, files)
    seen: set[str] = set()
    for name in files:
        if _is_requirements_file(name):
            _requirements(tree, inv, name, installed_py, seen)

    lock_roots: set[str] = set()
    for name in files:
        if posixpath.basename(name) == "package-lock.json" and "node_modules/" not in name:
            root = posixpath.dirname(name)
            modules_prefix = f"{root}/node_modules/" if root else "node_modules/"
            if installed and any(f.startswith(modules_prefix) for f in files):
                continue  # node_modules below is what actually runs
            _package_lock(tree, inv, name, include_dev)
            lock_roots.add(root)
    _node_modules(tree, inv, files, lock_roots)

    for name in files:
        if "node_modules/" in name:
            continue
        base = posixpath.basename(name)
        if base in UNSUPPORTED_MANIFESTS:
            inv.gap(f"{tree.label}:{name}: {UNSUPPORTED_MANIFESTS[base]} is not supported; dependencies not scanned")
        elif base == "package.json":
            root = posixpath.dirname(name)
            has_modules = any(f.startswith(f"{root}/node_modules/" if root else "node_modules/") for f in files)
            if root not in lock_roots and not has_modules:
                inv.gap(f"{tree.label}:{name}: no package-lock.json; dependencies not scanned")
        elif base in ("pyproject.toml", "setup.py", "setup.cfg") and posixpath.dirname(name) == "":
            if not any(_is_requirements_file(f) for f in files) and not installed_py:
                inv.gap(f"{tree.label}:{name}: {base} without requirements.txt is not supported")
    # A deployed zip with code but no metadata may be a bundle or vendored code.
    if isinstance(tree, ZipTree) and not inv.dependencies and any(f.endswith(CODE_SUFFIXES) for f in files):
        inv.gap(f"{tree.label}: no dependency metadata found; bundled or vendored code cannot be scanned "
                "(pass --allow-gaps if the function really has no dependencies)")
    return inv
