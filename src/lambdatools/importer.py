"""import: turn a backup into a project directory for remediate and package.

A deployed code.zip mixes the function's own code with its installed
dependencies. Python packages are told apart by their dist-info RECORD files
and written to requirements.txt with the exact versions that were deployed.
For Node.js, node_modules is dropped and the package-lock.json shipped in the
zip is kept. Environment variable values and credential files are never written.

When a file can't be attributed to a dependency with certainty, it is kept as
project code and a warning says why.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import sys
from dataclasses import dataclass, field
from email.parser import HeaderParser
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from lambdatools.common import backupdir, changelog, config
from lambdatools.common.inventory import ZipTree
from lambdatools.common.log import EXIT_OK, WARNINGS, ToolError, log, mode_prefix
from lambdatools.common.sanitize import clean, valid_package_name, valid_version
from lambdatools.package import SECRET_EXCLUDES, excluded
from lambdatools.remediate import set_block_pin

MAX_FILE_BYTES = 250 * 1024 * 1024
IMPORTED_VERSION = "0.0.0"
WARN_LIMIT = 20
# top_level.txt entries that are almost always the project's own, not the wheel's
GENERIC_TOPS = {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks", "scripts", "config"}
GENERATED = ("lambda-tools.json", "CHANGELOG.md")


@dataclass
class Project:
    files: dict[str, bytes] = field(default_factory=dict)
    modes: dict[str, int] = field(default_factory=dict)
    pins: list[tuple[str, str]] = field(default_factory=list)
    dropped: int = 0


def _top(name: str) -> str:
    return name.split("/", 1)[0]


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _warn_list(scope: str, items: list[str], message: str) -> None:
    for item in items[:WARN_LIMIT]:
        WARNINGS.add(scope, message.format(clean(item, 200)))
    if len(items) > WARN_LIMIT:
        WARNINGS.add(scope, f"... and {len(items) - WARN_LIMIT} more like that")


def _record_hash_ok(tree: ZipTree, path: str, digest: str) -> bool:
    algo, _, value = digest.partition("=")
    if algo != "sha256" or not value:
        return True  # nothing to compare against
    actual = base64.urlsafe_b64encode(hashlib.sha256(tree.read(path, limit=MAX_FILE_BYTES)).digest()).rstrip(b"=")
    return actual.decode() == value


def _top_level_match(path: str, tops: list[str]) -> bool:
    head = _top(path)
    if "/" in path:
        return head in tops
    base, _, ext = path.partition(".")
    return base in tops and (ext == "py" or ext.endswith(("so", "pyd")))


def python_dependencies(tree: ZipTree) -> tuple[set[str], list[tuple[str, str]]]:
    """Files owned by top-level installed distributions, and their (name, version) pins."""
    files = tree.files()
    fileset = set(files)
    owned: set[str] = set()
    pins: list[tuple[str, str]] = []
    patched: list[str] = []
    claimed: set[str] = set()  # RECORD-listed files kept because they were modified
    unhashed: list[str] = []
    relocated_dirs: set[str] = set()
    seen: dict[str, str] = {}
    dist_dirs = sorted({_top(f) for f in files if "/" in f and _top(f).endswith(".dist-info")})
    for dist in dist_dirs:
        meta_name = f"{dist}/METADATA"
        if meta_name not in fileset:
            WARNINGS.add("import", f"{dist} has no METADATA; its files stay in the project")
            continue
        headers = HeaderParser().parsestr(tree.text(meta_name))
        name, version = (headers.get("Name") or "").strip(), (headers.get("Version") or "").strip()
        if not valid_package_name("PyPI", name) or not valid_version(version):
            WARNINGS.add("import", f"{dist}: unparseable name/version {clean(name, 60)!r} {clean(version, 30)!r}; "
                                   "its files stay in the project")
            continue
        key = _canonical(name)
        if key in seen:
            raise ToolError(f"the zip has two installs of {name}: {seen[key]} and {dist} (left over from an upgrade?); "
                            "the deployed version is ambiguous, so import stops")
        seen[key] = dist
        members = {f for f in files if f.startswith(f"{dist}/")}
        record = f"{dist}/RECORD"
        if record in fileset:
            for row in csv.reader(io.StringIO(tree.text(record))):
                if not row or not row[0]:
                    continue
                path = posixpath.normpath(row[0])
                if path.startswith("/"):
                    continue
                relocated = path.startswith("../")
                while path.startswith("../"):
                    # pip --target moves bin/, share/, ... into the target; RECORD still points outside it
                    path = path[3:]
                if path not in fileset or path in members:
                    continue
                digest = row[1] if len(row) > 1 else ""
                if not digest and not path.endswith(".pyc"):
                    unhashed.append(f"{path} ({name})")
                    continue
                if digest and not _record_hash_ok(tree, path, digest):
                    patched.append(f"{path} ({name})")
                    claimed.add(path)
                    continue
                if relocated:
                    relocated_dirs.add(_top(path))
                members.add(path)
        else:
            tops = []
            if f"{dist}/top_level.txt" in fileset:
                tops = [t.strip() for t in tree.text(f"{dist}/top_level.txt").splitlines() if t.strip()]
            generic = sorted(set(tops) & GENERIC_TOPS)
            if generic:
                WARNINGS.add("import", f"{name} {version}: top_level.txt names {', '.join(generic)}; those are kept "
                                       "as project files")
                tops = [t for t in tops if t not in GENERIC_TOPS]
            if not tops:
                WARNINGS.add("import", f"{name} {version}: no RECORD or usable top_level.txt, so its files cannot be "
                                       "separated; they stay in the project")
                continue
            members |= {f for f in files if _top_level_match(f, tops)}
        owned |= members
        pins.append((name, version))
    _warn_list("import", patched, "{} differs from the hash in its RECORD (patched or stripped after install?); kept "
                                  "as a project file, and package will copy it over the installed package. After an "
                                  "upgrade that mixes versions: delete it unless the patch is still needed")
    _warn_list("import", unhashed, "{} is listed in a RECORD without a hash; kept as a project file")
    owned_dirs = {_top(f) for f in owned | claimed
                  if "/" in f and not _top(f).endswith(".dist-info") and _top(f) not in relocated_dirs}
    leftovers = [f for f in files if f not in owned | claimed and _top(f) in owned_dirs and "/__pycache__/" not in f
                 and not f.endswith(".pyc")]
    _warn_list("import", leftovers, "{} is inside a dependency's directory but not in its RECORD; kept as a project "
                                    "file, where it will merge with the installed package")
    nested = sorted({f.split(".dist-info/")[0] for f in files
                     if ".dist-info/" in f and "/" in f.split(".dist-info/")[0] and f not in owned})
    _warn_list("import", nested, "vendored package {}.dist-info is not at the zip root; kept as project files "
                                 "(scan still covers it)")
    eggs = sorted({_top(f) for f in files if _top(f).endswith(".egg-info")})
    _warn_list("import", eggs, "{} is an egg-info install; import can't separate it, so its files stay in the "
                               "project and it is not in requirements.txt")
    return owned, pins


def handler_paths(handler: str, runtime: str) -> list[str]:
    """Files in the zip that could hold the handler; empty when it lives elsewhere (e.g. a layer under /opt)."""
    if not handler or handler.startswith("/"):
        return []
    if runtime.startswith("python"):
        module = handler.rsplit(".", 1)[0] if "." in handler else ""
        if not module:
            return []
        base = module.replace(".", "/")
        return [base + ".py", base + "/__init__.py"]
    # Node: the part after the last "/" is split at its first dot (index.handlers.main -> index)
    head, _, last = handler.rpartition("/")
    module = last.split(".", 1)[0]
    if not module or "." not in last:
        return []
    prefix = f"{head}/" if head else ""
    return [prefix + module + ext for ext in (".js", ".mjs", ".cjs")]


def _matches(candidate: str, name: str) -> bool:
    """name is candidate itself or a compiled form of it (x.pyc, __pycache__/x.cpython-312.pyc)."""
    if name == candidate:
        return True
    if not candidate.endswith(".py") or not name.endswith(".pyc"):
        return False
    folder, _, base = candidate[:-3].rpartition("/")
    cache = f"{folder}/__pycache__/" if folder else "__pycache__/"
    return name == candidate[:-3] + ".pyc" or name.startswith(f"{cache}{base}.")


def check_handler(handler: str, runtime: str, zip_files: list[str], project_files: dict, has_layers: bool) -> None:
    """Refuse only when the handler was in the zip and import would drop it; otherwise warn."""
    candidates = handler_paths(handler, runtime)
    if any(c in project_files for c in candidates):
        return
    in_zip = [f for f in zip_files if any(_matches(c, f) for c in candidates)]
    if in_zip:
        raise ToolError(f"handler {clean(handler, 100)!r} is in the zip ({clean(in_zip[0], 200)}) but would not be in "
                        "the project: it is compiled-only, or was attributed to a dependency. Nothing written")
    where = "probably in a layer" if has_layers or not candidates else "not found in the zip"
    WARNINGS.add("import", f"handler {clean(handler, 100)!r} is {where}; check that the project can still run it")


def build_project(tree: ZipTree, runtime: str, label: str) -> Project:
    files = tree.files()
    project = Project()
    _warn_list("import", tree.skipped, "zip entry {!r} has an unsafe path; not imported")
    _warn_list("import", tree.links, "zip entry {!r} is a symlink; not imported")
    if runtime.startswith("python"):
        owned, project.pins = python_dependencies(tree)
    else:
        owned = {f for f in files if f.startswith("node_modules/") or "/node_modules/" in f}
        if "package.json" not in files:
            WARNINGS.add("import", "no package.json at the zip root (bundled code?); dependencies cannot be "
                                   "remediated, and scan will report a coverage gap")
        elif "package-lock.json" not in files:
            raise ToolError(f"{label}: the zip has package.json but no package-lock.json, so the deployed dependency "
                            "versions cannot be reproduced; import needs the lockfile")
    withheld = []  # paths only; contents are never read
    for name in files:
        if name in owned or "__pycache__/" in name or name.endswith(".pyc"):
            project.dropped += 1
            continue
        if excluded(name, SECRET_EXCLUDES):
            withheld.append(name)
            continue
        project.files[name] = tree.read(name, limit=MAX_FILE_BYTES)
        project.modes[name] = 0o755 if tree.mode(name) & 0o111 else 0o644
    _warn_list("import", withheld, "{} looks like a credential file; not imported. Copy it by hand if you need it, "
                                  "and keep it out of version control")
    if runtime.startswith("python") and not project.pins:
        tops = sorted({_top(f) for f in project.files if "/" in f and (f.endswith("/__init__.py"))})
        if tops:
            WARNINGS.add("import", f"no installed-package metadata (*.dist-info) found, so requirements.txt is empty; "
                                   f"packages such as {', '.join(tops[:5])} are kept as project code. If they are "
                                   "dependencies (e.g. stripped by a slim build), list them in requirements.txt yourself")
    return project


def check_collisions(names: list[str]) -> None:
    """Fail in dry-run too when two paths would clash on disk."""
    folded: dict[str, str] = {}
    dirs = {posixpath.dirname(n) for n in names}
    all_dirs = set()
    for d in dirs:
        while d:
            all_dirs.add(d)
            d = posixpath.dirname(d)
    folded_dirs = {d.casefold() for d in all_dirs}
    for name in names:
        if name.casefold() in folded_dirs:
            raise ToolError(f"zip entry {clean(name, 200)!r} is both a file and a directory; cannot import")
        key = name.casefold()
        if key in folded and folded[key] != name:
            raise ToolError(f"zip entries {clean(folded[key], 200)!r} and {clean(name, 200)!r} differ only in case "
                            "and would collide on a case-insensitive file system")
        folded[key] = name


def requirements_text(pins: list[tuple[str, str]], label: str) -> str:
    lines = [f"# Generated by `lambda-tools import` from {label}.",
             "# Exact versions that were deployed, direct and transitive; edit freely.",
             *(f"{n}=={v}" for n, v in sorted(pins, key=lambda p: p[0].lower()))]
    return "\n".join(lines) + "\n"


def _pin_line(line: str, name: str, version: str) -> tuple[str, str | None]:
    """Rewrite one requirement line for `name` as ==version, keeping extras, marker and comment.

    Returns (line, status); status is None when the line isn't a requirement for `name`.
    """
    body, newline = line.rstrip("\r\n"), line[len(line.rstrip("\r\n")):]
    code, hash_, comment = body.partition(" #")
    stripped = code.strip()
    if not stripped or stripped.startswith(("#", "-")) or stripped.endswith("\\"):
        return line, None
    try:
        req = Requirement(stripped)
    except InvalidRequirement:
        return line, None
    if canonicalize_name(req.name) != canonicalize_name(name):
        return line, None
    if req.url:
        return line, f"{req.name} is installed from a URL; left as is"
    status = "pinned"
    if req.specifier and not req.specifier.contains(version, prereleases=True):
        status = f"deployed {req.name} {version} does not satisfy {req.specifier}; pinned to the deployed version"
    extras = f"[{','.join(sorted(req.extras))}]" if req.extras else ""
    marker = f"; {req.marker}" if req.marker else ""
    indent = code[: len(code) - len(code.lstrip())]
    gap = code[len(code.rstrip()):]  # spacing before an inline comment
    tail = f"{gap}{hash_}{comment}" if hash_ else ""
    return f"{indent}{req.name}{extras}=={version}{marker}{tail}{newline}", status


def pin_existing_requirements(text: str, pins: list[tuple[str, str]]) -> str:
    """Pin the zip's own requirements.txt to the deployed versions.

    Listed packages are rewritten as ==deployed (whatever specifier they had);
    the rest of the deployed packages (transitive) go into the managed block
    that remediate maintains, so every deployed package is pinned in one file.
    """
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    unpinned = []
    for name, version in sorted(pins, key=lambda p: p[0].lower()):
        found = False
        for i, line in enumerate(lines):
            new, status = _pin_line(line, name, version)
            if status is None:
                continue
            found = True
            if status.endswith("left as is"):
                WARNINGS.add("import", f"requirements.txt: {status}")
                continue
            if status != "pinned":
                WARNINGS.add("import", f"requirements.txt: {status}")
            if "==" not in line.partition(" #")[0]:
                unpinned.append(name)
            lines[i] = new
        if not found:
            text_now = "".join(lines)
            lines = set_block_pin(text_now, name, version).splitlines(keepends=True)
    if unpinned:
        WARNINGS.add("import", f"requirements.txt pinned to the deployed versions: {', '.join(unpinned)} were not "
                               "pinned with ==")
    return "".join(lines)


def write_project(dest: Path, files: dict[str, bytes], modes: dict[str, int]) -> None:
    """Write into a new temp dir next to dest, then rename it into place."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / f".{dest.name}.import.tmp"
    try:
        os.mkdir(tmp, 0o700)
    except FileExistsError:
        raise ToolError(f"{tmp} already exists (another import running, or left from an earlier run); "
                        "remove it and retry") from None
    try:
        for name, data in files.items():
            target = tmp / name
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, modes.get(name, 0o644))
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o777 & ~umask)
        if dest.exists():
            dest.rmdir()  # only an empty directory reaches here
        os.rename(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("backup", type=Path, help="backup directory written by `lambda-tools backup --execute`")
    p.add_argument("--to", type=Path, help="new project directory (default: ./<function name>)")
    p.add_argument("--execute", "--apply", dest="execute", action="store_true", help="write the project (default: dry-run)")


def run(args: argparse.Namespace, sess_factory) -> int:
    backup = backupdir.load(args.backup)
    if backup.is_image:
        raise ToolError(f"{backup.label} is a container image function; there is no code.zip to import")
    conf = backup.configuration
    runtime = conf.get("Runtime", "")
    if not config.RUNTIME_RE.match(runtime):
        raise ToolError(f"runtime {runtime or '(none)'!r} is not supported; import handles python3.x and nodejsNN.x")
    name = conf.get("FunctionName")
    if not name:
        raise ToolError(f"{backup.path}/function.json has no FunctionName")
    dest = (args.to or Path.cwd() / name).resolve()
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise ToolError(f"{dest} already exists and is not empty; choose another --to")

    tree = ZipTree(backup.code(), f"{backup.path.name}/code.zip")
    project = build_project(tree, runtime, backup.label)
    files = dict(project.files)
    modes = dict(project.modes)

    handler = conf.get("Handler", "")
    check_handler(handler, runtime, tree.files(), files, bool(conf.get("Layers")))

    if runtime.startswith("python") and project.pins:
        if "requirements.txt" not in files:
            files["requirements.txt"] = requirements_text(project.pins, backup.label).encode()
        else:
            try:
                original = files["requirements.txt"].decode()
            except UnicodeDecodeError:
                raise ToolError("the zip's requirements.txt is not UTF-8; import can't pin it") from None
            files["requirements.txt"] = pin_existing_requirements(original, project.pins).encode()
    for generated in GENERATED:
        if generated in files:
            WARNINGS.add("import", f"the zip already has {generated}; kept it instead of generating one. Check that "
                                   "its version and settings match what is deployed")
    if config.CONFIG_NAME not in files:
        cfg = {"name": name, "function_name": name, "runtime": runtime,
               "architecture": (conf.get("Architectures") or ["x86_64"])[0], "version": IMPORTED_VERSION,
               "handler": handler, "account_id": backup.manifest.get("account"),
               "region": backup.manifest.get("region")}
        cfg = {k: v for k, v in cfg.items() if v}
        config.validate(cfg, Path(config.CONFIG_NAME))
        files[config.CONFIG_NAME] = config.render(cfg).encode()
        modes[config.CONFIG_NAME] = 0o644
    if "CHANGELOG.md" not in files:
        files["CHANGELOG.md"] = changelog.add_unreleased(None, [
            f"Imported from {backup.label} (CodeSha256 `{conf.get('CodeSha256')}`); "
            f"{len(project.pins)} dependencies pinned to the deployed versions"]).encode()
        modes["CHANGELOG.md"] = 0o644
    if conf.get("Layers"):
        WARNINGS.add("import", f"{len(conf['Layers'])} layer(s) are not part of the project (layers.json in the backup); "
                               "their dependencies are not in requirements.txt")
    check_collisions(sorted(files))

    prefix = mode_prefix(args.execute)
    log.info("%s Import %s -> %s", prefix, backup.label, dest)
    log.info("%s   %d project files, %d dependency files left out, %d pinned dependencies",
             prefix, len(files), project.dropped, len(project.pins))
    if args.execute:
        write_project(dest, files, modes)
        log.info("[EXECUTE] Wrote %s", dest)
    else:
        log.info("Dry-run: nothing written. Pass --execute to create the project.")

    sys.stdout.write(json.dumps({
        "project": str(dest), "written": bool(args.execute), "files": sorted(files),
        "pinned": [f"{n}=={v}" for n, v in project.pins], "dependency_files_left_out": project.dropped,
        "next": [f"lambda-tools scan {dest}", f"lambda-tools remediate {dest}", f"lambda-tools package {dest}"],
    }, indent=2) + "\n")
    return EXIT_OK
