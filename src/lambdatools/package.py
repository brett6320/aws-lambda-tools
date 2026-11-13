"""package: build a versioned, reproducible deployment zip with a changelog.

The build happens in a temp directory and is scanned before anything is
written. Write order: zip + manifest (exclusive create), CHANGELOG.md, then
lambda-tools.json and the release state, so an interrupted run never records
a version whose artifact does not exist.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from lambdatools import __version__
from lambdatools.common import changelog, config, proc, pypi, versions
from lambdatools.common.fsutil import atomic_write, create_exclusive, git_info, unified_diff, utc_now_iso
from lambdatools.common.inventory import DirTree
from lambdatools.common.log import EXIT_FINDINGS, EXIT_OK, WARNINGS, ToolError, log, mode_prefix
from lambdatools.common.osv import OsvClient
from lambdatools.remediate import _requirement_files, pip_platform_args
from lambdatools.scan import ScanResult, policy_from, scan_trees, summary

ZIP_LIMIT = 50 * 1024 * 1024
UNZIPPED_LIMIT = 250 * 1024 * 1024
# "/x" matches x at the project root only; a pattern without "/" matches any
# path segment; any other pattern is matched against the whole relative path.
# credentials and local state that must never ship
SECRET_EXCLUDES = [
    ".env", ".env.*", ".envrc", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".aws", ".ssh",
    "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "*.tfstate", "*.tfstate.*",
]
DEFAULT_EXCLUDES = [
    "/.venv", "/venv", "/dist", "/.lambda-tools", "/node_modules", "/tests", "/.pytest_cache", "/backups",
    "/lambda-tools.json", "/CHANGELOG.md", "/.gitignore",
    ".git", "__pycache__", "*.pyc", ".DS_Store",
    *SECRET_EXCLUDES,
]
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def zip_time() -> tuple:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        t = time.gmtime(max(int(epoch), 315532800))
        return t[:6]
    return FIXED_TIME


def excluded(rel: str, patterns: list[str]) -> bool:
    parts = rel.split("/")
    for p in patterns:
        if p.startswith("/"):
            if fnmatch.fnmatchcase(rel, p[1:]):
                return True
        elif "/" not in p:
            if any(fnmatch.fnmatchcase(part, p) for part in parts):
                return True
        elif fnmatch.fnmatchcase(rel, p):
            return True
    return False


def copy_source(src: Path, dest: Path, patterns: list[str]) -> None:
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel_dir = Path(dirpath).relative_to(src)
        keep = []
        for d in sorted(dirnames):
            rel = (rel_dir / d).as_posix()
            if excluded(rel, patterns):
                continue
            if (Path(dirpath) / d).is_symlink():
                raise ToolError(f"{rel} is a symlink; symlinks are not packaged (replace it with a real directory)")
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            rel = (rel_dir / f).as_posix()
            if excluded(rel, patterns):
                continue
            path = Path(dirpath) / f
            if path.is_symlink():
                raise ToolError(f"{rel} is a symlink; symlinks are not packaged")
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest / rel)


def install_python(staging: Path, requirements: Path, runtime: str, arch: str) -> list[dict]:
    """Install into staging for the Lambda platform; returns pip's resolved `install` entries."""
    with tempfile.TemporaryDirectory(prefix="lambda-tools-report-") as tmp:
        report = Path(tmp) / "report.json"
        # PIP_PRE=false overrides `pre = true` in pip config: unpinned packages resolve to stable releases only
        proc.run([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--no-input",
                  "--no-compile", "--report", str(report), "--target", str(staging), *pip_platform_args(runtime, arch),
                  "-r", str(requirements)], env={"PIP_PRE": "false"})
        return json.loads(report.read_text()).get("install", [])


def pinned_names(root: Path, requirements: str) -> set[str]:
    """Canonical names pinned with == (no wildcard) in the requirements file and its -r/-c includes."""
    names = set()
    for rel in _requirement_files(root, requirements):
        for line in (root / rel).read_text().splitlines():
            code = line.partition(" #")[0].strip()
            if not code or code.startswith(("#", "-")):
                continue
            try:
                req = Requirement(code)
            except InvalidRequirement:
                continue
            specs = list(req.specifier)
            if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
                names.add(canonicalize_name(req.name))
    return names


def check_latest_stable(installed: list[dict], pinned: set[str], runtime: str, arch: str) -> list[str]:
    """Warn about packages not pinned with == that resolved below their latest stable release."""
    stale, unchecked, checked = [], [], 0
    for item in installed:
        meta = item.get("metadata", {})
        name, version = meta.get("name", ""), meta.get("version", "")
        if not name or canonicalize_name(name) in pinned:
            continue
        latest = pypi.latest_stable(name)
        if latest is None:
            unchecked.append(name)
            continue
        checked += 1
        try:
            behind = Version(version) < Version(latest[0])
        except InvalidVersion:
            unchecked.append(name)
            continue
        if behind:
            reason = ("held back by a version constraint (its own specifier or another package's)" if pypi.has_compatible_wheel(latest[1], runtime, arch)
                      else f"{latest[0]} has no wheel for {runtime} on {arch}")
            stale.append(f"{name} {version} (latest stable {latest[0]}: {reason})")
    for s in stale:
        WARNINGS.add("package", f"not pinned and not at the latest stable release: {s}")
    if unchecked:
        WARNINGS.add("package", f"could not check the latest stable release on PyPI for: {', '.join(sorted(unchecked))}")
    log.info("Checked %d unpinned package(s) against PyPI: %d below the latest stable release", checked, len(stale))
    return stale


def npm_major() -> int:
    out = proc.run(["npm", "--version"], capture=True).strip()
    return int(out.split(".")[0])


def install_node(root: Path, staging: Path, arch: str, allow_scripts: bool) -> None:
    if not (staging / "package-lock.json").exists():
        raise ToolError("package-lock.json is required for reproducible Node.js builds; run npm install first")
    if npm_major() < 10:
        raise ToolError("npm 10 or newer is required to install Linux packages from another OS (--os/--cpu)")
    cmd = ["npm", "ci", "--omit=dev", "--no-audit", "--no-fund", "--os=linux", f"--cpu={'arm64' if arch == 'arm64' else 'x64'}"]
    if not allow_scripts:
        cmd.append("--ignore-scripts")
    # .npmrc may hold registry tokens: use it for the install, never package it.
    npmrc = staging / ".npmrc"
    if (root / ".npmrc").exists():
        shutil.copy2(root / ".npmrc", npmrc)
    try:
        proc.run(cmd, cwd=staging)
    finally:
        npmrc.unlink(missing_ok=True)
    for bin_dir in staging.rglob("node_modules/.bin"):
        shutil.rmtree(bin_dir)
    check_native(staging, allow_scripts)


def check_native(staging: Path, allow_scripts: bool) -> None:
    """Fail on native modules that were not built for Linux."""
    problems = []
    for path in staging.rglob("*"):
        if path.is_symlink():
            raise ToolError(f"{path.relative_to(staging)} is a symlink; refusing to package it")
        if path.name == "binding.gyp" and not allow_scripts:
            problems.append(f"{path.parent.relative_to(staging)} needs a native build")
        elif path.suffix == ".node" and path.is_file():
            with path.open("rb") as fh:
                magic = fh.read(4)
            if magic != b"\x7fELF":
                problems.append(f"{path.relative_to(staging)} is not a Linux binary")
    if problems:
        raise ToolError("native modules are not built for Lambda (" + "; ".join(problems[:5]) + "). "
                        "Build inside a Lambda-compatible Linux container (e.g. sam build --use-container)")


def build_zip(staging: Path) -> tuple[bytes, int, int]:
    """Deterministic zip of staging. Returns (bytes, file count, uncompressed size)."""
    import io
    buf = io.BytesIO()
    count = total = 0
    when = zip_time()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in staging.rglob("*") if p.is_file()):
            rel = path.relative_to(staging).as_posix()
            info = zipfile.ZipInfo(rel, date_time=when)
            info.create_system = 3
            executable = path.stat().st_mode & stat.S_IXUSR
            info.external_attr = ((0o100755 if executable else 0o100644) & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            data = path.read_bytes()
            zf.writestr(info, data, compresslevel=9)
            count += 1
            total += len(data)
    return buf.getvalue(), count, total


def dependency_map(result: ScanResult) -> dict[str, str]:
    return {f"{d.ecosystem}:{d.name}": d.version for d in result.inventory.sorted()}


def release_sections(prev: dict, deps: dict[str, str], result: ScanResult, artifact: str, sha256: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {"Security": [], "Dependencies": [], "Build": []}
    old = prev.get("dependencies", {}) if prev else {}
    if prev:
        for key in sorted(set(old) | set(deps)):
            if key not in old:
                sections["Dependencies"].append(f"Added {key} {deps[key]}")
            elif key not in deps:
                sections["Dependencies"].append(f"Removed {key} {old[key]}")
            elif old[key] != deps[key]:
                sections["Dependencies"].append(f"Changed {key} {old[key]} → {deps[key]}")
        current_ids = {f.vuln_id for f in result.findings}
        for vid in sorted(set(prev.get("vulnerabilities", [])) - current_ids):
            sections["Security"].append(f"Resolved {vid}")
    else:
        sections["Dependencies"].append(f"Initial release with {len(deps)} dependencies")
    for f in result.findings:
        label = f"ignored: {f.ignored}" if f.ignored else "allowed by --allow-vulnerable" if result.policy.fails(f) else "below fail-on threshold"
        sections["Security"].append(f"Known {f.severity} {f.vuln_id} in {f.dependency.ecosystem}:{f.dependency.name} "
                                    f"{f.dependency.version} ({label})")
    for g in result.inventory.gaps:
        sections["Security"].append(f"Not scanned: {g}")
    sections["Build"].append(f"Artifact `{artifact}` sha256 `{sha256}`")
    return sections


def next_version(current: str, bump: str | None, set_version: str | None,
                 scheme: str = "semver", today: date | None = None) -> str:
    if scheme == "date":
        if bump:
            raise ToolError("--bump doesn't apply with \"versioning\": \"date\"; the version is the build date "
                            "(use --set-version to choose one)")
        if set_version:
            if not versions.is_date_version(set_version):
                raise ToolError(f"--set-version {set_version!r} must be a date YYYY.MM.DD or YYYY.MM.DD.N")
            if versions.numeric_key(set_version) <= versions.numeric_key(current):
                raise ToolError(f"--set-version {set_version} must be later than the current version {current}")
            return set_version
        try:
            return versions.next_date_version(current, today or build_day())
        except ValueError as e:
            raise ToolError(f"{e}; pass --set-version to choose a later version") from None
    if bump is None and versions.is_date_version(current):
        raise ToolError(f"version {current} looks like a date; add \"versioning\": \"date\" to lambda-tools.json, "
                        "or pass --bump to treat it as X.Y.Z")
    if set_version:
        if not config.SEMVER_RE.match(set_version):
            raise ToolError(f"--set-version {set_version!r} must be X.Y.Z")
        if versions.numeric_key(set_version) <= versions.numeric_key(current):
            raise ToolError(f"--set-version {set_version} must be greater than the current version {current}")
        return set_version
    return versions.bump(current, bump or "patch")


def build_day() -> date:
    """The build date (UTC), used for the changelog and for date versions."""
    return datetime.now(timezone.utc).date()


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", type=Path, nargs="?", default=Path.cwd(), help="project directory (default: current directory)")
    v = p.add_mutually_exclusive_group()
    v.add_argument("--bump", choices=("patch", "minor", "major"),
                   help="version part to increment (default: patch; not used with date versioning)")
    v.add_argument("--set-version", help="explicit new version, X.Y.Z or YYYY.MM.DD[.N] (must be greater than the current one)")
    p.add_argument("--runtime", help="override the runtime from lambda-tools.json")
    p.add_argument("--arch", choices=("x86_64", "arm64"), help="override the architecture from lambda-tools.json")
    p.add_argument("--out", type=Path, help="artifact directory (default: PATH/dist)")
    p.add_argument("--fail-on", choices=config.FAIL_ON_CHOICES, help="lowest severity that blocks the build (default: low)")
    p.add_argument("--allow-vulnerable", action="store_true", help="build even if findings meet --fail-on (recorded in the changelog)")
    p.add_argument("--allow-gaps", action="store_true", help="build even if some dependencies could not be scanned")
    p.add_argument("--allow-scripts", action="store_true", help="run npm install scripts (off by default)")
    p.add_argument("--execute", "--apply", dest="execute", action="store_true", help="write artifact and records (default: dry-run)")


def run(args: argparse.Namespace, sess_factory) -> int:
    root = args.path.resolve()
    cfg = config.load_project(root, required=True)
    for key in ("name", "runtime", "version"):
        if key not in cfg.data:
            raise ToolError(f"{cfg.path}: missing required key {key!r}")
    name = cfg.get("name")
    runtime = config.resolve(args.runtime, None, cfg, "runtime", None)
    if not config.RUNTIME_RE.match(runtime):
        raise ToolError(f"runtime {runtime!r} is not a supported Lambda runtime")
    arch = config.resolve(args.arch, None, cfg, "architecture", "x86_64")
    current = cfg.get("version")
    state = config.load_state(root)
    if state.get("version") and state["version"] != current:
        raise ToolError(f"lambda-tools.json version {current} disagrees with {config.state_path(root)} "
                        f"({state['version']}); fix one of them by hand")
    version = next_version(current, args.bump, args.set_version, cfg.get("versioning", "semver"))
    out_dir = (args.out or root / "dist").resolve()
    artifact_name = f"{name}-{version}.zip"
    artifact, manifest_path = out_dir / artifact_name, out_dir / f"{name}-{version}.manifest.json"
    changelog_path = root / "CHANGELOG.md"
    old_log = changelog_path.read_text() if changelog_path.exists() else None
    for path in (artifact, manifest_path):
        if path.exists():
            raise ToolError(f"{path} already exists; versions are immutable. Bump to a new version, or if an "
                            f"earlier --execute was interrupted before lambda-tools.json was updated, delete the "
                            f"orphaned {version} artifact/manifest (and its CHANGELOG.md section) and rerun")
    if old_log and changelog.has_version(old_log, version):
        raise ToolError(f"CHANGELOG.md already has a section for {version}")

    prefix = mode_prefix(args.execute)
    log.info("%s Packaging %s %s -> %s (%s, %s)", prefix, name, version, artifact, runtime, arch)
    with tempfile.TemporaryDirectory(prefix="lambda-tools-build-") as tmp:
        staging = Path(tmp) / "staging"
        staging.mkdir()
        patterns = DEFAULT_EXCLUDES + cfg.get("exclude", [])
        if out_dir.is_relative_to(root) and out_dir != root:
            patterns.append("/" + out_dir.relative_to(root).as_posix())  # never package earlier artifacts
        copy_source(root, staging, patterns)
        if runtime.startswith("python"):
            req_name = cfg.get("requirements", "requirements.txt")
            req = root / req_name
            if req.exists():
                installed = install_python(staging, req, runtime, arch)
                check_latest_stable(installed, pinned_names(root, req_name), runtime, arch)
        else:
            install_node(root, staging, arch, args.allow_scripts)

        policy = policy_from(cfg, args.fail_on)
        result = scan_trees(f"{name} {version}", [DirTree(staging, skip_dirs={"__pycache__"})], policy, OsvClient(),
                            installed=True)
        if result.failing and not args.allow_vulnerable:
            for f in result.failing:
                WARNINGS.add("package", f"{f.severity} {f.vuln_id} in {f.dependency.ecosystem}:{f.dependency.name} "
                                        f"{f.dependency.version} (fix: {f.fixed or 'none'})")
            raise ToolError(f"{len(result.failing)} finding(s) at or above fail-on {policy.fail_on}; run "
                            "`lambda-tools remediate`, add a time-limited ignore entry, or pass --allow-vulnerable",
                            EXIT_FINDINGS)
        if result.inventory.gaps and not args.allow_gaps:
            for g in result.inventory.gaps:
                WARNINGS.add("package", f"not scanned: {g}")
            raise ToolError(f"{len(result.inventory.gaps)} coverage gap(s); fix them or pass --allow-gaps", EXIT_FINDINGS)

        data, count, unzipped = build_zip(staging)

    if unzipped > UNZIPPED_LIMIT:
        raise ToolError(f"unzipped size {unzipped} bytes exceeds Lambda's {UNZIPPED_LIMIT}-byte limit (layers count too)")
    if len(data) > ZIP_LIMIT:
        WARNINGS.add("package", f"zip is {len(data)} bytes; over 50 MB it must be uploaded through S3")
    sha256 = hashlib.sha256(data).hexdigest()
    deps = dependency_map(result)
    sections = release_sections(state, deps, result, artifact_name, sha256)
    today = build_day().isoformat()
    new_log = changelog.release(old_log, version, today, sections)
    manifest = {
        "name": name, "version": version, "built_at": utc_now_iso(), "tool_version": __version__,
        "artifact": artifact_name, "sha256": sha256, "size": len(data), "unzipped_size": unzipped, "files": count,
        "runtime": runtime, "architecture": arch, "git": git_info(root),
        "dependencies": [d.to_dict() for d in result.inventory.sorted()],
        "scan": {**summary(result), "findings_detail": [f.to_dict() for f in result.findings],
                 "coverage_gaps": result.inventory.gaps},
    }
    new_cfg = {**cfg.data, "version": version}
    new_state = {
        "version": version, "released_at": manifest["built_at"], "artifact": artifact_name, "sha256": sha256,
        "dependencies": deps, "vulnerabilities": sorted({f.vuln_id for f in result.findings}),
    }

    sys.stdout.write(unified_diff(old_log or "", new_log, "CHANGELOG.md"))
    sys.stdout.write(unified_diff(cfg.raw_text or "", config.render(new_cfg), config.CONFIG_NAME))
    if args.execute:
        create_exclusive(artifact, data)
        create_exclusive(manifest_path, (json.dumps(manifest, indent=2) + "\n").encode())
        log.info("[EXECUTE] Wrote %s and %s", artifact, manifest_path.name)
        atomic_write(changelog_path, new_log)
        config.save_project(cfg, new_cfg)
        config.save_state(root, new_state)
        log.info("[EXECUTE] Updated CHANGELOG.md, %s and %s", config.CONFIG_NAME, config.state_path(root).relative_to(root))
    else:
        log.info("Dry-run: nothing written. Pass --execute to write the artifact and records.")

    sys.stdout.write(f"\n{'Built' if args.execute else 'Would build'} {artifact} ({len(data)} bytes, {count} files)\n"
                     f"sha256 {sha256}\n")
    if args.execute and cfg.get("function_name"):
        sys.stdout.write(f"Deploy: aws lambda update-function-code --function-name {cfg.get('function_name')} "
                         f"--zip-file fileb://{artifact} --publish\n")
    return EXIT_OK
