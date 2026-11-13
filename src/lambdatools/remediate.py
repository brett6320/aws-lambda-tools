"""remediate: raise vulnerable dependency versions to fixed ones, then verify.

Python: edits `==` pins in requirements files in place; transitive packages get
pins inside a marked block in the main requirements file. Node.js: bumps
direct dependencies in package.json and adds `overrides` for transitive ones,
then regenerates package-lock.json. Every proposal is re-resolved and
re-scanned before anything is written.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

from lambdatools.common import changelog, config, proc
from lambdatools.common.fsutil import atomic_write, unified_diff
from lambdatools.common.inventory import DirTree, Inventory, build_inventory, normalize
from lambdatools.common.log import EXIT_FINDINGS, EXIT_OK, WARNINGS, ToolError, log, mode_prefix
from lambdatools.common.osv import Finding, OsvClient, Policy, evaluate, package_fix
from lambdatools.scan import policy_from

MAX_ROUNDS = 3
BLOCK_BEGIN = "# BEGIN lambda-tools remediation (pins for transitive dependencies)"
BLOCK_END = "# END lambda-tools remediation"
NPM_FILES = ("package.json", "package-lock.json", ".npmrc")


@dataclass
class Plan:
    edits: dict[str, tuple[str, str]] = field(default_factory=dict)  # relpath -> (old, new)
    bumps: list[tuple[str, str, str, str, list[str]]] = field(default_factory=list)  # eco, name, old, new, ids
    remaining: list[Finding] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)


def runtime_info(cfg: config.ProjectConfig, root: Path) -> tuple[str, str]:
    runtime = cfg.get("runtime")
    if runtime:
        return ("python" if runtime.startswith("python") else "node"), runtime
    if (root / "package.json").exists():
        return "node", "nodejs20.x"
    return "python", "python3.12"


def pip_platform_args(runtime: str, arch: str) -> list[str]:
    plat = "manylinux2014_aarch64" if arch == "arm64" else "manylinux2014_x86_64"
    return ["--platform", plat, "--implementation", "cp", "--python-version", runtime.removeprefix("python"),
            "--only-binary=:all:"]


# --- Python ---------------------------------------------------------------------

def _name_pattern(name: str) -> str:
    return "[-_.]+".join(re.escape(p) for p in re.split(r"[-_.]+", canonicalize_name(name)))


def rewrite_pin(text: str, name: str, new_version: str) -> tuple[str, str]:
    """Rewrite `name==x` lines. Returns (text, status): 'pinned', 'absent' or 'manual: why'."""
    # The lookahead stops "requests" from matching "requests-toolbelt".
    pattern = re.compile(rf"^(\s*{_name_pattern(name)}(?=\s*(?:\[|[=<>!~;@#\\]|$))\s*(?:\[[^\]]*\])?\s*)"
                         rf"([^\s;#\\]*)(.*)$", re.I)
    out, status = [], "absent"
    for line in text.splitlines(keepends=True):
        m = pattern.match(line.rstrip("\r\n"))
        if m and not line.lstrip().startswith("#"):
            spec = m.group(2)
            if re.fullmatch(r"===?[^,]+", spec):
                line = m.group(1) + "==" + new_version + m.group(3) + line[len(line.rstrip("\r\n")):]
                status = "pinned"
            elif status != "pinned":
                status = f"manual: {name} has specifier {spec or '(none)'!r}; pin it with =="
        out.append(line)
    return "".join(out), status


def set_block_pin(text: str, name: str, version: str) -> str:
    begins, ends = text.count(BLOCK_BEGIN), text.count(BLOCK_END)
    if (begins, ends) == (0, 0):
        text = (text.rstrip("\n") + "\n\n" if text.strip() else "") + f"{BLOCK_BEGIN}\n{BLOCK_END}\n"
    elif (begins, ends) != (1, 1) or text.index(BLOCK_BEGIN) > text.index(BLOCK_END):
        raise ToolError("requirements remediation markers are unbalanced or duplicated; fix them by hand")
    start = text.index(BLOCK_BEGIN) + len(BLOCK_BEGIN) + 1
    end = text.index(BLOCK_END)
    lines = [l for l in text[start:end].splitlines() if l.strip()]
    pat = re.compile(rf"^{_name_pattern(name)}\s*==", re.I)
    lines = [l for l in lines if not pat.match(l)] + [f"{name}=={version}"]
    return text[:start] + "".join(l + "\n" for l in sorted(lines, key=str.lower)) + text[end:]


def _requirement_files(root: Path, main: str) -> list[str]:
    ordered, todo = [], [main]
    while todo:
        rel = todo.pop(0)
        if rel in ordered or not (root / rel).exists():
            continue
        ordered.append(rel)
        for m in re.finditer(r"^\s*(?:-r|--requirement|-c|--constraint)[= ]\s*(\S+)", (root / rel).read_text(), re.M):
            include = os.path.normpath(Path(rel).parent / m.group(1))
            if include.startswith("..") or os.path.isabs(include):
                raise ToolError(f"{rel} includes {m.group(1)}, outside the project; remediate needs all "
                                "requirement files inside the project directory")
            todo.append(include)
    return ordered


def resolve_python(files: dict[str, str], main: str, runtime: str, arch: str) -> Inventory:
    """Resolve requirements with pip (no install) and inventory the result."""
    with tempfile.TemporaryDirectory(prefix="lambda-tools-resolve-") as tmp:
        for rel, text in files.items():
            (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / rel).write_text(text)
        report = Path(tmp) / ".report.json"
        proc.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet",
                  "--disable-pip-version-check", "--no-input", "--report", str(report), "--target", str(Path(tmp) / ".t"),
                  *pip_platform_args(runtime, arch), "-r", str(Path(tmp) / main)])
        data = json.loads(report.read_text())
    inv = Inventory(label="resolved requirements")
    for item in data.get("install", []):
        meta = item.get("metadata", {})
        inv.add("PyPI", meta.get("name", ""), meta.get("version", ""), "pip resolution", direct=bool(item.get("requested")))
    return inv


def plan_python(root: Path, cfg: config.ProjectConfig, client: OsvClient, policy: Policy, runtime: str, arch: str) -> Plan:
    main = cfg.get("requirements", "requirements.txt")
    rels = _requirement_files(root, main)
    if not rels:
        raise ToolError(f"{root / main} not found")
    original = {rel: (root / rel).read_text() for rel in rels}
    if any(re.search(r"--hash[= ]", t) for t in original.values()):
        raise ToolError("requirements use --hash pins; bump versions with your lock tool (e.g. pip-compile "
                        "--generate-hashes) instead, then run scan")
    current = dict(original)
    plan = Plan()
    for round_no in range(1, MAX_ROUNDS + 1):
        inv = resolve_python(current, main, runtime, arch)
        findings, _ = evaluate(inv.sorted(), client, policy)
        actionable = _group([f for f in findings if policy.fails(f)])
        if not actionable or round_no == MAX_ROUNDS:
            plan.remaining = [f for f in findings if policy.fails(f)]
            break
        changed = False
        for (eco, name), group in actionable.items():
            fix, unfixable = package_fix(group)
            old = group[0].dependency.version
            if not fix:
                continue
            status = "absent"
            for rel in rels:
                current[rel], s = rewrite_pin(current[rel], group[0].dependency.name, fix)
                status = s if s != "absent" and status != "pinned" else status
            if status.startswith("manual"):
                if status.removeprefix("manual: ") not in plan.manual:
                    plan.manual.append(status.removeprefix("manual: "))
                continue
            if status == "absent":
                current[main] = set_block_pin(current[main], group[0].dependency.name, fix)
            plan.bumps.append((eco, group[0].dependency.name, old, fix, sorted({f.vuln_id for f in group if f.fixed})))
            changed = True
        if not changed:
            plan.remaining = [f for f in findings if policy.fails(f)]
            break
    plan.edits = {rel: (original[rel], current[rel]) for rel in rels if original[rel] != current[rel]}
    return plan


# --- Node.js --------------------------------------------------------------------

def bump_spec(old_spec: str, version: str) -> str:
    prefix = old_spec[0] if old_spec[:1] in ("^", "~") else ""
    return prefix + version


def apply_npm_fix(pkg: dict, name: str, version: str) -> None:
    for section in ("dependencies", "optionalDependencies"):
        deps = pkg.get(section) or {}
        if name in deps:
            deps[name] = bump_spec(deps[name], version)
            return
    pkg.setdefault("overrides", {})[name] = version


def lock_inventory(lock_dir: Path) -> Inventory:
    tree = DirTree(lock_dir)
    tree._files = [f for f in tree.files() if f == "package-lock.json"]
    return build_inventory(tree)


def relock(root: Path, package_json: str) -> tuple[str, Inventory]:
    """Regenerate package-lock.json for package_json in a temp copy."""
    with tempfile.TemporaryDirectory(prefix="lambda-tools-npm-") as tmp:
        for name in NPM_FILES:
            if (root / name).exists():
                shutil.copy2(root / name, Path(tmp) / name)
        (Path(tmp) / "package.json").write_text(package_json)
        proc.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=Path(tmp))
        lock = (Path(tmp) / "package-lock.json").read_text()
        return lock, lock_inventory(Path(tmp))


def plan_node(root: Path, client: OsvClient, policy: Policy) -> Plan:
    if not (root / "package-lock.json").exists():
        raise ToolError(f"{root / 'package-lock.json'} not found; run npm install to create it first")
    original_pkg = (root / "package.json").read_text()
    original_lock = (root / "package-lock.json").read_text()
    pkg = json.loads(original_pkg)
    indent = "\t" if re.search(r'^\{\r?\n\t"', original_pkg) else 4 if re.search(r'^\{\r?\n {4}"', original_pkg) else 2
    inv = lock_inventory(root)
    lock = original_lock
    plan = Plan()
    for round_no in range(1, MAX_ROUNDS + 1):
        findings, _ = evaluate(inv.sorted(), client, policy)
        actionable = _group([f for f in findings if policy.fails(f)])
        plan.remaining = [f for f in findings if policy.fails(f)]
        if not actionable or round_no == MAX_ROUNDS:
            break
        changed = False
        for (eco, name), group in actionable.items():
            fix, _ = package_fix(group)
            if not fix:
                continue
            apply_npm_fix(pkg, group[0].dependency.name, fix)
            plan.bumps.append((eco, group[0].dependency.name, group[0].dependency.version, fix,
                               sorted({f.vuln_id for f in group if f.fixed})))
            changed = True
        if not changed:
            break
        new_pkg = json.dumps(pkg, indent=indent, ensure_ascii=False) + "\n"
        json.loads(new_pkg)  # validate before use
        lock, inv = relock(root, new_pkg)
    new_pkg = json.dumps(pkg, indent=indent, ensure_ascii=False) + "\n"
    if plan.bumps:
        plan.edits["package.json"] = (original_pkg, new_pkg)
        plan.edits["package-lock.json"] = (original_lock, lock)
    return plan


def _group(findings: list[Finding]) -> dict[tuple[str, str], list[Finding]]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.dependency.ecosystem, normalize(f.dependency.ecosystem, f.dependency.name)), []).append(f)
    return groups


# --- Command --------------------------------------------------------------------

def merged_bumps(plan: Plan) -> list[tuple[str, str, str, str, list[str]]]:
    """One entry per package across rounds: first old version, last new version."""
    merged: dict[tuple[str, str], list] = {}
    for eco, name, old, new, ids in plan.bumps:
        key = (eco, normalize(eco, name))
        if key in merged:
            merged[key][3] = new
            merged[key][4] = sorted(set(merged[key][4]) | set(ids))
        else:
            merged[key] = [eco, name, old, new, list(ids)]
    return [tuple(v) for v in merged.values()]


def changelog_entries(plan: Plan) -> list[str]:
    return [f"Upgraded {eco}:{name} {old} → {new} (fixes {', '.join(ids)})" for eco, name, old, new, ids in merged_bumps(plan)]


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", type=Path, nargs="?", default=Path.cwd(), help="project directory (default: current directory)")
    p.add_argument("--fail-on", choices=config.FAIL_ON_CHOICES, help="lowest severity to remediate (default: low)")
    p.add_argument("--execute", "--apply", dest="execute", action="store_true", help="write changes (default: dry-run)")


def run(args: argparse.Namespace, sess_factory) -> int:
    root = args.path.resolve()
    cfg = config.load_project(root)
    policy = policy_from(cfg, args.fail_on)
    client = OsvClient()
    kind, runtime = runtime_info(cfg, root)
    arch = cfg.get("architecture", "x86_64")
    log.info("Planning %s remediation for %s", kind, root)
    plan = plan_node(root, client, policy) if kind == "node" else plan_python(root, cfg, client, policy, runtime, arch)

    prefix = mode_prefix(args.execute)
    for rel, (old, new) in plan.edits.items():
        if rel == "package-lock.json":
            sys.stdout.write(f"--- package-lock.json regenerated by npm ({len(old.splitlines())} -> {len(new.splitlines())} lines)\n")
        else:
            sys.stdout.write(unified_diff(old, new, rel))
    for eco, name, old, new, ids in merged_bumps(plan):
        log.info("%s %s:%s %s -> %s (%s)", prefix, eco, name, old, new, ", ".join(ids))
    for m in plan.manual:
        WARNINGS.add("remediate", f"needs a manual change: {m}")
    for f in plan.remaining:
        WARNINGS.add("remediate", f"still open after remediation: {f.dependency.ecosystem}:{f.dependency.name} "
                                  f"{f.dependency.version} {f.vuln_id} ({f.severity}; fix: {f.fixed or 'none available'})")

    if args.execute and plan.edits:
        changelog_path = root / "CHANGELOG.md"
        old_log = changelog_path.read_text() if changelog_path.exists() else None
        new_log = changelog.add_unreleased(old_log, changelog_entries(plan))
        for rel, (_, new) in plan.edits.items():
            atomic_write(root / rel, new)
            log.info("[EXECUTE] Wrote %s", root / rel)
        atomic_write(changelog_path, new_log)
        log.info("[EXECUTE] Recorded %d change(s) in CHANGELOG.md [Unreleased]", len(merged_bumps(plan)))
    elif plan.edits:
        log.info("Dry-run: nothing written. Pass --execute to apply these changes.")
    else:
        log.info("No changes to make.")

    sys.stdout.write(f"\nRemediation summary: {len(merged_bumps(plan))} upgrade(s), {len(plan.remaining)} still open, "
                     f"{len(plan.manual)} need manual changes\n")
    return EXIT_FINDINGS if plan.remaining or plan.manual else EXIT_OK
