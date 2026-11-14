"""scan: find known vulnerabilities in a function's or project's dependencies."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from botocore.exceptions import ClientError

from lambdatools.common import aws, backupdir, config, runtimes
from lambdatools.common.fsutil import atomic_write, refuse_if_tracked_location, utc_now_iso
from lambdatools.common.inventory import Inventory, Tree, ZipTree, build_inventory, open_path
from lambdatools.common.log import EXIT_FINDINGS, EXIT_OK, WARNINGS, ToolError, log
from lambdatools.common.osv import Finding, OsvClient, Policy, evaluate
from lambdatools.common.sanitize import clean

NOTE_RUNTIME = (
    "Packages provided by the Lambda runtime itself (for example boto3 in Python "
    "runtimes) are not in the deployment package and are not scanned."
)


@dataclass
class ScanResult:
    target: str
    inventory: Inventory
    findings: list[Finding]
    policy: Policy
    notes: list[str] = field(default_factory=list)
    runtime: runtimes.RuntimeStatus | None = None

    @property
    def failing(self) -> list[Finding]:
        return [f for f in self.findings if self.policy.fails(f)]

    def exit_code(self, allow_gaps: bool, allow_deprecated_runtime: bool = False) -> int:
        deprecated = self.runtime is not None and self.runtime.level == "deprecated" and not allow_deprecated_runtime
        if self.failing or (self.inventory.gaps and not allow_gaps) or deprecated:
            return EXIT_FINDINGS
        return EXIT_OK

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_at": utc_now_iso(),
            "fail_on": self.policy.fail_on,
            "dependencies": [d.to_dict() for d in self.inventory.sorted()],
            "findings": [f.to_dict() for f in self.findings],
            "coverage_gaps": self.inventory.gaps,
            "notes": self.notes,
            "runtime": ({"runtime": self.runtime.runtime, "status": self.runtime.level, "message": self.runtime.message,
                         "newest": self.runtime.newest} if self.runtime else None),
            "summary": summary(self),
        }


def summary(result: ScanResult) -> dict:
    counts: dict[str, int] = {}
    for f in result.findings:
        if not f.ignored:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "dependencies": len(result.inventory.dependencies),
        "findings": counts,
        "ignored": sum(1 for f in result.findings if f.ignored),
        "failing": len(result.failing),
        "coverage_gaps": len(result.inventory.gaps),
    }


def policy_from(cfg: config.ProjectConfig | None, fail_on: str | None) -> Policy:
    level = config.resolve(fail_on, "LAMBDA_TOOLS_FAIL_ON", cfg, "fail_on", "low")
    if level not in config.FAIL_ON_CHOICES:
        raise ToolError(f"LAMBDA_TOOLS_FAIL_ON must be one of {', '.join(config.FAIL_ON_CHOICES)}")
    return Policy(fail_on=level, ignore=(cfg.get("ignore", []) if cfg else []))


def scan_trees(target: str, trees: list[Tree], policy: Policy, client: OsvClient, include_dev: bool = False,
               notes: list[str] | None = None, gaps: list[str] | None = None,
               installed: bool | None = None) -> ScanResult:
    inv = Inventory(label=target)
    for tree in trees:
        inv.merge(build_inventory(tree, include_dev=include_dev, installed=installed))
    for g in gaps or []:
        inv.gap(g)
    deps = inv.sorted()
    log.info("Inventoried %d dependencies in %s; querying OSV", len(deps), target)
    findings, policy_warnings = evaluate(deps, client, policy) if deps else ([], [])
    for w in policy_warnings:
        WARNINGS.add(target, w)
    return ScanResult(target=target, inventory=inv, findings=findings, policy=policy, notes=notes or [])


def function_trees(sess, function: str, qualifier: str | None,
                   cfg: config.ProjectConfig | None) -> tuple[str, list[Tree], list[str], list[str], str | None]:
    """Download a function's code and layers (verified) as in-memory trees."""
    lam = aws.client(sess, "lambda")
    params = {"FunctionName": function, **({"Qualifier": qualifier} if qualifier else {})}
    try:
        fn = lam.get_function(**params)
    except ClientError as e:
        raise ToolError(f"get_function {function}: {aws.error_code(e)}") from None
    conf = fn["Configuration"]
    aws.check_function_scope(conf["FunctionArn"], aws.caller_account(sess),
                             cfg.get("account_id") if cfg else None, sess.region_name)
    if conf.get("PackageType") == "Image":
        raise ToolError(
            f"{conf['FunctionName']} is a container image function ({fn['Code'].get('ImageUri')}); "
            "scan the image with a container scanner such as Amazon Inspector"
        )
    target = conf["FunctionArn"]
    trees: list[Tree] = [ZipTree(aws.download_verified(fn["Code"]["Location"], conf["CodeSha256"], "function code"), "function")]
    notes = [NOTE_RUNTIME]
    gaps: list[str] = []
    for layer in conf.get("Layers", []):
        arn = layer["Arn"]
        try:
            meta = lam.get_layer_version_by_arn(Arn=arn)
        except ClientError as e:
            gaps.append(f"layer {arn}: cannot read ({aws.error_code(e)}); not scanned")
            continue
        content = meta["Content"]
        trees.append(ZipTree(aws.download_verified(content["Location"], content["CodeSha256"], f"layer {arn}"), f"layer:{arn}"))
    return target, trees, notes, gaps, conf.get("Runtime")


def backup_trees(path: Path) -> tuple[str, list[Tree], list[str], list[str], str | None]:
    """Scan a backup's verified code.zip; layers are not in backups, so they are a gap."""
    backup = backupdir.load(path)
    gaps = [f"layer {layer.get('Arn')}: contents are not stored in backups; not scanned"
            for layer in backup.configuration.get("Layers", [])]
    return (backup.label, [ZipTree(backup.code(), f"{path.name}/code.zip")], [NOTE_RUNTIME], gaps,
            backup.configuration.get("Runtime"))


def render_text(result: ScanResult, out=None) -> None:
    out = out or sys.stdout
    s = summary(result)
    out.write(f"Target: {clean(result.target)}\n")
    out.write(f"Dependencies scanned: {s['dependencies']}\n\n")
    if result.findings:
        rows = [("SEVERITY", "PACKAGE", "VERSION", "FIX", "ID", "SUMMARY")]
        for f in result.findings:
            sev = f.severity + (" (ignored)" if f.ignored else "")
            ident = f.vuln_id + (f" ({', '.join(f.aliases[:2])})" if f.aliases else "")
            rows.append((sev, f"{f.dependency.ecosystem}:{f.dependency.name}", f.dependency.version,
                         f.fixed or "none", ident, f.summary[:70]))
        widths = [max(len(r[i]) for r in rows) for i in range(5)]
        for r in rows:
            out.write("  ".join(r[i].ljust(widths[i]) for i in range(5)) + "  " + r[5] + "\n")
        out.write("\n")
    else:
        out.write("No known vulnerabilities found.\n\n")
    out.write("Coverage:\n")
    if result.inventory.gaps:
        for g in result.inventory.gaps:
            out.write(f"  NOT SCANNED  {clean(g)}\n")
    else:
        out.write("  All dependency manifests found were scanned.\n")
    for n in result.notes:
        out.write(f"  NOTE  {clean(n)}\n")
    if result.runtime:
        label = {"ok": "OK", "warn": "WARNING", "deprecated": "DEPRECATED"}[result.runtime.level]
        out.write(f"\nRuntime:\n  {label}  {clean(result.runtime.message)}\n")
    findings = ", ".join(f"{k.lower()}={v}" for k, v in sorted(s["findings"].items())) or "none"
    out.write(f"\nSummary: findings {findings}; ignored {s['ignored']}; failing (fail-on {result.policy.fail_on}) "
              f"{s['failing']}; coverage gaps {s['coverage_gaps']}\n")


def add_arguments(p: argparse.ArgumentParser) -> None:
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("path", nargs="?", type=Path, help="project directory or deployment zip to scan")
    src.add_argument("--function", metavar="FUNCTION",
                     help="deployed function to scan: name, ARN, or partial ARN (downloads code and layers); give a version or alias with --qualifier")
    p.add_argument("--qualifier", help="version or alias, with --function")
    p.add_argument("--project", type=Path, help="directory holding lambda-tools.json (default: PATH, or current directory)")
    p.add_argument("--fail-on", choices=config.FAIL_ON_CHOICES, help="lowest severity that fails (default: low)")
    p.add_argument("--allow-gaps", action="store_true", help="do not fail when some dependencies could not be scanned")
    p.add_argument("--allow-deprecated-runtime", action="store_true",
                   help="do not fail when the function's runtime is deprecated (it is still reported)")
    p.add_argument("--include-dev", action="store_true", help="include npm devDependencies from package-lock.json")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--report", type=Path, help="also write the JSON report to this file")


def run(args: argparse.Namespace, sess_factory) -> int:
    project_dir = args.project or (args.path if args.path and args.path.is_dir() else Path.cwd())
    cfg = config.load_project(project_dir)
    policy = policy_from(cfg, args.fail_on)
    client = OsvClient()
    if args.function:
        target, trees, notes, gaps, runtime = function_trees(sess_factory(cfg), args.function, args.qualifier, cfg)
    elif backupdir.is_backup(args.path):
        target, trees, notes, gaps, runtime = backup_trees(args.path)
    else:
        target, trees, notes, gaps = str(args.path), [open_path(args.path)], [NOTE_RUNTIME], []
        runtime = cfg.get("runtime")
    result = scan_trees(target, trees, policy, client, include_dev=args.include_dev, notes=notes, gaps=gaps)
    result.runtime = runtimes.report(runtime, "scan")

    report = result.to_dict()
    if args.report:
        refuse_if_tracked_location(args.report, "report")
        atomic_write(args.report, json.dumps(report, indent=2) + "\n", mode=0o600)
        log.info("Wrote report to %s", args.report)
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        render_text(result)
    return result.exit_code(args.allow_gaps, args.allow_deprecated_runtime)
