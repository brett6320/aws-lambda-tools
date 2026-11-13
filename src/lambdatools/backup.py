"""backup: capture a Lambda function's code, configuration, and permissions.

Read-only against AWS. Environment variable values are stored in `pass`
(or redacted when `pass` is unavailable) and never written to backup files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

from lambdatools import __version__
from lambdatools.common import aws, config, secretstore
from lambdatools.common.fsutil import data_dir, ensure_private_dir, refuse_if_tracked_location, utc_now_iso, utc_stamp
from lambdatools.common.log import EXIT_FINDINGS, EXIT_OK, WARNINGS, ToolError, log, mode_prefix

REDACTED = "<redacted>"

NOT_BACKED_UP = [
    "Triggers configured on the source service (S3 notifications, SNS subscriptions, EventBridge rules, "
    "API Gateway integrations, CloudFront/Lambda@Edge associations). Resource policy principals in "
    "policies.json show which services may invoke the function.",
    "CloudWatch Logs log group settings (retention, KMS key, subscription filters).",
    "Container images for Image package type functions (only the image URI is recorded).",
    "Layer contents (layer metadata is recorded in layers.json).",
]


@dataclass
class Collector:
    lam: Any
    missing: list[dict] = field(default_factory=list)
    calls: int = 0

    def get(self, surface: str, fn: Callable[[], Any], empty: Any = None) -> Any:
        """Call fn. Not found means empty; any other error marks the surface unknown."""
        self.calls += 1
        try:
            return fn()
        except ClientError as e:
            code = aws.error_code(e)
            if code in aws.NOT_FOUND:
                return empty
            self.missing.append({"surface": surface, "error": code})
            WARNINGS.add("backup", f"{surface}: {code}; not backed up")
            return None
        except (AttributeError, NotImplementedError) as e:
            self.missing.append({"surface": surface, "error": type(e).__name__})
            WARNINGS.add("backup", f"{surface}: not supported by this boto3 version; not backed up")
            return None

    def paginate(self, surface: str, op: str, key: str, **params) -> list | None:
        def go():
            items = []
            for page in self.lam.get_paginator(op).paginate(**params):
                items.extend(page.get(key, []))
            return items
        return self.get(surface, go, empty=[])


def _drop_metadata(resp: Any) -> Any:
    if isinstance(resp, dict):
        resp = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    return resp


def extract_environment(obj: Any, values: dict, context: str = "$LATEST") -> tuple[set[str], list[str]]:
    """Remove env var values from every config object in obj, in place.

    Values are collected into values[context][key]. Returns the set of
    contexts that had values and any Environment.Error messages.
    """
    contexts: set[str] = set()
    errors: list[str] = []

    def walk(node: Any, ctx: str) -> None:
        if isinstance(node, dict):
            ctx = str(node.get("Version", ctx)) if "FunctionArn" in node else ctx
            env = node.get("Environment")
            if isinstance(env, dict):
                variables = env.get("Variables")
                if isinstance(variables, dict) and variables:
                    values.setdefault(ctx, {}).update(variables)
                    env["Variables"] = {k: REDACTED for k in variables}
                    contexts.add(ctx)
                if env.get("Error"):
                    errors.append(f"{ctx}: {env['Error'].get('ErrorCode', 'Error')}")
            for v in node.values():
                walk(v, ctx)
        elif isinstance(node, list):
            for v in node:
                walk(v, ctx)

    walk(obj, context)
    return contexts, errors


def collect(lam, iam, function: str, qualifier: str | None, include_iam: bool) -> tuple[dict, dict, list[dict]]:
    """Return (files: name -> object, code_info, missing)."""
    c = Collector(lam)
    params = {"FunctionName": function, **({"Qualifier": qualifier} if qualifier else {})}
    try:
        fn = lam.get_function(**params)
    except ClientError as e:
        raise ToolError(f"get_function {function}: {aws.error_code(e)}") from None
    fn = _drop_metadata(fn)
    code_info = dict(fn.get("Code", {}))
    aws.strip_presigned(fn)
    conf = fn["Configuration"]
    name, arn = conf["FunctionName"], conf["FunctionArn"]
    base_arn = arn.split(":function:")[0] + f":function:{name}"

    files: dict[str, Any] = {"function.json": fn}
    versions = c.paginate("versions", "list_versions_by_function", "Versions", FunctionName=name)
    aliases = c.paginate("aliases", "list_aliases", "Aliases", FunctionName=name)
    files["versions.json"] = versions
    files["aliases.json"] = aliases

    qualifiers = [None] + [a["Name"] for a in aliases or []] + [v["Version"] for v in versions or [] if v["Version"] != "$LATEST"]
    policies = {}
    for q in qualifiers:
        kw = {"FunctionName": name, **({"Qualifier": q} if q else {})}
        resp = c.get(f"policy:{q or '$LATEST'}", lambda kw=kw: lam.get_policy(**kw))
        if resp:
            policies[q or "$LATEST"] = {"Policy": json.loads(resp["Policy"]), "RevisionId": resp.get("RevisionId")}
    files["policies.json"] = policies

    esms: dict[str, dict] = {}
    for target in [base_arn] + [f"{base_arn}:{q}" for q in qualifiers if q]:
        for m in c.paginate(f"event-source-mappings:{target}", "list_event_source_mappings", "EventSourceMappings",
                            FunctionName=target) or []:
            esms[m["UUID"]] = m
    for uuid, m in esms.items():
        if m.get("EventSourceMappingArn"):
            tags = c.get(f"event-source-mapping-tags:{uuid}", lambda a=m["EventSourceMappingArn"]: lam.list_tags(Resource=a))
            m["Tags"] = (tags or {}).get("Tags", {})
    files["event-source-mappings.json"] = list(esms.values())

    files["event-invoke-configs.json"] = c.paginate("event-invoke-configs", "list_function_event_invoke_configs",
                                                    "FunctionEventInvokeConfigs", FunctionName=name)
    files["function-urls.json"] = c.paginate("function-urls", "list_function_url_configs", "FunctionUrlConfigs",
                                             FunctionName=name)
    files["concurrency.json"] = {
        "reserved": _drop_metadata(c.get("reserved-concurrency", lambda: lam.get_function_concurrency(FunctionName=name))),
        "provisioned": c.paginate("provisioned-concurrency", "list_provisioned_concurrency_configs",
                                  "ProvisionedConcurrencyConfigs", FunctionName=name),
    }

    signing = _drop_metadata(c.get("code-signing", lambda: lam.get_function_code_signing_config(FunctionName=name)))
    if signing and signing.get("CodeSigningConfigArn"):
        signing["CodeSigningConfig"] = _drop_metadata(c.get(
            "code-signing-config", lambda: lam.get_code_signing_config(CodeSigningConfigArn=signing["CodeSigningConfigArn"])))
    files["code-signing.json"] = signing

    files["recursion.json"] = _drop_metadata(c.get("recursion", lambda: lam.get_function_recursion_config(FunctionName=name)))
    files["runtime-management.json"] = {
        q or "$LATEST": _drop_metadata(c.get(
            f"runtime-management:{q or '$LATEST'}",
            lambda q=q: lam.get_runtime_management_config(FunctionName=name, **({"Qualifier": q} if q else {}))))
        for q in [None] + [v["Version"] for v in versions or [] if v["Version"] != "$LATEST"]
    }
    if hasattr(lam, "get_function_scaling_config"):
        files["scaling.json"] = {
            a["Name"]: _drop_metadata(c.get(f"scaling:{a['Name']}",
                                            lambda q=a["Name"]: lam.get_function_scaling_config(FunctionName=name, Qualifier=q)))
            for a in aliases or []
        }
    files["tags.json"] = (c.get("tags", lambda: lam.list_tags(Resource=base_arn)) or {}).get("Tags", {})

    layers = []
    for layer in conf.get("Layers", []):
        meta = c.get(f"layer:{layer['Arn']}", lambda a=layer["Arn"]: lam.get_layer_version_by_arn(Arn=a))
        layers.append(aws.strip_presigned(_drop_metadata(meta)) if meta else {"LayerVersionArn": layer["Arn"], "unavailable": True})
    files["layers.json"] = layers

    if include_iam:
        files["iam-role.json"] = collect_role(c, iam, conf["Role"])
    return files, code_info, c.missing


def collect_role(c: Collector, iam, role_arn: str) -> dict | None:
    role_name = role_arn.rsplit("/", 1)[-1]
    role = c.get("iam:role", lambda: iam.get_role(RoleName=role_name))
    if role is None:
        return None
    result: dict[str, Any] = {"Role": role["Role"], "AttachedPolicies": [], "InlinePolicies": {}}

    def pages(surface, op, key, **kw):
        def go():
            out = []
            for page in iam.get_paginator(op).paginate(**kw):
                out.extend(page.get(key, []))
            return out
        return c.get(surface, go, empty=[]) or []

    for att in pages("iam:attached-policies", "list_attached_role_policies", "AttachedPolicies", RoleName=role_name):
        pol = c.get(f"iam:policy:{att['PolicyArn']}", lambda a=att["PolicyArn"]: iam.get_policy(PolicyArn=a))
        doc = None
        if pol:
            ver = c.get(f"iam:policy-version:{att['PolicyArn']}", lambda a=att["PolicyArn"], v=pol["Policy"]["DefaultVersionId"]:
                        iam.get_policy_version(PolicyArn=a, VersionId=v))
            doc = ver["PolicyVersion"]["Document"] if ver else None
        result["AttachedPolicies"].append({**att, "Document": doc})
    for pname in pages("iam:inline-policies", "list_role_policies", "PolicyNames", RoleName=role_name):
        pol = c.get(f"iam:inline-policy:{pname}", lambda p=pname: iam.get_role_policy(RoleName=role_name, PolicyName=p))
        result["InlinePolicies"][pname] = pol["PolicyDocument"] if pol else None
    return result


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n").encode()


def write_backup(dest: Path, files: dict[str, bytes]) -> None:
    """Write all files into a temp dir next to dest, then rename it into place."""
    ensure_private_dir(dest.parent)
    tmp = dest.parent / f".{dest.name}.tmp"
    if dest.exists() or tmp.exists():
        raise ToolError(f"{dest} (or a leftover {tmp.name}) already exists; refusing to overwrite it")
    ensure_private_dir(tmp)
    try:
        for name, data in files.items():
            fd = os.open(tmp / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        os.rename(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("function", help="function name or ARN")
    p.add_argument("--qualifier", help="version or alias to back up (default: $LATEST)")
    p.add_argument("--out", type=Path, help="backup root directory (default: $LAMBDA_TOOLS_BACKUP_DIR or the per-user data dir)")
    p.add_argument("--no-iam", action="store_true", help="skip the execution role and its policies")
    p.add_argument("--project", type=Path, default=Path.cwd(), help="directory holding lambda-tools.json")
    p.add_argument("--execute", "--apply", dest="execute", action="store_true", help="write the backup (default: dry-run)")


def run(args: argparse.Namespace, sess_factory) -> int:
    cfg = config.load_project(args.project)
    sess = sess_factory(cfg)
    lam, iam = aws.client(sess, "lambda"), aws.client(sess, "iam")
    caller = aws.caller_account(sess)
    try:
        preflight = lam.get_function_configuration(FunctionName=args.function,
                                                   **({"Qualifier": args.qualifier} if args.qualifier else {}))
    except ClientError as e:
        raise ToolError(f"get_function_configuration {args.function}: {aws.error_code(e)}") from None
    aws.check_function_scope(preflight["FunctionArn"], caller, cfg.get("account_id"), sess.region_name)
    del preflight  # holds environment values; the redacted copy comes from collect()

    files, code_info, missing = collect(lam, iam, args.function, args.qualifier, include_iam=not args.no_iam)
    conf = files["function.json"]["Configuration"]
    arn, name = conf["FunctionArn"], conf["FunctionName"]
    account, region = arn.split(":")[4], arn.split(":")[3]

    values: dict[str, dict] = {}
    contexts, env_errors = extract_environment(files, values)
    for err in env_errors:
        ctx, _, code = err.partition(": ")
        missing.append({"surface": f"environment:{ctx}", "error": code})
        WARNINGS.add("backup", f"environment of {err}: Lambda could not return values (KMS); not backed up")

    backup_id = utc_stamp()
    root = config.resolve(args.out, "LAMBDA_TOOLS_BACKUP_DIR", None, None, data_dir() / "backups")
    dest = Path(root).expanduser() / account / region / name / backup_id
    refuse_if_tracked_location(dest, "backup")

    pass_ok, pass_reason = secretstore.availability()
    pass_path = secretstore.entry_path("lambda-tools", account, region, name, backup_id) if values and pass_ok else None
    env_mode = "none" if not values else "pass" if pass_ok else "redacted"
    if env_errors:
        env_mode = "unavailable" if env_mode == "none" else env_mode
    if values and not pass_ok:
        WARNINGS.add("backup", f"{pass_reason}; environment variable values are redacted in this backup")

    prefix = mode_prefix(args.execute)
    is_image = conf.get("PackageType") == "Image"
    log.info("%s Backup of %s -> %s", prefix, arn, dest)
    for fname in files:
        log.info("%s   %s", prefix, fname)
    if not is_image:
        log.info("%s   code.zip (%s bytes, sha256 %s)", prefix, conf.get("CodeSize"), conf.get("CodeSha256"))
    if pass_path:
        log.info("%s Environment values for %s -> pass:%s", prefix, ", ".join(sorted(contexts)), pass_path)

    manifest = {
        "tool": "lambda-tools", "tool_version": __version__, "created_at": utc_now_iso(), "backup_id": backup_id,
        "function_arn": arn, "account": account, "region": region, "qualifier": args.qualifier,
        "complete": not missing, "missing": missing,
        "environment": {"values": env_mode, "pass_path": pass_path, "contexts": sorted(contexts), "errors": env_errors},
        "code": {"package_type": conf.get("PackageType", "Zip"), "sha256": conf.get("CodeSha256"),
                 "image_uri": code_info.get("ImageUri"), "resolved_image_uri": code_info.get("ResolvedImageUri")},
        "not_backed_up": NOT_BACKED_UP,
    }

    if args.execute:
        payload = {name_: _dump(obj) for name_, obj in files.items()}
        if not is_image:
            payload["code.zip"] = aws.download_verified(code_info["Location"], conf["CodeSha256"], "function code")
        manifest["files"] = {n: hashlib.sha256(d).hexdigest() for n, d in sorted(payload.items())}
        payload["manifest.json"] = _dump(manifest)
        if pass_path:
            secretstore.insert(pass_path, json.dumps({"function_arn": arn, "backup_id": backup_id, "values": values}, indent=2))
            log.info("[EXECUTE] Stored environment values in pass:%s", pass_path)
        try:
            write_backup(dest, payload)
        except BaseException:
            if pass_path:
                log.error("Backup files were not written; pass entry %s is orphaned (remove: pass rm %s)", pass_path, pass_path)
            raise
        log.info("[EXECUTE] Wrote backup %s", dest)
    else:
        log.info("Dry-run: nothing written. Pass --execute to write the backup.")

    out = {"backup": str(dest), "function_arn": arn, "complete": not missing, "missing": missing,
           "environment_values": env_mode, "pass_path": pass_path, "written": bool(args.execute)}
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    if missing:
        log.error("Backup is incomplete: %d surface(s) could not be read; see manifest.json 'missing'", len(missing))
        return EXIT_FINDINGS
    return EXIT_OK
