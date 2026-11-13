"""AWS session helpers, identity checks, and verified code downloads."""

from __future__ import annotations

import base64
import hashlib
import os
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from lambdatools import __version__
from lambdatools.common.log import WARNINGS, ToolError, log

MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024
NOT_FOUND = {"ResourceNotFoundException", "NoSuchEntity", "NotFoundException"}


def resolve_region(flag: str | None, cfg=None) -> str | None:
    """--region > AWS_REGION / AWS_DEFAULT_REGION > region in lambda-tools.json; None leaves it to the profile."""
    override = flag or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    configured = cfg.get("region") if cfg is not None else None
    if override and configured and override != configured:
        WARNINGS.add("aws", f"region {override} (from --region or AWS_REGION) overrides region {configured} "
                            f"in {cfg.path}")
    return override or configured


def session(profile: str | None, region: str | None) -> boto3.Session:
    log.debug("Using profile=%s region=%s", profile or "default", region or "default")
    s = boto3.Session(profile_name=profile, region_name=region)
    if not s.region_name:
        raise ToolError("no AWS region configured; pass --region or set AWS_REGION")
    return s


def client(sess: boto3.Session, service: str):
    config = Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra=f"lambda-tools/{__version__}")
    return sess.client(service, config=config)


def error_code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "Unknown")


def caller_account(sess: boto3.Session) -> str:
    try:
        return client(sess, "sts").get_caller_identity()["Account"]
    except ClientError as e:
        raise ToolError(f"cannot verify AWS identity ({error_code(e)}); check credentials") from None


def check_function_scope(function_arn: str, caller: str, expected_account: str | None, session_region: str | None) -> None:
    """One identity per scope: the function must belong to the caller's account and the session's region.

    The session region already reflects --region > AWS_REGION > lambda-tools.json, so it is the one to check.
    """
    parts = function_arn.split(":")
    account, region = parts[4], parts[3]
    if account != caller:
        raise ToolError(f"function {function_arn} belongs to account {account}, but credentials are for {caller}")
    if expected_account and account != expected_account:
        raise ToolError(f"function account {account} does not match account_id {expected_account} in lambda-tools.json")
    if session_region and region != session_region:
        raise ToolError(f"function {function_arn} is in region {region}, but this run uses region {session_region} "
                        "(set with --region, AWS_REGION, or region in lambda-tools.json)")


def download_verified(url: str, expected_sha256_b64: str, what: str) -> bytes:
    """Download a presigned code URL and verify it against Lambda's CodeSha256."""
    req = urllib.request.Request(url, headers={"User-Agent": f"lambda-tools/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except OSError as e:
        raise ToolError(f"download of {what} failed: {e}") from None
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ToolError(f"{what} exceeds {MAX_DOWNLOAD_BYTES} bytes; refusing to read")
    actual = base64.b64encode(hashlib.sha256(data).digest()).decode()
    if actual != expected_sha256_b64:
        raise ToolError(f"{what} checksum mismatch (expected {expected_sha256_b64}, got {actual})")
    return data


def strip_presigned(obj):
    """Remove presigned download URLs (Code.Location, Content.Location) in place."""
    if isinstance(obj, dict):
        for key in ("Code", "Content"):
            inner = obj.get(key)
            if isinstance(inner, dict) and "Location" in inner:
                inner.pop("Location")
        for value in obj.values():
            strip_presigned(value)
    elif isinstance(obj, list):
        for value in obj:
            strip_presigned(value)
    return obj
