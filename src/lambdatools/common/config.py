"""Project configuration (lambda-tools.json) and release state.

Precedence: CLI flag > environment variable > config file > built-in default.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from lambdatools.common.fsutil import atomic_write
from lambdatools.common.log import ToolError

CONFIG_NAME = "lambda-tools.json"
STATE_DIR = ".lambda-tools"
STATE_NAME = "release-state.json"

SEVERITIES = ("low", "medium", "high", "critical")
FAIL_ON_CHOICES = (*SEVERITIES, "none")
RUNTIME_RE = re.compile(r"^(python3\.\d+|nodejs\d+\.x)$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
# X.Y.Z, or YYYY.MM.DD.N (a same-day rebuild) when versioning is "date"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:\.\d+)?$")
VERSIONING_CHOICES = ("semver", "date")


def _str(v: Any) -> bool:
    return isinstance(v, str) and v != ""


def _str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _ignore_list(v: Any) -> bool:
    if not isinstance(v, list):
        return False
    for item in v:
        if not isinstance(item, dict) or set(item) - {"id", "reason", "expires"}:
            return False
        if not all(_str(item.get(k)) for k in ("id", "reason", "expires")):
            return False
        try:
            date.fromisoformat(item["expires"])
        except ValueError:
            return False
    return True


# key -> (validator, description used in error messages)
SCHEMA: dict[str, tuple] = {
    "name": (lambda v: _str(v) and re.match(r"^[A-Za-z0-9._-]+$", v), "a name of letters, digits, '.', '_' or '-'"),
    "function_name": (_str, "a Lambda function name or ARN"),
    "runtime": (lambda v: _str(v) and RUNTIME_RE.match(v), "a Lambda runtime such as python3.12 or nodejs20.x"),
    "architecture": (lambda v: v in ("x86_64", "arm64"), "x86_64 or arm64"),
    "version": (lambda v: _str(v) and VERSION_RE.match(v), "a version X.Y.Z (or YYYY.MM.DD[.N] with date versioning)"),
    "versioning": (lambda v: v in VERSIONING_CHOICES, f"one of {', '.join(VERSIONING_CHOICES)}"),
    "handler": (_str, "a handler string"),
    "requirements": (_str, "a path to a requirements file"),
    "exclude": (_str_list, "a list of glob patterns"),
    "fail_on": (lambda v: v in FAIL_ON_CHOICES, f"one of {', '.join(FAIL_ON_CHOICES)}"),
    "ignore": (_ignore_list, "a list of {id, reason, expires: YYYY-MM-DD}"),
    "account_id": (lambda v: _str(v) and re.match(r"^\d{12}$", v), "a 12-digit AWS account ID"),
    "region": (_str, "an AWS region"),
}


@dataclass
class ProjectConfig:
    path: Path
    data: dict = field(default_factory=dict)
    raw_text: str | None = None

    @property
    def root(self) -> Path:
        return self.path.parent

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


def validate(data: Any, source: Path) -> dict:
    if not isinstance(data, dict):
        raise ToolError(f"{source}: top level must be a JSON object")
    for key, value in data.items():
        if key not in SCHEMA:
            raise ToolError(f"{source}: unknown key {key!r} (allowed: {', '.join(sorted(SCHEMA))})")
        check, description = SCHEMA[key]
        if not check(value):
            raise ToolError(f"{source}: key {key!r} must be {description}")
    if data.get("versioning", "semver") != "date" and str(data.get("version", "")).count(".") == 3:
        raise ToolError(f"{source}: a four-part version needs \"versioning\": \"date\"")
    return data


def load_project(root: Path, required: bool = False) -> ProjectConfig:
    path = root / CONFIG_NAME
    if not path.exists():
        if required:
            raise ToolError(f"{path} not found; create it (see README: Configuration)")
        return ProjectConfig(path=path)
    text = path.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ToolError(f"{path}: invalid JSON: {e}") from None
    return ProjectConfig(path=path, data=validate(data, path), raw_text=text)


def render(data: dict) -> str:
    return json.dumps(data, indent=2) + "\n"


def save_project(cfg: ProjectConfig, data: dict) -> None:
    text = render(validate(data, cfg.path))
    validate(json.loads(text), cfg.path)
    atomic_write(cfg.path, text)


def resolve(flag: Any, env_name: str | None, cfg: ProjectConfig | None, key: str | None, default: Any) -> Any:
    """Apply flag > env > config > default."""
    if flag is not None:
        return flag
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    if cfg is not None and key and key in cfg.data:
        return cfg.data[key]
    return default


def state_path(root: Path) -> Path:
    return root / STATE_DIR / STATE_NAME


def load_state(root: Path) -> dict:
    path = state_path(root)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ToolError(f"{path}: invalid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ToolError(f"{path}: top level must be a JSON object")
    return data


def save_state(root: Path, state: dict) -> None:
    atomic_write(state_path(root), json.dumps(state, indent=2, sort_keys=True) + "\n")
