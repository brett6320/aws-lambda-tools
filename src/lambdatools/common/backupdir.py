"""Read a backup directory written by `lambda-tools backup`, verifying it first."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from lambdatools.common.log import ToolError

NOTE_LAYERS = "Layer contents are not stored in backups; layers listed in layers.json were not scanned."


@dataclass
class Backup:
    path: Path
    manifest: dict

    @property
    def function(self) -> dict:
        return self.json("function.json")

    @property
    def configuration(self) -> dict:
        return self.function["Configuration"]

    @property
    def is_image(self) -> bool:
        return self.manifest.get("code", {}).get("package_type") == "Image"

    @property
    def label(self) -> str:
        return f"backup {self.manifest.get('backup_id')} of {self.manifest.get('function_arn')}"

    def json(self, name: str):
        return json.loads((self.path / name).read_text())

    def code(self) -> bytes:
        if self.is_image:
            raise ToolError(f"{self.label} is a container image function; its backup holds only the image URI")
        return (self.path / "code.zip").read_bytes()


def is_backup(path: Path) -> bool:
    manifest = path / "manifest.json"
    if not path.is_dir() or not manifest.is_file():
        return False
    try:
        return json.loads(manifest.read_text()).get("tool") == "lambda-tools"
    except (json.JSONDecodeError, AttributeError):
        return False


def load(path: Path) -> Backup:
    """Load a backup and check every file against the sha256 in its manifest."""
    if not is_backup(path):
        raise ToolError(f"{path} is not a lambda-tools backup (no manifest.json written by `lambda-tools backup`)")
    manifest = json.loads((path / "manifest.json").read_text())
    files = manifest.get("files")
    if not isinstance(files, dict) or "function.json" not in files:
        raise ToolError(f"{path}/manifest.json has no file checksums; the backup is incomplete or was not written with --execute")
    for name, digest in files.items():
        target = path / name
        if "/" in name or name.startswith(".") or not target.is_file():
            raise ToolError(f"{path}: file {name!r} listed in manifest.json is missing")
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise ToolError(f"{path}: {name} does not match its checksum in manifest.json; the backup was modified")
    return Backup(path=path, manifest=manifest)
