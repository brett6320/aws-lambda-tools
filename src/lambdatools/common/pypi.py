"""Latest stable releases from PyPI's JSON API (stdlib only).

Used by `package` to check that requirements not pinned with == resolved to
the newest stable release. The check is advisory: when PyPI can't be reached
or doesn't know the package (a private index), the caller reports the
package as unchecked rather than failing the build.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from packaging.tags import Tag
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from lambdatools import __version__
from lambdatools.common.log import log

API = "https://pypi.org/pypi/{name}/json"
TIMEOUT = 30


def latest_stable(name: str) -> tuple[str, list[dict]] | None:
    """(version, release files) of the newest non-prerelease, non-yanked release; None if unknown."""
    url = API.format(name=urllib.parse.quote(canonicalize_name(name)))
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"lambda-tools/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (OSError, ValueError) as e:  # HTTPError (e.g. 404 for a private package) is an OSError
        log.debug("PyPI lookup for %s failed: %s", name, e)
        return None
    best: tuple[Version, str, list[dict]] | None = None
    for raw, files in (data.get("releases") or {}).items():
        try:
            version = Version(raw)
        except InvalidVersion:
            continue
        live = [f for f in files or [] if isinstance(f, dict) and not f.get("yanked")]
        if version.is_prerelease or version.is_devrelease or not live:
            continue
        if best is None or version > best[0]:
            best = (version, raw, live)
    return (best[1], best[2]) if best else None


def _fits(tag: Tag, py: str, arch: str) -> bool:
    """Whether a wheel tag installs on Lambda's Linux for CPython `py` (e.g. "312") and `arch`."""
    machine = "aarch64" if arch == "arm64" else "x86_64"
    if tag.platform != "any" and not (tag.platform.startswith(("manylinux", "linux")) and tag.platform.endswith(machine)):
        return False
    if tag.interpreter in ("py3", f"py{py[0]}", f"cp{py}"):
        return True
    # abi3 wheels built for an older CPython 3.x also install on newer ones
    return tag.abi == "abi3" and tag.interpreter.startswith("cp3") and int(tag.interpreter[3:] or 0) <= int(py[1:])


def has_compatible_wheel(files: list[dict], runtime: str, arch: str) -> bool:
    py = runtime.removeprefix("python").replace(".", "")
    for f in files:
        filename = f.get("filename", "")
        if not filename.endswith(".whl"):
            continue
        try:
            _, _, _, tags = parse_wheel_filename(filename)
        except InvalidWheelFilename:
            continue
        if any(_fits(t, py, arch) for t in tags):
            return True
    return False
