import io
import json

import pytest

from lambdatools.common.log import WARNINGS


class FakeOsv:
    """urlopen stand-in: affected maps (ecosystem, name, version) -> vuln ids."""

    def __init__(self, affected=None, vulns=None, fail=False):
        self.affected = affected or {}
        self.vulns = vulns or {}
        self.fail = fail
        self.requests = []

    def __call__(self, req, timeout=None):
        if self.fail:
            raise OSError("network unreachable")
        self.requests.append(req.full_url)
        if req.full_url.endswith("/v1/querybatch"):
            body = json.loads(req.data)
            results = []
            for q in body["queries"]:
                key = (q["package"]["ecosystem"], q["package"]["name"].lower(), q["version"])
                ids = self.affected.get(key, [])
                results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            payload = {"results": results}
        else:
            payload = self.vulns[req.full_url.rsplit("/", 1)[1]]
        return io.BytesIO(json.dumps(payload).encode())


def vuln(vid, ecosystem, name, fixed=None, severity=None, aliases=(), cvss=None, introduced="0"):
    events = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])
    v = {
        "id": vid,
        "aliases": list(aliases),
        "summary": f"{name} problem",
        "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                      "ranges": [{"type": "ECOSYSTEM", "events": events}]}],
    }
    if severity:
        v["database_specific"] = {"severity": severity}
    if cvss:
        v["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    return v


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(tmp_path / "no-store"))
    monkeypatch.delenv("LAMBDA_TOOLS_FAIL_ON", raising=False)
    monkeypatch.delenv("LAMBDA_TOOLS_BACKUP_DIR", raising=False)
    yield
    WARNINGS._items.clear()
