"""OSV.dev client, severity scoring, and fix-version selection."""

from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import date

from lambdatools import __version__
from lambdatools.common import versions
from lambdatools.common.inventory import Dependency, normalize
from lambdatools.common.log import ToolError, log
from lambdatools.common.sanitize import clean, valid_version

DEFAULT_URL = "https://api.osv.dev"
BATCH_LIMIT = 1000
SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 5}


class OsvError(ToolError):
    pass


# --- CVSS v3 base score -------------------------------------------------------

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3["C"][m["C"]]) * (1 - _CVSS3["I"][m["I"]]) * (1 - _CVSS3["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploitability = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10.0))


def rating(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def severity_of(vuln: dict) -> str:
    labels = []
    for holder in [vuln, *vuln.get("affected", [])]:
        label = (holder.get("database_specific") or {}).get("severity")
        if isinstance(label, str):
            labels.append("MEDIUM" if label.upper() == "MODERATE" else label.upper())
    labels = [l for l in labels if l in SEVERITY_RANK]
    if labels:
        return max(labels, key=SEVERITY_RANK.__getitem__)
    scores = [cvss3_score(s.get("score", "")) for s in vuln.get("severity", []) if s.get("type") == "CVSS_V3"]
    scores = [s for s in scores if s is not None]
    return rating(max(scores)) if scores else "UNKNOWN"


# --- Findings -----------------------------------------------------------------

@dataclass
class Finding:
    dependency: Dependency
    vuln_id: str
    aliases: list[str]
    severity: str
    summary: str
    fixed: str | None
    ignored: str | None = None

    def ids(self) -> set[str]:
        return {self.vuln_id, *self.aliases}

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.dependency.ecosystem,
            "package": self.dependency.name,
            "version": self.dependency.version,
            "id": self.vuln_id,
            "aliases": self.aliases,
            "severity": self.severity,
            "summary": self.summary,
            "fixed": self.fixed,
            "ignored": self.ignored,
            "sources": self.dependency.sources,
        }


def fixed_version(vuln: dict, dep: Dependency) -> str | None:
    """Smallest fixed version greater than the installed one, or None."""
    current = versions.parse(dep.ecosystem, dep.version)
    if current is None:
        return None
    candidates = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != dep.ecosystem or normalize(dep.ecosystem, pkg.get("name", "")) != normalize(dep.ecosystem, dep.name):
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                # The string is written into requirements/package.json: accept only clean versions.
                parsed = versions.parse(dep.ecosystem, fixed) if isinstance(fixed, str) and valid_version(fixed) else None
                if parsed is not None and parsed > current:
                    candidates.append((parsed, fixed))
    return min(candidates)[1] if candidates else None


# --- Client -------------------------------------------------------------------

class OsvClient:
    def __init__(self, base_url: str | None = None, timeout: float = 30.0, opener=None):
        self.base_url = (base_url or os.environ.get("LAMBDA_TOOLS_OSV_URL") or DEFAULT_URL).rstrip("/")
        self.timeout = timeout
        self._open = opener or urllib.request.urlopen
        self._vulns: dict[str, dict] = {}

    def _request(self, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method="POST" if data else "GET",
            headers={"Content-Type": "application/json", "User-Agent": f"lambda-tools/{__version__}"},
        )
        try:
            with self._open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            raise OsvError(f"OSV request {path} failed ({e}); scan results are unknown, not clean") from None

    def query_batch(self, deps: list[Dependency]) -> list[list[str]]:
        """Vulnerability IDs affecting each dependency, in input order."""
        results: list[list[str]] = [[] for _ in deps]
        pending = [(i, None) for i in range(len(deps))]
        while pending:
            chunk, pending = pending[:BATCH_LIMIT], pending[BATCH_LIMIT:]
            queries = []
            for i, token in chunk:
                q = {"package": {"ecosystem": deps[i].ecosystem, "name": deps[i].name}, "version": deps[i].version}
                if token:
                    q["page_token"] = token
                queries.append(q)
            log.debug("OSV querybatch with %d queries", len(queries))
            answer = self._request("/v1/querybatch", {"queries": queries}).get("results", [])
            if len(answer) != len(chunk):
                raise OsvError("OSV returned a different number of results than queries; scan results are unknown")
            for (i, _), res in zip(chunk, answer):
                results[i].extend(v["id"] for v in res.get("vulns", []) if isinstance(v.get("id"), str))
                if res.get("next_page_token"):
                    pending.append((i, res["next_page_token"]))
        return results

    def vuln(self, vuln_id: str) -> dict:
        if vuln_id not in self._vulns:
            self._vulns[vuln_id] = self._request(f"/v1/vulns/{urllib.request.quote(vuln_id, safe='')}")
        return self._vulns[vuln_id]


# --- Evaluation ---------------------------------------------------------------

@dataclass
class Policy:
    fail_on: str = "low"
    ignore: list[dict] = field(default_factory=list)
    today: date = field(default_factory=date.today)

    def threshold(self) -> int | None:
        return None if self.fail_on == "none" else SEVERITY_RANK[self.fail_on.upper()]

    def fails(self, finding: Finding) -> bool:
        limit = self.threshold()
        # UNKNOWN ranks above CRITICAL, so it fails whenever anything does.
        return limit is not None and not finding.ignored and SEVERITY_RANK[finding.severity] >= limit

    def ignore_reason(self, ids: set[str]) -> tuple[str | None, str | None]:
        """(reason if ignored, warning if an ignore entry has expired)."""
        for entry in self.ignore:
            if entry["id"] in ids:
                if date.fromisoformat(entry["expires"]) < self.today:
                    return None, f"ignore entry for {entry['id']} expired on {entry['expires']}"
                return f"{entry['reason']} (until {entry['expires']})", None
        return None, None


def evaluate(deps: list[Dependency], client: OsvClient, policy: Policy) -> tuple[list[Finding], list[str]]:
    """Return findings (deduplicated by alias) and policy warnings."""
    ids_per_dep = client.query_batch(deps)
    findings: list[Finding] = []
    warnings: list[str] = []
    for dep, ids in zip(deps, ids_per_dep):
        merged: list[Finding] = []
        for vuln_id in dict.fromkeys(ids):
            vuln = client.vuln(vuln_id)
            if vuln.get("withdrawn"):
                continue
            aliases = sorted({a for a in vuln.get("aliases", []) if isinstance(a, str)} - {vuln_id})
            finding = Finding(
                dependency=dep,
                vuln_id=clean(vuln_id, 64),
                aliases=[clean(a, 64) for a in aliases],
                severity=severity_of(vuln),
                summary=clean(vuln.get("summary") or vuln.get("details") or "", 160),
                fixed=fixed_version(vuln, dep),
            )
            twin = next((f for f in merged if f.ids() & finding.ids()), None)
            if twin is None:
                merged.append(finding)
                continue
            # A known severity from any alias beats UNKNOWN; otherwise keep the highest.
            if twin.severity == "UNKNOWN" or (
                finding.severity != "UNKNOWN" and SEVERITY_RANK[finding.severity] > SEVERITY_RANK[twin.severity]
            ):
                twin.severity = finding.severity
            twin.aliases = sorted((twin.ids() | finding.ids()) - {twin.vuln_id})
            if finding.fixed and (not twin.fixed or versions.parse(dep.ecosystem, finding.fixed) > versions.parse(dep.ecosystem, twin.fixed)):
                twin.fixed = finding.fixed
        for f in merged:
            f.ignored, warning = policy.ignore_reason(f.ids())
            if warning:
                warnings.append(warning)
        findings.extend(merged)
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.dependency.key, f.vuln_id))
    return findings, warnings


def package_fix(findings: list[Finding]) -> tuple[str | None, list[Finding]]:
    """Highest per-vulnerability fix for one package and the findings with no fix."""
    eco = findings[0].dependency.ecosystem
    fixes = [f.fixed for f in findings if f.fixed]
    return versions.max_version(eco, fixes), [f for f in findings if not f.fixed]
