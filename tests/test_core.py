import io
import json
import zipfile
from datetime import date

import pytest

from conftest import FakeOsv, vuln
from lambdatools.common import changelog, config, versions
from lambdatools.common.inventory import DirTree, ZipTree, build_inventory
from lambdatools.common.log import ToolError
from lambdatools.common.osv import OsvClient, OsvError, Policy, cvss3_score, evaluate, severity_of
from lambdatools.common.sanitize import clean


# --- versions -------------------------------------------------------------------

def test_pep440_ordering():
    assert versions.parse("PyPI", "1.0.post1") > versions.parse("PyPI", "1.0")
    assert versions.parse("PyPI", "1!0.1") > versions.parse("PyPI", "2.0")
    assert versions.parse("PyPI", "2.0rc1") < versions.parse("PyPI", "2.0")


def test_semver_ordering():
    assert versions.parse("npm", "1.0.0-alpha") < versions.parse("npm", "1.0.0-alpha.1") < versions.parse("npm", "1.0.0")
    assert versions.parse("npm", "1.0.0-2") < versions.parse("npm", "1.0.0-alpha")
    assert versions.parse("npm", "1.10.0") > versions.parse("npm", "1.9.9")
    assert versions.parse("npm", "not-a-version") is None


def test_bump_and_compare():
    assert versions.bump("1.2.3", "patch") == "1.2.4"
    assert versions.bump("1.2.3", "minor") == "1.3.0"
    assert versions.bump("1.2.3", "major") == "2.0.0"
    assert versions.release_greater("1.10.0", "1.9.0")


# --- severity -------------------------------------------------------------------

@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3(vector, score):
    assert cvss3_score(vector) == score


def test_severity_sources():
    assert severity_of({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == "CRITICAL"
    assert severity_of({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}) == "UNKNOWN"


# --- inventory ------------------------------------------------------------------

def _project(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\nflask>=2\n-r extra.txt\n")
    (tmp_path / "extra.txt").write_text("urllib3[socks]==1.26.0 ; python_version >= '3'\n")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/minimist": {"version": "1.2.0"},
            "node_modules/jest": {"version": "29.0.0", "dev": True},
        },
    }))
    (tmp_path / "yarn.lock").write_text("")
    return tmp_path


def test_inventory_directory(tmp_path):
    inv = build_inventory(DirTree(_project(tmp_path)))
    found = {(d.ecosystem, d.name, d.version, d.direct) for d in inv.sorted()}
    assert ("PyPI", "requests", "2.25.0", True) in found
    assert ("PyPI", "urllib3", "1.26.0", True) in found
    assert ("npm", "lodash", "4.17.20", True) in found
    assert ("npm", "minimist", "1.2.0", False) in found
    assert not any(d.name == "jest" for d in inv.sorted())
    assert any("flask is not pinned" in g for g in inv.gaps)
    assert any("yarn.lock" in g for g in inv.gaps)


def test_inventory_lockfile_v1_is_a_gap(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    inv = build_inventory(DirTree(tmp_path))
    assert any("lockfileVersion 1" in g for g in inv.gaps)


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_inventory_zip_untrusted_names(tmp_path):
    data = _zip({
        "requests-2.25.0.dist-info/METADATA": "Name: requests\nVersion: 2.25.0\n",
        "../evil-1.0.dist-info/METADATA": "Name: evil\nVersion: 1.0\n",
        "nodejs/node_modules/left-pad/package.json": json.dumps({"name": "left-pad", "version": "1.0.0"}),
        "bad-1.dist-info/METADATA": "Name: bad\x1b[31m\nVersion: 1\n",
    })
    inv = build_inventory(ZipTree(data, "code.zip"))
    names = {d.name for d in inv.sorted()}
    assert names == {"requests", "left-pad"}
    assert all("\x1b" not in g for g in inv.gaps)


def test_zip_bomb_guard():
    data = _zip({"big": "x" * 1000})
    with pytest.raises(ToolError):
        ZipTree(data, "bomb.zip", max_total=100)


def test_clean_strips_escapes():
    assert clean("ok\x1b[2J\nnext‮") == "ok next"


# --- OSV evaluation -------------------------------------------------------------

def _deps(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\nidna==2.0\n")
    return build_inventory(DirTree(tmp_path)).sorted()


def test_evaluate_dedupes_aliases_and_picks_fix(tmp_path):
    fake = FakeOsv(
        affected={("PyPI", "requests", "2.25.0"): ["PYSEC-1", "GHSA-1", "GHSA-2"], ("PyPI", "idna", "2.0"): ["GHSA-W"]},
        vulns={
            "PYSEC-1": vuln("PYSEC-1", "PyPI", "requests", fixed="2.31.0", aliases=["CVE-1", "GHSA-1"]),
            "GHSA-1": vuln("GHSA-1", "PyPI", "requests", fixed="2.31.0", severity="HIGH", aliases=["CVE-1"]),
            "GHSA-2": vuln("GHSA-2", "PyPI", "requests", fixed="2.26.0"),
            "GHSA-W": {**vuln("GHSA-W", "PyPI", "idna", fixed="3.7"), "withdrawn": "2024-01-01T00:00:00Z"},
        },
    )
    findings, _ = evaluate(_deps(tmp_path), OsvClient(opener=fake), Policy())
    by_id = {f.vuln_id: f for f in findings}
    assert set(by_id) == {"PYSEC-1", "GHSA-2"}
    assert by_id["PYSEC-1"].severity == "HIGH"
    assert "GHSA-1" in by_id["PYSEC-1"].aliases
    assert by_id["PYSEC-1"].fixed == "2.31.0"


def test_unknown_severity_fails_and_ignores_expire(tmp_path):
    fake = FakeOsv(affected={("PyPI", "requests", "2.25.0"): ["X-1"]},
                   vulns={"X-1": vuln("X-1", "PyPI", "requests")})
    policy = Policy(fail_on="critical", ignore=[{"id": "X-1", "reason": "accepted", "expires": "2020-01-01"}],
                    today=date(2026, 1, 1))
    findings, warnings = evaluate(_deps(tmp_path), OsvClient(opener=fake), policy)
    assert findings[0].severity == "UNKNOWN" and policy.fails(findings[0])
    assert warnings and "expired" in warnings[0]
    policy.ignore[0]["expires"] = "2030-01-01"
    findings, _ = evaluate(_deps(tmp_path), OsvClient(opener=fake), policy)
    assert findings[0].ignored and not policy.fails(findings[0])


def test_osv_unreachable_fails_closed(tmp_path):
    with pytest.raises(OsvError, match="not clean"):
        evaluate(_deps(tmp_path), OsvClient(opener=FakeOsv(fail=True)), Policy())


# --- changelog ------------------------------------------------------------------

def test_changelog_flow():
    text = changelog.add_unreleased(None, ["Upgraded PyPI:requests 2.25.0 → 2.31.0 (fixes GHSA-1)"])
    text = text.replace("## [Unreleased]\n", "## [Unreleased]\n\nHuman note.\n")
    released = changelog.release(text, "1.0.1", "2026-11-13", {"Build": ["Artifact `x.zip` sha256 `ab`"]})
    unreleased, rest = released.split("## [1.0.1] - 2026-11-13")
    assert "Human note." not in unreleased and changelog.BEGIN in unreleased
    assert "Human note." in rest
    assert "### Security\n\n- Upgraded PyPI:requests" in rest
    assert "### Build" in rest
    with pytest.raises(ToolError):
        changelog.release(released, "1.0.1", "2026-11-13", {})


def test_changelog_unbalanced_markers():
    text = changelog.SKELETON.replace(changelog.END, "")
    with pytest.raises(ToolError, match="unbalanced"):
        changelog.add_unreleased(text, ["x"])


# --- config ---------------------------------------------------------------------

def test_config_rejects_unknown_and_bad_types(tmp_path):
    (tmp_path / "lambda-tools.json").write_text(json.dumps({"name": "x", "colour": 1}))
    with pytest.raises(ToolError, match="unknown key 'colour'"):
        config.load_project(tmp_path)
    (tmp_path / "lambda-tools.json").write_text(json.dumps({"version": "1.0"}))
    with pytest.raises(ToolError, match="'version' must be"):
        config.load_project(tmp_path)


def test_precedence(tmp_path, monkeypatch):
    (tmp_path / "lambda-tools.json").write_text(json.dumps({"fail_on": "high"}))
    cfg = config.load_project(tmp_path)
    assert config.resolve(None, "LAMBDA_TOOLS_FAIL_ON", cfg, "fail_on", "low") == "high"
    monkeypatch.setenv("LAMBDA_TOOLS_FAIL_ON", "medium")
    assert config.resolve(None, "LAMBDA_TOOLS_FAIL_ON", cfg, "fail_on", "low") == "medium"
    assert config.resolve("critical", "LAMBDA_TOOLS_FAIL_ON", cfg, "fail_on", "low") == "critical"


# --- review regressions ---------------------------------------------------------

def test_zip_without_metadata_is_a_gap():
    inv = build_inventory(ZipTree(_zip({"index.js": "bundled()"}), "bundle.zip"))
    assert not inv.dependencies and any("no dependency metadata" in g for g in inv.gaps)


def test_zip_scans_node_modules_even_with_lockfile():
    data = _zip({
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/jest": {"version": "29.0.0", "dev": True}}}),
        "node_modules/jest/package.json": json.dumps({"name": "jest", "version": "29.0.0"}),
    })
    assert {d.name for d in build_inventory(ZipTree(data, "z")).sorted()} == {"jest"}


def test_unsafe_zip_entries_are_gaps():
    inv = build_inventory(ZipTree(_zip({"node_modules\\x\\package.json": "{}"}), "win.zip"))
    assert any("unsafe path" in g for g in inv.gaps)


def test_fixed_version_must_be_clean(tmp_path):
    from lambdatools.common.osv import fixed_version
    dep = _deps(tmp_path)[1]  # requests 2.25.0
    assert fixed_version(vuln("X", "PyPI", "requests", fixed=" 2.31.0 \n"), dep) is None
    assert fixed_version(vuln("X", "PyPI", "requests", fixed="2.31.0"), dep) == "2.31.0"


def test_gap_messages_are_sanitized():
    from lambdatools.common.inventory import Inventory
    inv = Inventory()
    inv.gap("bad\x1b[31m name\n")
    assert inv.gaps == ["bad name"]
