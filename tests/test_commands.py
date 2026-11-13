import argparse
import io
import json
import os
import stat
import urllib.request
import zipfile
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from conftest import FakeOsv, vuln
from lambdatools import backup, package, remediate
from lambdatools.common import aws, changelog
from lambdatools.common.log import ToolError

CANARY = "canary-secret-7f3a9"
REGION = "us-east-1"


def _code_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", "def handler(e, c):\n    return 1\n")
    return buf.getvalue()


@pytest.fixture
def lambda_env(monkeypatch):
    with mock_aws():
        sess = boto3.Session(region_name=REGION)
        iam = sess.client("iam")
        role = iam.create_role(
            RoleName="fn-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
        )["Role"]
        iam.put_role_policy(RoleName="fn-role", PolicyName="inline",
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}))
        lam = sess.client("lambda")
        lam.create_function(FunctionName="fn", Runtime="python3.12", Role=role["Arn"], Handler="handler.handler",
                            Code={"ZipFile": _code_zip()}, Environment={"Variables": {"API_KEY": CANARY}})
        lam.publish_version(FunctionName="fn")
        lam.create_alias(FunctionName="fn", Name="live", FunctionVersion="1")
        lam.add_permission(FunctionName="fn", StatementId="s3", Action="lambda:InvokeFunction",
                           Principal="s3.amazonaws.com")
        monkeypatch.setattr(aws, "download_verified", lambda url, sha, what: _code_zip())
        yield sess


def _backup_args(tmp_path, execute):
    return argparse.Namespace(function="fn", qualifier=None, out=tmp_path / "backups", no_iam=False,
                              project=tmp_path, execute=execute)


def _all_bytes(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in root.rglob("*") if p.is_file())


def test_backup_dry_run_writes_nothing(tmp_path, lambda_env, capsys):
    backup.run(_backup_args(tmp_path, execute=False), lambda *_: lambda_env)
    out = json.loads(capsys.readouterr().out)
    assert out["written"] is False and out["environment_values"] == "redacted"
    assert not (tmp_path / "backups").exists()


def test_backup_redacts_when_pass_missing(tmp_path, lambda_env, capsys, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    code = backup.run(_backup_args(tmp_path, execute=True), lambda *_: lambda_env)
    out = json.loads(capsys.readouterr().out)
    # moto does not implement these APIs; unreadable surfaces must make the backup incomplete.
    moto_gaps = {"function-urls", "provisioned-concurrency", "recursion", "runtime-management:$LATEST",
                 "runtime-management:1", "scaling:live"}
    assert code == 1 and out["complete"] is False
    assert {m["surface"] for m in out["missing"]} <= moto_gaps
    dest = Path(out["backup"])
    assert CANARY.encode() not in _all_bytes(tmp_path / "backups")
    manifest = json.loads((dest / "manifest.json").read_text())
    assert manifest["environment"]["values"] == "redacted"
    assert set(manifest["environment"]["contexts"]) >= {"$LATEST", "1"}
    fn = json.loads((dest / "function.json").read_text())
    assert fn["Configuration"]["Environment"]["Variables"] == {"API_KEY": "<redacted>"}
    assert "Location" not in fn["Code"]
    assert "s3.amazonaws.com" in (dest / "policies.json").read_text()
    assert "inline" in (dest / "iam-role.json").read_text()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in dest.iterdir())
    for name, digest in manifest["files"].items():
        import hashlib
        assert hashlib.sha256((dest / name).read_bytes()).hexdigest() == digest


def test_backup_stores_values_in_pass(tmp_path, lambda_env, capsys, monkeypatch):
    bin_dir, store = tmp_path / "bin", tmp_path / "store"
    bin_dir.mkdir()
    store.mkdir()
    (store / ".gpg-id").write_text("test\n")
    captured = tmp_path / "pass-input"
    script = bin_dir / "pass"
    script.write_text(f"#!/bin/sh\necho \"$@\" > '{captured}.args'\ncat > '{captured}'\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(store))

    backup.run(_backup_args(tmp_path, execute=True), lambda *_: lambda_env)
    out = json.loads(capsys.readouterr().out)
    assert out["environment_values"] == "pass"
    assert out["pass_path"].startswith("lambda-tools/123456789012/us-east-1/fn/")
    stored = json.loads(captured.read_text())
    assert stored["values"]["$LATEST"]["API_KEY"] == CANARY
    assert CANARY not in Path(f"{captured}.args").read_text()
    assert CANARY.encode() not in _all_bytes(tmp_path / "backups")


def test_backup_refuses_unignored_git_location(tmp_path, lambda_env):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    with pytest.raises(ToolError, match="not ignored"):
        backup.run(_backup_args(tmp_path, execute=True), lambda *_: lambda_env)


def test_scope_check_rejects_other_account():
    with pytest.raises(ToolError, match="belongs to account"):
        aws.check_function_scope("arn:aws:lambda:us-east-1:111111111111:function:x", "222222222222", None, None)


def test_download_verified_checks_sha(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: io.BytesIO(b"payload"))
    with pytest.raises(ToolError, match="checksum mismatch"):
        aws.download_verified("https://example.invalid/x", "AAAA", "code")


# --- package --------------------------------------------------------------------

def _py_project(root: Path, vendored=None):
    (root / "handler.py").write_text("def handler(e, c):\n    return 1\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text("")
    (root / ".env").write_text("SECRET=1\n")
    (root / "lambda-tools.json").write_text(json.dumps({"name": "demo", "runtime": "python3.12", "version": "1.0.0",
                                                         "function_name": "demo-fn"}, indent=2) + "\n")
    if vendored:
        d = root / f"{vendored[0]}-{vendored[1]}.dist-info"
        d.mkdir()
        (d / "METADATA").write_text(f"Name: {vendored[0]}\nVersion: {vendored[1]}\n")


def _package_args(root, execute=True, **kw):
    base = dict(path=root, bump=None, set_version=None, runtime=None, arch=None, out=None, fail_on=None,
                allow_vulnerable=False, allow_gaps=False, allow_scripts=False, allow_deprecated_runtime=False,
                execute=execute)
    base.update(kw)
    return argparse.Namespace(**base)


def test_package_dry_run_writes_nothing(tmp_path, monkeypatch):
    _py_project(tmp_path)
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    before = (tmp_path / "lambda-tools.json").read_text()
    assert package.run(_package_args(tmp_path, execute=False), None) == 0
    assert not (tmp_path / "dist").exists() and not (tmp_path / "CHANGELOG.md").exists()
    assert (tmp_path / "lambda-tools.json").read_text() == before


def test_package_versions_changelog_and_immutability(tmp_path, monkeypatch, capsys):
    _py_project(tmp_path)
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    assert package.run(_package_args(tmp_path), None) == 0
    art = tmp_path / "dist" / "demo-1.0.1.zip"
    names = zipfile.ZipFile(art).namelist()
    assert names == ["handler.py"]
    manifest = json.loads((tmp_path / "dist" / "demo-1.0.1.manifest.json").read_text())
    assert manifest["version"] == "1.0.1" and manifest["scan"]["failing"] == 0
    assert json.loads((tmp_path / "lambda-tools.json").read_text())["version"] == "1.0.1"
    log = (tmp_path / "CHANGELOG.md").read_text()
    assert "## [1.0.1]" in log and manifest["sha256"] in log
    state = json.loads((tmp_path / ".lambda-tools" / "release-state.json").read_text())
    assert state["version"] == "1.0.1"

    assert package.run(_package_args(tmp_path, bump="minor"), None) == 0
    assert "## [1.1.0]" in (tmp_path / "CHANGELOG.md").read_text()
    with pytest.raises(ToolError, match="greater than"):
        package.run(_package_args(tmp_path, set_version="1.0.5"), None)


def test_package_blocks_vulnerable_build(tmp_path, monkeypatch):
    _py_project(tmp_path, vendored=("requests", "2.25.0"))
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv(
        affected={("PyPI", "requests", "2.25.0"): ["GHSA-1"]},
        vulns={"GHSA-1": vuln("GHSA-1", "PyPI", "requests", fixed="2.31.0", severity="HIGH")}))
    with pytest.raises(ToolError, match="finding"):
        package.run(_package_args(tmp_path), None)
    assert not (tmp_path / "dist").exists()
    assert package.run(_package_args(tmp_path, allow_vulnerable=True), None) == 0
    assert "Known HIGH GHSA-1" in (tmp_path / "CHANGELOG.md").read_text()


def test_zip_is_deterministic(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "run.sh").write_text("#!/bin/sh\n")
    (tmp_path / "run.sh").chmod(0o700)
    first = package.build_zip(tmp_path)[0]
    os.utime(tmp_path / "a.py", (1, 1))
    assert package.build_zip(tmp_path)[0] == first
    modes = {i.filename: i.external_attr >> 16 for i in zipfile.ZipFile(io.BytesIO(first)).infolist()}
    assert modes == {"a.py": 0o100644, "run.sh": 0o100755}


def test_excludes():
    pats = package.DEFAULT_EXCLUDES
    assert package.excluded("tests", pats) and not package.excluded("pkg/tests", pats)
    assert package.excluded("pkg/__pycache__", pats) and package.excluded("pkg/.env.prod", pats)
    assert package.excluded("deep/key.pem", pats) and not package.excluded("handler.py", pats)


# --- remediate ------------------------------------------------------------------

def test_rewrite_pin_keeps_extras_and_markers():
    text = "Requests[socks]==2.25.0 ; python_version >= '3' # pinned\nother==1\n"
    new, status = remediate.rewrite_pin(text, "requests", "2.31.0")
    assert status == "pinned"
    assert new == "Requests[socks]==2.31.0 ; python_version >= '3' # pinned\nother==1\n"
    assert remediate.rewrite_pin("requests>=2\n", "requests", "2.31.0")[1].startswith("manual")
    assert remediate.rewrite_pin("flask==1\n", "requests", "2.31.0")[1] == "absent"


def test_block_pins_are_managed():
    text = remediate.set_block_pin("flask==3.0.0\n", "urllib3", "1.26.18")
    text = remediate.set_block_pin(text, "urllib3", "2.2.2")
    assert text.count(remediate.BLOCK_BEGIN) == 1 and "urllib3==2.2.2" in text and "1.26.18" not in text
    with pytest.raises(ToolError, match="unbalanced"):
        remediate.set_block_pin(text + remediate.BLOCK_END + "\n", "x", "1")


def test_npm_fix_direct_vs_override():
    pkg = {"dependencies": {"lodash": "^4.17.0"}}
    remediate.apply_npm_fix(pkg, "lodash", "4.17.21")
    remediate.apply_npm_fix(pkg, "minimist", "1.2.8")
    assert pkg == {"dependencies": {"lodash": "^4.17.21"}, "overrides": {"minimist": "1.2.8"}}


def test_remediate_python_refuses_hashes(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0 --hash=sha256:abc\n")
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    args = argparse.Namespace(path=tmp_path, fail_on=None, execute=False)
    with pytest.raises(ToolError, match="--hash"):
        remediate.run(args, None)


def test_remediate_python_end_to_end(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
    resolved = {"2.25.0": [("requests", "2.25.0"), ("urllib3", "1.26.0")],
                "2.31.0": [("requests", "2.31.0"), ("urllib3", "1.26.0")]}

    def fake_resolve(files, main, runtime, arch):
        from lambdatools.common.inventory import Inventory
        inv = Inventory()
        pin = files[main].split("requests==")[1].split()[0]
        block_urllib3 = "urllib3==2.2.2" in files[main]
        for name, ver in resolved[pin]:
            inv.add("PyPI", name, "2.2.2" if name == "urllib3" and block_urllib3 else ver, "pip")
        return inv

    monkeypatch.setattr(remediate, "resolve_python", fake_resolve)
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv(
        affected={("PyPI", "requests", "2.25.0"): ["GHSA-R"], ("PyPI", "urllib3", "1.26.0"): ["GHSA-U"]},
        vulns={"GHSA-R": vuln("GHSA-R", "PyPI", "requests", fixed="2.31.0", severity="MODERATE"),
               "GHSA-U": vuln("GHSA-U", "PyPI", "urllib3", fixed="2.2.2", severity="HIGH")}))
    args = argparse.Namespace(path=tmp_path, fail_on=None, execute=True)
    assert remediate.run(args, None) == 0
    req = (tmp_path / "requirements.txt").read_text()
    assert req.startswith("requests==2.31.0\n") and "urllib3==2.2.2" in req and remediate.BLOCK_BEGIN in req
    log = (tmp_path / "CHANGELOG.md").read_text()
    assert "Upgraded PyPI:requests 2.25.0 → 2.31.0 (fixes GHSA-R)" in log and changelog.BEGIN in log


def test_bumps_merge_across_rounds():
    plan = remediate.Plan(bumps=[("npm", "lodash", "4.17.15", "4.18.0", ["A"]), ("npm", "lodash", "4.18.0", "4.18.1", ["B"])])
    assert remediate.changelog_entries(plan) == ["Upgraded npm:lodash 4.17.15 → 4.18.1 (fixes A, B)"]


def test_rewrite_pin_exact_name_only():
    text = "requests-toolbelt==1.0.0\nboto3==1.0\n"
    assert remediate.rewrite_pin(text, "requests", "2.31.0") == (text, "absent")


def test_node_remediate_writes_nothing_without_bumps(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text('{\r\n\t"name": "x"\r\n}')
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    args = argparse.Namespace(path=tmp_path, fail_on=None, execute=True)
    assert remediate.run(args, None) == 0
    assert (tmp_path / "package.json").read_bytes() == b'{\r\n\t"name": "x"\r\n}'
    assert not (tmp_path / "CHANGELOG.md").exists()


def test_backup_parent_dirs_are_private(tmp_path, lambda_env, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    backup.run(_backup_args(tmp_path, execute=True), lambda *_: lambda_env)
    for d in (tmp_path / "backups").rglob("*"):
        if d.is_dir():
            assert stat.S_IMODE(d.stat().st_mode) == 0o700, d


def test_cli_aws_call_does_not_recurse_in_ssl(tmp_path):
    """Regression: truststore must be injected before botocore is imported."""
    import subprocess
    import sys
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
           "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x", "AWS_EC2_METADATA_DISABLED": "true",
           "AWS_ENDPOINT_URL": "http://127.0.0.1:9"}
    result = subprocess.run([sys.executable, "-m", "lambdatools", "scan", "--function", "nope", "--region", "us-east-1"],
                            capture_output=True, text=True, env=env, timeout=120, cwd=tmp_path)
    assert "RecursionError" not in result.stderr, result.stderr[-2000:]
    assert result.returncode == 2


def test_root_backups_dir_is_never_packaged_or_scanned(tmp_path):
    from lambdatools.common.inventory import DirTree
    (tmp_path / "backups" / "x").mkdir(parents=True)
    (tmp_path / "backups" / "x" / "function.json").write_text("{}")
    (tmp_path / "lib" / "backups").mkdir(parents=True)
    (tmp_path / "lib" / "backups" / "mod.py").write_text("")
    assert package.excluded("backups", package.DEFAULT_EXCLUDES)
    assert not package.excluded("lib/backups", package.DEFAULT_EXCLUDES)
    files = DirTree(tmp_path).files()
    assert "lib/backups/mod.py" in files and not any(f.startswith("backups/") for f in files)


# --- backups as scan input ------------------------------------------------------

def _fake_backup(root: Path, layers=(), code=None, tamper=False, runtime="python3.12", handler="handler.handler"):
    import hashlib
    root.mkdir(parents=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in (code or {
            "handler.py": "import requests\n",
            "requests-2.25.0.dist-info/METADATA": "Name: requests\nVersion: 2.25.0\n",
        }).items():
            zf.writestr(name, data)
    files = {
        "code.zip": buf.getvalue(),
        "function.json": json.dumps({"Configuration": {
            "FunctionName": "orders-api", "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:orders-api",
            "Runtime": runtime, "Architectures": ["arm64"], "Handler": handler, "CodeSha256": "abc=",
            "Layers": [{"Arn": a} for a in layers]}}).encode(),
    }
    import hashlib
    manifest = {"tool": "lambda-tools", "backup_id": "20261113T000000Z", "account": "123456789012", "region": "us-east-1",
                "function_arn": "arn:aws:lambda:us-east-1:123456789012:function:orders-api",
                "code": {"package_type": "Zip"},
                "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}
    for n, d in files.items():
        (root / n).write_bytes(d)
    (root / "manifest.json").write_text(json.dumps(manifest))
    if tamper:
        (root / "function.json").write_text("{}")
    return root


def _scan_args(path, **kw):
    base = dict(path=path, function=None, qualifier=None, project=None, fail_on=None, allow_gaps=False,
                include_dev=False, json=True, report=None, allow_deprecated_runtime=False)
    base.update(kw)
    return argparse.Namespace(**base)


def test_scan_backup_dir_scans_its_code_zip(tmp_path, monkeypatch, capsys):
    from lambdatools import scan
    backup_dir = _fake_backup(tmp_path / "b", layers=["arn:aws:lambda:us-east-1:123456789012:layer:x:1"])
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv(
        affected={("PyPI", "requests", "2.25.0"): ["GHSA-1"]},
        vulns={"GHSA-1": vuln("GHSA-1", "PyPI", "requests", fixed="2.31.0", severity="HIGH")}))
    assert scan.run(_scan_args(backup_dir), None) == 1
    report = json.loads(capsys.readouterr().out)
    assert [f["id"] for f in report["findings"]] == ["GHSA-1"]
    assert any("layer" in g for g in report["coverage_gaps"])


def test_scan_rejects_tampered_backup(tmp_path):
    from lambdatools import scan
    with pytest.raises(ToolError, match="checksum"):
        scan.run(_scan_args(_fake_backup(tmp_path / "b", tamper=True)), None)


def test_scan_dir_with_only_archives_is_a_gap(tmp_path, monkeypatch, capsys):
    from lambdatools import scan
    (tmp_path / "code.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    assert scan.run(_scan_args(tmp_path), None) == 1
    assert "archives are not opened" in json.loads(capsys.readouterr().out)["coverage_gaps"][0]


def _import_args(backup_dir, to, execute=True, name=None):
    return argparse.Namespace(backup=backup_dir, to=to, execute=execute, name=name)


PY_CODE = {
    "handler.py": "import requests\n",
    "lib/util.py": "X = 1\n",
    "requests/__init__.py": "",
    "requests/api.py": "",
    "requests/__pycache__/api.cpython-312.pyc": "",
    "requests-2.25.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n",
    "requests-2.25.0.dist-info/RECORD": "requests/__init__.py,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\nrequests/api.py,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n"
                                        "requests-2.25.0.dist-info/METADATA,,\n../../bin/evil,,\n../../bin/req,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n",
    "bin/req": "",
    "six.py": "",
    "six-1.16.0.dist-info/METADATA": "Name: six\nVersion: 1.16.0\n",
    "six-1.16.0.dist-info/top_level.txt": "six\n",
}


def test_import_python_backup(tmp_path, capsys):
    from lambdatools import importer
    exe = zipfile.ZipInfo("bin/run.sh")
    exe.external_attr = 0o755 << 16
    code = dict(PY_CODE)
    code[exe] = "#!/bin/sh\n"
    backup_dir = _fake_backup(tmp_path / "b", code=code)
    dest = tmp_path / "proj"
    assert importer.run(_import_args(backup_dir, dest), None) == 0
    files = sorted(str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file())
    assert files == ["CHANGELOG.md", "bin/run.sh", "handler.py", "lambda-tools.json", "lib/util.py", "requirements.txt",
                     "tests/events/generic.json", "tests/smoke_config.json", "tests/test_smoke.py"]
    reqs = (dest / "requirements.txt").read_text()
    assert "requests==2.25.0\nsix==1.16.0\n" in reqs
    cfg = json.loads((dest / "lambda-tools.json").read_text())
    assert cfg == {"name": "orders-api", "function_name": "orders-api", "runtime": "python3.12",
                   "architecture": "arm64", "version": "0.0.0", "handler": "handler.handler",
                   "account_id": "123456789012", "region": "us-east-1"}
    assert "Imported from backup 20261113T000000Z" in (dest / "CHANGELOG.md").read_text()
    assert os.stat(dest / "bin/run.sh").st_mode & 0o111
    assert not os.stat(dest / "handler.py").st_mode & 0o111
    out = json.loads(capsys.readouterr().out)
    assert out["written"] and out["pinned"] == ["requests==2.25.0", "six==1.16.0"]
    # remediate can rewrite the generated pins
    assert remediate.rewrite_pin(reqs, "requests", "2.31.0") == (reqs.replace("2.25.0", "2.31.0"), "pinned")


def test_import_dry_run_writes_nothing(tmp_path, capsys):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE)
    assert importer.run(_import_args(backup_dir, tmp_path / "proj", execute=False), None) == 0
    assert not (tmp_path / "proj").exists()
    assert "requirements.txt" in json.loads(capsys.readouterr().out)["files"]


def test_import_refuses_non_empty_destination(tmp_path):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE)
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "keep.txt").write_text("x")
    with pytest.raises(ToolError, match="not empty"):
        importer.run(_import_args(backup_dir, tmp_path / "proj"), None)
    assert (tmp_path / "proj" / "keep.txt").read_text() == "x"


def test_import_into_empty_destination(tmp_path, capsys):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE)
    (tmp_path / "proj").mkdir()
    assert importer.run(_import_args(backup_dir, tmp_path / "proj"), None) == 0
    assert (tmp_path / "proj" / "handler.py").exists()


def test_import_pins_existing_requirements_to_deployed_versions(tmp_path, capsys):
    # regression: an unpinned requirements.txt in the zip left the deployed pins in a side file that
    # remediate doesn't manage, so scan failed while remediate had nothing to change
    from lambdatools import importer
    original = "# app deps\nrequests[socks] >= 2.0 ; python_version >= '3.8'  # http\nsix @ https://x/six.whl\n"
    code = dict(PY_CODE, **{"requirements.txt": original})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "proj"), None)
    req = (tmp_path / "proj" / "requirements.txt").read_text()
    assert req == "# app deps\nrequests[socks]==2.25.0; python_version >= \"3.8\"  # http\nsix @ https://x/six.whl\n"
    assert not (tmp_path / "proj" / "requirements.deployed.txt").exists()
    warnings = _import_warnings()
    assert "requests were not pinned" in warnings and "six is installed from a URL" in warnings
    # remediate can now bump the pinned line
    assert remediate.rewrite_pin(req, "requests", "2.31.0")[1] == "pinned"


def test_import_puts_transitive_deployed_packages_in_managed_block(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"requirements.txt": "requests\n"})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "proj"), None)
    req = (tmp_path / "proj" / "requirements.txt").read_text()
    assert req == f"requests==2.25.0\n\n{remediate.BLOCK_BEGIN}\nsix==1.16.0\n{remediate.BLOCK_END}\n"


def test_import_warns_when_deployed_version_breaks_specifier(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"requirements.txt": "requests<2.0\nsix==1.0.0\n"})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "proj"), None)
    assert (tmp_path / "proj" / "requirements.txt").read_text() == "requests==2.25.0\nsix==1.16.0\n"
    assert "does not satisfy <2.0" in _import_warnings()


def test_import_dist_info_without_record_or_top_level_keeps_files(tmp_path, capsys):
    from lambdatools import importer
    from lambdatools.common.log import WARNINGS
    code = {"handler.py": "", "mystery/__init__.py": "",
            "mystery-1.0.dist-info/METADATA": "Name: mystery\nVersion: 1.0\n"}
    backup_dir = _fake_backup(tmp_path / "b", code=code)
    importer.run(_import_args(backup_dir, tmp_path / "proj"), None)
    assert (tmp_path / "proj" / "mystery" / "__init__.py").exists()
    assert not (tmp_path / "proj" / "requirements.txt").exists()
    assert any("cannot be separated" in m for m in WARNINGS._items["import"])


def test_import_node_needs_lockfile(tmp_path):
    from lambdatools import importer
    code = {"index.js": "", "package.json": "{}", "node_modules/lodash/index.js": ""}
    backup_dir = _fake_backup(tmp_path / "b", code=code, runtime="nodejs20.x", handler="index.handler")
    with pytest.raises(ToolError, match="package-lock.json"):
        importer.run(_import_args(backup_dir, tmp_path / "proj"), None)


def test_import_node_drops_node_modules(tmp_path, capsys):
    from lambdatools import importer
    code = {"index.js": "", "package.json": "{}", "package-lock.json": "{}", "node_modules/lodash/index.js": ""}
    backup_dir = _fake_backup(tmp_path / "b", code=code, runtime="nodejs20.x", handler="index.handler")
    importer.run(_import_args(backup_dir, tmp_path / "proj"), None)
    assert (tmp_path / "proj" / "package-lock.json").exists()
    assert not (tmp_path / "proj" / "node_modules").exists()
    assert not (tmp_path / "proj" / "requirements.txt").exists()


def test_import_rejects_tampered_backup(tmp_path):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE, tamper=True)
    with pytest.raises(ToolError, match="checksum"):
        importer.run(_import_args(backup_dir, tmp_path / "proj"), None)


def _record_line(path, data):
    import base64
    import hashlib
    digest = base64.urlsafe_b64encode(hashlib.sha256(data.encode()).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}\n"


def _import_warnings():
    from lambdatools.common.log import WARNINGS
    return " | ".join(WARNINGS._items["import"])


def test_import_keeps_patched_dependency_files(tmp_path, capsys):
    from lambdatools import importer
    code = {"handler.py": "", "lib1/__init__.py": "patched\n", "lib1/core.py": "x\n",
            "lib1-1.0.dist-info/METADATA": "Name: lib1\nVersion: 1.0\n",
            "lib1-1.0.dist-info/RECORD": _record_line("lib1/__init__.py", "original\n") + _record_line("lib1/core.py", "x\n")}
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert (tmp_path / "p/lib1/__init__.py").read_text() == "patched\n"
    assert not (tmp_path / "p/lib1/core.py").exists()
    assert "differs from the hash" in _import_warnings()


def test_import_top_level_fallback_is_narrow(tmp_path, capsys):
    from lambdatools import importer
    code = {"handler.py": "", "tests/test_x.py": "", "foo/__init__.py": "", "foo.json": "{}",
            "foo-1.0.dist-info/METADATA": "Name: foo\nVersion: 1.0\n",
            "foo-1.0.dist-info/top_level.txt": "foo\ntests\n"}
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert (tmp_path / "p/tests/test_x.py").exists() and (tmp_path / "p/foo.json").exists()
    assert not (tmp_path / "p/foo").exists()


def test_import_refuses_when_handler_would_be_lost(tmp_path):
    from lambdatools import importer
    code = {"handler.pyc": "", "x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
    with pytest.raises(ToolError, match="handler"):
        importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert not (tmp_path / "p").exists()


def test_import_keeps_zip_changelog_and_config(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"CHANGELOG.md": "mine\n", "lambda-tools.json": '{"version": "3.1.0"}'})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert (tmp_path / "p/CHANGELOG.md").read_text() == "mine\n"
    assert "3.1.0" in (tmp_path / "p/lambda-tools.json").read_text()


def test_import_warns_without_dist_info(tmp_path, capsys):
    from lambdatools import importer
    code = {"handler.py": "", "requests/__init__.py": ""}
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert "requirements.txt is empty" in _import_warnings()


def test_import_warns_on_files_outside_record(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"requests/extra.py": ""})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert (tmp_path / "p/requests/extra.py").exists()
    assert "not in its RECORD" in _import_warnings()


def test_import_refuses_duplicate_installs(tmp_path):
    from lambdatools import importer
    code = dict(PY_CODE, **{"requests-2.31.0.dist-info/METADATA": "Name: requests\nVersion: 2.31.0\n"})
    with pytest.raises(ToolError, match="two installs"):
        importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)


def test_import_leaves_out_credential_files(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{".env": "SECRET=1", "conf/.npmrc": "_authToken=x", "key.pem": ""})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    for name in (".env", "conf/.npmrc", "key.pem"):
        assert not (tmp_path / "p" / name).exists()
    assert "credential file" in _import_warnings()


def test_import_case_collision_fails_in_dry_run(tmp_path):
    from lambdatools import importer
    code = dict(PY_CODE, **{"Handler.py": ""})
    with pytest.raises(ToolError, match="differ only in case"):
        importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p", execute=False), None)


def test_import_skips_dot_entries_and_symlinks(tmp_path, capsys):
    from lambdatools import importer
    link = zipfile.ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    code = {**PY_CODE, "foo/..": "x", link: "/etc/passwd"}
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert not (tmp_path / "p/link").exists()
    assert "symlink" in _import_warnings() and "unsafe path" in _import_warnings()
    assert not (tmp_path / ".p.import.tmp").exists()


def test_import_refuses_leftover_temp_dir(tmp_path):
    from lambdatools import importer
    (tmp_path / ".p.import.tmp").mkdir()
    with pytest.raises(ToolError, match="already exists"):
        importer.run(_import_args(_fake_backup(tmp_path / "b", code=PY_CODE), tmp_path / "p"), None)


def test_import_refuses_image_function(tmp_path):
    import hashlib
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE)
    manifest = json.loads((backup_dir / "manifest.json").read_text())
    manifest["code"] = {"package_type": "Image"}
    (backup_dir / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ToolError, match="container image"):
        importer.run(_import_args(backup_dir, tmp_path / "p"), None)


def test_import_maps_relocated_record_paths(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE)
    code["requests-2.25.0.dist-info/RECORD"] += "../../share/man/req.1,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n"
    code["share/man/req.1"] = ""
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert not (tmp_path / "p/share").exists()


def test_import_node_drops_nested_node_modules(tmp_path, capsys):
    from lambdatools import importer
    code = {"index.js": "", "package.json": "{}", "package-lock.json": "{}",
            "packages/a/node_modules/x/index.js": "", "packages/a/a.js": ""}
    backup_dir = _fake_backup(tmp_path / "b", code=code, runtime="nodejs20.x", handler="index.handler")
    importer.run(_import_args(backup_dir, tmp_path / "p"), None)
    assert (tmp_path / "p/packages/a/a.js").exists()
    assert not (tmp_path / "p/packages/a/node_modules").exists()


def test_import_handler_in_package_init(tmp_path, capsys):
    from lambdatools import importer
    code = {"app/__init__.py": "def handler(e, c): pass\n"}
    assert importer.run(_import_args(_fake_backup(tmp_path / "b", code=code, handler="app.handler"),
                                     tmp_path / "p"), None) == 0


def test_import_handler_from_layer_warns(tmp_path, capsys):
    from lambdatools import importer
    code = {"handler.py": ""}
    backup_dir = _fake_backup(tmp_path / "b", code=code, layers=["arn:aws:lambda:us-east-1:1:layer:dd:1"],
                              handler="datadog_lambda.handler.handler")
    assert importer.run(_import_args(backup_dir, tmp_path / "p"), None) == 0
    assert "probably in a layer" in _import_warnings()


@pytest.mark.parametrize("handler", ["index.handlers.main", "/opt/nodejs/node_modules/dd/handler.handler"])
def test_import_node_handler_forms(tmp_path, capsys, handler):
    from lambdatools import importer
    code = {"index.js": "", "package.json": "{}", "package-lock.json": "{}"}
    backup_dir = _fake_backup(tmp_path / "b", code=code, runtime="nodejs20.x", handler=handler)
    assert importer.run(_import_args(backup_dir, tmp_path / "p"), None) == 0


def test_import_unhashed_record_row_does_not_claim_user_file(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"utils.py": "mine\n"})
    code["requests-2.25.0.dist-info/RECORD"] += "utils.py,,\n"
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p"), None)
    assert (tmp_path / "p/utils.py").read_text() == "mine\n"




def _cfg(region):
    from lambdatools.common import config as cfgmod
    return cfgmod.ProjectConfig(path=Path("lambda-tools.json"), data={"region": region} if region else {})


@pytest.fixture
def no_region_env(monkeypatch):
    for var in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_region_comes_from_config_when_not_given(no_region_env):
    assert aws.resolve_region(None, _cfg("eu-west-1")) == "eu-west-1"
    assert aws.resolve_region(None, None) is None


@pytest.mark.parametrize("flag,env", [("us-west-2", None), (None, "us-west-2")])
def test_region_flag_or_env_overrides_config_with_warning(no_region_env, flag, env):
    from lambdatools.common.log import WARNINGS
    if env:
        no_region_env.setenv("AWS_REGION", env)
    assert aws.resolve_region(flag, _cfg("eu-west-1")) == "us-west-2"
    assert any("overrides region eu-west-1" in m for m in WARNINGS._items["aws"])


def test_scope_check_rejects_function_outside_session_region():
    with pytest.raises(ToolError, match="this run uses region us-west-2"):
        aws.check_function_scope("arn:aws:lambda:us-east-1:111111111111:function:x", "111111111111", None, "us-west-2")


def test_backup_with_explicit_region_differing_from_config(tmp_path, lambda_env, capsys):
    # regression: an explicit region (here the session's us-east-1) that differs from the config used to be an error
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "lambda-tools.json").write_text(json.dumps({"region": "us-west-2"}))
    args = _backup_args(tmp_path, execute=False)
    args.project = tmp_path / "proj"
    backup.run(args, lambda *_: lambda_env)  # used to raise ToolError: region mismatch
    assert json.loads(capsys.readouterr().out)["written"] is False


def _remediate_unmanaged_setup(tmp_path, monkeypatch):
    from lambdatools.common.inventory import Inventory

    def fake_resolve(files, main, runtime, arch):
        inv = Inventory()
        inv.add("PyPI", "idna", "3.15", "pip")
        return inv

    monkeypatch.setattr(remediate, "resolve_python", fake_resolve)
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv(
        affected={("PyPI", "requests", "2.25.0"): ["GHSA-R"]},
        vulns={"GHSA-R": vuln("GHSA-R", "PyPI", "requests", fixed="2.31.0", severity="MODERATE")}))
    (tmp_path / "requirements.txt").write_text("idna==3.15\n")


def test_remediate_reports_vendored_packages_it_cannot_manage(tmp_path, monkeypatch, capsys):
    # regression: scan failed on a vendored package while remediate said "No changes to make" and exited 0
    from lambdatools.common.log import WARNINGS
    _remediate_unmanaged_setup(tmp_path, monkeypatch)
    (tmp_path / "requests-2.25.0.dist-info").mkdir()
    (tmp_path / "requests-2.25.0.dist-info" / "METADATA").write_text("Name: requests\nVersion: 2.25.0\n")
    args = argparse.Namespace(path=tmp_path, fail_on=None, execute=True)
    assert remediate.run(args, None) == 1
    assert "1 outside managed files" in capsys.readouterr().out
    assert any("requests 2.25.0 in requests-2.25.0.dist-info/METADATA (GHSA-R)" in m
               for m in WARNINGS._items["remediate"])
    assert (tmp_path / "requirements.txt").read_text() == "idna==3.15\n"


def test_remediate_reports_requirement_files_not_included(tmp_path, monkeypatch, capsys):
    _remediate_unmanaged_setup(tmp_path, monkeypatch)
    (tmp_path / "requirements-dev.txt").write_text("requests==2.25.0\n")
    assert remediate.run(argparse.Namespace(path=tmp_path, fail_on=None, execute=False), None) == 1


def test_remediate_included_requirement_files_are_managed(tmp_path, monkeypatch, capsys):
    _remediate_unmanaged_setup(tmp_path, monkeypatch)
    (tmp_path / "requirements.txt").write_text("idna==3.15\n-r requirements-extra.txt\n")
    (tmp_path / "requirements-extra.txt").write_text("six==1.16.0\n")
    assert remediate.run(argparse.Namespace(path=tmp_path, fail_on=None, execute=False), None) == 0


class FakePyPI:
    """urlopen stand-in for https://pypi.org/pypi/<name>/json."""

    def __init__(self, releases):
        self.releases = releases  # name -> {version: [filenames]}, or yanked as ("file", True)

    def __call__(self, req, timeout=None):
        name = req.full_url.split("/pypi/")[1].split("/")[0]
        if name not in self.releases:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        files = {v: [{"filename": f, "yanked": False} if isinstance(f, str) else {"filename": f[0], "yanked": f[1]}
                     for f in fs] for v, fs in self.releases[name].items()}
        return io.BytesIO(json.dumps({"releases": files}).encode())


def test_latest_stable_skips_prereleases_and_yanked(monkeypatch):
    from lambdatools.common import pypi
    monkeypatch.setattr(urllib.request, "urlopen", FakePyPI({"lib": {
        "1.0.0": ["lib-1.0.0-py3-none-any.whl"], "1.1.0": [("lib-1.1.0-py3-none-any.whl", True)],
        "2.0.0rc1": ["lib-2.0.0rc1-py3-none-any.whl"], "1.0.1": ["lib-1.0.1-py3-none-any.whl"]}}))
    assert pypi.latest_stable("lib")[0] == "1.0.1"
    assert pypi.latest_stable("private-thing") is None


@pytest.mark.parametrize("filename,arch,ok", [
    ("x-1-py3-none-any.whl", "arm64", True),
    ("x-1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "x86_64", True),
    ("x-1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "arm64", False),
    ("x-1-cp38-abi3-manylinux2014_aarch64.whl", "arm64", True),
    ("x-1-cp313-cp313-manylinux2014_x86_64.whl", "x86_64", False),
    ("x-1-cp312-cp312-macosx_11_0_arm64.whl", "arm64", False),
    ("x-1.tar.gz", "x86_64", False),
])
def test_has_compatible_wheel(filename, arch, ok):
    from lambdatools.common import pypi
    assert pypi.has_compatible_wheel([{"filename": filename}], "python3.12", arch) is ok


def test_pinned_names_follows_includes(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nurllib3>=2\nsix\nidna==3.*\n-r more.txt\n")
    (tmp_path / "more.txt").write_text("Certifi===2024.1.1  # pinned\n")
    assert package.pinned_names(tmp_path, "requirements.txt") == {"requests", "certifi"}


def test_check_latest_stable_warns_on_stale_unpinned(monkeypatch):
    from lambdatools.common.log import WARNINGS
    monkeypatch.setattr(urllib.request, "urlopen", FakePyPI({
        "requests": {"2.33.0": ["requests-2.33.0-py3-none-any.whl"]},
        "native": {"3.0.0": ["native-3.0.0-cp312-cp312-manylinux2014_x86_64.whl"]},
        "urllib3": {"2.8.0": ["urllib3-2.8.0-py3-none-any.whl"]},
        "pinned": {"9.0.0": ["pinned-9.0.0-py3-none-any.whl"]}}))
    installed = [{"metadata": {"name": n, "version": v}} for n, v in
                 [("requests", "2.32.0"), ("native", "2.0.0"), ("urllib3", "2.8.0"), ("pinned", "1.0.0"), ("private", "1.0")]]
    stale = package.check_latest_stable(installed, {"pinned"}, "python3.12", "arm64")
    assert stale == ["requests 2.32.0 (latest stable 2.33.0: held back by a version constraint (its own specifier or another package's))",
                     "native 2.0.0 (latest stable 3.0.0: 3.0.0 has no wheel for python3.12 on arm64)"]
    assert any("could not check" in m and "private" in m for m in WARNINGS._items["package"])


def test_install_python_forces_stable_releases(tmp_path, monkeypatch):
    calls = {}

    def fake_run(cmd, cwd=None, timeout=1800, capture=False, env=None):
        calls["env"] = env
        Path(cmd[cmd.index("--report") + 1]).write_text(json.dumps({"install": []}))
        return ""

    monkeypatch.setattr(package.proc, "run", fake_run)
    (tmp_path / "requirements.txt").write_text("requests\n")
    assert package.install_python(tmp_path / "s", tmp_path / "requirements.txt", "python3.12", "x86_64") == []
    assert calls["env"] == {"PIP_PRE": "false"}


@pytest.mark.parametrize("current,expected", [
    ("0.0.0", "2026.11.13"),            # switching from X.Y.Z (e.g. a fresh import)
    ("2026.11.12", "2026.11.13"),
    ("2026.11.13", "2026.11.13.1"),     # second build the same day
    ("2026.11.13.1", "2026.11.13.2"),
])
def test_next_date_version(current, expected):
    from datetime import date
    from lambdatools.common import versions
    assert versions.next_date_version(current, date(2026, 11, 13)) == expected


def test_next_date_version_refuses_versions_after_today():
    from datetime import date
    from lambdatools.common import versions
    with pytest.raises(ValueError, match="not earlier than today's date 2026.11.13"):
        versions.next_date_version("2026.11.14", date(2026, 11, 13))


def test_date_versions_are_zero_padded():
    from datetime import date
    from lambdatools.common import versions
    assert versions.next_date_version("2026.03.01", date(2026, 3, 4)) == "2026.03.04"


@pytest.mark.parametrize("kw,match", [
    ({"bump": "patch"}, "--bump doesn't apply"),
    ({"set_version": "2026.13.01"}, "must be a date"),
    ({"set_version": "2026.11.12"}, "must be later"),
])
def test_date_versioning_rejects(kw, match):
    from datetime import date
    with pytest.raises(ToolError, match=match):
        package.next_version("2026.11.12", kw.get("bump"), kw.get("set_version"), "date", date(2026, 11, 13))


def test_date_versioning_set_version_same_day_counter():
    from datetime import date
    assert package.next_version("2026.11.13", None, "2026.11.13.5", "date", date(2026, 11, 13)) == "2026.11.13.5"


def test_semver_mode_refuses_to_patch_bump_a_date():
    with pytest.raises(ToolError, match="looks like a date"):
        package.next_version("2026.11.13", None, None)
    assert package.next_version("2026.11.13", "patch", None) == "2026.11.14"  # explicit --bump is honored
    assert package.next_version("1000.10.10", None, None) == "1000.10.11"     # not a plausible date
    assert package.next_version("1.0.0", None, "2026.11.03") == "2026.11.03"  # padded --set-version no longer crashes


def test_config_four_part_version_needs_date_versioning():
    from lambdatools.common import config as cfgmod
    cfgmod.validate({"version": "2026.11.13.1", "versioning": "date"}, Path("x"))
    with pytest.raises(ToolError, match="needs \"versioning\": \"date\""):
        cfgmod.validate({"version": "2026.11.13.1"}, Path("x"))
    with pytest.raises(ToolError, match="versioning"):
        cfgmod.validate({"versioning": "calver"}, Path("x"))


def test_package_with_date_versioning_end_to_end(tmp_path, monkeypatch, capsys):
    from datetime import date
    _py_project(tmp_path)
    cfg = json.loads((tmp_path / "lambda-tools.json").read_text())
    cfg.update(version="0.0.0", versioning="date")
    (tmp_path / "lambda-tools.json").write_text(json.dumps(cfg))
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    monkeypatch.setattr(package, "build_day", lambda: date(2026, 11, 3))
    assert package.run(_package_args(tmp_path), None) == 0
    assert package.run(_package_args(tmp_path), None) == 0
    assert (tmp_path / "dist" / "demo-2026.11.03.zip").exists() and (tmp_path / "dist" / "demo-2026.11.03.1.zip").exists()
    assert json.loads((tmp_path / "lambda-tools.json").read_text())["version"] == "2026.11.03.1"
    log = (tmp_path / "CHANGELOG.md").read_text()
    assert "## [2026.11.03.1] - 2026-11-03" in log and "## [2026.11.03] - 2026-11-03" in log


def test_import_name_renames_project_but_keeps_function_name(tmp_path, monkeypatch, capsys):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE)
    monkeypatch.chdir(tmp_path)
    assert importer.run(_import_args(backup_dir, None, name="orders"), None) == 0
    cfg = json.loads((tmp_path / "orders" / "lambda-tools.json").read_text())
    assert cfg["name"] == "orders" and cfg["function_name"] == "orders-api"
    assert "function:orders-api as orders (CodeSha256" in (tmp_path / "orders" / "CHANGELOG.md").read_text()
    out = json.loads(capsys.readouterr().out)
    assert out["name"] == "orders" and out["function_name"] == "orders-api"


def test_import_name_is_validated(tmp_path):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code=PY_CODE)
    with pytest.raises(ToolError, match="--name"):
        importer.run(_import_args(backup_dir, tmp_path / "p", name="bad/name"), None)


def test_import_name_not_applied_over_zip_config_warns(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"lambda-tools.json": '{"name": "old"}'})
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=code), tmp_path / "p", name="orders"), None)
    assert json.loads((tmp_path / "p" / "lambda-tools.json").read_text())["name"] == "old"
    assert "--name orders was not applied" in _import_warnings()


def test_package_artifact_uses_renamed_project(tmp_path, monkeypatch, capsys):
    from lambdatools import importer
    backup_dir = _fake_backup(tmp_path / "b", code={"handler.py": "def handler(e, c):\n    return 1\n"})
    importer.run(_import_args(backup_dir, tmp_path / "p", name="orders"), None)
    capsys.readouterr()
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    assert package.run(_package_args(tmp_path / "p"), None) == 0
    out = capsys.readouterr().out
    assert (tmp_path / "p" / "dist" / "orders-0.0.1.zip").exists()
    assert "--function-name orders-api " in out


def _write_backup_json(backup_dir, name, data):
    """Add a file to a fake backup and re-sign the manifest."""
    import hashlib
    (backup_dir / name).write_text(json.dumps(data))
    manifest = json.loads((backup_dir / "manifest.json").read_text())
    manifest["files"][name] = hashlib.sha256((backup_dir / name).read_bytes()).hexdigest()
    (backup_dir / "manifest.json").write_text(json.dumps(manifest))


def test_sample_events_follow_triggers(tmp_path):
    from lambdatools import smoke
    from lambdatools.common import backupdir
    b = _fake_backup(tmp_path / "b", code=PY_CODE)
    _write_backup_json(b, "policies.json", {"$LATEST": {"Policy": {"Statement": [
        {"Principal": {"Service": "events.amazonaws.com"},
         "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:events:us-east-1:123456789012:rule/nightly"}}},
        {"Principal": {"Service": "s3.amazonaws.com"},
         "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::uploads"}}},
        {"Principal": {"Service": "iot.amazonaws.com"}}]}}})
    _write_backup_json(b, "event-source-mappings.json",
                       [{"EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:jobs"}])
    events = smoke.sample_events(backupdir.load(b))
    assert sorted(events) == ["eventbridge.json", "s3.json", "sqs.json"]
    assert events["eventbridge.json"]["resources"] == ["arn:aws:events:us-east-1:123456789012:rule/nightly"]
    assert events["s3.json"]["Records"][0]["s3"]["bucket"]["name"] == "uploads"
    assert events["sqs.json"]["Records"][0]["eventSourceARN"].endswith(":jobs")
    assert "no sample event for trigger iot.amazonaws.com; add one in tests/events/" in _import_warnings().split(" | ")


def test_smoke_scaffold_never_writes_env_values():
    from lambdatools import smoke
    conf = {"Handler": "app.handler", "FunctionName": "fn",
            "Environment": {"Variables": {"API_TOKEN": "s3cr3t-value", "MODE": "prod"}}}
    files = smoke.scaffold(conf, {"region": "eu-west-1", "account": "111111111111"}, {"generic.json": {}})
    cfg = json.loads(files["tests/smoke_config.json"])
    assert cfg["environment"] == {"API_TOKEN": "smoke-test", "MODE": "smoke-test"}
    assert b"s3cr3t" not in b"".join(files.values())


def _smoke_project(root, handler_body):
    from lambdatools import smoke
    root.mkdir()
    (root / "app.py").write_text(handler_body)
    files = smoke.scaffold({"Handler": "app.handler", "FunctionName": "fn", "Environment": {"Variables": {"MODE": "x"}}},
                           {"region": "us-east-1", "account": "123456789012"},
                           {"ok.json": {"name": "a"}, "bad.json": {}})
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)


def _run_generated(root, update=False, record_new=True, environ=None):
    """Runs the generated test the way `lambda-tools test` does (bootstrap, environment, flags), minus the OS sandbox."""
    import subprocess
    import sys
    from lambdatools import smoke
    with pytest.MonkeyPatch.context() as mp:
        for key, value in (environ or {}).items():
            mp.setenv(key, value)
        env = smoke.test_env()
    if update:
        env["LAMBDA_TOOLS_UPDATE_BASELINE"] = "1"
    if record_new:
        env["LAMBDA_TOOLS_RECORD_NEW"] = "1"
    results = root.parent / "results.jsonl"
    results.unlink(missing_ok=True)
    env["LAMBDA_TOOLS_RESULTS"] = str(results)
    proc = subprocess.run(smoke.test_command(sys.executable, None, root), cwd=root, env=env,
                          capture_output=True, text=True, timeout=300)
    baseline = root / "tests" / "smoke_baseline.json"
    had = json.loads(baseline.read_text()) if baseline.exists() else {}
    events = {p.name for p in (root / "tests" / "events").glob("*.json")}
    now = smoke.merge_results(had, smoke.read_results(results), events, update)
    if now != had:
        baseline.write_text(json.dumps(now, indent=2, sort_keys=True) + "\n")
    return proc


HANDLER_V1 = """import os
import boto3
import urllib.request

def handler(event, context):
    assert os.environ["MODE"] == "smoke-test" and context.function_name == "fn"
    boto3.client("s3").create_bucket(Bucket="smoke")   # answered by moto
    if not event:
        urllib.request.urlopen("https://example.com")  # network is blocked
    return {"hello": event["name"]}
"""


def test_generated_smoke_test_records_then_compares(tmp_path):
    root = tmp_path / "proj"
    _smoke_project(root, HANDLER_V1)
    first = _run_generated(root)
    assert first.returncode == 0, first.stdout + first.stderr
    baseline = json.loads((root / "tests" / "smoke_baseline.json").read_text())
    assert baseline == {"ok.json": "ok", "bad.json": "urllib.error.URLError"}
    assert _run_generated(root).returncode == 0
    # a regression: the handler now fails on an event that used to work
    (root / "app.py").write_text(HANDLER_V1.replace('event["name"]', 'event["missing"]'))
    broken = _run_generated(root)
    assert broken.returncode == 1 and "outcome changed from 'ok' to 'builtins.KeyError'" in broken.stdout
    assert _run_generated(root, update=True).returncode == 0
    assert json.loads((root / "tests" / "smoke_baseline.json").read_text())["ok.json"] == "builtins.KeyError"


def test_generated_smoke_test_needs_a_recorded_outcome_after_requirements_change(tmp_path):
    root = tmp_path / "proj"
    _smoke_project(root, HANDLER_V1)
    (root / "tests" / "events" / "bad.json").unlink()
    result = _run_generated(root, record_new=False)  # what `run` does when the requirements differ
    assert result.returncode == 1 and "has no baseline outcome" in result.stdout
    assert not (root / "tests" / "smoke_baseline.json").exists()


def test_generated_smoke_test_is_skipped_by_a_plain_pytest_run(tmp_path):
    import subprocess
    import sys
    root = tmp_path / "proj"
    _smoke_project(root, HANDLER_V1)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "LAMBDA_TOOLS_"))}
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_smoke.py"],
                            cwd=root, env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 5 and "skipped" in result.stdout  # 5: nothing ran
    assert not (root / "tests" / "smoke_baseline.json").exists()


def test_generated_smoke_test_handles_slash_handlers_and_ignores_project_pytest_config(tmp_path):
    root = tmp_path / "proj"
    _smoke_project(root, HANDLER_V1)
    (root / "src").mkdir()
    (root / "app.py").rename(root / "src" / "app.py")
    cfg = json.loads((root / "tests" / "smoke_config.json").read_text())
    (root / "tests" / "smoke_config.json").write_text(json.dumps({**cfg, "handler": "src/app.handler"}))
    (root / "pytest.ini").write_text("[pytest]\naddopts = -n auto --cov\n")
    (root / "tests" / "conftest.py").write_text("import not_installed_anywhere\n")
    result = _run_generated(root)
    assert result.returncode == 0, result.stdout + result.stderr


def test_smoke_env_drops_developer_environment(monkeypatch):
    from lambdatools import smoke
    monkeypatch.setenv("AWS_PROFILE", "prod")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://example.com")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-x")
    env = smoke.test_env()
    assert not {"AWS_PROFILE", "AWS_ENDPOINT_URL", "GITHUB_TOKEN", "PYTEST_ADDOPTS"} & set(env)
    assert env["AWS_CONFIG_FILE"] == env["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
    assert env["AWS_ACCESS_KEY_ID"] == "testing" and env["AWS_EC2_METADATA_DISABLED"] == "true"


def test_smoke_test_deps_pin_to_recorded_versions_unless_project_names_them():
    from lambdatools import smoke
    pins = {"boto3": "1.35.0", "botocore": "1.35.0", "moto": "5.0.1", "pytest": "8.3.0"}
    assert smoke.test_deps([], pins) == ["boto3==1.35.0", "botocore==1.35.0", "moto==5.0.1", "pytest==8.3.0"]
    assert smoke.test_deps(["boto3==1.34.0\nrequests\n"], pins) == ["moto==5.0.1", "pytest==8.3.0"]
    assert smoke.test_deps([], {}) == ["boto3", "moto>=5", "pytest>=8"]


# Each vector a handler might use to reach the network or another process; all must be refused before
# the operating system sees them. The listener on 127.0.0.1 proves nothing was connected.
NETWORK_PROBES = """import asyncio, ctypes, multiprocessing, os, socket, subprocess, sys, urllib.request
from socket import getaddrinfo as early_getaddrinfo
import pytest
PORT = int(os.environ["PROBE_PORT"])

def _udp():
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", PORT))

def _unix():
    socket.socket(socket.AF_UNIX).connect("/var/run/docker.sock")

async def _aio():
    await asyncio.open_connection("127.0.0.1", PORT)

VECTORS = {
    "connect": lambda: socket.socket().connect(("127.0.0.1", PORT)),
    "connect_ex": lambda: socket.socket().connect_ex(("127.0.0.1", PORT)),
    "create_connection": lambda: socket.create_connection(("127.0.0.1", PORT)),
    "c_socket": lambda: __import__("_socket").socket().connect(("127.0.0.1", PORT)),
    "early_getaddrinfo": lambda: early_getaddrinfo("example.com", 443),
    "gethostbyname": lambda: socket.gethostbyname("example.com"),
    "gethostbyname_ex": lambda: socket.gethostbyname_ex("example.com"),
    "getnameinfo": lambda: socket.getnameinfo(("127.0.0.1", PORT), 0),
    "udp_sendto": _udp,
    "unix": _unix,
    "urllib": lambda: urllib.request.urlopen(f"http://127.0.0.1:{PORT}", timeout=2),
    "asyncio": lambda: asyncio.run(_aio()),
    "subprocess": lambda: subprocess.run(["curl", f"http://127.0.0.1:{PORT}"]),
    "os_system": lambda: os.system("curl http://127.0.0.1:%d" % PORT),
    "os_exec": lambda: os.execv("/usr/bin/curl", ["curl"]),
    "posix_spawn": lambda: os.posix_spawn("/usr/bin/curl", ["curl"], {}),
    "mp_spawn": lambda: multiprocessing.get_context("spawn").Process(target=print).start(),
    "mp_forkserver": lambda: multiprocessing.get_context("forkserver").Process(target=print).start(),
    "subinterpreter": lambda: __import__("_interpreters" if sys.version_info >= (3, 13) else "_xxsubinterpreters"),
}

@pytest.mark.parametrize("name", sorted(VECTORS))
def test_blocked(name):
    # ConnectionRefusedError / PermissionError (or URLError wrapping them); ImportError for subinterpreters
    with pytest.raises((OSError, ImportError)):
        VECTORS[name]()
"""


def test_smoke_bootstrap_blocks_every_network_and_process_vector(tmp_path):
    import socket
    import subprocess
    import sys
    from lambdatools import smoke
    (tmp_path / "test_probe.py").write_text(NETWORK_PROBES)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0)
    env = {**smoke.test_env(), "PROBE_PORT": str(listener.getsockname()[1])}
    cmd = [sys.executable, "-c", smoke.BOOTSTRAP, "-q", "-p", "no:cacheprovider", "-c", os.devnull,
           "--rootdir", str(tmp_path), "test_probe.py"]
    result = subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=300)
    with pytest.raises(BlockingIOError):
        listener.accept()  # nothing ever connected
    listener.close()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "19 passed" in result.stdout


def test_generated_smoke_test_guards_itself_without_the_bootstrap(tmp_path):
    import subprocess
    import sys
    root = tmp_path / "proj"
    _smoke_project(root, "import socket\ndef handler(event, context):\n"
                         "    return socket.socket().connect_ex(('192.0.2.1', 80))\n")
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("AWS_")},
           "LAMBDA_TOOLS_SMOKE": "1", "LAMBDA_TOOLS_RECORD_NEW": "1",
           "LAMBDA_TOOLS_RESULTS": str(tmp_path / "results.jsonl")}
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_smoke.py"],
                            cwd=root, env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    from lambdatools import smoke
    assert set(smoke.read_results(tmp_path / "results.jsonl").values()) == {"builtins.ConnectionRefusedError"}


# Runs with no audit hook at all, as C extensions or ctypes would: only the OS sandbox stands in the way
OS_PROBE = """import json, os, socket, subprocess, sys
port, sock_path, root = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def attempt(fn):
    try:
        fn()
        return "allowed"
    except Exception as e:
        return type(e).__name__
def write(path):
    with open(path, "w") as f:
        f.write("x")
print(json.dumps({
    "tcp": attempt(lambda: socket.create_connection(("127.0.0.1", port), timeout=5)),
    "dns": attempt(lambda: socket.getaddrinfo("example.com", 443)),
    "unix": attempt(lambda: socket.socket(socket.AF_UNIX).connect(sock_path)),
    "exec": attempt(lambda: subprocess.run(["/bin/echo"], check=True, capture_output=True)),
    "write_project": attempt(lambda: write(os.path.join(root, "planted.py"))),
    "write_home": attempt(lambda: write(os.path.expanduser("~/.lambda-tools-sandbox-probe"))),
    "write_tests": attempt(lambda: write(os.path.join(root, "tests", "conftest.py"))),
    "write_tmp": attempt(lambda: write(os.path.join(os.environ["TMPDIR"], "ok.txt"))),
}))
"""


def test_smoke_os_sandbox_blocks_network_below_python(tmp_path):
    """The OS layer: code that skips the audit hook can't connect, resolve names, start programs, reach
    local Unix sockets, or plant files outside tests/."""
    import socket
    import subprocess
    import sys
    from pathlib import Path
    from lambdatools import smoke
    root = tmp_path / "proj"
    (root / "tests").mkdir(parents=True)
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    prefix = smoke.isolation_prefix(Path(sys.executable), root, scratch)
    if prefix is None:
        pytest.skip("no OS sandbox on this machine")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0)
    import tempfile
    # AF_UNIX paths are short; on Linux, also outside /tmp, /run and $HOME, which the old sandbox hid
    sock_path = os.path.join(tempfile.mkdtemp(dir="/var/tmp" if sys.platform.startswith("linux") else "/tmp"),
                             "s.sock")
    unix = socket.socket(socket.AF_UNIX)
    unix.bind(sock_path)
    unix.listen()
    unix.settimeout(0)
    result = subprocess.run([*prefix, sys.executable, "-c", OS_PROBE, str(listener.getsockname()[1]), sock_path,
                             str(root)], capture_output=True, text=True, timeout=60, cwd=root,
                            env={**os.environ, "TMPDIR": str(scratch)})
    for sock in (listener, unix):
        with pytest.raises(BlockingIOError):
            sock.accept()  # nothing ever connected
        sock.close()
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout)
    assert outcome.pop("write_tmp") == "allowed"  # the per-run temp directory, where results go
    if sys.platform.startswith("linux"):
        outcome.pop("exec")  # bwrap can't refuse exec; children stay in the sandbox
    assert "allowed" not in outcome.values(), outcome
    assert not (root / "tests" / "conftest.py").exists()
    assert not (root / "planted.py").exists()
    assert not (Path.home() / ".lambda-tools-sandbox-probe").exists()


def test_test_command_fails_closed_without_os_sandbox(tmp_path, monkeypatch):
    import sys
    from pathlib import Path
    from lambdatools import smoke
    (tmp_path / "lambda-tools.json").write_text(json.dumps({"name": "x", "runtime": "python3.12", "version": "1.0.0"}))
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_smoke.py").write_text("")
    monkeypatch.setattr(smoke, "find_python", lambda runtime, explicit: (sys.executable, "3.12"))
    monkeypatch.setattr(smoke, "ensure_env", lambda *a, **k: Path(sys.executable))
    monkeypatch.setattr(smoke, "isolation_prefix", lambda *a: None)
    args = argparse.Namespace(path=tmp_path, init=False, python=None, update_baseline=False, backup=None,
                              execute=False, allow_unisolated=False)
    with pytest.raises(ToolError, match="--allow-unisolated"):
        smoke.run(args, None)


def test_installed_versions_reads_metadata_without_running_the_venv(tmp_path):
    from lambdatools import smoke
    site = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    for name, version in (("moto", "5.0.1"), ("boto3", "1.35.0"), ("other", "1.0")):
        d = site / f"{name}-{version}.dist-info"
        d.mkdir(parents=True)
        (d / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    (site / "zz.pth").write_text("import sys; sys.exit('a .pth file ran')\n")
    python = tmp_path / "venv" / "bin" / "python"  # doesn't exist: nothing is executed
    assert smoke.installed_versions(python) == {"boto3": "1.35.0", "moto": "5.0.1"}


def test_generated_smoke_test_fails_when_handler_missing(tmp_path):
    root = tmp_path / "proj"
    _smoke_project(root, "def other(event, context):\n    return 1\n")
    result = _run_generated(root)
    assert result.returncode == 1 and "test_handler_imports" in result.stdout


def test_import_writes_smoke_tests(tmp_path, capsys):
    from lambdatools import importer
    importer.run(_import_args(_fake_backup(tmp_path / "b", code=PY_CODE), tmp_path / "p"), None)
    cfg = json.loads((tmp_path / "p" / "tests" / "smoke_config.json").read_text())
    assert cfg["handler"] == "handler.handler" and cfg["function_name"] == "orders-api"
    assert (tmp_path / "p" / "tests" / "events" / "generic.json").exists()
    assert json.loads(capsys.readouterr().out)["next"][0].startswith("lambda-tools test ")


def test_find_python_checks_version(tmp_path):
    import sys
    from lambdatools import smoke
    here = "%d.%d" % sys.version_info[:2]
    assert smoke.find_python(f"python{here}", sys.executable)[1] == here
    with pytest.raises(ToolError, match="but the function runs on python3.9"):
        smoke.find_python("python3.9", sys.executable)


def test_test_command_refuses_node_and_missing_tests(tmp_path):
    from lambdatools import smoke
    (tmp_path / "lambda-tools.json").write_text(json.dumps({"name": "x", "runtime": "nodejs20.x", "version": "1.0.0"}))
    args = argparse.Namespace(path=tmp_path, init=False, python=None, update_baseline=False, backup=None, execute=False,
                              allow_unisolated=False)
    with pytest.raises(ToolError, match="Python runtimes only"):
        smoke.run(args, None)
    (tmp_path / "lambda-tools.json").write_text(json.dumps({"name": "x", "runtime": "python3.12", "version": "1.0.0"}))
    with pytest.raises(ToolError, match="test --init"):
        smoke.run(args, None)


def test_test_init_dry_run_then_execute(tmp_path):
    from lambdatools import smoke
    (tmp_path / "lambda-tools.json").write_text(json.dumps(
        {"name": "x", "runtime": "python3.12", "version": "1.0.0", "handler": "app.handler"}))
    args = argparse.Namespace(path=tmp_path, init=True, python=None, update_baseline=False, backup=None, execute=False)
    assert smoke.run(args, None) == 0 and not (tmp_path / "tests").exists()
    args.execute = True
    assert smoke.run(args, None) == 0
    assert json.loads((tmp_path / "tests" / "smoke_config.json").read_text())["handler"] == "app.handler"
    with pytest.raises(ToolError, match="already exist"):
        smoke.run(args, None)


def test_runtime_check_levels():
    from datetime import date
    from lambdatools.common import runtimes
    on = date(2026, 11, 13)
    assert runtimes.check("python3.13", on).level == "ok"
    status = runtimes.check("python3.10", on)
    assert status.level == "deprecated" and "deprecated on 2026-10-31" in status.message
    assert "move to python3.14" in status.message
    nearing = runtimes.check("python3.11", date(2027, 3, 1))  # deprecated 2027-06-30, within WARN_DAYS
    assert nearing.level == "warn" and "will be deprecated on 2027-06-30" in nearing.message
    assert runtimes.check("python3.15", on).level == "warn"  # preview
    assert runtimes.check("python3.99", on).level == "warn"  # unknown is never "ok"
    assert runtimes.check("nodejs20.x", on).level == "deprecated"
    assert runtimes.newest_supported("nodejs18.x", on) == "nodejs24.x"
    assert runtimes.check("python3.13", date(2029, 7, 1)).level == "deprecated"
    assert runtimes.stale_table_warning(on) is None
    assert "last checked" in runtimes.stale_table_warning(date(2028, 1, 1))


def _deprecated_project(root):
    _py_project(root)
    cfg = json.loads((root / "lambda-tools.json").read_text())
    (root / "lambda-tools.json").write_text(json.dumps({**cfg, "runtime": "python3.9"}, indent=2) + "\n")


def test_package_refuses_deprecated_runtime_unless_allowed(tmp_path, monkeypatch, capsys):
    _deprecated_project(tmp_path)
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    with pytest.raises(ToolError, match="python3.9 was deprecated.*--allow-deprecated-runtime"):
        package.run(_package_args(tmp_path), None)
    assert not (tmp_path / "dist").exists()
    assert package.run(_package_args(tmp_path, allow_deprecated_runtime=True), None) == 0
    assert "Built for deprecated runtime python3.9" in (tmp_path / "CHANGELOG.md").read_text()
    assert "update-function-configuration --function-name demo-fn --runtime python3.9" in capsys.readouterr().out


def test_scan_fails_on_deprecated_runtime(tmp_path, monkeypatch, capsys):
    from lambdatools import scan
    backup_dir = _fake_backup(tmp_path / "b", runtime="python3.9")
    monkeypatch.setattr(urllib.request, "urlopen", FakeOsv())
    assert scan.run(_scan_args(backup_dir), None) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["runtime"]["status"] == "deprecated" and report["findings"] == []
    assert scan.run(_scan_args(backup_dir, allow_deprecated_runtime=True), None) == 0
