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
    backup.run(_backup_args(tmp_path, execute=False), lambda: lambda_env)
    out = json.loads(capsys.readouterr().out)
    assert out["written"] is False and out["environment_values"] == "redacted"
    assert not (tmp_path / "backups").exists()


def test_backup_redacts_when_pass_missing(tmp_path, lambda_env, capsys, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    code = backup.run(_backup_args(tmp_path, execute=True), lambda: lambda_env)
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

    backup.run(_backup_args(tmp_path, execute=True), lambda: lambda_env)
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
        backup.run(_backup_args(tmp_path, execute=True), lambda: lambda_env)


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
                allow_vulnerable=False, allow_gaps=False, allow_scripts=False, execute=execute)
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
    backup.run(_backup_args(tmp_path, execute=True), lambda: lambda_env)
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
                include_dev=False, json=True, report=None)
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


def _import_args(backup_dir, to, execute=True):
    return argparse.Namespace(backup=backup_dir, to=to, execute=execute)


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
    assert files == ["CHANGELOG.md", "bin/run.sh", "handler.py", "lambda-tools.json", "lib/util.py", "requirements.txt"]
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


def test_import_keeps_existing_requirements(tmp_path, capsys):
    from lambdatools import importer
    code = dict(PY_CODE, **{"requirements.txt": "requests\n"})
    backup_dir = _fake_backup(tmp_path / "b", code=code)
    importer.run(_import_args(backup_dir, tmp_path / "proj"), None)
    assert (tmp_path / "proj" / "requirements.txt").read_text() == "requests\n"
    assert "requests==2.25.0" in (tmp_path / "proj" / "requirements.deployed.txt").read_text()


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
