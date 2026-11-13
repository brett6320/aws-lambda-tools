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
