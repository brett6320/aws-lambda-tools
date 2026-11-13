"""test: run a Python function's smoke tests in a venv that matches its runtime.

Smoke tests answer one question: does the handler still import and behave the
same on sample events? They are meant to run before and after `remediate`,
which changes dependency versions.

`import` writes the tests (tests/test_smoke.py, tests/smoke_config.json, and
sample events chosen from the function's triggers); `test --init` writes them
for a project that wasn't imported. The first run records each event's
outcome ("ok" or the exception type) in tests/smoke_baseline.json; later runs
fail when an outcome changes. AWS calls go to moto, other network access is
blocked, and environment variables get placeholder values.

Network blocking has two layers. In the test process, a Python audit hook
(installed before pytest, conftest files, plugins or the project load)
refuses every socket connect, send, and name lookup, every attempt to
start a process, and subinterpreters; audit events fire inside the interpreter before the
operating system sees the call, so they also cover connect_ex, UDP, and
references to socket functions taken before the test started. Code that
bypasses the socket module (C extensions with their own networking, ctypes)
is stopped by the second layer: the whole test process runs in an OS sandbox
(macOS sandbox-exec, Linux bubblewrap) with no network, no access to local
services that could connect for it, and writes only to tests/ and a temp
directory. When no sandbox is available the command refuses to run unless
--allow-unisolated.
Network is used only before the tests start, by pip, to build the venv.

The venv uses the local `python3.X` that matches the function's runtime and
installs the project's requirements for this machine, plus boto3 (provided
by the Lambda runtime), pytest, and moto. It is cached per requirements set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import re
import tempfile
from pathlib import Path

from packaging.utils import canonicalize_name

from lambdatools.common import backupdir, config
from lambdatools.common.fsutil import data_dir, ensure_private_dir
from lambdatools.common.log import EXIT_FINDINGS, EXIT_OK, WARNINGS, ToolError, log, mode_prefix
from lambdatools.common.sanitize import clean

TEST_FILE = "tests/test_smoke.py"
CONFIG_FILE = "tests/smoke_config.json"
EVENTS_DIR = "tests/events"
BASELINE_FILE = "tests/smoke_baseline.json"
TEST_DEPS = ["boto3", "pytest>=8", "moto>=5"]
# Recorded with the baseline and reused, so a later run differs only in the project's own requirements
PINNED = ("boto3", "botocore", "moto", "pytest")
META_KEY = "_recorded_with"
PLACEHOLDER = "smoke-test"

# Audit events (https://docs.python.org/3/library/audit_events.html) refused while smoke tests run
NETWORK_EVENTS = ("socket.connect", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo",
                  "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo")
PROCESS_EVENTS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile",
                  "_winapi.CreateProcess")
# Subinterpreters don't inherit audit hooks, so importing them is refused too
SUBINTERPRETER_MODULES = ("_interpreters", "_xxsubinterpreters", "_interpchannels", "_xxinterpchannels",
                          "_interpqueues", "concurrent.interpreters")

# The in-process guard, shared by BOOTSTRAP and the generated test. multiprocessing's spawn and
# forkserver start processes through _posixsubprocess.fork_exec, which raises no audit event.
GUARD = f"""import sys
NETWORK_EVENTS = {set(NETWORK_EVENTS)!r}
PROCESS_EVENTS = {set(PROCESS_EVENTS)!r}
SUBINTERPRETER_MODULES = {set(SUBINTERPRETER_MODULES)!r}
_GUARD = {{"on": False}}


def _audit(event, args):
    if not _GUARD["on"]:
        return
    if event in NETWORK_EVENTS:
        raise ConnectionRefusedError(f"network access is blocked in smoke tests ({{event}})")
    if event in PROCESS_EVENTS:
        raise PermissionError(f"starting processes is blocked in smoke tests ({{event}})")
    if event == "import" and args[0] in SUBINTERPRETER_MODULES:
        raise ImportError(f"subinterpreters are blocked in smoke tests ({{args[0]}})")


def _no_fork_exec(*args, **kwargs):
    raise PermissionError("starting processes is blocked in smoke tests (fork_exec)")


def _guard(on):
    _GUARD["on"] = on
    try:
        import _posixsubprocess
    except ImportError:  # Windows
        return
    if on:
        _GUARD.setdefault("fork_exec", _posixsubprocess.fork_exec)
        _posixsubprocess.fork_exec = _no_fork_exec
    elif "fork_exec" in _GUARD:
        _posixsubprocess.fork_exec = _GUARD["fork_exec"]


sys.addaudithook(_audit)
"""

# Runs pytest with the guard on before pytest, plugins, conftest files, or the project load. The
# project root is still first on sys.path (cwd), as on Lambda; the hook is in place before anything
# there can be imported.
BOOTSTRAP = GUARD + """_guard(True)
import pytest
sys.exit(pytest.main(sys.argv[1:]))
"""


def _sb(path: str | Path) -> str:
    """A path as a sandbox profile string literal."""
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def macos_profile(executables: list[Path], prefixes: list[Path], writable: list[Path],
                  readonly: list[Path] = ()) -> str:
    """Seatbelt profile: no network, no Mach services (DNS, launchd, LaunchServices go through them), no
    Apple Events, no programs other than the test Python, and writes only to the given directories."""
    # framework builds re-exec Python.app inside their own prefix
    execs = " ".join([*(f"(literal {_sb(p)})" for p in executables), *(f"(subpath {_sb(p)})" for p in prefixes)])
    dirs = " ".join(f"(subpath {_sb(p)})" for p in writable)
    # later rules win: the project and venv stay read-only even inside a writable temp directory
    locked = "".join(f"(deny file-write* (subpath {_sb(p)}))" for p in readonly)
    return ("(version 1)(allow default)"
            "(deny network*)(deny mach-lookup)(deny appleevent-send)"
            f"(deny process-exec*)(allow process-exec* {execs})"
            f'(deny file-write*)(allow file-write* {dirs} (literal "/dev/null") (literal "/dev/tty") '
            '(regex #"^/dev/fd/"))' + locked)


def linux_sandbox(root: Path, keep: list[Path], tmp: Path) -> list[str]:
    """bubblewrap: new network, user, PID and IPC namespaces, and a filesystem that holds only the
    system directories, the interpreter, the venv and the project, all read-only, plus an empty /tmp
    and the per-run temp directory. No host Unix socket (Docker, LXD, D-Bus, systemd-resolved, nscd,
    ssh-agent) is visible. bwrap can't refuse exec, but child processes stay inside the sandbox."""
    cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
           "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    for top in ("/usr", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
        if os.path.islink(top):  # merged-/usr systems
            cmd += ["--symlink", os.readlink(top), top]
        elif os.path.isdir(top):
            cmd += ["--ro-bind", top, top]
    for path in sorted({q for p in keep for q in (p.absolute(), p.resolve())}):
        cmd += ["--ro-bind", str(path), str(path)]
    tmp = tmp.resolve()
    return cmd + ["--bind", str(tmp), str(tmp), "--chdir", str(root.resolve())]


# The generated test. It is constant: everything about the function comes from smoke_config.json.
TEST_TEMPLATE = '''"""Smoke tests generated by lambda-tools. Run them with `lambda-tools test .`

The first run records each event's outcome in smoke_baseline.json ("ok", or the
exception type when the handler raises on that sample event). Later runs fail
when an outcome changes, for example after `lambda-tools remediate` upgrades a
dependency. Re-record with `lambda-tools test . --update-baseline`.

AWS calls go to moto, other network access and starting processes are
blocked, and environment variables get placeholder values. Add events to
tests/events/ and edit freely.
"""

import importlib
import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from moto import mock_aws

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
CONFIG = json.loads((TESTS / "smoke_config.json").read_text())
EVENTS = sorted((TESTS / "events").glob("*.json"))
BASELINE = TESTS / "smoke_baseline.json"
UPDATE = os.environ.get("LAMBDA_TOOLS_UPDATE_BASELINE") == "1"  # set with LAMBDA_TOOLS_RESULTS
RECORD_NEW = os.environ.get("LAMBDA_TOOLS_RECORD_NEW") == "1"

# Outcomes depend on the venv `lambda-tools test` builds, so a project's ordinary test run skips these
if os.environ.get("LAMBDA_TOOLS_SMOKE") != "1":
    pytest.skip("run smoke tests with `lambda-tools test`", allow_module_level=True)


class Context:
    """The parts of the Lambda context object handlers usually read."""

    def __init__(self):
        self.function_name = CONFIG["function_name"]
        self.function_version = "$LATEST"
        self.invoked_function_arn = (f"arn:aws:lambda:{CONFIG['region']}:{CONFIG['account_id']}"
                                     f":function:{CONFIG['function_name']}")
        self.memory_limit_in_mb = str(CONFIG["memory_mb"])
        self.aws_request_id = str(uuid.uuid4())
        self.log_group_name = f"/aws/lambda/{CONFIG['function_name']}"
        self.log_stream_name = "smoke-test"

    def get_remaining_time_in_millis(self):
        return CONFIG["timeout_s"] * 1000


# Network and process guard. Python audit hooks run before the operating system sees a call, so this
# also refuses connect_ex, UDP, and socket functions imported before the test started. Hooks can't be
# removed, so this one only acts while a smoke test runs. `lambda-tools test` also turns it on before
# pytest starts, and runs the whole process in an OS sandbox without network access.
__GUARD__

@pytest.fixture(autouse=True)
def lambda_environment(monkeypatch):
    env = {
        "AWS_REGION": CONFIG["region"], "AWS_DEFAULT_REGION": CONFIG["region"],
        "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
        "AWS_LAMBDA_FUNCTION_NAME": CONFIG["function_name"], "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
        "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": str(CONFIG["memory_mb"]), "LAMBDA_TASK_ROOT": str(ROOT),
        **CONFIG["environment"],
    }
    # never the developer's own profiles, credential_process, or SSO settings
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.syspath_prepend(str(ROOT))
    before = set(sys.modules)
    # moto answers AWS calls before they reach a socket; everything else is refused
    with mock_aws():
        _guard(True)
        try:
            yield
        finally:
            _guard(False)
    for name in set(sys.modules) - before:  # import the project fresh for every test
        path = getattr(sys.modules[name], "__file__", None) or ""
        if path.startswith(str(ROOT)):
            del sys.modules[name]


def _handler():
    module_name, _, func = CONFIG["handler"].rpartition(".")
    return getattr(importlib.import_module(module_name.replace("/", ".")), func)


def test_handler_imports():
    assert callable(_handler())


@pytest.mark.parametrize("event_file", EVENTS, ids=lambda p: p.stem)
def test_handler_outcome_matches_baseline(event_file):
    handler = _handler()
    try:
        handler(json.loads(event_file.read_text()), Context())
        outcome = "ok"
    except Exception as e:
        outcome = f"{type(e).__module__}.{type(e).__qualname__}"
    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    if UPDATE or (RECORD_NEW and event_file.name not in baseline):
        # the project is read-only while tests run; `lambda-tools test` merges this into the baseline
        with open(os.environ["LAMBDA_TOOLS_RESULTS"], "a") as results:
            results.write(json.dumps({event_file.name: outcome}) + "\\n")
        return
    assert event_file.name in baseline, (
        f"{event_file.name} has no baseline outcome for the requirements it was recorded with; check out "
        "those requirements and run `lambda-tools test --update-baseline`")
    assert outcome == baseline[event_file.name], (
        f"{event_file.name}: outcome changed from {baseline[event_file.name]!r} to {outcome!r}")
'''
TEST_TEMPLATE = TEST_TEMPLATE.replace("__GUARD__", GUARD.replace("import sys\n", "", 1))


# --- Sample events ----------------------------------------------------------------

def _arn_name(arn: str | None, default: str) -> str:
    """Last segment of an ARN (bucket, queue, topic, table, rule)."""
    if not arn:
        return default
    tail = arn.split(":")[-1]
    return tail.split("/")[-1] if "/" in tail else tail or default


def _event(kind: str, region: str, account: str, source_arn: str | None) -> dict:
    if kind == "sqs":
        arn = source_arn or f"arn:aws:sqs:{region}:{account}:queue"
        return {"Records": [{"messageId": "00000000-0000-0000-0000-000000000000", "receiptHandle": "handle",
                             "body": "{}", "attributes": {"ApproximateReceiveCount": "1", "SentTimestamp": "0"},
                             "messageAttributes": {}, "md5OfBody": "99914b932bd37a50b983c5e7c90ae93b",
                             "eventSource": "aws:sqs", "eventSourceARN": arn, "awsRegion": region}]}
    if kind == "sns":
        arn = source_arn or f"arn:aws:sns:{region}:{account}:topic"
        return {"Records": [{"EventSource": "aws:sns", "EventVersion": "1.0", "EventSubscriptionArn": f"{arn}:sub",
                             "Sns": {"Type": "Notification", "MessageId": "id", "TopicArn": arn, "Subject": None,
                                     "Message": "{}", "Timestamp": "2026-01-01T00:00:00.000Z",
                                     "MessageAttributes": {}}}]}
    if kind == "s3":
        bucket = _arn_name(source_arn, "bucket")
        return {"Records": [{"eventVersion": "2.1", "eventSource": "aws:s3", "awsRegion": region,
                             "eventTime": "2026-01-01T00:00:00.000Z", "eventName": "ObjectCreated:Put",
                             "s3": {"s3SchemaVersion": "1.0", "bucket": {"name": bucket, "arn": f"arn:aws:s3:::{bucket}"},
                                    "object": {"key": "smoke-test.json", "size": 2, "eTag": "etag"}}}]}
    if kind == "kinesis":
        arn = source_arn or f"arn:aws:kinesis:{region}:{account}:stream/stream"
        return {"Records": [{"eventSource": "aws:kinesis", "eventSourceARN": arn, "awsRegion": region,
                             "eventID": "shardId-000000000000:0", "eventName": "aws:kinesis:record",
                             "kinesis": {"partitionKey": "key", "data": "e30=", "sequenceNumber": "0",
                                         "approximateArrivalTimestamp": 0, "kinesisSchemaVersion": "1.0"}}]}
    if kind == "dynamodb":
        arn = source_arn or f"arn:aws:dynamodb:{region}:{account}:table/table/stream/0"
        return {"Records": [{"eventSource": "aws:dynamodb", "eventSourceARN": arn, "awsRegion": region,
                             "eventID": "1", "eventName": "INSERT",
                             "dynamodb": {"Keys": {"id": {"S": "1"}}, "NewImage": {"id": {"S": "1"}},
                                          "SequenceNumber": "1", "StreamViewType": "NEW_AND_OLD_IMAGES"}}]}
    if kind == "eventbridge":
        rule = source_arn or f"arn:aws:events:{region}:{account}:rule/rule"
        return {"version": "0", "id": "00000000-0000-0000-0000-000000000000", "detail-type": "Scheduled Event",
                "source": "aws.events", "account": account, "time": "2026-01-01T00:00:00Z", "region": region,
                "resources": [rule], "detail": {}}
    if kind == "apigateway":
        return {"resource": "/", "path": "/", "httpMethod": "GET", "headers": {}, "multiValueHeaders": {},
                "queryStringParameters": None, "multiValueQueryStringParameters": None, "pathParameters": None,
                "stageVariables": None, "body": None, "isBase64Encoded": False,
                "requestContext": {"accountId": account, "stage": "smoke", "requestId": "id", "httpMethod": "GET",
                                   "path": "/", "identity": {"sourceIp": "127.0.0.1"}}}
    if kind == "function-url":
        return {"version": "2.0", "routeKey": "$default", "rawPath": "/", "rawQueryString": "", "headers": {},
                "body": None, "isBase64Encoded": False,
                "requestContext": {"accountId": account, "requestId": "id", "stage": "$default",
                                   "http": {"method": "GET", "path": "/", "protocol": "HTTP/1.1",
                                            "sourceIp": "127.0.0.1", "userAgent": "smoke-test"}}}
    if kind == "alb":
        return {"requestContext": {"elb": {"targetGroupArn": source_arn or ""}}, "httpMethod": "GET", "path": "/",
                "queryStringParameters": {}, "headers": {}, "body": "", "isBase64Encoded": False}
    raise ValueError(kind)


SERVICE_KINDS = {"s3.amazonaws.com": "s3", "sns.amazonaws.com": "sns", "events.amazonaws.com": "eventbridge",
                 "apigateway.amazonaws.com": "apigateway", "elasticloadbalancing.amazonaws.com": "alb"}
ESM_KINDS = {"sqs": "sqs", "kinesis": "kinesis", "dynamodb": "dynamodb"}


def _backup_json(backup, name: str, default):
    try:
        return backup.json(name)
    except (OSError, ValueError):
        return default


def sample_events(backup, scope: str = "import") -> dict[str, dict]:
    """One sample event per trigger found in the backup; {"generic.json": {}} when none are found."""
    region, account = backup.manifest.get("region", "us-east-1"), backup.manifest.get("account", "123456789012")
    found: dict[str, str | None] = {}
    for policy in _backup_json(backup, "policies.json", {}).values():
        for statement in (policy.get("Policy") or {}).get("Statement", []):
            principal = statement.get("Principal")
            service = principal.get("Service") if isinstance(principal, dict) else None
            if not isinstance(service, str):
                continue
            source = (statement.get("Condition") or {}).get("ArnLike", {}).get("AWS:SourceArn")
            kind = SERVICE_KINDS.get(service)
            if kind:
                found.setdefault(kind, source)
            else:
                WARNINGS.add(scope, f"no sample event for trigger {clean(service, 80)}; add one in {EVENTS_DIR}/")
    for mapping in _backup_json(backup, "event-source-mappings.json", []):
        arn = mapping.get("EventSourceArn") or ""
        kind = ESM_KINDS.get(arn.split(":")[2] if arn.count(":") >= 2 else "")
        if kind:
            found.setdefault(kind, arn)
        elif arn:
            WARNINGS.add(scope, f"no sample event for event source {clean(arn, 120)}; add one in {EVENTS_DIR}/")
    if _backup_json(backup, "function-urls.json", []):
        found.setdefault("function-url", None)
    if not found:
        return {"generic.json": {}}
    return {f"{kind}.json": _event(kind, region, account, source) for kind, source in sorted(found.items())}


def scaffold(conf: dict, manifest: dict, events: dict[str, dict]) -> dict[str, bytes]:
    """Files for tests/: the constant test module, its config, and sample events. No env values are written."""
    names = sorted(((conf.get("Environment") or {}).get("Variables") or {}).keys())
    smoke_config = {
        "handler": conf.get("Handler", ""), "function_name": conf.get("FunctionName", "function"),
        "region": manifest.get("region") or "us-east-1", "account_id": manifest.get("account") or "123456789012",
        "memory_mb": conf.get("MemorySize") or 128, "timeout_s": conf.get("Timeout") or 3,
        "environment": {name: PLACEHOLDER for name in names},
    }
    files = {TEST_FILE: TEST_TEMPLATE.encode(), CONFIG_FILE: (json.dumps(smoke_config, indent=2) + "\n").encode()}
    for name, event in events.items():
        files[f"{EVENTS_DIR}/{name}"] = (json.dumps(event, indent=2) + "\n").encode()
    return files


# --- Running ----------------------------------------------------------------------

def find_python(runtime: str, explicit: str | None) -> tuple[str, str]:
    """(interpreter path, X.Y) for the runtime's Python version."""
    want = runtime.removeprefix("python")
    candidate = explicit or shutil.which(f"python{want}")
    if not candidate:
        raise ToolError(f"python{want} not found; the function runs on {runtime}. Install Python {want}, "
                        "or pass --python PATH")
    try:
        got = subprocess.run([candidate, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                             capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        raise ToolError(f"cannot run {candidate}: {e}") from None
    if got != want:
        raise ToolError(f"{candidate} is Python {got}, but the function runs on {runtime}")
    return candidate, got


def env_key(py_version: str, requirement_texts: list[str], test_deps: list[str] = TEST_DEPS) -> str:
    h = hashlib.sha256()
    for part in (py_version, *test_deps, *requirement_texts):
        h.update(part.encode() + b"\0")
    return h.hexdigest()[:16]


def requirement_texts(root: Path, requirements: Path | None) -> list[str]:
    if not requirements:
        return []
    from lambdatools.remediate import _requirement_files  # -r/-c includes change the environment too
    return [(root / rel).read_text() for rel in _requirement_files(root, str(requirements.relative_to(root)))]


def requirements_digest(texts: list[str]) -> str:
    return hashlib.sha256("\0".join(texts).encode()).hexdigest()[:16]


def test_deps(texts: list[str], pins: dict[str, str]) -> list[str]:
    """TEST_DEPS, pinned to the versions the baseline was recorded with unless the project names them itself."""
    named = {canonicalize_name(m.group(1)) for text in texts for line in text.splitlines()
             if (m := re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line))}
    if named & {"boto3", "botocore"}:  # they pin each other closely; leave both to the project
        named |= {"boto3", "botocore"}
    specs = {re.split(r"[<>=!~]", d)[0]: d for d in TEST_DEPS}
    return [f"{name}=={pins[name]}" if name in pins else specs[name]
            for name in sorted(set(specs) | set(pins)) if canonicalize_name(name) not in named]


def installed_versions(env_python: Path) -> dict[str, str]:
    """Versions of the test tools in a test environment, read from its metadata without running it."""
    from importlib.metadata import distributions
    venv = env_python.parent.parent
    paths = [str(p) for p in (*venv.glob("lib/python*/site-packages"), venv / "Lib" / "site-packages") if p.is_dir()]
    found = {canonicalize_name(d.metadata["Name"] or ""): d.version for d in distributions(path=paths)}
    return {name: found[name] for name in PINNED if name in found}


def ensure_env(python: str, py_version: str, root: Path, requirements: Path | None,
               pins: dict[str, str] | None = None) -> Path:
    """A cached venv with the project's requirements and the test tools; returns its python."""
    texts = requirement_texts(root, requirements)
    deps = test_deps(texts, pins or {})
    envs = ensure_private_dir(data_dir() / "test-envs")
    target = envs / env_key(py_version, texts, deps)
    bin_python = target / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    if (target / ".ready").exists():
        log.info("Using cached test environment %s", target)
        return bin_python
    tmp = Path(tempfile.mkdtemp(prefix=f".{target.name}-", dir=envs))
    try:
        log.info("Creating test environment for Python %s (cached for these requirements)", py_version)
        subprocess.run([python, "-m", "venv", str(tmp)], check=True, stdout=sys.stderr, timeout=600)
        cmd = [str(tmp / bin_python.relative_to(target)), "-m", "pip", "install", "--quiet",
               "--disable-pip-version-check", "--no-input", *deps]
        if requirements:
            cmd += ["-r", str(requirements)]
        subprocess.run(cmd, check=True, stdout=sys.stderr, timeout=1800, cwd=root,
                       env={**os.environ, "PIP_PRE": "false"})
        (tmp / ".ready").write_text("")
        if target.exists():  # another run finished first
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            os.rename(tmp, target)
    except (OSError, subprocess.SubprocessError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ToolError(f"could not create the test environment: {e}") from None
    return bin_python


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", type=Path, nargs="?", default=Path.cwd(), help="project directory (default: current directory)")
    p.add_argument("--update-baseline", action="store_true",
                   help="re-record every event's outcome instead of comparing (after a change you have reviewed)")
    p.add_argument("--python", help="interpreter to use (default: python3.X on PATH matching the runtime)")
    p.add_argument("--init", action="store_true",
                   help="write the smoke tests into a project that wasn't imported (dry-run unless --execute)")
    p.add_argument("--backup", type=Path, help="with --init: take triggers and env var names from this backup")
    p.add_argument("--execute", "--apply", dest="execute", action="store_true", help="with --init: write the files")
    p.add_argument("--allow-unisolated", action="store_true",
                   help="run even when no OS network sandbox is available, relying on the in-process guard alone")


def isolation_prefix(env_python: Path, root: Path, tmp: Path) -> list[str] | None:
    """A command prefix that runs the tests without network access, if this machine has one that works."""
    real_python = Path(os.path.realpath(env_python))
    if sys.platform == "darwin":
        profile = macos_profile([env_python], [real_python.parent.parent], [tmp.resolve(), Path("/private/tmp")],
                                readonly=[root.resolve(), env_python.parent.parent.resolve()])
        prefix = ["sandbox-exec", "-p", profile]
    elif sys.platform.startswith("linux"):
        prefix = linux_sandbox(root, [root, env_python.parent.parent, real_python.parent.parent], tmp)
    else:
        return None
    if not shutil.which(prefix[0]):
        return None
    try:  # e.g. user namespaces disabled, or already inside a sandbox that forbids nesting
        probe = subprocess.run([*prefix, str(env_python), "-c", "pass"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return prefix if probe.returncode == 0 else None


def read_results(path: Path) -> dict[str, str]:
    """Outcomes the test recorded: one JSON object per line, each {event file: outcome}."""
    found: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            entry = json.loads(line)
            found.update({k: v for k, v in entry.items() if isinstance(k, str) and isinstance(v, str)})
    return found


def merge_results(baseline: dict, new: dict[str, str], events: set[str], update: bool) -> dict:
    """The baseline after a run: new outcomes added; with update, outcomes of deleted events dropped."""
    now = {**baseline, **{k: v for k, v in new.items() if k in events}}
    if update:
        now = {k: v for k, v in now.items() if k in events or k == META_KEY}
    return now


def test_command(env_python: Path, isolation: list[str] | None, root: Path) -> list[str]:
    # -c os.devnull: ignore the project's own pytest settings (addopts, plugins) and conftest at its root
    return [*(isolation or []), str(env_python), "-c", BOOTSTRAP, "-q", "-p", "no:cacheprovider",
            "-c", os.devnull, "--rootdir", str(root), "--noconftest", TEST_FILE]


# Passed through to the test process; everything else (tokens in the shell, AWS_*, proxies, PYTEST_*) is not
ENV_ALLOW = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "TZ", "SYSTEMROOT")


def test_env() -> dict[str, str]:
    """The test process's environment: placeholder AWS credentials and nothing of the developer's."""
    env = {k: os.environ[k] for k in ENV_ALLOW if k in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", LAMBDA_TOOLS_SMOKE="1",
               AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
               AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
               AWS_EC2_METADATA_DISABLED="true")
    return env


def init(args: argparse.Namespace, root: Path, cfg: config.ProjectConfig) -> int:
    existing = [rel for rel in (TEST_FILE, CONFIG_FILE) if (root / rel).exists()]
    if existing:
        raise ToolError(f"{', '.join(existing)} already exist(s); remove them to regenerate")
    if args.backup:
        backup = backupdir.load(args.backup)
        conf, manifest, events = backup.configuration, backup.manifest, sample_events(backup, "test")
    else:
        conf = {"Handler": cfg.get("handler", ""), "FunctionName": cfg.get("function_name") or cfg.get("name")}
        manifest = {"region": cfg.get("region"), "account": cfg.get("account_id")}
        events = {"generic.json": {}}
    if not conf.get("Handler"):
        raise ToolError("no handler: set \"handler\" in lambda-tools.json, or pass --backup")
    files = scaffold(conf, manifest, events)
    prefix = mode_prefix(args.execute)
    for rel in sorted(files):
        if (root / rel).exists():
            log.info("%s Keep existing %s", prefix, rel)
            continue
        log.info("%s Write %s", prefix, rel)
        if args.execute:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(files[rel])
    if not args.execute:
        log.info("Dry-run: nothing written. Pass --execute to write the smoke tests.")
    return EXIT_OK


def run(args: argparse.Namespace, sess_factory) -> int:
    root = args.path.resolve()
    cfg = config.load_project(root, required=True)
    runtime = cfg.get("runtime", "")
    if not runtime.startswith("python"):
        raise ToolError(f"smoke tests support Python runtimes only for now (this project uses {runtime})")
    if args.init:
        return init(args, root, cfg)
    if not (root / TEST_FILE).exists():
        raise ToolError(f"{root / TEST_FILE} not found; `import` writes it, or run `lambda-tools test --init`")

    python, py_version = find_python(runtime, args.python)
    req = root / cfg.get("requirements", "requirements.txt")
    req = req if req.exists() else None
    if req is None:
        WARNINGS.add("test", f"{cfg.get('requirements', 'requirements.txt')} not found; testing without the project's dependencies")
    baseline = root / BASELINE_FILE
    had_baseline = json.loads(baseline.read_text()) if baseline.exists() else {}
    recorded_with = had_baseline.get(META_KEY) or {}
    digest = requirements_digest(requirement_texts(root, req))
    pins = {} if args.update_baseline else recorded_with.get("test_deps", {})
    env_python = ensure_env(python, py_version, root, req, pins)

    tmp = Path(tempfile.mkdtemp(prefix="lambda-tools-smoke-"))
    isolation = isolation_prefix(env_python, root, tmp)
    if isolation is None:
        if not args.allow_unisolated:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ToolError("no OS sandbox is available here (macOS sandbox-exec, or Linux bwrap with user "
                            "namespaces); pass --allow-unisolated to rely on the in-process guard alone")
        WARNINGS.add("test", "ran without an OS sandbox; only the in-process guard blocked network access")

    env = test_env()
    env["TMPDIR"] = str(tmp)
    results = tmp / "results.jsonl"
    env["LAMBDA_TOOLS_RESULTS"] = str(results)
    if args.update_baseline:
        env["LAMBDA_TOOLS_UPDATE_BASELINE"] = "1"
    elif not recorded_with or recorded_with.get("requirements") == digest:
        # new events may be recorded only against the requirements the baseline was taken with;
        # after remediate they must already have an outcome to compare
        env["LAMBDA_TOOLS_RECORD_NEW"] = "1"
    cmd = test_command(env_python, isolation, root)
    log.info("Running: %s pytest %s (%s)", env_python, TEST_FILE,
             f"OS sandbox: {isolation[0]}" if isolation else "no OS sandbox")
    try:
        result = subprocess.run(cmd, cwd=root, env=env, stdout=sys.stderr, timeout=1800)
        new = read_results(results)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if result.returncode not in (0, 1):
        raise ToolError(f"pytest exited with status {result.returncode}; see the output above")

    events = {p.name for p in (root / EVENTS_DIR).glob("*.json")}
    now = merge_results(had_baseline, new, events, args.update_baseline)
    recorded = sorted(k for k in new if k in events)
    compared = len([k for k in now if k in events]) - len(recorded)
    if now and (args.update_baseline or not recorded_with):
        now[META_KEY] = {"requirements": digest, "test_deps": installed_versions(env_python)}
    if now != json.loads(baseline.read_text() if baseline.exists() else "{}"):
        tmp = baseline.with_suffix(".tmp")
        tmp.write_text(json.dumps(now, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, baseline)
    if result.returncode == 0:
        summary = f"Smoke tests passed: {compared} event outcome(s) matched the baseline"
    else:
        summary = "Smoke tests FAILED: see the pytest output above"
    if recorded:
        summary += f"; recorded {len(recorded)} new baseline outcome(s) in {BASELINE_FILE} (commit it)"
    sys.stdout.write(summary + "\n")
    return EXIT_OK if result.returncode == 0 else EXIT_FINDINGS
