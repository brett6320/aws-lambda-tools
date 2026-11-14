# `lambda-tools test`: Smoke-test a Python function

[← All commands](../../README.md#commands)

All commands accept `--profile`, `--region`, `-v` and `-q`, and share the exit codes and output conventions described in the [README](../../README.md#commands).

```bash
lambda-tools test [PATH] [--update-baseline] [--python PY] [--allow-unisolated]
lambda-tools test [PATH] --init [--backup BACKUP_DIR] [--execute]
```

These are smoke tests for Python functions. They check whether the handler still imports and behaves the same on sample events after a change such as a dependency upgrade. They don't check that it does the *right* thing; add your own tests for that.

- **What gets written:** `import` (or `test --init`) writes `tests/test_smoke.py`, `tests/smoke_config.json`, and `tests/events/*.json`. The test file is constant code. Everything about the function is in `smoke_config.json`: handler, function name, region, memory, timeout, and environment variable *names* with placeholder values. Values from the deployed function are never written.
- **Sample events** are picked from the triggers recorded in the backup: S3, SNS, SQS, Kinesis, DynamoDB streams, EventBridge rules, API Gateway (REST), function URLs, and ALB. Without a backup, or without triggers, there is a single `generic.json` (`{}`). Add your own events to `tests/events/` at any time.
- **Baseline:** the first run records each event's outcome in `tests/smoke_baseline.json`, as `ok` or the exception type. It also records a digest of the requirements and the versions of `boto3`, `botocore`, `moto`, and `pytest` it ran with. Later runs reuse those versions (unless your requirements name them), so a run after `remediate` differs only in your own dependencies. Later runs fail if an outcome changes, and exit 1. New events are recorded the first time they run, but only while the requirements are the ones the baseline was taken with. After `remediate`, an event without an outcome fails instead of quietly becoming the new baseline. `--update-baseline` re-records everything, drops outcomes for deleted events, and takes the newest test tools.
- **No network.** Smoke tests can't open a connection, directly or through a local service that would connect for them. Two layers enforce this:
  - **Inside the test process: an audit hook.** It is installed before pytest, plugins, or your code load. It refuses:
    - every socket connect, send, and name lookup: TCP, UDP, Unix sockets, `connect_ex`, asyncio, and functions imported before the test started;
    - starting processes: `subprocess`, `os.system`, `exec`, `posix_spawn`, and multiprocessing's spawn and forkserver;
    - subinterpreters, which don't inherit the hook.
  - **Around the test process: an OS sandbox.** This layer also stops code that bypasses Python, such as C-extension database clients or `ctypes`.
    - **macOS** (`sandbox-exec`) denies all network operations. It denies every Mach service lookup, which covers DNS (mDNSResponder), launchd, and LaunchServices. It also denies Apple Events. Only the test Python may be executed, so `curl`, `open`, and `launchctl` are refused. Writes are allowed only to `tests/` and temp directories.
    - **Linux** uses bubblewrap (`bwrap`): new network, user, PID, and IPC namespaces. The filesystem is read-only except `tests/`. `/tmp`, `/run`, and your home directory are replaced by empty, throwaway tmpfs, so host Unix sockets (Docker, D-Bus, systemd-resolved, nscd, ssh-agent) aren't reachable. bwrap can't refuse starting programs, but they run inside the same sandbox. Install it with `apt install bubblewrap` or `dnf install bubblewrap`. It needs unprivileged user namespaces, which some hosts (Ubuntu 24.04+ AppArmor defaults) and Docker's default seccomp profile disable.
  - **If no sandbox works** (as on Windows, or on Linux without bwrap), `test` refuses to run unless you pass `--allow-unisolated`. With that flag only the audit hook protects you, and a warning says so. Code that bypasses Python can then reach the network.
  - **The network is used only** by `pip`, before the tests start, to build the venv. Installing a package from source runs its build code at that point, as any `pip install` does.
  - **Nothing runs outside the sandbox afterwards.** The tool reads the test-tool versions for the baseline from the venv's metadata files without starting its Python. The venv and your project (apart from `tests/`) are read-only to the test, so a test can't plant code that runs later.
- **Nothing of yours reaches the test.** AWS calls go to moto. The test process gets placeholder AWS credentials, `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` pointed at `/dev/null`, and the instance-metadata lookup disabled. Of your shell environment it keeps only `PATH`, `HOME`, locale, temp-dir, and time-zone variables, so your tokens, profiles, `AWS_ENDPOINT_URL`, and `PYTEST_*` settings never reach the handler. Your project's own pytest configuration, `conftest.py` files, and auto-loaded pytest plugins are ignored. The handler module is imported fresh for each test.
- **Plain `pytest`** skips `tests/test_smoke.py`. Outcomes are only meaningful in the venv `test` builds.
- **Environment:** a venv on the local `python3.X` that matches the runtime (or `--python`). It gets the project's requirements, installed for this machine, plus `boto3` (which the Lambda runtime provides), `pytest`, and `moto`. It's cached under `test-envs/` in the [data directory](../configuration.md#data-directory), one per requirements set, so the first run after a `remediate` builds a new one. Delete that folder to reclaim space.
- **Limits:**
  - These test your code with the same dependency versions, not the exact Linux zip that `package` builds. Native extensions are installed for the machine running the test, not for Lambda's Linux.
  - Only exceptions count as outcomes. A handler that catches errors and returns `statusCode: 500` or `batchItemFailures` records `ok`.
  - A handler that fails at import (for example, it reads a secret at cold start) fails `test_handler_imports` until you adjust `smoke_config.json` or the code.
  - Node.js isn't supported yet.
