# lambda-tools

[![CI](https://github.com/brett6320/aws-lambda-tools/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-lambda-tools/actions/workflows/ci.yml)
[![CodeQL](https://github.com/brett6320/aws-lambda-tools/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-lambda-tools/actions/workflows/codeql.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-lambda-tools%2Fbadges%2Fcoverage.json)](https://github.com/brett6320/aws-lambda-tools/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)

Find and fix known vulnerabilities in AWS Lambda functions the same way every time:

| Command | What it does | Touches AWS |
|---|---|---|
| `backup` | Captures a function's code, configuration, versions, aliases, permissions, triggers, and execution role. Environment variable values go to `pass`. | Read-only |
| `scan` | Checks a project, a deployment zip, or a deployed function (plus its layers) against [OSV.dev](https://osv.dev). | Read-only (with `--function`) |
| `import` | Turns a backup into a project directory: your code, a `requirements.txt` pinned to the deployed versions, `lambda-tools.json`, and a changelog. | No |
| `test` | Runs smoke tests for Python functions: the handler on sample events, compared with a recorded baseline, with AWS mocked and network blocked. Run it before and after `remediate`. | No |
| `remediate` | Upgrades vulnerable dependencies to fixed versions, re-resolves and re-scans to verify, and records the change in `CHANGELOG.md`. | No |
| `package` | Builds a reproducible, versioned deployment zip for the Lambda platform, scans it, and blocks the build on findings. Updates the changelog and version. | No |

Supports Python (`requirements.txt`) and Node.js (`package-lock.json` v2/v3) functions.

Every command that changes something is a **dry-run by default**. It shows what would change; pass `--execute` (or `--apply`) to do it.

## Quick start

The example function is `orders-api-PRD-USE1`: the `orders-api` service, deployed to production in us-east-1. Every command is a dry-run until you add `--execute`. Read what it would do first, then run it again with the flag.

**Already have the function's source?** Skip to [step 3](#3-record-a-smoke-test-baseline). **Starting a brand-new function?** See [Starting fresh](#starting-fresh) below.

### 1. Back up what's deployed

```bash
lambda-tools backup orders-api-PRD-USE1 --region us-east-1 --out ./backups            # dry-run
lambda-tools backup orders-api-PRD-USE1 --region us-east-1 --out ./backups --execute
```

This saves the code, configuration, versions, aliases, permissions, triggers, and execution role to `./backups/<account>/us-east-1/orders-api-PRD-USE1/<UTC timestamp>/`. Environment variable values go to `pass`, or are redacted if `pass` isn't set up. The path is printed as `"backup"` in the JSON output. To capture it:

```bash
BACKUP=$(lambda-tools backup orders-api-PRD-USE1 --region us-east-1 --out ./backups --execute -q | jq -r .backup)
```

`./backups` is a good spot inside a repository because git ignores it. Exit code 1 means some part couldn't be read; the `"missing"` list says which.

### 2. Import the backup as a project

```bash
lambda-tools import "$BACKUP" --name orders-api                        # dry-run: lists the files and pins
lambda-tools import "$BACKUP" --name orders-api --execute              # writes ./orders-api/
```

`--name` drops the environment and region suffixes, so one project can serve every deployment of the function. The project, the artifacts (`dist/orders-api-…zip`), and the default `--to` folder use the new name, while `function_name` in `lambda-tools.json` keeps `orders-api-PRD-USE1` for the deploy command. Leave `--name` out to keep the function name.

The project gets your code without the installed packages, a `requirements.txt` pinned to the exact versions that were deployed, a `lambda-tools.json`, a `CHANGELOG.md`, and smoke tests in `tests/` (Python), with one sample event per trigger the backup found. Look over the warnings. Then:

- To use date versions such as `2026.11.13`, add `"versioning": "date"` to `lambda-tools.json`. See [Versions](#versions).
- Commit the project to git, so every later change shows up as a diff.

### 3. Record a smoke-test baseline

```bash
lambda-tools test ./orders-api
```

This runs the handler on each sample event in `tests/events/` with the dependency versions that are deployed now, and records each outcome in `tests/smoke_baseline.json`. The outcome is `ok`, or the exception type when the handler raises on a synthetic event. Commit the baseline. AWS calls are answered by moto, environment variables get placeholder values, and the test process can't open a network connection (an audit hook inside it, plus an OS sandbox around it), so nothing real is touched. Python only for now; it needs the local `python3.X` that matches the runtime. For a project that wasn't imported, run `lambda-tools test ./orders-api --init --execute` first. See [test](#test).

### 4. Scan

```bash
lambda-tools scan ./orders-api
```

This lists each vulnerable package with its severity, the version that fixes it, and the advisory IDs. Exit 0 means clean. Exit 1 means findings or coverage gaps, which are things that couldn't be checked, such as unpinned requirements. To check what's actually running instead of the project, use `lambda-tools scan --function orders-api-PRD-USE1 --region us-east-1`.

### 5. Remediate, then test again

```bash
lambda-tools remediate ./orders-api              # dry-run: shows the requirements.txt diff
lambda-tools remediate ./orders-api --execute    # writes it, and records the upgrades in CHANGELOG.md
lambda-tools test ./orders-api                   # same outcomes as the baseline?
```

Each vulnerable package is upgraded to the lowest version that fixes all of its known advisories. Each one is checked by re-resolving the dependencies and scanning again before anything is written. Whatever is left (no fix available, a version range it won't rewrite, or a file it doesn't manage) is listed at the end, and the exit code is 1.

If `test` now fails, an upgrade changed how the handler behaves on a sample event. Look at the change before packaging. Once you've confirmed the new behavior is right, re-record with `lambda-tools test ./orders-api --update-baseline`.

### 6. Package

```bash
lambda-tools package ./orders-api                # dry-run: next version, changelog diff, sha256
lambda-tools package ./orders-api --execute      # dist/orders-api-0.0.1.zip + .manifest.json
```

Dependencies are installed for Lambda's Linux platform and scanned again. The build stops if anything at or above `fail_on` turns up. The version goes up (see [Versions](#versions)), and the changelog gets a section for it.

**Choosing the version with `--set-version`.** An imported project starts at `0.0.0`, so its first build is `0.0.1` (or today's date with `"versioning": "date"`). To match the version you already use for the function, set it explicitly. It must be later than the current version:

```bash
lambda-tools package ./orders-api --set-version 1.5.0 --execute          # X.Y.Z versioning
lambda-tools package ./orders-api --set-version 2026.11.13 --execute     # date versioning
```

After that, builds count up from the version you set. `--set-version` and `--bump` can't be combined. With date versioning, `--bump` is refused.

### 7. Deploy

`lambda-tools` doesn't deploy. `package --execute` prints the command for the function in `function_name`:

```bash
aws lambda update-function-code --function-name orders-api-PRD-USE1 \
    --zip-file fileb://orders-api/dist/orders-api-0.0.1.zip --publish
```

To deploy the same artifact to other environments, point `--function-name` at each one, such as `orders-api-SBX-USE1`. Afterwards, check production with `lambda-tools scan --function orders-api-PRD-USE1 --region us-east-1`.

### Starting fresh

For a new function, create `lambda-tools.json` next to your code:

```json
{
  "name": "orders-api",
  "function_name": "orders-api-PRD-USE1",
  "runtime": "python3.13",
  "architecture": "arm64",
  "handler": "handler.handler",
  "version": "0.0.0",
  "versioning": "date"
}
```

Then list your dependencies in `requirements.txt` (or `package.json` plus `package-lock.json` for Node.js), and follow steps 3–7.

## Example

[`examples/demo-function`](examples/demo-function) is a **demo-only** Python function with a deliberately vulnerable dependency. Its README walks through scan → remediate → package. Do not deploy it.

## Installation

You need Python 3.11+ and git. Node.js projects also need npm 10+.

`install.sh` installs a pinned commit into user space, never from the working tree. Each commit gets its own virtualenv, and a `current` link is switched only after an install succeeds.

```bash
./install.sh                    # dry-run: shows what it would do
./install.sh --execute          # install HEAD
./install.sh --ref v0.2.0 --execute
./install.sh --status
./install.sh --uninstall --execute   # removes only what it installed
```

The command lands in `~/.local/bin/lambda-tools` (override with `LAMBDA_TOOLS_BIN_DIR`).

For development:

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

## Configuration

Settings resolve in this order: **CLI flag > environment variable > `lambda-tools.json` > built-in default**. Unknown keys and wrong types are errors that name the key and the file.

`lambda-tools.json` lives in the function's project directory:

```json
{
  "name": "orders-api",
  "function_name": "orders-api-prod",
  "runtime": "python3.12",
  "architecture": "arm64",
  "version": "1.4.2",
  "requirements": "requirements.txt",
  "exclude": ["docs", "*.md"],
  "fail_on": "low",
  "account_id": "123456789012",
  "region": "us-east-1",
  "ignore": [
    {"id": "GHSA-xxxx-xxxx-xxxx", "reason": "not reachable: we never parse untrusted YAML", "expires": "2027-01-31"}
  ]
}
```

| Key | Used by | Meaning |
|---|---|---|
| `name`, `runtime`, `version` | package (required) | Artifact name, Lambda runtime (`python3.x` / `nodejsNN.x`), current released version |
| `versioning` | package | `semver` (default): `X.Y.Z`, raised with `--bump`. `date`: the build date `YYYY.MM.DD` (UTC, zero-padded), with `.1`, `.2`, … for further builds the same day. See [Versions](#versions) |
| `architecture` | package, remediate | `x86_64` (default) or `arm64`; selects Linux wheels / npm `--cpu` |
| `function_name` | package | Used to print the deploy command |
| `requirements` | package, remediate | Python requirements file (default `requirements.txt`) |
| `exclude` | package | Extra patterns. `/x` matches only at the project root; a pattern without `/` matches any path segment; anything else matches the whole relative path |
| `fail_on` | scan, package, remediate | Lowest failing severity: `low` (default), `medium`, `high`, `critical`, `none` |
| `ignore` | scan, package, remediate | Accepted risks. Each needs an `id` (or alias), `reason`, and `expires`. Expired entries stop applying and produce a warning. Ignored findings are still listed and recorded in the changelog |
| `account_id` | backup, scan | If set, the function must be in this account |
| `region` | backup, scan | Region to use when neither `--region` nor `AWS_REGION` is set. When one of them is set, it wins and a warning names both regions |

| Environment variable | Meaning |
|---|---|
| `AWS_PROFILE`, `AWS_REGION` | Defaults for `--profile` / `--region` |
| `LAMBDA_TOOLS_FAIL_ON` | Default for `--fail-on` |
| `LAMBDA_TOOLS_BACKUP_DIR` | Default backup root |
| `LAMBDA_TOOLS_OSV_URL` | OSV API base URL (for a mirror) |
| `PASSWORD_STORE_DIR` | `pass` store location |
| `SOURCE_DATE_EPOCH` | Timestamp written into zip entries (default 1980-01-01) |

## Commands

All commands accept `--profile`, `--region`, `-v` (debug logging and tracebacks), and `-q` (warnings and errors only). Results go to stdout; logs and warnings go to stderr, and warnings are repeated, grouped, after the main output.

**Exit codes:** `0` OK · `1` findings, coverage gaps, or an incomplete backup · `2` error (including OSV being unreachable, which never counts as clean).

### backup

```bash
lambda-tools backup FUNCTION [--qualifier Q] [--out DIR] [--no-iam] [--execute]
```

Writes `<root>/<account>/<region>/<function>/<UTC timestamp>/`. The root is `--out`, `$LAMBDA_TOOLS_BACKUP_DIR`, or `~/.local/share/lambda-tools/backups`. The directory is `0700` and its files are `0600`. It is built in a temp directory and renamed into place, and the tool refuses a location inside a git work tree unless git ignores it.

| File | Contents |
|---|---|
| `function.json` | `get_function`: full configuration, tags, reserved concurrency (presigned URL removed) |
| `versions.json`, `aliases.json` | All published versions and aliases |
| `policies.json` | Resource policy for `$LATEST`, every alias, and every version |
| `event-source-mappings.json` | Mappings for the function, its aliases, and its versions, with tags |
| `event-invoke-configs.json`, `function-urls.json`, `concurrency.json` | Async invoke config, function URLs, reserved and provisioned concurrency |
| `code-signing.json`, `recursion.json`, `runtime-management.json`, `scaling.json`, `tags.json` | Remaining function-level settings |
| `layers.json` | Layer version metadata |
| `iam-role.json` | Execution role, trust policy, permissions boundary, attached policy documents, inline policies |
| `code.zip` | Deployment package, verified against `CodeSha256` |
| `manifest.json` | sha256 of every file, completeness, where the env values are, what is not backed up |

**Environment variables.** Values are removed from every configuration object, including every published version, and replaced with `<redacted>`.

- If `pass` is installed and initialized, all values go into a single entry, `lambda-tools/<account>/<region>/<function>/<timestamp>`, as JSON keyed by version. The values are passed to `pass` on stdin.
- If `pass` is unavailable, values are redacted and the tool warns.
- If `pass` is available but the write fails, the backup fails rather than dropping the values.

To read the values back: `pass show lambda-tools/123456789012/us-east-1/my-function/20261113T160754Z`.

**Completeness.** "Not configured" (ResourceNotFound) is recorded as empty. Any other error, such as access denied or throttling, is listed under `missing` in `manifest.json`, and the command exits 1.

**Not backed up** (also listed in the manifest):

- Triggers configured on the source service: S3 notifications, SNS subscriptions, EventBridge rules, API Gateway, CloudFront.
- CloudWatch log group settings.
- Container images (only the URI is recorded).
- Layer contents.

There is no restore command yet. The JSON files keep AWS's own response shapes so a restore can be scripted.

### scan

```bash
lambda-tools scan PATH                       # project directory, deployment zip, or backup directory
lambda-tools scan --function NAME [--qualifier Q]
    [--fail-on LEVEL] [--allow-gaps] [--include-dev] [--json] [--report FILE]
```

What it reads:

- **Python:** `*.dist-info/METADATA` (installed packages) and `requirements*.txt` (`==` pins, following `-r` includes).
- **Node.js:** `package-lock.json` v2/v3 (devDependencies skipped unless `--include-dev`), or `node_modules/**/package.json` when there is no lockfile.

A **backup directory** (written by `lambda-tools backup --execute`) is checked against its manifest checksums, and then its `code.zip` is scanned. Layers aren't stored in backups, so they are reported as coverage gaps.

In any other directory, zip files aren't opened. If a directory holds archives but no dependency manifests, that is a coverage gap rather than a clean result.

With `--function`, the function's code and every layer are downloaded, verified against their sha256, and read in memory. Nothing is extracted or executed.

**Coverage gaps fail the scan** (exit 1) unless you pass `--allow-gaps`. A gap is anything that couldn't be inventoried:

- `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`
- Unpinned requirements
- v1 lockfiles
- Unreadable layers

Container image functions exit 2 with a pointer to an image scanner.

**Severity.**

- The tool uses the advisory's own rating (GitHub's `database_specific.severity`) or a CVSS v3 base score.
- If neither exists, the severity is `UNKNOWN`. UNKNOWN ranks highest, so it fails whenever anything does.
- Advisories that are aliases of each other (GHSA / PYSEC / CVE) are merged into one finding.
- Withdrawn advisories are skipped.

### import

```bash
lambda-tools import BACKUP_DIR [--name NAME] [--to DIR] [--execute]
```

Use this when the deployed function has no source checkout. It turns a backup's `code.zip` into a project that `scan`, `remediate`, and `package` can work on. The backup is checked against its manifest checksums first.

- **Python:** packages installed at the zip root are told apart from your code by their `*.dist-info/RECORD`, or by `top_level.txt` when there is no RECORD. Their files are left out. `requirements.txt` pins every one of them, direct and transitive, to the deployed version. If the zip already has a `requirements.txt`, that file is kept but pinned. Each package it lists becomes `==<deployed version>`, keeping extras, markers, and comments. Unpinned or ranged specifiers are reported. Transitive packages go into the managed block that `remediate` maintains. That way `remediate` manages every deployed package, and `scan` has no unpinned-requirement gaps.
- **Node.js:** every `node_modules/` directory is left out, and the zip's `package-lock.json` is kept. A zip with `package.json` but no lockfile is refused, because the deployed versions can't be reproduced. Bundled code without a `package.json` is imported with a warning.
- Also written: `lambda-tools.json` (name, runtime, architecture, handler, account, region, version `0.0.0`) and `CHANGELOG.md`. If the zip already contains either file, the zip's copy is kept, with a warning.

When import can't be sure a file belongs to a dependency, it keeps the file as project code and warns. Cases:

- A dependency file that differs from its RECORD hash, which usually means it was patched after install.
- A file inside a dependency's directory that its RECORD doesn't list.
- Packages with no `dist-info` (for example, a "slim" build) or with only `egg-info`.
- `top_level.txt` names such as `tests` or `config`.
- RECORD entries without a hash.

Import refuses, and writes nothing, when:

- the handler is in the zip but wouldn't end up in the project, for example because it is compiled-only (a handler that lives in a layer, such as a monitoring wrapper, only gets a warning);
- the same package is installed twice;
- two paths would collide (including paths that differ only in case);
- the function is a container image.

Credential files (`.env*`, `.npmrc`, `.pypirc`, `*.pem`, `*.key`, and others) and environment variable values are never written. `__pycache__`, symlinks, and unsafe zip paths are skipped. Layers aren't part of the project.

`--name` sets the project name used in `lambda-tools.json`, in artifact names, and as the default `--to`. Use it to drop environment or region suffixes, for example `orders-api-PRD-USE1` → `orders-api`. `function_name` keeps the deployed name. If the zip already has its own `lambda-tools.json`, that file is kept and `--name` isn't applied (you get a warning).

`--to` defaults to `./<name>`, and that directory must not exist or must be empty. The project is written to a temp directory beside it and then renamed into place.

### test

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
- **Environment:** a venv on the local `python3.X` that matches the runtime (or `--python`). It gets the project's requirements, installed for this machine, plus `boto3` (which the Lambda runtime provides), `pytest`, and `moto`. It's cached under `~/.local/share/lambda-tools/test-envs/`, one per requirements set, so the first run after a `remediate` builds a new one. Delete that folder to reclaim space.
- **Limits:**
  - These test your code with the same dependency versions, not the exact Linux zip that `package` builds. Native extensions are installed for the machine running the test, not for Lambda's Linux.
  - Only exceptions count as outcomes. A handler that catches errors and returns `statusCode: 500` or `batchItemFailures` records `ok`.
  - A handler that fails at import (for example, it reads a secret at cold start) fails `test_handler_imports` until you adjust `smoke_config.json` or the code.
  - Node.js isn't supported yet.

### remediate

```bash
lambda-tools remediate [PATH] [--fail-on LEVEL] [--execute]
```

**Python.**

1. Resolves `requirements.txt` with `pip install --dry-run --report` for the Lambda platform (from `runtime` and `architecture`).
2. Scans the resolved set, transitive dependencies included.
3. Raises `==` pins in place, keeping extras and markers. Transitive packages are pinned inside a marked block in the main requirements file:

   ```
   # BEGIN lambda-tools remediation (pins for transitive dependencies)
   urllib3==2.2.2
   # END lambda-tools remediation
   ```

4. Re-resolves and re-scans, for up to 3 rounds, until nothing actionable remains.

It refuses `--hash` requirements, because you need to regenerate those with your lock tool. Non-`==` specifiers are reported as needing a manual change.

**Node.js.**

- Direct dependencies get their spec bumped, keeping any `^` or `~`.
- Transitive ones get an `overrides` entry.
- `package-lock.json` is regenerated with `npm install --package-lock-only --ignore-scripts` in a temp copy, re-scanned, and only then written.

**What remediate can't change.** remediate edits only the main requirements file (and the files it includes with `-r`/`-c`), or `package.json` and `package-lock.json`. scan reads more than that, including packages installed or vendored into the project directory (`*.dist-info`) and other `requirements*.txt` files. remediate also checks for vulnerable packages in those places and lists each one as "not managed by remediate". These exit 1, so remediate never reports "nothing to do" while scan still fails.

Every proposed change is verified before it is written. Written files are backed up to `~/.local/share/lambda-tools/file-backups/` first, and the log prints the restore command. Applied upgrades are added to the managed block in `CHANGELOG.md` → `[Unreleased]`. Anything still open, or needing a manual change, is listed at the end and makes the exit code 1.

### package

```bash
lambda-tools package [PATH] [--bump patch|minor|major | --set-version VERSION] [--execute]
    [--runtime R] [--arch A] [--out DIR] [--fail-on LEVEL]
    [--allow-vulnerable] [--allow-gaps] [--allow-scripts]
```

1. Copies the source into a temp directory. Default excludes: `.git`, `.venv`, `tests/` and `backups/` at the root, `dist/`, `__pycache__`, `.env*`, `*.pem`, `*.key`, `.npmrc`, `lambda-tools.json`, `CHANGELOG.md`. Symlinks are refused.
2. Installs dependencies for Lambda's Linux platform:
   - **Python:** `pip install --target --platform manylinux2014_<arch> --only-binary=:all:`. Requirements not pinned with `==` resolve to the newest **stable** release; `PIP_PRE=false` overrides any `pre = true` in your pip config. After installing, each unpinned package is checked against its latest stable release on PyPI. A package left on an older version gets a warning with the likely reason: either a version constraint (its own specifier or another package's), or no Linux wheel for the runtime and architecture. Packages PyPI doesn't know, such as ones from a private index, are listed as unchecked.
   - **Node.js:** `npm ci --omit=dev --os=linux --cpu=<arch> --ignore-scripts`. Native modules that aren't Linux binaries fail the build with advice to build in a container.
3. Scans the result. Findings at or above `--fail-on`, or coverage gaps, block the build unless you explicitly allow them. Allowed findings are recorded in the changelog.
4. Builds a deterministic zip (sorted entries, fixed timestamps, `0644`/`0755` modes), so the same inputs give the same sha256. It fails over Lambda's 250 MB unzipped limit and warns over 50 MB zipped.
5. With `--execute`, writes in this order:
   1. `dist/<name>-<version>.zip` and `.manifest.json`, created exclusively, so versions are immutable.
   2. `CHANGELOG.md`.
   3. `lambda-tools.json` and `.lambda-tools/release-state.json`.

The new changelog section contains:

- Your `[Unreleased]` notes.
- **Security:** upgrades, resolved advisories, and known or allowed findings.
- **Dependencies:** added, removed, or changed versions compared with the previous release.
- **Build:** the artifact and its sha256.

#### Versions

Only `package --execute` changes the version. A dry-run shows the next version, `remediate` adds its upgrades to `[Unreleased]` in the changelog, and `import` starts a project at `0.0.0`.

- **`"versioning": "semver"`** (the default): each build raises the patch number. Use `--bump minor|major` to raise another part, or `--set-version X.Y.Z` to set one.
- **`"versioning": "date"`**: each build is versioned with its UTC build date, such as `2026.11.13`. Further builds the same day get `2026.11.13.1`, `2026.11.13.2`, and so on. `--bump` is refused. `--set-version YYYY.MM.DD[.N]` picks a specific date, which must be later than the current version. Switching an existing project from `X.Y.Z` to dates works, because dates sort after it.

If a project's version looks like a date (for example `2026.11.13`) but `versioning` isn't set to `date`, `package` stops rather than raising it to a fake date such as `2026.11.14`. Add `"versioning": "date"`, or pass `--bump` to treat it as `X.Y.Z`.

Commit `.lambda-tools/release-state.json`. It is the baseline for the next release's dependency and security diff, so cleaning `dist/` doesn't lose history.

## IAM permissions

| Command | Actions |
|---|---|
| backup | `sts:GetCallerIdentity`, `lambda:GetFunction`, `lambda:GetFunctionConfiguration`, `lambda:ListVersionsByFunction`, `lambda:ListAliases`, `lambda:GetPolicy`, `lambda:ListEventSourceMappings`, `lambda:ListTags`, `lambda:ListFunctionEventInvokeConfigs`, `lambda:ListFunctionUrlConfigs`, `lambda:GetFunctionConcurrency`, `lambda:ListProvisionedConcurrencyConfigs`, `lambda:GetFunctionCodeSigningConfig`, `lambda:GetCodeSigningConfig`, `lambda:GetFunctionRecursionConfig`, `lambda:GetRuntimeManagementConfig`, `lambda:GetFunctionScalingConfig`, `lambda:GetLayerVersion`; with IAM: `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListRolePolicies`, `iam:GetRolePolicy` |
| scan `--function` | `sts:GetCallerIdentity`, `lambda:GetFunction`, `lambda:GetLayerVersion` |
| remediate, package | none (network access to OSV.dev, PyPI or the npm registry) |

`lambda:GetFunction` returns environment variable values. If they are encrypted with a customer-managed KMS key, the caller also needs `kms:Decrypt`. Without it, the backup records the values as unavailable.

## Security notes

- Botocore and urllib3 debug logging stay at WARNING even with `-v`, because their debug output would include environment variable values.
- External strings (package names, versions, advisory summaries) are stripped of control characters and escape sequences before they are shown or written.
- Downloaded code is checked against Lambda's `CodeSha256`, size-capped, and read in memory only.
- `.npmrc` is used during the install but never packaged.

## Platform notes

- **macOS:** TLS uses the system keychain through `truststore`. npm installs Linux packages through `--os/--cpu`. Native modules still need a Linux build, e.g. `sam build --use-container`.
- **Linux:** uses the system CA bundle (`ca-certificates`).
- **Windows:** uses the Windows certificate store. Backups go under `%LOCALAPPDATA%\lambda-tools`. `pass` is usually unavailable there, so values are redacted. `install.sh` needs Git Bash or WSL.

## Design notes

This suite follows `DESIGN_PRINCIPLES.md`. Deliberate departures from the usual one-directory-per-tool AWS tool layout:

- differs: one package and one `lambda-tools` command with subcommands, so all four commands share inventory, OSV, severity, and policy code. That shared code is what keeps remediation consistent.
- differs: no `.env` loading (`python-dotenv`). Configuration comes only from flags, environment variables, and `lambda-tools.json`.
- differs: `scan` and `remediate` are not AWS-mutating, so `scan` has no `--execute` flag. `backup` keeps one because it writes files and `pass` entries.
