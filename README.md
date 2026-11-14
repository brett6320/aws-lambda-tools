# lambda-tools

[![CI](https://github.com/brett6320/aws-lambda-tools/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-lambda-tools/actions/workflows/ci.yml)
[![CodeQL](https://github.com/brett6320/aws-lambda-tools/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-lambda-tools/actions/workflows/codeql.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-lambda-tools%2Fbadges%2Fcoverage.json)](https://github.com/brett6320/aws-lambda-tools/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)

Find and fix known vulnerabilities in AWS Lambda functions the same way every time:

| Command | What it does | Touches AWS |
|---|---|---|
| [`backup`](docs/commands/backup.md) | Captures a function's code, configuration, versions, aliases, permissions, triggers, and execution role. Environment variable values go to `pass`. | Read-only |
| [`scan`](docs/commands/scan.md) | Checks a project, a deployment zip, or a deployed function (plus its layers) against [OSV.dev](https://osv.dev). | Read-only (with `--function`) |
| [`import`](docs/commands/import.md) | Turns a backup into a project directory: your code, a `requirements.txt` pinned to the deployed versions, `lambda-tools.json`, and a changelog. | No |
| [`test`](docs/commands/test.md) | Runs smoke tests for Python functions: the handler on sample events, compared with a recorded baseline, with AWS mocked and network blocked. Run it before and after `remediate`. | No |
| [`remediate`](docs/commands/remediate.md) | Upgrades vulnerable dependencies to fixed versions, re-resolves and re-scans to verify, and records the change in `CHANGELOG.md`. | No |
| [`package`](docs/commands/package.md) | Builds a reproducible, versioned deployment zip for the Lambda platform, scans it, and blocks the build on findings. Updates the changelog and version. | No |

Supports Python (`requirements.txt`) and Node.js (`package-lock.json` v2/v3) functions.

Every command that changes something is a **dry-run by default**. It shows what would change; pass `--execute` (or `--apply`) to do it.

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

## Quick start

The example function is `orders-api-PRD-USE1`: the `orders-api` service, deployed to production in us-east-1. For each command that writes, read the dry-run first, then run it again with `--execute`.

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

- To use date versions such as `2026.11.13`, add `"versioning": "date"` to `lambda-tools.json`. See [Versions](docs/commands/package.md#versions).
- Commit the project to git, so every later change shows up as a diff.

### 3. Record a smoke-test baseline

```bash
lambda-tools test ./orders-api
```

This runs the handler on each sample event in `tests/events/` with the dependency versions that are deployed now, and records each outcome in `tests/smoke_baseline.json`. The outcome is `ok`, or the exception type when the handler raises on a synthetic event. Commit the baseline. AWS calls are answered by moto, environment variables get placeholder values, and the test process can't open a network connection (an audit hook inside it, plus an OS sandbox around it), so nothing real is touched. Python only for now; it needs the local `python3.X` that matches the runtime. For a project that wasn't imported, run `lambda-tools test ./orders-api --init --execute` first. See [test](docs/commands/test.md).

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

Dependencies are installed for Lambda's Linux platform and scanned again. The build stops if anything at or above `fail_on` turns up. The version goes up (see [Versions](docs/commands/package.md#versions)), and the changelog gets a section for it.

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

If you changed `runtime` (for example, off a deprecated one), update the function's configuration as well. `package` prints this command too:

```bash
aws lambda update-function-configuration --function-name orders-api-PRD-USE1 --runtime python3.13
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

## Configuration

Settings come from CLI flags, environment variables, and `lambda-tools.json` in the project directory, in that order. See [Configuration](docs/configuration.md) for every key and variable.

## Commands

All commands accept `--profile`, `--region`, `-v` (debug logging and tracebacks), and `-q` (warnings and errors only). Results go to stdout; logs and warnings go to stderr, and warnings are repeated, grouped, after the main output.

**Exit codes:** `0` OK · `1` findings, coverage gaps, or an incomplete backup · `2` error (including OSV being unreachable, which never counts as clean).

Each command has its own reference page:

| Command | Reference |
|---|---|
| `backup` | [docs/commands/backup.md](docs/commands/backup.md): back up a deployed function |
| `scan` | [docs/commands/scan.md](docs/commands/scan.md): scan for known vulnerabilities |
| `import` | [docs/commands/import.md](docs/commands/import.md): import a backup as a project |
| `test` | [docs/commands/test.md](docs/commands/test.md): smoke-test a Python function |
| `remediate` | [docs/commands/remediate.md](docs/commands/remediate.md): upgrade vulnerable dependencies |
| `package` | [docs/commands/package.md](docs/commands/package.md): build a versioned deployment zip |

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

- differs: one package and one `lambda-tools` command with subcommands, so all six commands share inventory, OSV, severity, and policy code. That shared code is what keeps remediation consistent.
- differs: no `.env` loading (`python-dotenv`). Configuration comes only from flags, environment variables, and `lambda-tools.json`.
- differs: `scan` and `remediate` are not AWS-mutating, so `scan` has no `--execute` flag. `backup` keeps one because it writes files and `pass` entries.
