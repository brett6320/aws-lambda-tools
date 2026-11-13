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
| `remediate` | Upgrades vulnerable dependencies to fixed versions, re-resolves and re-scans to verify, and records the change in `CHANGELOG.md`. | No |
| `package` | Builds a reproducible, versioned deployment zip for the Lambda platform, scans it, and blocks the build on findings. Updates the changelog and version. | No |

Supports Python (`requirements.txt`) and Node.js (`package-lock.json` v2/v3) functions.

Every command that changes something is a **dry-run by default**. It shows what would change; pass `--execute` (or `--apply`) to do it.

## A typical workflow

```bash
lambda-tools backup my-function --execute         # snapshot what is deployed now
lambda-tools scan --function my-function          # what is vulnerable in production?
lambda-tools import backups/<account>/<region>/my-function/<id> --to ./my-function-src --execute
                                                  # only when you have no source checkout
lambda-tools remediate ./my-function-src          # review the proposed upgrades
lambda-tools remediate ./my-function-src --execute
lambda-tools package ./my-function-src            # dry-run: version, changelog diff, sha256
lambda-tools package ./my-function-src --execute  # dist/my-function-1.4.3.zip + manifest
```

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
lambda-tools import BACKUP_DIR [--to DIR] [--execute]
```

Use this when the deployed function has no source checkout. It turns a backup's `code.zip` into a project that `scan`, `remediate`, and `package` can work on. The backup is checked against its manifest checksums first.

- **Python:** packages installed at the zip root are told apart from your code by their `*.dist-info/RECORD`, or by `top_level.txt` when there is no RECORD. Their files are left out. `requirements.txt` pins every one of them, direct and transitive, to the deployed version. If the zip already has a `requirements.txt`, that file is kept and the deployed versions go to `requirements.deployed.txt`.
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

`--to` defaults to `./<function name>`, and that directory must not exist or must be empty. The project is written to a temp directory beside it and then renamed into place.

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
lambda-tools package [PATH] [--bump patch|minor|major | --set-version X.Y.Z] [--execute]
    [--runtime R] [--arch A] [--out DIR] [--fail-on LEVEL]
    [--allow-vulnerable] [--allow-gaps] [--allow-scripts]
```

1. Copies the source into a temp directory. Default excludes: `.git`, `.venv`, `tests/` and `backups/` at the root, `dist/`, `__pycache__`, `.env*`, `*.pem`, `*.key`, `.npmrc`, `lambda-tools.json`, `CHANGELOG.md`. Symlinks are refused.
2. Installs dependencies for Lambda's Linux platform:
   - **Python:** `pip install --target --platform manylinux2014_<arch> --only-binary=:all:`.
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
