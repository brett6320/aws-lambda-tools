# Configuration

[← README](../README.md)

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
| `versioning` | package | `semver` (default): `X.Y.Z`, raised with `--bump`. `date`: the build date `YYYY.MM.DD` (UTC, zero-padded), with `.1`, `.2`, … for further builds the same day. See [Versions](commands/package.md#versions) |
| `architecture` | package, remediate | `x86_64` (default) or `arm64`; selects Linux wheels / npm `--cpu` |
| `function_name` | package, test | The deployed function: used to print the deploy command and in the smoke tests' Lambda context |
| `handler` | test | Handler such as `handler.handler` or `src/app.handler`. `import` sets it; `test --init` needs it |
| `requirements` | package, remediate | Python requirements file (default `requirements.txt`) |
| `exclude` | package | Extra patterns. `/x` matches only at the project root; a pattern without `/` matches any path segment; anything else matches the whole relative path |
| `fail_on` | scan, package, remediate | Lowest failing severity: `low` (default), `medium`, `high`, `critical`, `none` |
| `ignore` | scan, package, remediate | Accepted risks. Each needs an `id` (or alias), `reason`, and `expires`. Expired entries stop applying and produce a warning. Ignored findings are still listed and recorded in the changelog |
| `account_id` | backup, scan | If set, the function must be in this account. `backup --project` and `scan --project` read it from that project's file |
| `region` | backup, scan | Region to use when neither `--region` nor `AWS_REGION` is set. When one of them is set, it wins and a warning names both regions |

| Environment variable | Meaning |
|---|---|
| `AWS_PROFILE`, `AWS_REGION` | Defaults for `--profile` / `--region` |
| `LAMBDA_TOOLS_FAIL_ON` | Default for `--fail-on` |
| `LAMBDA_TOOLS_BACKUP_DIR` | Default backup root |
| `LAMBDA_TOOLS_OSV_URL` | OSV API base URL (for a mirror) |
| `PASSWORD_STORE_DIR` | `pass` store location |
| `SOURCE_DATE_EPOCH` | Timestamp written into zip entries (default 1980-01-01) |
| `XDG_DATA_HOME` | Parent of the data directory (see below) |
| `LAMBDA_TOOLS_BIN_DIR` | Where `install.sh` puts the `lambda-tools` command (default `~/.local/bin`) |

## Data directory

Backups (unless `--out` or `LAMBDA_TOOLS_BACKUP_DIR` says otherwise), copies of files that `remediate` changes, and the cached smoke-test venvs live in a per-user data directory:

| Platform | Data directory |
|---|---|
| macOS, Linux | `$XDG_DATA_HOME/lambda-tools`, or `~/.local/share/lambda-tools` when `XDG_DATA_HOME` isn't set |
| Windows | `%LOCALAPPDATA%\lambda-tools` |

