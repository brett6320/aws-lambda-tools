# Requirements and permissions

[← README](../README.md)

## Software

| Needed for | Requirement |
|---|---|
| Everything | Python 3.11+ and git (`install.sh` installs a pinned commit with them) |
| Node.js projects | npm 10+ |
| Keeping environment variable values in a backup | [`pass`](https://www.passwordstore.org/), initialized (`pass init <gpg-id>`). Without it, values are redacted and the backup says so |
| `test` | The local `python3.X` that matches the function's runtime (or `--python`) |
| `test`, isolation | An OS sandbox: `sandbox-exec` (built into macOS) or bubblewrap on Linux (`apt install bubblewrap` / `dnf install bubblewrap`, with unprivileged user namespaces allowed). Without one, `test` refuses unless `--allow-unisolated`. See [test](commands/test.md) |
| Native Node.js modules | A Linux build, for example `sam build --use-container` (see [Platform notes](../README.md#platform-notes)) |

## Network access

| Command | Reaches |
|---|---|
| `backup`, `scan --function` | AWS APIs (Lambda, IAM, STS), and the presigned S3 URLs Lambda returns for the function code (and, with `scan --function`, its layers) |
| `scan`, `remediate`, `package` | [OSV.dev](https://osv.dev) (or `LAMBDA_TOOLS_OSV_URL`). An unreachable OSV is an error, never a clean result |
| `remediate`, `package` | PyPI or the npm registry, to resolve and install dependencies |
| `test` | PyPI, only while building the cached venv. The tests themselves have no network access |
| `import` | Nothing |

## IAM permissions

| Command | Actions |
|---|---|
| backup | `sts:GetCallerIdentity`, `lambda:GetFunction`, `lambda:GetFunctionConfiguration`, `lambda:ListVersionsByFunction`, `lambda:ListAliases`, `lambda:GetPolicy`, `lambda:ListEventSourceMappings`, `lambda:ListTags`, `lambda:ListFunctionEventInvokeConfigs`, `lambda:ListFunctionUrlConfigs`, `lambda:GetFunctionConcurrency`, `lambda:ListProvisionedConcurrencyConfigs`, `lambda:GetFunctionCodeSigningConfig`, `lambda:GetCodeSigningConfig`, `lambda:GetFunctionRecursionConfig`, `lambda:GetRuntimeManagementConfig`, `lambda:GetFunctionScalingConfig`, `lambda:GetLayerVersion`; with IAM: `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListRolePolicies`, `iam:GetRolePolicy` |
| scan `--function` | `sts:GetCallerIdentity`, `lambda:GetFunction`, `lambda:GetLayerVersion` |
| remediate, package | none (network access to OSV.dev, PyPI or the npm registry) |

`lambda:GetFunction` returns environment variable values. If they are encrypted with a customer-managed KMS key, the caller also needs `kms:Decrypt`. Without it, the backup records the values as unavailable.
