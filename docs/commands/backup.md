# `lambda-tools backup`: Back up a deployed function

[← All commands](../../README.md#commands)

All commands accept `--profile`, `--region`, `-v` and `-q`, and share the exit codes and output conventions described in the [README](../../README.md#commands).

```bash
lambda-tools backup FUNCTION [--qualifier VERSION_OR_ALIAS] [--out DIR] [--no-iam] [--project DIR] [--execute]
```

`FUNCTION` is a name (`orders-api-PRD-USE1`), an ARN (`arn:aws:lambda:us-east-1:123456789012:function:orders-api-PRD-USE1`), or a partial ARN (`123456789012:function:orders-api-PRD-USE1`). Give a version or alias with `--qualifier`, not as a `:1` or `:prod` suffix: Lambda accepts the suffix, but the backup would then not record which version it holds. An ARN doesn't choose the region; the run uses `--region`, `AWS_REGION`, or `region` in `lambda-tools.json`, and refuses a function in another region or account.

Writes `<root>/<account>/<region>/<function>/<UTC timestamp>/`. The root is `--out`, `$LAMBDA_TOOLS_BACKUP_DIR`, or `backups/` in the [data directory](../configuration.md#data-directory). `--project` (default: the current directory) points at a directory whose `lambda-tools.json` supplies `account_id` and `region`. The directory is `0700` and its files are `0600`. It is built in a temp directory and renamed into place, and the tool refuses a location inside a git work tree unless git ignores it.

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
