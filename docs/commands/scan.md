# `lambda-tools scan`: Scan for known vulnerabilities

[← All commands](../../README.md#commands)

All commands accept `--profile`, `--region`, `-v` and `-q`, and share the exit codes and output conventions described in the [README](../../README.md#commands).

```bash
lambda-tools scan PATH                       # project directory, deployment zip, or backup directory
lambda-tools scan --function NAME [--qualifier Q]
    [--project DIR] [--fail-on LEVEL] [--allow-gaps] [--allow-deprecated-runtime] [--include-dev] [--json] [--report FILE]
```

`--project` names the directory whose `lambda-tools.json` supplies `fail_on`, `ignore`, `account_id` and `region`. It defaults to `PATH` when that is a directory, otherwise the current directory.

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

**Deprecated runtimes fail the scan** (exit 1) unless you pass `--allow-deprecated-runtime`. The runtime comes from the function, the backup, or `runtime` in `lambda-tools.json`. See [Runtime lifecycle](package.md#runtime-lifecycle).

**Severity.**

- The tool uses the advisory's own rating (GitHub's `database_specific.severity`) or a CVSS v3 base score.
- If neither exists, the severity is `UNKNOWN`. UNKNOWN ranks highest, so it fails whenever anything does.
- Advisories that are aliases of each other (GHSA / PYSEC / CVE) are merged into one finding.
- Withdrawn advisories are skipped.
