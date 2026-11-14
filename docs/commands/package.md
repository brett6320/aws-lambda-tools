# `lambda-tools package`: Build a versioned deployment zip

[← All commands](../../README.md#commands)

All commands accept `--profile`, `--region`, `-v` and `-q`, and share the exit codes and output conventions described in the [README](../../README.md#commands).

```bash
lambda-tools package [PATH] [--bump patch|minor|major | --set-version VERSION] [--execute]
    [--runtime R] [--arch A] [--out DIR] [--fail-on LEVEL]
    [--allow-vulnerable] [--allow-gaps] [--allow-scripts] [--allow-deprecated-runtime]
```

`package` refuses to build for a deprecated runtime and names the newest supported one. Change `runtime` in `lambda-tools.json`, test, and build again. `--allow-deprecated-runtime` builds anyway and records that in the changelog's Security section.

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

## Versions

Only `package --execute` changes the version. A dry-run shows the next version, `remediate` adds its upgrades to `[Unreleased]` in the changelog, and `import` starts a project at `0.0.0`.

- **`"versioning": "semver"`** (the default): each build raises the patch number. Use `--bump minor|major` to raise another part, or `--set-version X.Y.Z` to set one.
- **`"versioning": "date"`**: each build is versioned with its UTC build date, such as `2026.11.13`. Further builds the same day get `2026.11.13.1`, `2026.11.13.2`, and so on. `--bump` is refused. `--set-version YYYY.MM.DD[.N]` picks a specific date, which must be later than the current version. Switching an existing project from `X.Y.Z` to dates works, because dates sort after it.

If a project's version looks like a date (for example `2026.11.13`) but `versioning` isn't set to `date`, `package` stops rather than raising it to a fake date such as `2026.11.14`. Add `"versioning": "date"`, or pass `--bump` to treat it as `X.Y.Z`.

Commit `.lambda-tools/release-state.json`. It is the baseline for the next release's dependency and security diff, so cleaning `dist/` doesn't lose history.

## Runtime lifecycle

AWS publishes the [runtime deprecation schedule](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) only as a documentation page, so `lambda-tools` carries a copy, dated when it was checked. Every command that sees a runtime (`backup`, `import`, `scan`, `package`) compares it with today's date:

| Status | When | Effect |
|---|---|---|
| Supported | More than 180 days before deprecation | Nothing |
| Nearing deprecation | Within 180 days of deprecation | Warning, with the runtime to move to |
| Preview | AWS lists it as preview, such as `python3.15` | Warning: not for production |
| Unknown | Not in the copied schedule (newer than the copy) | Warning to check the AWS page |
| Deprecated | On or after the deprecation date | Warning; `scan` and `package` fail unless `--allow-deprecated-runtime` |

After deprecation, Lambda first blocks creating functions on the runtime and later blocks updating them. The message says which stage applies. A copy of the schedule older than a year adds a warning to upgrade `lambda-tools`.
