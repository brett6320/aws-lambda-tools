# `lambda-tools remediate`: Upgrade vulnerable dependencies

[← All commands](../../README.md#commands)

All commands accept `--profile`, `--region`, `-v` and `-q`, and share the exit codes and output conventions described in the [README](../../README.md#commands).

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
