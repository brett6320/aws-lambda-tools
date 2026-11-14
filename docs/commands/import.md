# `lambda-tools import`: Import a backup as a project

[← All commands](../../README.md#commands)

All commands accept `--profile`, `--region`, `-v` and `-q`, and share the exit codes and output conventions described in the [README](../../README.md#commands).

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
