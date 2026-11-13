# ⚠️ DEMO ONLY: demo-function

**This is not a real function. Do not deploy it.** It exists only to show how
`lambda-tools` works, and its dependencies are **deliberately vulnerable**
(`requests==2.25.0`) so that `scan` and `remediate` have something to find.

## Layout

```
examples/demo-function/
├── README.md            this file
├── lambda-tools.json    project config: name, runtime, version (no function_name, so no deploy hint)
├── handler.py           the Lambda handler
├── requirements.txt     pinned dependencies (intentionally outdated)
└── tests/               unit tests: excluded from the package
```

Running the tools creates the rest:

```
├── CHANGELOG.md                     by remediate / package
├── .lambda-tools/release-state.json by package --execute (commit this in a real project)
└── dist/                            by package --execute (gitignored)
    ├── demo-function-0.1.1.zip
    └── demo-function-0.1.1.manifest.json
```

## Walkthrough

Run these from the repository root. Each one is a dry-run unless it has `--execute`.

```bash
lambda-tools scan examples/demo-function                  # finds the requests advisories, exits 1
lambda-tools remediate examples/demo-function             # shows the requirements.txt diff
lambda-tools remediate examples/demo-function --execute   # applies it and records it in CHANGELOG.md
lambda-tools package examples/demo-function               # dry-run: version, changelog, sha256
lambda-tools package examples/demo-function --execute     # writes dist/ and bumps the version
```

To reset the demo afterwards (run `git clean` with `-n` first to see what it deletes):

```bash
git checkout -- examples/demo-function
git clean -fdx examples/demo-function   # removes CHANGELOG.md, .lambda-tools/, dist/
```
