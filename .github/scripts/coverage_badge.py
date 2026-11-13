"""Turn a coverage.py JSON report into a shields.io endpoint badge.

Usage: coverage_badge.py COVERAGE_JSON BADGE_JSON
Prints a one-line Markdown summary for the job summary.
"""

import json
import sys


def color(percent: float) -> str:
    for limit, name in ((90, "brightgreen"), (80, "green"), (70, "yellowgreen"), (60, "yellow")):
        if percent >= limit:
            return name
    return "red"


def main() -> None:
    source, dest = sys.argv[1:3]
    percent = json.load(open(source))["totals"]["percent_covered"]
    badge = {"schemaVersion": 1, "label": "coverage", "message": f"{percent:.0f}%", "color": color(percent)}
    with open(dest, "w") as fh:
        json.dump(badge, fh)
    print(f"Coverage: **{percent:.1f}%**")


if __name__ == "__main__":
    main()
