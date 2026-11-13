"""Lambda runtime lifecycle: deprecated, nearing deprecation, preview, or unknown.

AWS publishes the schedule only as a documentation page, not through an API,
so it is copied here with the date it was checked. Comparing against today's
date keeps the result correct as deprecation dates pass. A runtime missing
from the table (one released after TABLE_DATE) is reported as unknown, never
as fine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone

from lambdatools.common.log import WARNINGS

SOURCE = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
TABLE_DATE = date(2026, 11, 13)
WARN_DAYS = 180  # warn this long before a runtime is deprecated

# runtime: (deprecation, block function create, block function update); None = not scheduled
SCHEDULE: dict[str, tuple[date | None, date | None, date | None]] = {
    "python3.15": (None, None, None),
    "python3.14": (date(2029, 6, 30), date(2029, 7, 31), date(2029, 8, 31)),
    "python3.13": (date(2029, 6, 30), date(2029, 7, 31), date(2029, 8, 31)),
    "python3.12": (date(2028, 10, 31), date(2028, 11, 30), date(2029, 1, 10)),
    "python3.11": (date(2027, 6, 30), date(2027, 7, 29), date(2027, 8, 31)),
    "python3.10": (date(2026, 10, 31), date(2027, 7, 29), date(2027, 8, 31)),
    "python3.9": (date(2025, 12, 15), date(2027, 7, 29), date(2027, 8, 31)),
    "python3.8": (date(2024, 10, 14), date(2027, 7, 29), date(2027, 8, 31)),
    "python3.7": (date(2023, 12, 4), date(2024, 1, 9), date(2027, 8, 31)),
    "python3.6": (date(2022, 7, 18), date(2022, 7, 18), date(2022, 8, 29)),
    "python2.7": (date(2021, 7, 15), date(2021, 7, 15), date(2022, 5, 30)),
    "nodejs26.x": (None, None, None),
    "nodejs24.x": (date(2028, 4, 30), date(2028, 6, 1), date(2028, 7, 1)),
    "nodejs22.x": (date(2027, 5, 30), date(2027, 7, 29), date(2027, 8, 31)),
    "nodejs20.x": (date(2026, 4, 30), date(2027, 7, 29), date(2027, 8, 31)),
    "nodejs18.x": (date(2025, 9, 1), date(2027, 7, 29), date(2027, 8, 31)),
    "nodejs16.x": (date(2024, 6, 12), date(2027, 7, 29), date(2027, 8, 31)),
    "nodejs14.x": (date(2023, 12, 4), date(2024, 1, 9), date(2027, 8, 31)),
    "nodejs12.x": (date(2023, 3, 31), date(2023, 3, 31), date(2023, 4, 30)),
    "nodejs10.x": (date(2021, 7, 30), date(2021, 7, 30), date(2022, 2, 14)),
}
# Listed by AWS as public preview: not for production use.
PREVIEW = {"python3.15", "nodejs26.x"}


@dataclass
class RuntimeStatus:
    runtime: str
    level: str  # "ok", "warn", or "deprecated"
    message: str
    newest: str | None  # newest supported, non-preview runtime of the same language


def today() -> date:
    return datetime.now(timezone.utc).date()


def _version_key(runtime: str) -> tuple[int, ...]:
    digits = runtime.removeprefix("python").removeprefix("nodejs").removesuffix(".x")
    return tuple(int(p) for p in digits.split(".") if p.isdigit())


def newest_supported(runtime: str, on: date) -> str | None:
    family = "python" if runtime.startswith("python") else "nodejs"
    live = [r for r, (dep, _, _) in SCHEDULE.items()
            if r.startswith(family) and r not in PREVIEW and (dep is None or dep > on)]
    return max(live, key=_version_key) if live else None


def check(runtime: str, on: date | None = None) -> RuntimeStatus:
    on = on or today()
    newest = newest_supported(runtime, on)
    upgrade = f"; move to {newest}" if newest and newest != runtime else ""
    if runtime not in SCHEDULE:
        return RuntimeStatus(runtime, "warn", f"{runtime} is not in lambda-tools' runtime table (checked "
                             f"{TABLE_DATE}); check its status at {SOURCE}", newest)
    if runtime in PREVIEW:
        return RuntimeStatus(runtime, "warn", f"{runtime} is a preview runtime, not for production use{upgrade}", newest)
    deprecated, block_create, block_update = SCHEDULE[runtime]
    if deprecated and deprecated <= on:
        if block_update and block_update <= on:
            stage = f"Lambda has blocked updates to functions on it since {block_update}"
        elif block_create and block_create <= on:
            stage = f"Lambda blocks new functions on it, and blocks updates from {block_update}"
        else:
            stage = f"Lambda blocks new functions from {block_create} and updates from {block_update}"
        return RuntimeStatus(runtime, "deprecated", f"{runtime} was deprecated on {deprecated} (no more security "
                             f"updates); {stage}{upgrade}", newest)
    if deprecated and (deprecated - on).days <= WARN_DAYS:
        return RuntimeStatus(runtime, "warn", f"{runtime} will be deprecated on {deprecated} "
                             f"({(deprecated - on).days} days){upgrade}", newest)
    return RuntimeStatus(runtime, "ok", f"{runtime} is supported" + (f" until {deprecated}" if deprecated else ""), newest)


def stale_table_warning(on: date | None = None) -> str | None:
    """A note when the copied schedule is old enough that newer runtimes or date changes may be missing."""
    age = ((on or today()) - TABLE_DATE).days
    if age > 365:
        return (f"lambda-tools' runtime schedule was last checked {TABLE_DATE} ({age} days ago); "
                f"upgrade lambda-tools or check {SOURCE}")
    return None


def report(runtime: str | None, scope: str) -> RuntimeStatus | None:
    """check() plus deferred warnings for anything that isn't plainly supported."""
    if not runtime:
        return None
    status = check(runtime)
    if status.level != "ok":
        WARNINGS.add(scope, status.message)
    stale = stale_table_warning()
    if stale:
        WARNINGS.add(scope, stale)
    return status
