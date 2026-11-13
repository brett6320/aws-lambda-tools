"""Back up, scan, remediate, and package AWS Lambda functions."""

from __future__ import annotations

import argparse
import os
import sys
import traceback

from lambdatools import __version__
from lambdatools.common import log as logmod
from lambdatools.common.log import EXIT_ERROR, WARNINGS, ToolError, log

COMMANDS = {
    "backup": ("lambdatools.backup", "back up a function's code, configuration, and permissions"),
    "scan": ("lambdatools.scan", "check dependencies for known vulnerabilities (OSV.dev)"),
    "remediate": ("lambdatools.remediate", "upgrade vulnerable dependencies to fixed versions"),
    "package": ("lambdatools.package", "build a versioned deployment zip and update the changelog"),
}


def build_parser() -> tuple[argparse.ArgumentParser, dict]:
    import importlib

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", help="AWS profile (default: $AWS_PROFILE or the default chain)")
    common.add_argument("--region", help="AWS region (default: $AWS_REGION or the profile's region)")
    common.add_argument("-v", "--verbose", action="store_true", help="debug logging and full tracebacks")
    common.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")

    parser = argparse.ArgumentParser(prog="lambda-tools", description=__doc__)
    parser.add_argument("--version", action="version", version=f"lambda-tools {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    modules = {}
    for name, (module_name, help_text) in COMMANDS.items():
        module = importlib.import_module(module_name)
        p = sub.add_parser(name, parents=[common], help=help_text, description=module.__doc__,
                           formatter_class=argparse.RawDescriptionHelpFormatter)
        module.add_arguments(p)
        modules[name] = module
    return parser, modules


def main(argv: list[str] | None = None) -> None:
    parser, modules = build_parser()
    args = parser.parse_args(argv)
    logmod.setup(verbose=args.verbose, quiet=args.quiet)

    import truststore
    truststore.inject_into_ssl()

    def sess_factory():
        from lambdatools.common import aws
        return aws.session(args.profile or os.environ.get("AWS_PROFILE"),
                           args.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))

    code = EXIT_ERROR
    try:
        code = modules[args.command].run(args, sess_factory)
    except ToolError as e:
        log.error("%s", e)
        code = e.exit_code
    except KeyboardInterrupt:
        log.error("interrupted")
        code = 130
    except Exception as e:  # last-resort handler: one line unless -v
        from botocore.exceptions import BotoCoreError, ClientError
        if isinstance(e, ClientError):
            err = e.response.get("Error", {})
            log.error("AWS error %s: %s", err.get("Code"), err.get("Message"))
        elif isinstance(e, BotoCoreError):
            log.error("AWS client error: %s", e)
        else:
            log.error("unexpected error: %s: %s (rerun with -v for details)", type(e).__name__, e)
        if args.verbose:
            traceback.print_exc()
    finally:
        WARNINGS.flush()
    sys.exit(code)
