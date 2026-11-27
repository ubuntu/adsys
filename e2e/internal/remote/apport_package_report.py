#!/usr/bin/python3

"""Collect an apport report for a package without apport hook UI prompts.

The hooks apport runs for a package may ask the user questions, which the
end-to-end suite has neither a terminal nor an operator to answer. Driving them
with NoninteractiveHookUI declines every question instead, so the report can be
collected from a non-interactive SSH session.
"""

import argparse
import sys

from apport.report import Report
from apport.ui import NoninteractiveHookUI


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("package", help="package to collect information for")
    parser.add_argument("report_path", help="path to write the report to")
    return parser.parse_args(argv)


def collect_report(package: str) -> Report:
    """Collect OS, environment, package, and hook information."""
    report = Report("Bug")
    report.add_proc_environ()
    report.add_os_info()
    report.add_package_info(package)
    report.add_hooks_info(ui=NoninteractiveHookUI(), package=package)
    return report


def main(argv: list[str] | None = None) -> None:
    """Collect a package report and write it to the requested path."""
    args = parse_args(argv)
    report = collect_report(args.package)
    try:
        with open(args.report_path, "wb") as report_file:
            report.write(report_file)
    except OSError as error:
        sys.exit(f"Cannot write report: {error}")

    print(f"Wrote report to {args.report_path}")


if __name__ == "__main__":
    main()
