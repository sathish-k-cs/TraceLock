import argparse
import sys

from .parser import parse_file
from .correlator import build_chains
from .risk import assess_risk
from .story import build_story
from .report import format_report, build_json_report, save_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TraceLock - Security Event Correlation Engine"
    )

    parser.add_argument(
        "logfile",
        help="Path to the security log file",
    )

    parser.add_argument(
        "--json",
        help="Save JSON analysis report to this file",
    )

    args = parser.parse_args()

    try:
        events = parse_file(args.logfile)
    except OSError as error:
        print(f"Error reading log file: {error}", file=sys.stderr)
        return 1

    if not events:
        print("No valid security events found.")
        return 0

    chains = build_chains(events)

    assessments = [
        assess_risk(chain)
        for chain in chains
    ]

    stories = [
        build_story(chain, assessment)
        for chain, assessment in zip(
            chains,
            assessments,
        )
    ]

    report = format_report(
        chains,
        assessments,
        stories,
    )

    print(report)

    if args.json:
        json_report = build_json_report(
            chains,
            assessments,
            stories,
        )

        save_report(
            args.json,
            json_report,
        )

        print()
        print(f"JSON report saved to: {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())