#!/usr/bin/env python3
"""Parse Apache access log lines and produce simple summaries."""

import argparse
import collections
import re
import sys
from typing import Iterable, Iterator, Optional

# Matches combined log format; ignores optional trailing fields we do not need.
LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<method>\S+)\s+(?P<path>[^\s\"]+)\s+(?P<protocol>[^\s\"]+)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)"
)


def read_lines(path: Optional[str]) -> Iterator[str]:
    if path is None or path == "-":
        for line in sys.stdin:
            yield line.rstrip("\n")
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line.rstrip("\n")


def parse_logs(lines: Iterable[str]) -> dict:
    total = 0
    status_counts = collections.Counter()
    ip_counts = collections.Counter()
    path_counts = collections.Counter()

    for raw_line in lines:
        total += 1
        match = LOG_PATTERN.match(raw_line)
        if not match:
            continue

        ip = match.group("ip")
        status = match.group("status")

        ip_counts[ip] += 1
        status_counts[status] += 1

    return {
        "total": total,
        "parsed": sum(status_counts.values()),
        "status": status_counts,
        "ip": ip_counts,
        "path": path_counts,
    }


def print_summary(summary: dict) -> None:
    print("Last IPs:")
    for ip, count in summary["ip"].most_common():
        print(f"  {ip}: {count}")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse Apache access logs piped from get-remote-logs.py or a file.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Input file path (default: stdin).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    summary = parse_logs(read_lines(args.input))
    print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
