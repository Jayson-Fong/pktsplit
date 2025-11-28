#!/usr/bin/env python3

"""
Command-line entry point for executing pktsplit.
"""


import argparse
import sys


# noinspection PyUnresolvedReferences
from pktsplit import runtime  # type: ignore[attr-defined]


# noinspection PyPep8Naming
# pylint: disable=invalid-name
def PositiveInteger(value: str) -> int:
    """
    Ensures that the given value is a positive integer.

    Used for argument parsing, casts `value` into an `int`
    then verifies that the value is strictly positive.

    :param value: Value to validate.
    :return:Validated integer value.
    """

    normalized = int(value)

    if normalized < 0:
        raise argparse.ArgumentTypeError("Value must be >= 1")

    return normalized


def main() -> None:
    """
    Parses from the command-line and executes pktsplit.

    :return: None
    """

    parser = argparse.ArgumentParser(
        description="Split a pcap/pcapng stream from stdin into rotated files."
    )
    parser.add_argument(
        "--write",
        "-w",
        default="{index}.pcap",
        help="Output filename pattern, e.g., {index}.pcap",
    )
    parser.add_argument(
        "--rotate-seconds",
        "-G",
        type=PositiveInteger,
        default=None,
        help="Rotate to a new file after this many seconds (>=1)",
    )
    parser.add_argument(
        "--max-packets",
        "-P",
        type=PositiveInteger,
        default=None,
        help="Optional maximum packets per file",
    )

    args = parser.parse_args()

    if sys.stdin.isatty():
        sys.exit("Error: stdin is a TTY. Did you forget to pipe data?")

    runtime.run_stream(args.write, args.rotate_seconds, args.max_packets)


if __name__ == "__main__":
    main()


__all__ = ["main"]
