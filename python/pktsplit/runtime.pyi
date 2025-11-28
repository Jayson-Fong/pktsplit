"""
Core logic components implemented using a Rust backend
"""

from typing import Optional

# pylint: disable=unused-argument
def run_stream(
    output_pattern: str,
    rotate_seconds: Optional[int] = None,
    max_packets: Optional[int] = None,
) -> None:
    """
    Retrieves packets from stdin and writes them to files, rotating them as needed.

    :param output_pattern: Format for output file names, such as `{index}.pcap`
    :param rotate_seconds: Number of seconds until a new file is created
    :param max_packets: Number of packets until a new file is created
    :return: None
    """
