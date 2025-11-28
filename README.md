<!--suppress HtmlDeprecatedAttribute-->
<div align="center">
   <h1>🪓 pktsplit</h1>
</div>

<hr />

<div align="center">

[💼 Purpose](#purpose) | [🏁 Usage](#usage) | [⚙️ Installation](#installation)

</div>

<hr />

# Purpose

pktsplit is a simple Python package written in Rust to facilitate splitting pcap files into smaller chunks from
standard input based on rotation conditions, such as packet count and time intervals.

It is designed to facilitate sensor development for packet capturing where there is no access to a network tap.

<details>
<summary>⚡ Use case: U.S. Department of Energy's CyberForce Competition</summary>

This package was originally developed to help with packet captures during the [Department of Energy's CyberForce 
Competition](https://cyberforce.energy.gov/), which features a red-blue exercise requiring incident response and where
packet capture and analysis is useful. Particularly, to help streamline a sensor collection for ingestion into Arkime
without requiring the target endpoint to initiate the connection.

For the creation of a network sensor, the following constraints were identified:

- Endpoints provided would generally lack resources, whether memory, disk space, or both.
- Insufficient privilege was granted to perform a network-level capture across endpoints.
- Endpoint configurations varied, including both Unix and Windows-based operating systems.
- Certain systems are considered "assume-breach" and modification should be minimized.
- Creating additional endpoints was prohibited.

Additionally, it was developed considering the following self-imposed constraints:

- Sensor systems do not have a publicly accessible IP address.
- For rapid analysis and ease of use, the sensor would run Arkime, including these constraints:
  - While the `capture` command could accept from standard input, it only read files once closed.

To develop a packet capture solution that satisfies these constraints, the [Georgia Institute of 
Technology](https://gatech.edu) team opted to initiate packet capture over Secure Shell (SSH) from the sensor, executing 
the `tcpdump` or `WinDump.exe` over SSH and streaming the pcap files, then piping it to Arkime's capture command and
reinitiating the capture proces over a set interval. Two captures were conducted to cover for the capture's startup
when once instance went down. However, this leads to the following issues:

- Packets were duplicated multiple times.
- Parallel tcpdump/WinDump processes led to unnecessary resource consumption.

By leveraging pktsplit, these issues are mitigated through enabling the creation of smaller pcap files that are
properly closed and no longer written to while continuing to capture packets. This thereby prevents data loss while
limiting each endpoint to a single capture process.

</details>

# Usage

To capture packets from a remote host and split the pcap data into smaller chunks:

```shell
ssh -t 192.168.1.1 "tcpdump -nU -s0 -w - 'port 22'" | pktsplit -w '192.168.1.1-{index}.pcap' -G 15
```

The `pktsplit` command offers the ability to rotate by seconds, packet count, or both:

- `--rotate-seconds` / `-G`: Rotate to a new file after the specified number of seconds.
- `--max-packets` / `-P`: Rotate to a new file after the specified number of packets. 

<details>
<summary>🦉Ingesting into Arkime</summary>

As `pktsplit` outputs pcap files and closes them upon rotation, they can be picked up by Arkime's `capture` command:

```shell
/opt/arkime/bin/capture --copy -q -n 192.168.1.1 -R .
```

</details>

# Installation

`pktsplit` is available on PyPI:

```shell
pip install pktsplit
```

You may alternatively install from source for the latest development version:

```shell
pip install git+https://github.com/Jayson-Fong/pktsplit.git
```
