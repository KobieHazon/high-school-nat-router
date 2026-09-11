# Python NAT Router

My high-school software NAT router project.

## Project Summary

This 2017 project implements network address translation in Python 2 on CentOS 7. It captures Ethernet frames from two interfaces, maintains ARP and per-protocol NAT state, rewrites ICMP/TCP/UDP packet fields, transmits rebuilt packets, records logs, and displays recent traffic in a wxPython monitor.

## Project background

I completed this project in high school in 2017. The eight Python modules and `scripts/NATscript.sh` contain my implementation, and `data/ICMPTypes.txt` is my protocol-reference file.

Scapy, dpkt, and wxPython are third-party runtime dependencies referenced by the source; their code is not included.

The recovered implementation is preserved in Git history. The layout follow-up moves source and data into dedicated directories and adapts only the launcher and ICMP reference-file lookup; it does not modernize the routing algorithm.

## Files

- `src/Main.py` contains capture/sending threads, ARP state, NAT tables, and packet-routing logic.
- `src/IpHandler.py`, `src/IcmpHandler.py`, `src/TcpHandler.py`, and `src/UdpHandler.py` parse and rewrite protocol fields.
- `src/SendRecieve.py` rebuilds and sends packets through Scapy.
- `src/NATmonitor.py` provides the wxPython traffic monitor.
- `src/LoggingSystem.py` implements command-line logging modes.
- `scripts/NATscript.sh` configures the historical firewall prerequisites and starts the program.
- `data/ICMPTypes.txt` maps ICMP type numbers to names.

## Validate

```sh
make check
```

The repository check verifies the complete selected source set, authorship headers, core implementation markers, and the absence of private or generated artifacts. Separate container validation compiled all eight modules under Python 2.7 and exercised bounded IPv4, Ethernet, ICMP, and lookup helpers. The full router still requires root-level raw sockets, two controlled interfaces, legacy Python 2 packages, and firewall changes; it must not be run on a normal host or live network.

## Omitted Recovered Material

- Seven generated `.pyc` files were omitted.
- The final DOCX/PDF report and project-proposal DOCX were not included because they expose a student ID and school/class submission details.
- The other preliminary DOCX was not included because it identifies a teacher/recipient and retains generic author metadata.
- Two example reports by other students were excluded.
- A separate 12-byte `NATFinal/ChangeHeader.py` fragment containing only `import scapy` was excluded because it is not part of the complete submitted code directory.

The original recovered archive remains the local source of record for those artifacts.

## Repository layout

- `src/`: the eight historical Python 2 implementation modules; sibling imports are unchanged.
- `data/`: read-only ICMP reference data, resolved relative to the module rather than the current directory.
- `scripts/`: repository checks and the privileged historical CentOS launcher.
- `tests/`: offline packet-helper and resource-path regression checks.

Run `make check` from the repository root. In a disposable Python 2.7 Linux environment, run `python -B tests/test_helpers.py`; these tests do not capture packets or modify networking. Only in the separately configured, isolated CentOS routing lab, the launcher is `bash scripts/NATscript.sh`. It changes firewall rules and is not a setup command for a normal computer.
