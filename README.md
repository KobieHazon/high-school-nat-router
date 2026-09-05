# Python NAT Router

My high-school software NAT router project.

## Project Summary

This 2017 project implements network address translation in Python 2 on CentOS 7. It captures Ethernet frames from two interfaces, maintains ARP and per-protocol NAT state, rewrites ICMP/TCP/UDP packet fields, transmits rebuilt packets, records logs, and displays recent traffic in a wxPython monitor.

## Provenance and Authorship

- Era: high school, completed in 2017.
- I wrote the eight Python modules and `NATscript.sh`.
- The recovered final report describes the project as independently developed and identifies no collaborator.
- `ICMPTypes.txt` is protocol reference data used by the implementation.
- Scapy, dpkt, and wxPython are third-party runtime dependencies referenced by the source; their code is not included.
- The implementation files are preserved byte-for-byte from the recovered project directory. Only repository documentation and validation metadata were added here.

## Files

- `Main.py` contains capture/sending threads, ARP state, NAT tables, and packet-routing logic.
- `IpHandler.py`, `IcmpHandler.py`, `TcpHandler.py`, and `UdpHandler.py` parse and rewrite protocol fields.
- `SendRecieve.py` rebuilds and sends packets through Scapy.
- `NATmonitor.py` provides the wxPython traffic monitor.
- `LoggingSystem.py` implements command-line logging modes.
- `NATscript.sh` configures the historical firewall prerequisites and starts the program.
- `ICMPTypes.txt` maps ICMP type numbers to names.

## Validate

```sh
make check
```

The check is deliberately static: it verifies the complete selected source set, authorship headers, core implementation markers, and the absence of private or generated artifacts. The router requires root-level raw sockets, two controlled interfaces, legacy Python 2 packages, and firewall changes; it must not be run on a normal host or live network.

## Omitted Recovered Material

- Seven generated `.pyc` files were omitted.
- The final DOCX/PDF report and two preliminary DOCX files were not included because they expose a student ID and school/class submission details.
- Two example reports by other students were excluded.
- A separate 12-byte `NATFinal/ChangeHeader.py` fragment containing only `import scapy` was excluded because it is not part of the complete submitted code directory.

The original recovered archive remains the local source of record for those artifacts.
