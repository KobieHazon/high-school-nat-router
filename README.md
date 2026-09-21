# Python NAT Router

My high-school software NAT router project.

## Project Summary

This 2017 project implements network address translation in Python 2 on CentOS 7. It captures Ethernet frames from two interfaces, maintains ARP and per-protocol NAT state, rewrites ICMP/TCP/UDP packet fields, transmits rebuilt packets, records logs, and displays recent traffic in a wxPython monitor.

## Project background

I completed this project in high school in 2017. The eight Python modules and `scripts/NATscript.sh` contain my implementation, and `data/ICMPTypes.txt` is my protocol-reference file.

Scapy, dpkt, and wxPython are third-party runtime dependencies referenced by the source; their code is not included.

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

`make test` builds a Python 2.7 environment with real Scapy, dpkt, and wxPython, then runs the packet and helper tests with external networking disabled. The tests exercise TCP/UDP translation in both directions, independent client mappings, state cleanup, ICMP source/payload preservation, and rebuilt IP checksums. Interface/ARP discovery uses fixed lab addresses, and transmission is captured at the send boundary; no packets leave the container.

Full two-interface forwarding, concurrent traffic, and the wxPython monitor's event loop are not covered by this suite. The privileged launcher belongs only in a disposable, isolated lab: it changes firewall rules and must not run on a normal host or live network.

## Repository layout

- `src/`: the eight historical Python 2 implementation modules; sibling imports are unchanged.
- `data/`: read-only ICMP reference data, resolved relative to the module rather than the current directory.
- `scripts/`: repository checks and the privileged historical CentOS launcher.
- `tests/`: packet-translation, packet-helper, and resource-path regression checks.

Run `make check` from the repository root. In a disposable Python 2.7 Linux environment, run `python -B tests/test_helpers.py`; these tests do not capture packets or modify networking. Only in the separately configured, isolated CentOS routing lab, the launcher is `bash scripts/NATscript.sh`. It changes firewall rules and is not a setup command for a normal computer.

## Project report

[The project report](docs/project-report.pdf) covers the design, implementation, interface, and testing.
