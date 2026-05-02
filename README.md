# Network-Scanner-Project

A high-performance, multi-threaded TCP port scanner written in Python for internal network audits and security assessments. 

The tool scans single hosts, IP ranges, full CIDR blocks, or hostnames in parallel using a thread pool, with proper timeouts so it never hangs on filtered ports, and a polished CLI built with `argparse`.

---

## Features

- **TCP Connect Scanning** using the standard `socket` module with strict per-connection timeouts so filtered/dropped ports never stall the scan.
- **Subnet & range parsing** powered by the `ipaddress` module — supports single IPs, hostnames, CIDR blocks (`192.168.1.0/24`), inclusive ranges (`10.0.0.1-10.0.0.50`), and comma-separated mixes of all of them.
- **Flexible port specification** — single ports, ranges (`1-1024`), or comma lists (`22,80,443,8000-8100`).

--
## Requirements

- *Python 3.8+*
- *No external dependencies* — uses only the Python standard library (socket, ipaddress, argparse, threading, concurrent.futures).

---

## Installation

Clone the repository and you're ready to go — there is nothing to pip install.

bash
git clone https://github.com/<your-org>/Network-Scanner-Project.git
cd Network-Scanner-Project
python network_scanner.py --help


Optionally make the script directly executable on Linux/macOS:

bash
chmod +x network_scanner.py
./network_scanner.py --help

---