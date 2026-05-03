# Network-Scanner-Project

A high-performance, multi-threaded TCP port scanner written in Python for internal network audits and security assessments. 

The tool scans single hosts, IP ranges, full CIDR blocks, or hostnames in parallel using a thread pool, with proper timeouts so it never hangs on filtered ports, and a polished CLI built with `argparse`.

---

## Features

- **TCP Connect Scanning** using the standard `socket` module with strict per-connection timeouts so filtered/dropped ports never stall the scan.
- **Subnet & range parsing** powered by the `ipaddress` module — supports single IPs, hostnames, CIDR blocks (`192.168.1.0/24`), inclusive ranges (`10.0.0.1-10.0.0.50`), and comma-separated mixes of all of them.
- **Flexible port specification** — single ports, ranges (`1-1024`), or comma lists (`22,80,443,8000-8100`).
- **High-performance multi-threading** via `concurrent.futures.ThreadPoolExecutor` with a configurable worker count.
- **Professional CLI** with `argparse` — clear `--help`, validated input, and rich examples.
- **Live progress bar** that updates in place as the scan runs.
- **Color-coded output** with ANSI styling (auto-disabled in non-TTY environments via `--no-color`).
- **Service identification** for ~70 well-known TCP services.
- **Optional banner grabbing** (`--banner`) for quick service fingerprinting on open ports.
- **Text reports** (`-o report.txt`) grouped by host for documentation and audit trails.
- **Graceful Ctrl+C handling** — pending tasks are cancelled cleanly.

--
## Requirements

- *Python 3.8+*
- *No external dependencies* — uses only the Python standard library (socket, ipaddress, argparse, threading, concurrent.futures).

---

## Installation

Clone the repository and you're ready to go — there is nothing to `pip install`.

```bash
git clone https://github.com/<your-org>/Network-Scanner-Project.git
cd Network-Scanner-Project
python network_scanner.py --help
```

Optionally make the script directly executable on Linux/macOS:

```bash
chmod +x network_scanner.py
./network_scanner.py --help
```

---

---

## Project Structure

```text
Network-Scanner-Project/
├── network_scanner.py   # The full scanner (single-file, no external deps)
└── README.md            # This file
```

---

--

## Usage

```text
python network_scanner.py -t <TARGET> [-p <PORTS>] [--threads N] [--timeout S] [--banner] [-o file]
```

### Arguments

| Flag | Description | Default |
| ---- | ----------- | ------- |
| `-t, --target` | Target IP, hostname, CIDR block, range, or comma-separated list. **Required.** | — |
| `-p, --ports`  | Ports to scan: single, range, or comma list. | `1-1024` |
| `--threads`    | Number of worker threads (1–1000). | `100` |
| `--timeout`    | Per-connection timeout in seconds. | `1.0` |
| `--banner`     | Attempt a lightweight banner grab on open ports. | off |
| `-o, --output` | Write a text report to the given file path. | — |
| `--no-color`   | Disable ANSI colors in the terminal output. | off |
| `--no-banner-art` | Hide the ASCII banner at startup. | off |
| `-q, --quiet`  | Suppress the live progress bar. | off |

---

## Examples

**1. Scan a full /24 subnet for the most common ports:**

```bash
python network_scanner.py -t 192.168.1.0/24 -p 22,80,443
```

**2. Scan an IP range for the first 1024 ports with 200 threads:**

```bash
python network_scanner.py -t 10.0.0.1-10.0.0.50 -p 1-1024 --threads 200
```

**3. Full-port sweep against a hostname with an aggressive timeout:**

```bash
python network_scanner.py -t example.com -p 1-65535 --timeout 0.5
```

**4. Scan one host with banner grabbing and write a report:**

```bash
python network_scanner.py -t 192.168.1.1 -p 1-1024 --banner -o report.txt
```

**5. Mixed targets (single IP + CIDR + hostname):**

```bash
python network_scanner.py -t "192.168.1.1,10.0.0.0/30,scanme.example.com" -p 22,80,443
```

---

## Sample Output

```text
   _   _      _   ____
  | \ | | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
  |  \| |/ _ \ __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  | |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |
  |_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|

        Multi-Threaded TCP Network Auditor v1.0

[i] Targets:  254 host(s)
[i] Ports:    3 per host (762 total connection attempts)
[i] Threads:  100
[i] Timeout:  1.0s
[i] Banner:   disabled

[*] Scan started at 2026-04-29T14:22:11

[+] 192.168.1.1:22   open (SSH)
[+] 192.168.1.1:80   open (HTTP)
[+] 192.168.1.42:443 open (HTTPS)
[*] Scanning [██████████████████████████████] 762/762 (100.0%)

[*] Scan finished at 2026-04-29T14:22:18
[*] Duration: 7.34s
[*] Open ports discovered: 3
```

---

## How It Works (Project Phases)

This project is organized along the four required development phases:

### 1. Core Networking
TCP connections are attempted with `socket.socket(AF_INET, SOCK_STREAM)`. Each socket sets `settimeout()` so filtered/dropped ports never hang the scanner. `connect_ex()` is used so connection failures are returned as error codes rather than exceptions, letting us cleanly distinguish **open**, **closed** (`ECONNREFUSED`), and **filtered** (timeout) states.

### 2. Subnet Parsing
The `ipaddress` module powers `parse_targets()`, which expands CIDR blocks into individual hosts (`network.hosts()`), validates IPs, and resolves hostnames via `socket.gethostbyname()`. IP ranges (`a.b.c.d-a.b.c.e`) and comma-separated mixes are also supported and de-duplicated.

### 3. High Performance — Multi-threading
Work is fanned out with `concurrent.futures.ThreadPoolExecutor`. Every `(host, port)` pair becomes a future; results are consumed via `as_completed()` so output and progress update as soon as each scan finishes. A `threading.Lock` prevents interleaved prints. Worker count is user-configurable (`--threads`) with a sensible default of 100.

### 4. CLI Interface
`argparse` provides the full command-line experience: required/optional flags, defaults, validation, multi-line examples in `--help`, and proper exit codes (`0` success, `2` bad input, `130` user interrupt).

---


## Version Control & Collaboration

This project is developed and tracked through a GitHub repository named **`Network-Scanner-Project`**. Every group member is expected to have a visible commit history reflecting their contributions across the four development phases.

---

## Responsible Use

This tool is intended **only** for authorized internal auditing, lab work, and security assessments on networks you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction and against the acceptable-use policy of most networks. Always get permission first.

---

## License

Apache-2.0 license — see repository for details.

---
