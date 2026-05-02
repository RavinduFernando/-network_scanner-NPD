#!/usr/bin/env python3

"""
Network Discovery & Auditing Tool
A high-performance, multi-threaded TCP port scanner for internal network audits.

Author: Junior Security Engineer
Project: Network-Scanner-Project
"""

    ## Member 1 (Phase 2 — Subnet parsing )

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPC", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-Sub", 631: "IPP", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2375: "Docker",
    2376: "Docker-SSL", 27017: "MongoDB", 3000: "Node/Dev",
    3306: "MySQL", 3389: "RDP", 5000: "Dev/UPnP", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "K8s-API", 7000: "Cassandra", 7001: "WebLogic",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8086: "InfluxDB", 8088: "Hadoop", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached",
}


class Colors:
    """ANSI color codes for a polished terminal experience."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if not attr.startswith("_") and attr.isupper():
                setattr(cls, attr, "")


print_lock = threading.Lock()


def parse_targets(target_str):
    """Parse a target string into a list of IP addresses.

    Accepts:
      - Single IP:        192.168.1.10
      - CIDR block:       192.168.1.0/24
      - IP range:         192.168.1.10-192.168.1.50
      - Hostname:         example.com
      - Comma-separated:  192.168.1.1,192.168.1.5,10.0.0.0/30
    """
    hosts = []
    for chunk in target_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        if "/" in chunk:
            try:
                network = ipaddress.ip_network(chunk, strict=False)
                hosts.extend(str(host) for host in network.hosts())
                if network.num_addresses == 1:
                    hosts.append(str(network.network_address))
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR block '{chunk}': {exc}")
        elif "-" in chunk and chunk.count(".") >= 3:
            try:
                start_str, end_str = chunk.split("-", 1)
                start_ip = ipaddress.ip_address(start_str.strip())
                end_ip = ipaddress.ip_address(end_str.strip())
                if int(end_ip) < int(start_ip):
                    raise ValueError("end address is lower than start address")
                current = int(start_ip)
                while current <= int(end_ip):
                    hosts.append(str(ipaddress.ip_address(current)))
                    current += 1
            except ValueError as exc:
                raise ValueError(f"Invalid IP range '{chunk}': {exc}")
        else:
            try:
                ipaddress.ip_address(chunk)
                hosts.append(chunk)
            except ValueError:
                try:
                    resolved = socket.gethostbyname(chunk)
                    hosts.append(resolved)
                except socket.gaierror:
                    raise ValueError(f"Cannot resolve target '{chunk}'")

    seen = set()
    unique = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return unique


def parse_ports(ports_str):
    """Parse a port specification string into a sorted list of unique ports.

    Accepts:
      - Single port:         80
      - Range:               1-1024
      - Comma list:          22,80,443
      - Mixed:               22,80,443,8000-8100
    """
    ports = set()
    for chunk in ports_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start_str, end_str = chunk.split("-", 1)
                start, end = int(start_str), int(end_str)
            except ValueError:
                raise ValueError(f"Invalid port range '{chunk}'")
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port range '{chunk}' out of bounds (1-65535)")
            if end < start:
                raise ValueError(f"Port range '{chunk}' is reversed")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"Invalid port '{chunk}'")
            if not (1 <= port <= 65535):
                raise ValueError(f"Port '{port}' out of bounds (1-65535)")
            ports.add(port)
    return sorted(ports)
 
     ## Member 2 (Phase 1 — Core networking )

def grab_banner(sock, timeout=1.0):
    """Best-effort banner grab from an open socket. Returns short text or ''."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(128)
        if not data:
            return ""
        return data.decode("utf-8", errors="replace").strip().split("\n")[0][:80]
    except (socket.timeout, OSError):
        return ""


def scan_port(host, port, timeout, do_banner=False):
    """Attempt a TCP connection to host:port.

    Returns a dict describing the result. The 'state' is one of:
      - 'open'      : connection succeeded
      - 'closed'    : actively refused
      - 'filtered'  : timed out (likely firewalled / dropped)
      - 'error'     : unexpected socket error
    """
    result = {
        "host": host,
        "port": port,
        "state": "closed",
        "service": COMMON_SERVICES.get(port, "unknown"),
        "banner": "",
    }

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        rc = sock.connect_ex((host, port))
        if rc == 0:
            result["state"] = "open"
            if do_banner:
                result["banner"] = grab_banner(sock)
        else:
            err_name = socket.errno.errorcode.get(rc, str(rc))
            if err_name in ("ECONNREFUSED",):
                result["state"] = "closed"
            else:
                result["state"] = "filtered"
    except socket.timeout:
        result["state"] = "filtered"
    except OSError:
        result["state"] = "error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return result


class ScanProgress:
    """Thread-safe progress tracker that prints a single updating line."""

    def __init__(self, total, enabled=True):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()
        self.enabled = enabled and sys.stdout.isatty()

    def tick(self):
        with self.lock:
            self.done += 1
            if not self.enabled:
                return
            pct = (self.done / self.total) * 100 if self.total else 100
            bar_len = 30
            filled = int(bar_len * self.done / self.total) if self.total else bar_len
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(
                f"\r{Colors.CYAN}[*]{Colors.RESET} Scanning "
                f"[{Colors.GREEN}{bar}{Colors.RESET}] "
                f"{self.done}/{self.total} ({pct:5.1f}%)"
            )
            sys.stdout.flush()

    def finish(self):
        if self.enabled:
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()


## Member 3 (Phase 3 — High performance)

def run_scan(hosts, ports, threads, timeout, banner_grab, show_progress):
    """Run the multi-threaded scan and return a list of open-port results."""
    tasks = [(host, port) for host in hosts for port in ports]
    total = len(tasks)
    open_results = []
    progress = ScanProgress(total, enabled=show_progress)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_map = {
            pool.submit(scan_port, host, port, timeout, banner_grab): (host, port)
            for host, port in tasks
        }
        try:
            for future in as_completed(future_map):
                try:
                    result = future.result()
                except Exception:
                    progress.tick()
                    continue
                progress.tick()
                if result["state"] == "open":
                    open_results.append(result)
                    with print_lock:
                        progress.finish()
                        banner_txt = (
                            f"  {Colors.DIM}{result['banner']}{Colors.RESET}"
                            if result["banner"] else ""
                        )
                        print(
                            f"{Colors.GREEN}[+]{Colors.RESET} "
                            f"{Colors.BOLD}{result['host']}{Colors.RESET}:"
                            f"{Colors.YELLOW}{result['port']}{Colors.RESET} "
                            f"{Colors.CYAN}open{Colors.RESET} "
                            f"({result['service']}){banner_txt}"
                        )
        except KeyboardInterrupt:
            progress.finish()
            print(f"\n{Colors.RED}[!]{Colors.RESET} Scan interrupted by user. Cancelling pending tasks...")
            pool.shutdown(wait=False, cancel_futures=True)
            raise

    progress.finish()
    return open_results


def write_report(path, hosts, ports, results, started_at, finished_at):
    """Write a human-readable scan report to disk."""
    elapsed = (finished_at - started_at).total_seconds()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("Network Scanner Report\n")
        fh.write("=" * 60 + "\n")
        fh.write(f"Started:   {started_at.isoformat(timespec='seconds')}\n")
        fh.write(f"Finished:  {finished_at.isoformat(timespec='seconds')}\n")
        fh.write(f"Duration:  {elapsed:.2f}s\n")
        fh.write(f"Hosts:     {len(hosts)}\n")
        fh.write(f"Ports:     {len(ports)} (per host)\n")
        fh.write(f"Findings:  {len(results)} open port(s)\n")
        fh.write("=" * 60 + "\n\n")

        by_host = {}
        for r in results:
            by_host.setdefault(r["host"], []).append(r)
        for host in sorted(by_host, key=lambda x: ipaddress.ip_address(x)):
            fh.write(f"Host: {host}\n")
            fh.write("-" * 40 + "\n")
            fh.write(f"{'PORT':>6}  {'STATE':<10}  {'SERVICE':<14}  BANNER\n")
            for r in sorted(by_host[host], key=lambda x: x["port"]):
                fh.write(
                    f"{r['port']:>6}  {r['state']:<10}  "
                    f"{r['service']:<14}  {r['banner']}\n"
                )
            fh.write("\n")
        if not results:
            fh.write("No open ports were discovered.\n")