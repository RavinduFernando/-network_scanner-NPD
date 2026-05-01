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
 
