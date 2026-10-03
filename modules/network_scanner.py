"""
modules/network_scanner.py
--------------------------
Nmap-backed network reconnaissance for authorised lab targets.
"""

import logging
import os
import shutil
import socket

logger = logging.getLogger(__name__)


class NmapSetupError(RuntimeError):
    """Raised when the Nmap runtime or Python wrapper is unavailable."""


def _load_nmap():
    """
    Load the python-nmap wrapper and locate the Nmap executable.

    The executable is searched in:
    1. Windows PATH
    2. Standard 32-bit Nmap installation path
    3. Standard 64-bit Nmap installation path
    """

    # First try PATH.
    nmap_path = shutil.which("nmap")

    # If PATH is unavailable to the Flask/Python process,
    # explicitly check the standard Windows installation locations.
    if not nmap_path:
        standard_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]

        for path in standard_paths:
            if os.path.isfile(path):
                nmap_path = path
                break

    if not nmap_path:
        raise NmapSetupError(
            "Nmap is required for network reconnaissance but was not found. "
            "Install Nmap from https://nmap.org/download.html or add Nmap to "
            "the Windows PATH."
        )

    try:
        import nmap
    except ImportError as exc:
        raise NmapSetupError(
            "The python-nmap package is required. Install dependencies with "
            "'pip install -r requirements.txt'."
        ) from exc

    logger.info("Using Nmap executable: %s", nmap_path)

    return nmap, nmap_path


def validate_target(target: str) -> str:
    """
    Accept a hostname or IP address and reject shell-like scan targets.
    """
    target = (target or "").strip()

    if not target:
        raise ValueError("No network target provided.")

    blocked = set(" /\\;|&$`()<>\"'")

    if any(ch in target for ch in blocked):
        raise ValueError(
            "Enter a single authorised IP address or hostname."
        )

    try:
        socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(
            f"Could not resolve target '{target}'."
        ) from exc

    return target


def run_half_open_scan(target: str) -> dict:
    """
    Run a TCP SYN half-open scan.

    Requires Nmap and may require administrator privileges on Windows.
    """
    target = validate_target(target)

    return _run_scan(
        target,
        "half_open",
        "-sS -T4 --top-ports 1000",
    )


def run_aggressive_scan(target: str) -> dict:
    """
    Run an Nmap aggressive scan.

    -A enables:
    - OS detection
    - Version detection
    - Default NSE script scanning
    - Traceroute
    """
    target = validate_target(target)

    return _run_scan(
        target,
        "aggressive",
        "-A -T4",
    )


def _run_scan(target: str, scan_type: str, arguments: str) -> dict:
    """
    Execute an Nmap scan and convert its results into the application's
    standard network scan result structure.
    """

    nmap, nmap_path = _load_nmap()

    try:
        # Explicitly tell python-nmap where Nmap is installed.
        scanner = nmap.PortScanner(
            nmap_search_path=(nmap_path,)
        )
    except Exception as exc:
        raise RuntimeError(
            f"Could not initialise Nmap at '{nmap_path}': {exc}"
        ) from exc

    logger.info(
        "Starting %s Nmap scan against %s",
        scan_type,
        target,
    )

    try:
        scanner.scan(
            hosts=target,
            arguments=arguments,
        )

    except nmap.PortScannerError as exc:
        raise RuntimeError(
            f"Nmap scan failed: {exc}"
        ) from exc

    except Exception as exc:
        raise RuntimeError(
            f"Network scan failed: {exc}"
        ) from exc

    result = {
        "source": "Network Scanner",
        "target": target,
        "scan_type": scan_type,
        "command": f"nmap {arguments} {target}",
        "hosts": [],
        "findings": [],
    }

    for host in scanner.all_hosts():

        host_data = scanner[host]

        host_result = {
            "host": host,
            "hostname": _first_hostname(host_data),
            "state": host_data.state(),
            "ports": [],
            "os_matches": _parse_os_matches(host_data),
            "scripts": [],
            "traceroute": _parse_traceroute(host_data),
        }

        # Extract ports and service information.
        for protocol in host_data.all_protocols():

            ports = sorted(
                host_data[protocol].keys()
            )

            for port in ports:

                port_info = host_data[protocol][port]

                script_output = (
                    port_info.get("script", {})
                    or {}
                )

                if script_output:
                    host_result["scripts"].append(
                        {
                            "port": f"{port}/{protocol}",
                            "scripts": script_output,
                        }
                    )

                host_result["ports"].append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "state": port_info.get(
                            "state",
                            "unknown",
                        ),
                        "service": port_info.get(
                            "name",
                            "unknown",
                        ),
                        "product": port_info.get(
                            "product",
                            "",
                        ),
                        "version": port_info.get(
                            "version",
                            "",
                        ),
                        "extra": port_info.get(
                            "extrainfo",
                            "",
                        ),
                    }
                )

        result["hosts"].append(host_result)

    result["findings"] = _build_findings(result)

    return result


def _first_hostname(host_data) -> str:
    """Return the first hostname reported by Nmap."""

    hostnames = host_data.hostnames()

    if hostnames:
        return hostnames[0].get(
            "name",
            "",
        )

    return ""


def _parse_os_matches(host_data) -> list[dict]:
    """Extract Nmap OS detection matches."""

    matches = []

    for item in host_data.get(
        "osmatch",
        []
    ) or []:

        matches.append(
            {
                "name": item.get(
                    "name",
                    "",
                ),
                "accuracy": item.get(
                    "accuracy",
                    "",
                ),
            }
        )

    return matches


def _parse_traceroute(host_data) -> list[dict]:
    """Extract Nmap traceroute hop information."""

    trace = host_data.get(
        "trace",
        {}
    ) or {}

    hops = trace.get(
        "hops",
        []
    ) or []

    return [
        {
            "ttl": hop.get(
                "ttl",
                "",
            ),
            "ipaddr": hop.get(
                "ipaddr",
                "",
            ),
            "rtt": hop.get(
                "rtt",
                "",
            ),
            "host": hop.get(
                "host",
                "",
            ),
        }
        for hop in hops
    ]


def _build_findings(scan_result: dict) -> list[dict]:
    """
    Convert discovered network ports into the application's
    standard finding format.
    """

    findings = []

    for host in scan_result["hosts"]:

        for port in host["ports"]:

            service_bits = [
                port.get("service") or "unknown"
            ]

            version = " ".join(
                bit
                for bit in [
                    port.get("product"),
                    port.get("version"),
                    port.get("extra"),
                ]
                if bit
            )

            if version:
                service_bits.append(version)

            findings.append(
                {
                    "type": (
                        "Open Network Port"
                        if port["state"] == "open"
                        else "Network Port"
                    ),
                    "source": "Network Scanner",
                    "severity": (
                        "Low"
                        if port["state"] == "open"
                        else "Info"
                    ),
                    "url": host["host"],
                    "target": host["host"],
                    "field": (
                        f"{port['port']}/{port['protocol']}"
                    ),
                    "payload": scan_result["command"],
                    "evidence": (
                        f"Port {port['port']}/"
                        f"{port['protocol']} is "
                        f"{port['state']} "
                        f"({' - '.join(service_bits)})."
                    ),
                    "description": (
                        "Nmap identified a network service "
                        "during authorised reconnaissance."
                    ),
                    "impact": (
                        "Open services increase exposed "
                        "attack surface and should be reviewed "
                        "for business need and patch status."
                    ),
                    "fix": (
                        "Restrict unnecessary services, "
                        "firewall unused ports, and keep "
                        "exposed services patched."
                    ),
                    "mitigation": (
                        "Restrict unnecessary services, "
                        "firewall unused ports, and keep "
                        "exposed services patched."
                    ),
                }
            )

    return findings