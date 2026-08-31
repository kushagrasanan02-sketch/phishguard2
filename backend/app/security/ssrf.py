import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional
from fastapi import HTTPException, status
from app.core.config import settings

# List of blocked IP networks (RFC 1918, Loopback, Link-Local, Cloud Metadata)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"), # AWS / GCP / Azure metadata endpoint
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

UNSUPPORTED_SCHEMES = ("javascript", "file", "data", "ftp", "gopher", "dict", "ldap", "tftp", "blob", "vbscript")

def normalize_and_validate_url(url_str: str) -> Tuple[str, str, str]:
    """
    Validates, normalizes, and checks URL against protocol and format policies.
    Returns tuple: (normalized_url, scheme, hostname)
    """
    if not url_str or not isinstance(url_str, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL string cannot be empty."
        )

    clean_url = url_str.strip()

    # Reject unsupported scheme prefixes explicitly
    lower_url = clean_url.lower()
    for scheme_prefix in UNSUPPORTED_SCHEMES:
        if lower_url.startswith(f"{scheme_prefix}:"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported protocol '{scheme_prefix}'. Only HTTP and HTTPS are permitted for security probes."
            )

    # Prepend scheme if user entered domain without protocol
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    try:
        parsed = urlparse(clean_url)
        port = parsed.port
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL structure: Malformed port or host specification."
        )

    # Reject unsupported protocols
    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are permitted for security probes."
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL structure: Hostname could not be parsed."
        )

    # Normalize hostname (lowercase)
    normalized_hostname = hostname.lower()
    
    # Reconstruct normalized URL
    scheme = parsed.scheme.lower()
    path = parsed.path if parsed.path else ""
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    port_part = f":{port}" if port and port not in (80, 443) else ""

    normalized_url = f"{scheme}://{normalized_hostname}{port_part}{path}{query}{fragment}"

    # Perform SSRF Defense Validation
    validate_ssrf_protection(normalized_hostname)

    return normalized_url, scheme, normalized_hostname

def validate_ssrf_protection(hostname: str) -> None:
    """
    Enforces strict Server-Side Request Forgery (SSRF) protections.
    Prevents probes targeting internal infrastructure, localhost, or cloud metadata.
    """
    # 1. Check if hostname is an explicit raw IP address
    try:
        ip_obj = ipaddress.ip_address(hostname)
        for net in BLOCKED_NETWORKS:
            if ip_obj in net:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Security Policy Violation: Target IP '{hostname}' belongs to a private/internal network range."
                )
        return # Raw public IP passed
    except ValueError:
        pass # Hostname is a domain name, proceed to DNS resolution check

    # 2. Check for explicit localhost/internal names
    if hostname in ("localhost", "loopback", "metadata.google.internal"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security Policy Violation: Domain '{hostname}' targets internal infrastructure."
        )

    # 3. DNS Resolution check to catch DNS rebinding or private resolution
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for res in resolved_ips:
            ip_str = res[4][0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
                for net in BLOCKED_NETWORKS:
                    if resolved_ip in net:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Security Policy Violation: Target domain '{hostname}' resolves to private IP '{ip_str}'."
                        )
            except ValueError:
                continue
    except socket.gaierror:
        # DNS resolution error handled gracefully in subsequent domain analysis modules
        pass
