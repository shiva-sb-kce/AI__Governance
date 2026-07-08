"""
SSRF Detector — OWASP API7
Server-Side Request Forgery
-----------------------------
Detects SSRF payloads in request body/params:
  - AWS metadata endpoint (169.254.169.254)
  - Internal network ranges (10.x, 172.x, 192.168.x)
  - Localhost variants
  - Cloud metadata endpoints
  - File:// protocol
  - Gopher:// protocol (blind SSRF)
"""

import re
import logging

logger = logging.getLogger("SSRFDetector")

# SSRF payload patterns
SSRF_PATTERNS = [
    # AWS / cloud metadata
    (r"169\.254\.169\.254",                    "AWS metadata endpoint"),
    (r"metadata\.google\.internal",            "GCP metadata endpoint"),
    (r"169\.254\.170\.2",                      "ECS metadata endpoint"),

    # Internal IP ranges
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",    "Internal network 10.x.x.x"),
    (r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b","Internal network 172.16-31.x.x"),
    (r"\b192\.168\.\d+\.\d+\b",                "Internal network 192.168.x.x"),

    # Localhost variants
    (r"\blocalhost\b",                          "Localhost access"),
    (r"\b127\.\d+\.\d+\.\d+\b",               "Loopback address"),
    (r"\[::1\]",                                "IPv6 loopback"),

    # Dangerous protocols
    (r"file://",                                "File protocol (path traversal)"),
    (r"gopher://",                              "Gopher protocol (blind SSRF)"),
    (r"dict://",                                "Dict protocol (SSRF)"),
    (r"ftp://",                                 "FTP protocol in URL param"),

    # URL obfuscation
    (r"0x7f000001",                            "Hex-encoded localhost"),
    (r"0177\.0\.0\.1",                         "Octal-encoded localhost"),
    (r"2130706433",                             "Integer-encoded localhost"),
]


def detect(request: dict) -> tuple[int, str | None]:
    """
    Scans body, params, and URL fields for SSRF payloads.
    Risk: +80
    """
    # Combine all string fields to scan
    targets = [
        str(request.get("body",   "") or ""),
        str(request.get("params", "") or ""),
        str(request.get("url",    "") or ""),
        str(request.get("endpoint","") or ""),
    ]
    combined = " ".join(targets)

    for pattern, description in SSRF_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            logger.warning("SSRF detected: %s in request", description)
            return 80, f"API7 — SSRF payload detected: {description}"

    return 0, None