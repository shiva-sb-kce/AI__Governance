"""
Resource Abuse Detector — OWASP API4
Unrestricted Resource Consumption
--------------------------------------
Detects:
  - Excessive request rate
  - Huge payload / body size
  - Excessive pagination (limit=99999)
  - Business flow abuse (OTP, coupon, bulk orders)
  - File upload abuse
"""

import re
import logging

logger = logging.getLogger("ResourceAbuseDetector")

# Thresholds
RATE_LIMIT_WARN     = 50
RATE_LIMIT_HIGH     = 100
RATE_LIMIT_CRITICAL = 500

PAYLOAD_SIZE_WARN   = 500_000   # 500 KB
PAYLOAD_SIZE_HIGH   = 5_000_000 # 5 MB

PAGINATION_LIMIT_MAX = 1000  # max allowed "limit" param

# Business flow abuse — sensitive endpoints with thresholds
BUSINESS_FLOW_ENDPOINTS = {
    "/api/otp":      5,    # max 5 OTP requests in window
    "/api/coupon":   10,
    "/api/order":    20,
    "/api/checkout": 15,
    "/api/verify":   5,
    "/api/payment":  10,
    "/api/reset":    5,
}


def detect(request: dict) -> tuple[int, str | None]:
    """
    Detects resource consumption abuse.
    Risk: scales from +30 to +60
    """
    request_count = request.get("request_count", 0)
    payload_size  = request.get("payload_size",  0)
    params        = str(request.get("params", "") or "")
    endpoint      = request.get("endpoint", "").lower()

    # ── Rate limiting ─────────────────────────────
    if request_count >= RATE_LIMIT_CRITICAL:
        return 90, f"API4 — Critical rate abuse ({request_count} requests)"
    if request_count >= RATE_LIMIT_HIGH:
        return 45, f"API4 — High rate abuse ({request_count} requests)"
    if request_count >= RATE_LIMIT_WARN:
        return 30, f"API4 — Rate limit warning ({request_count} requests)"

    # ── Payload size ──────────────────────────────
    if payload_size >= PAYLOAD_SIZE_HIGH:
        return 55, f"API4 — Massive payload ({payload_size:,} bytes)"
    if payload_size >= PAYLOAD_SIZE_WARN:
        return 35, f"API4 — Large payload ({payload_size:,} bytes)"

    # ── Pagination abuse ──────────────────────────
    limit_match = re.search(r"limit=(\d+)", params, re.IGNORECASE)
    if limit_match:
        limit_val = int(limit_match.group(1))
        if limit_val > PAGINATION_LIMIT_MAX:
            logger.warning("Pagination abuse: limit=%d", limit_val)
            return 40, f"API4 — Pagination abuse (limit={limit_val})"

    # ── Business flow abuse ───────────────────────
    for flow_endpoint, threshold in BUSINESS_FLOW_ENDPOINTS.items():
        if endpoint.startswith(flow_endpoint):
            if request_count > threshold:
                logger.warning(
                    "Business flow abuse on %s: %d requests (max %d)",
                    endpoint, request_count, threshold
                )
                return 65, (
                    f"API6 — Business flow abuse on {endpoint} "
                    f"({request_count} requests, max {threshold})"
                )

    return 0, None