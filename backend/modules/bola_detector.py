"""
BOLA Detector — OWASP API1
Broken Object Level Authorization
-----------------------------------
Detects when a user accesses objects
(records/resources) they don't own.

Examples:
  Employee 101 accessing /api/users/999
  User accessing /api/orders/5555 (not theirs)
  Intern accessing /api/salary/any_id
"""

import re
import logging

logger = logging.getLogger("BOLADetector")

# ── Object-level sensitive endpoint patterns ──
OBJECT_ENDPOINTS = [
    r"/api/users/(\d+)",
    r"/api/orders/(\d+)",
    r"/api/salary/(\d+)",
    r"/api/accounts/(\d+)",
    r"/api/profile/(\d+)",
    r"/api/payments/(\d+)",
    r"/api/invoices/(\d+)",
    r"/api/customers/(\d+)",
    r"/api/employees/(\d+)",
    r"/api/records/(\d+)",
    r"/api/documents/(\d+)",
    r"/api/reports/(\d+)",
]

# Roles that can access any object ID (admins)
PRIVILEGED_ROLES = {"admin", "superadmin"}


def detect(request: dict) -> tuple[int, str | None]:
    """
    Detects BOLA: user accessing an object ID
    that doesn't match their own user ID.

    Risk: +75
    """
    endpoint  = request.get("endpoint", "")
    user_id   = str(request.get("user_id", ""))
    role      = request.get("role", "").lower()

    # Admins can access any object
    if role in PRIVILEGED_ROLES:
        return 0, None

    for pattern in OBJECT_ENDPOINTS:
        match = re.search(pattern, endpoint, re.IGNORECASE)
        if match:
            accessed_id = match.group(1)
            # If user_id provided and doesn't match → BOLA
            if user_id and accessed_id != user_id:
                logger.warning(
                    "BOLA detected: user_id=%s accessing object_id=%s on %s",
                    user_id, accessed_id, endpoint
                )
                return 90, (
                    f"BOLA — user '{user_id}' accessing object "
                    f"'{accessed_id}' on {endpoint}"
                )

    return 0, None