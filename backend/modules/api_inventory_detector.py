"""
API Inventory Detector — OWASP API9
Improper Inventory Management
-------------------------------
Detects zombie/shadow/deprecated endpoints:
  - /api/v1, /api/v2 (old versions)
  - /api/test, /api/debug, /api/dev
  - /api/internal, /api/beta
  - Admin panels accidentally exposed
  - Documentation endpoints (swagger, redoc)
  - Backup endpoints (.bak, .old, .backup)
"""

import re
import logging

logger = logging.getLogger("APIInventoryDetector")

# Zombie / shadow endpoint patterns
ZOMBIE_PATTERNS = [
    # Old API versions
    (r"/api/v[1-9]\d*/",          "Old API version endpoint"),
    (r"/v[1-9]\d*/",              "Versioned endpoint (possible zombie)"),

    # Dev / test / debug endpoints
    (r"/api/(test|debug|dev|dummy|mock|sandbox)", "Test/debug endpoint exposed"),
    (r"/(test|debug|dev|dummy|mock)/?",           "Dev endpoint exposed"),

    # Internal / undocumented
    (r"/api/(internal|private|hidden|secret|undocumented)", "Internal endpoint exposed"),
    (r"/api/(beta|alpha|staging|preview)",                  "Staging endpoint exposed"),

    # Admin panel accidentally open
    (r"/(admin|administrator|wp-admin|phpmyadmin)", "Admin panel exposed"),
    (r"/api/(admin|superadmin|root)",               "Admin API exposed"),

    # API documentation (should not be public in prod)
    (r"/(swagger|redoc|openapi|api-docs|api-spec)", "API docs exposed publicly"),

    # Backup / old files
    (r"\.(bak|old|backup|orig|copy|tmp)(\?|$|/)",  "Backup file exposed"),

    # Health/metrics exposed
    (r"/(metrics|actuator|prometheus|healthz|readyz)", "Metrics endpoint exposed"),
]


def detect(request: dict) -> tuple[int, str | None]:
    """
    Detects access to zombie/shadow API endpoints.
    Risk: +45
    """
    endpoint = request.get("endpoint", "")

    for pattern, description in ZOMBIE_PATTERNS:
        if re.search(pattern, endpoint, re.IGNORECASE):
            logger.warning(
                "API inventory issue: %s on %s", description, endpoint
            )
            return 65, f"API9 — {description}: {endpoint}"

    return 0, None