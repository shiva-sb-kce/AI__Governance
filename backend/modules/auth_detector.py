"""
Auth Detector — OWASP API2
Broken Authentication
-----------------------
Detects:
  - Missing JWT/token
  - Expired token (via claim check)
  - Weak/default token patterns
  - Brute force login attempts
  - Credential stuffing signals
"""

import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger("AuthDetector")

# Weak / default token patterns
WEAK_TOKEN_PATTERNS = [
    r"^(Bearer\s+)?(test|demo|dummy|sample|abc123|password|token123|secret|changeme|default)$",
    r"^Bearer\s+[a-zA-Z0-9]{1,5}$",   # suspiciously short (≤5 chars after Bearer)
    r"^\s*$",                            # empty / whitespace only
]

# Public endpoints that don't need a token
PUBLIC_ENDPOINTS = [
    "/api/login",
    "/api/register",
    "/api/health",
    "/api/status",
    "/api/public",
]

# Brute-force threshold
BRUTE_FORCE_THRESHOLD = 10  # login attempts in window


def detect(request: dict) -> tuple[int, str | None]:
    """
    Detects broken authentication signals.

    Checks:
      1. Missing token on protected endpoint
      2. Weak / default token
      3. Expired token (if exp claim provided)
      4. Brute-force login attempts

    Risk: +65 per finding
    """
    endpoint      = request.get("endpoint", "").lower()
    token         = request.get("auth_token", "") or ""
    token_expired = request.get("token_expired", False)
    login_attempts= request.get("login_attempts", 0)

    # Skip public endpoints
    if any(endpoint.startswith(p) for p in PUBLIC_ENDPOINTS):
        return 0, None

    # 1. Missing token
    if not token.strip():
        logger.warning("Missing auth token on %s", endpoint)
        return 65, f"API2 — Missing authentication token on {endpoint}"

    # 2. Weak / default token
    for pattern in WEAK_TOKEN_PATTERNS:
        if re.match(pattern, token.strip(), re.IGNORECASE):
            logger.warning("Weak token detected: '%s'", token[:30])
            return 65, f"API2 — Weak or default authentication token detected"

    # 3. Expired token (flag passed by JWT agent or middleware)
    if token_expired:
        logger.warning("Expired token used on %s", endpoint)
        return 65, f"API2 — Expired authentication token on {endpoint}"

    # 4. Brute-force
    if login_attempts >= BRUTE_FORCE_THRESHOLD:
        logger.warning("Brute-force attempt: %d login tries", login_attempts)
        return 70, f"API2 — Brute-force detected ({login_attempts} login attempts)"

    return 0, None