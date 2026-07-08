"""
API Security Agent - Enterprise Grade
AI Governance Platform
---------------------------------------
Detects:
  - Unauthorized Admin Access
  - Rate Limit Abuse
  - Data Harvesting / Enumeration
  - Sensitive Data Endpoint Access
  - Privilege Escalation
  - Missing Auth Token
  - Suspicious HTTP Methods
  - Response Size Anomaly
  - API Injection Attempts
"""

import re
import logging
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("APISecurityAgent")


# ─────────────────────────────────────────────
# Configuration / Policy Tables
# ─────────────────────────────────────────────

# Roles allowed to access admin endpoints
ADMIN_ROLES = {"admin", "superadmin"}

# Roles allowed to access manager-level endpoints
MANAGER_ROLES = {"admin", "superadmin", "manager"}

# Sensitive endpoint patterns (PII / financial data)
SENSITIVE_ENDPOINTS = [
    "/api/customers",
    "/api/customer_data",
    "/api/payments",
    "/api/credit_cards",
    "/api/ssn",
    "/api/aadhar",
    "/api/pan",
    "/api/financial",
    "/api/salary",
    "/api/personal_data",
]

# HTTP methods that should never be used on sensitive paths
DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}

# Admin-only endpoint prefixes
ADMIN_ENDPOINTS = ["/api/admin", "/admin", "/api/internal", "/api/superuser"]

# Manager-only endpoint prefixes
MANAGER_ENDPOINTS = ["/api/reports", "/api/analytics", "/api/audit"]

# Rate limit thresholds
RATE_LIMIT_WARNING = 30     # requests → WARNING
RATE_LIMIT_HIGH    = 60     # requests → HIGH
RATE_LIMIT_CRITICAL = 100   # requests → CRITICAL

# Data harvesting detection (many records accessed one-by-one)
HARVEST_REQUEST_THRESHOLD = 20  # combined with sequential-id pattern

# Response size anomaly (bytes)
RESPONSE_SIZE_CRITICAL = 100_000  # 100 KB

# SQL / API injection patterns
INJECTION_PATTERNS = [
    r"(\bSELECT\b|\bDROP\b|\bINSERT\b|\bUNION\b)",
    r"(--|;|'|\")",
    r"(\.\./|%2e%2e)",
    r"(<script|javascript:|onerror=)",
]

# Severity thresholds
SEVERITY_MAP = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "SAFE"),
]

# Action map per severity
ACTION_MAP = {
    "CRITICAL": "BLOCK",
    "HIGH":     "BLOCK",
    "MEDIUM":   "FLAG",
    "LOW":      "MONITOR",
    "SAFE":     "ALLOW",
}


# ─────────────────────────────────────────────
# Helper Utilities
# ─────────────────────────────────────────────

def _get_severity(score: int) -> str:
    for threshold, label in SEVERITY_MAP:
        if score >= threshold:
            return label
    return "SAFE"


def _get_action(severity: str) -> str:
    return ACTION_MAP.get(severity, "MONITOR")


def _endpoint_matches(endpoint: str, patterns: list) -> bool:
    endpoint_lower = endpoint.lower()
    return any(endpoint_lower.startswith(p.lower()) for p in patterns)


# ─────────────────────────────────────────────
# Detection Modules
# ─────────────────────────────────────────────

def check_admin_access(request: dict) -> tuple[int, str | None]:
    """
    Rule: Non-admin roles must not access admin endpoints.
    Risk: +80
    """
    endpoint = request.get("endpoint", "")
    role     = request.get("role", "").lower()

    if _endpoint_matches(endpoint, ADMIN_ENDPOINTS):
        if role not in ADMIN_ROLES:
            logger.warning(f"Admin access attempt by role='{role}' on {endpoint}")
            return 80, "Unauthorized Admin Access"

    if _endpoint_matches(endpoint, MANAGER_ENDPOINTS):
        if role not in MANAGER_ROLES:
            logger.warning(f"Manager endpoint access by role='{role}' on {endpoint}")
            return 40, "Unauthorized Manager Endpoint Access"

    return 0, None


def check_rate_limit(request: dict) -> tuple[int, str | None]:
    """
    Rule: Too many requests in a short window = abuse.
    Risk: scales with count.
    """
    count = request.get("request_count", 0)

    if count >= RATE_LIMIT_CRITICAL:
        return 50, "Critical Rate Limit Abuse"
    elif count >= RATE_LIMIT_HIGH:
        return 35, "High Rate Limit Abuse"
    elif count >= RATE_LIMIT_WARNING:
        return 20, "Rate Limit Warning"

    return 0, None


def check_data_harvesting(request: dict) -> tuple[int, str | None]:
    """
    Rule: Sequential enumeration of customer/user records = harvesting.
    Risk: +60
    """
    endpoint = request.get("endpoint", "")
    count    = request.get("request_count", 0)

    # Pattern: accessing records one-by-one with high request count
    sequential_pattern = re.search(r"/\d+$", endpoint)
    if sequential_pattern and count >= HARVEST_REQUEST_THRESHOLD:
        logger.warning(f"Possible data harvesting: {endpoint} with {count} requests")
        return 60, "Possible Data Harvesting / API Enumeration"

    return 0, None


def check_sensitive_endpoint(request: dict) -> tuple[int, str | None]:
    """
    Rule: Low-privilege roles accessing PII/financial endpoints.
    Risk: +30
    """
    endpoint = request.get("endpoint", "")
    role     = request.get("role", "").lower()

    if _endpoint_matches(endpoint, SENSITIVE_ENDPOINTS):
        if role not in ADMIN_ROLES | MANAGER_ROLES:
            logger.warning(f"Sensitive endpoint access by role='{role}' on {endpoint}")
            return 30, "Sensitive Endpoint Access by Low-Privilege Role"

    return 0, None


def check_privilege_escalation(request: dict) -> tuple[int, str | None]:
    """
    Rule: DELETE/PUT/PATCH on sensitive or admin paths by non-admins.
    Risk: +50
    """
    endpoint = request.get("endpoint", "")
    method   = request.get("method", "").upper()
    role     = request.get("role", "").lower()

    is_dangerous_target = (
        _endpoint_matches(endpoint, ADMIN_ENDPOINTS) or
        _endpoint_matches(endpoint, SENSITIVE_ENDPOINTS)
    )

    if method in DANGEROUS_METHODS and is_dangerous_target and role not in ADMIN_ROLES:
        logger.warning(f"Privilege escalation attempt: {method} {endpoint} by role='{role}'")
        return 50, f"Privilege Escalation Attempt ({method} on restricted endpoint)"

    return 0, None


def check_missing_token(request: dict) -> tuple[int, str | None]:
    """
    Rule: Requests to any endpoint without an auth token.
    Risk: +40
    """
    token    = request.get("auth_token", None)
    endpoint = request.get("endpoint", "")

    # Public endpoints can be excluded here if needed
    public_paths = ["/api/health", "/api/status", "/api/login", "/api/register"]
    if any(endpoint.lower().startswith(p) for p in public_paths):
        return 0, None

    if not token or str(token).strip() == "":
        logger.warning(f"Missing auth token for endpoint: {endpoint}")
        return 40, "Missing Authentication Token"

    return 0, None


def check_response_size(request: dict) -> tuple[int, str | None]:
    """
    Rule: Unusually large response = possible excessive data exposure.
    Risk: +35
    """
    size = request.get("response_size", 0)

    if size >= RESPONSE_SIZE_CRITICAL:
        logger.warning(f"Large response size: {size} bytes")
        return 35, f"Excessive Data Exposure (response_size={size} bytes)"

    return 0, None


def check_injection_attempt(request: dict) -> tuple[int, str | None]:
    """
    Rule: SQL injection / path traversal / XSS patterns in endpoint or params.
    Risk: +70
    """
    endpoint = request.get("endpoint", "")
    params   = str(request.get("params", ""))

    combined = endpoint + " " + params

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            logger.warning(f"Injection attempt detected in: {combined[:100]}")
            return 70, "API Injection Attempt Detected"

    return 0, None


# ─────────────────────────────────────────────
# Main Agent Class
# ─────────────────────────────────────────────

class APISecurityAgent:

    def __init__(self):
        self.checks = [
            check_admin_access,
            check_rate_limit,
            check_data_harvesting,
            check_sensitive_endpoint,
            check_privilege_escalation,
            check_missing_token,
            check_response_size,
            check_injection_attempt,
        ]
        logger.info("APISecurityAgent initialized with %d detection modules.", len(self.checks))

    def analyze(self, request: dict) -> dict:
        """
        Run all detection modules against an API request.

        Args:
            request (dict): API call metadata. Expected keys:
                - user         (str)  : username or user ID
                - role         (str)  : user's role (admin, manager, employee, intern...)
                - endpoint     (str)  : API path e.g. /api/admin/users
                - method       (str)  : HTTP method (GET, POST, DELETE...)
                - request_count(int)  : number of requests in current window
                - auth_token   (str)  : bearer token or session token (optional)
                - response_size(int)  : size of API response in bytes (optional)
                - params       (str)  : query params or body as string (optional)

        Returns:
            dict: {
                risk_score (int),
                severity   (str),
                action     (str),
                reasons    (list[str]),
                timestamp  (str),
                user       (str),
                endpoint   (str)
            }
        """
        total_score = 0
        reasons     = []

        for check_fn in self.checks:
            score, reason = check_fn(request)
            if score > 0 and reason:
                total_score += score
                reasons.append(reason)

        # Cap score at 200 for display sanity
        total_score = min(total_score, 200)

        severity = _get_severity(total_score)
        action   = _get_action(severity)

        result = {
            "risk_score" : total_score,
            "severity"   : severity,
            "action"     : action,
            "reasons"    : reasons,
            "timestamp"  : datetime.now(timezone.utc).isoformat(),
            "user"       : request.get("user", "unknown"),
            "endpoint"   : request.get("endpoint", "unknown"),
        }

        logger.info(
            "Analysis complete | user=%s | endpoint=%s | score=%d | severity=%s | action=%s",
            result["user"], result["endpoint"],
            result["risk_score"], result["severity"], result["action"]
        )

        return result


# ─────────────────────────────────────────────
# Quick Self-Test (run directly)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    agent = APISecurityAgent()

    test_cases = [
        {
            "label": "Case 1 — Admin accessing admin endpoint (should be SAFE)",
            "request": {
                "user": "admin_user",
                "role": "admin",
                "endpoint": "/api/admin/users",
                "method": "GET",
                "request_count": 5,
                "auth_token": "Bearer abc123",
            }
        },
        {
            "label": "Case 2 — Intern accessing admin endpoint (CRITICAL)",
            "request": {
                "user": "intern_1",
                "role": "intern",
                "endpoint": "/api/admin/logs",
                "method": "DELETE",
                "request_count": 500,
                "auth_token": "Bearer xyz",
            }
        },
        {
            "label": "Case 3 — Employee accessing customer records (rate abuse + harvest)",
            "request": {
                "user": "employee_2",
                "role": "employee",
                "endpoint": "/api/customers/452",
                "method": "GET",
                "request_count": 120,
                "auth_token": "Bearer emp_token",
            }
        },
        {
            "label": "Case 4 — No auth token on sensitive endpoint",
            "request": {
                "user": "unknown",
                "role": "guest",
                "endpoint": "/api/payments",
                "method": "GET",
                "request_count": 3,
                "auth_token": "",
            }
        },
        {
            "label": "Case 5 — SQL injection attempt",
            "request": {
                "user": "attacker",
                "role": "employee",
                "endpoint": "/api/users",
                "method": "GET",
                "request_count": 2,
                "auth_token": "Bearer tok",
                "params": "id=1 UNION SELECT * FROM users--",
            }
        },
        {
            "label": "Case 6 — Large response size (data exposure)",
            "request": {
                "user": "manager_1",
                "role": "manager",
                "endpoint": "/api/reports",
                "method": "GET",
                "request_count": 2,
                "auth_token": "Bearer mgr_tok",
                "response_size": 150_000,
            }
        },
    ]

    print("\n" + "="*60)
    print("  API Security Agent — Enterprise Test Results")
    print("="*60)

    for case in test_cases:
        print(f"\n▶ {case['label']}")
        result = agent.analyze(case["request"])
        print(f"  risk_score : {result['risk_score']}")
        print(f"  severity   : {result['severity']}")
        print(f"  action     : {result['action']}")
        print(f"  reasons    : {result['reasons']}")
        print(f"  timestamp  : {result['timestamp']}")