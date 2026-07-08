"""
RBAC Governance Agent
AI Governance Platform
-----------------------
Enforces Role-Based Access Control across all API endpoints.

Detects:
  - Role not permitted for endpoint
  - HTTP method not allowed for role
  - Time-based access violations (off-hours)
  - Sensitive action by low-privilege role
  - Role escalation attempts
  - Cross-department data access
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("RBACAgent")


# ─────────────────────────────────────────────
# RBAC Permission Matrix
# ─────────────────────────────────────────────
# "*" means all endpoints allowed
# List means only those prefixes are allowed

RBAC_MATRIX = {
    "superadmin": {
        "endpoints": ["*"],
        "methods":   ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "off_hours_access": True,
    },
    "admin": {
        "endpoints": ["*"],
        "methods":   ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "off_hours_access": True,
    },
    "manager": {
        "endpoints": [
            "/api/reports",
            "/api/analytics",
            "/api/users",
            "/api/audit",
            "/api/profile",
            "/api/team",
            "/api/dashboard",
        ],
        "methods":   ["GET", "POST"],
        "off_hours_access": False,
    },
    "employee": {
        "endpoints": [
            "/api/profile",
            "/api/dashboard",
            "/api/tasks",
            "/api/notifications",
        ],
        "methods":   ["GET", "POST"],
        "off_hours_access": False,
    },
    "intern": {
        "endpoints": [
            "/api/profile/view",
            "/api/dashboard/view",
            "/api/notifications",
        ],
        "methods":   ["GET"],
        "off_hours_access": False,
    },
    "guest": {
        "endpoints": [
            "/api/login",
            "/api/register",
            "/api/health",
            "/api/status",
        ],
        "methods":   ["GET", "POST"],
        "off_hours_access": False,
    },
}

# Sensitive actions that always need admin/manager
SENSITIVE_ACTIONS = {
    "DELETE": 60,
    "PUT":    30,
    "PATCH":  20,
}

# Admin-only endpoint prefixes (hard block for non-admins)
ADMIN_ONLY_ENDPOINTS = [
    "/api/admin",
    "/api/internal",
    "/api/superuser",
    "/api/system",
    "/api/config",
]

# Cross-department endpoints (employees can't access other depts)
CROSS_DEPT_ENDPOINTS = [
    "/api/hr/",
    "/api/finance/",
    "/api/legal/",
    "/api/payroll/",
]

# Business hours (24h format, UTC)
BUSINESS_HOURS_START = 8   # 08:00
BUSINESS_HOURS_END   = 20  # 20:00

# Severity thresholds
SEVERITY_MAP = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "SAFE"),
]

ACTION_MAP = {
    "CRITICAL": "BLOCK",
    "HIGH":     "BLOCK",
    "MEDIUM":   "FLAG",
    "LOW":      "MONITOR",
    "SAFE":     "ALLOW",
}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _get_severity(score: int) -> str:
    for threshold, label in SEVERITY_MAP:
        if score >= threshold:
            return label
    return "SAFE"


def _get_action(severity: str) -> str:
    return ACTION_MAP.get(severity, "MONITOR")


def _endpoint_allowed(endpoint: str, allowed: list) -> bool:
    if allowed == ["*"]:
        return True
    endpoint_lower = endpoint.lower()
    return any(endpoint_lower.startswith(p.lower()) for p in allowed)


def _is_business_hours(hour: Optional[int] = None) -> bool:
    if hour is None:
        hour = datetime.now(timezone.utc).hour
    return BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END


# ─────────────────────────────────────────────
# Detection Modules
# ─────────────────────────────────────────────

def check_role_exists(request: dict) -> tuple[int, str | None]:
    """
    Rule: Unknown/unrecognized role gets flagged immediately.
    Risk: +50
    """
    role = request.get("role", "").lower()
    if role not in RBAC_MATRIX:
        logger.warning("Unknown role '%s' attempted access", role)
        return 50, f"Unknown role '{role}' — not in RBAC matrix"
    return 0, None


def check_endpoint_permission(request: dict) -> tuple[int, str | None]:
    """
    Rule: Role must have permission for the endpoint being accessed.
    Risk: +80
    """
    role     = request.get("role", "").lower()
    endpoint = request.get("endpoint", "")

    if role not in RBAC_MATRIX:
        return 0, None  # already caught by check_role_exists

    allowed = RBAC_MATRIX[role]["endpoints"]
    if not _endpoint_allowed(endpoint, allowed):
        logger.warning("RBAC violation: role='%s' not permitted on '%s'", role, endpoint)
        return 80, f"RBAC violation — role '{role}' not permitted on {endpoint}"

    return 0, None


def check_method_permission(request: dict) -> tuple[int, str | None]:
    """
    Rule: Role must be allowed to use the HTTP method.
    Risk: +50
    """
    role   = request.get("role", "").lower()
    method = request.get("method", "").upper()

    if role not in RBAC_MATRIX:
        return 0, None

    allowed_methods = RBAC_MATRIX[role]["methods"]
    if method not in allowed_methods:
        logger.warning("Method violation: role='%s' used %s (not allowed)", role, method)
        return 50, f"Method not allowed — role '{role}' cannot use {method}"

    return 0, None


def check_admin_only_endpoints(request: dict) -> tuple[int, str | None]:
    """
    Rule: Admin-only endpoints are hard-blocked for non-admin roles.
    Risk: +80
    """
    role     = request.get("role", "").lower()
    endpoint = request.get("endpoint", "")

    if role in ("admin", "superadmin"):
        return 0, None

    endpoint_lower = endpoint.lower()
    for admin_path in ADMIN_ONLY_ENDPOINTS:
        if endpoint_lower.startswith(admin_path.lower()):
            logger.warning("Admin-only endpoint accessed by role='%s': %s", role, endpoint)
            return 80, f"Admin-only endpoint accessed by role '{role}'"

    return 0, None


def check_sensitive_action(request: dict) -> tuple[int, str | None]:
    """
    Rule: DELETE/PUT/PATCH by low-privilege roles = suspicious.
    Risk: varies by method (see SENSITIVE_ACTIONS)
    """
    role   = request.get("role", "").lower()
    method = request.get("method", "").upper()

    if role in ("admin", "superadmin", "manager"):
        return 0, None

    if method in SENSITIVE_ACTIONS:
        risk = SENSITIVE_ACTIONS[method]
        logger.warning("Sensitive action %s by role='%s'", method, role)
        return risk, f"Sensitive action '{method}' performed by low-privilege role '{role}'"

    return 0, None


def check_off_hours_access(request: dict) -> tuple[int, str | None]:
    """
    Rule: Roles without off-hours permission accessing outside business hours.
    Risk: +30
    """
    role = request.get("role", "").lower()
    hour = request.get("hour", None)  # optional: pass current hour for testing

    if role not in RBAC_MATRIX:
        return 0, None

    off_hours_ok = RBAC_MATRIX[role].get("off_hours_access", False)
    if off_hours_ok:
        return 0, None

    currently_business_hours = _is_business_hours(hour)
    if not currently_business_hours:
        logger.warning("Off-hours access by role='%s' at hour=%s", role, hour)
        return 30, f"Off-hours access by role '{role}' outside business hours (08:00–20:00 UTC)"

    return 0, None


def check_cross_department(request: dict) -> tuple[int, str | None]:
    """
    Rule: Employees/interns accessing other department data.
    Risk: +40
    """
    role     = request.get("role", "").lower()
    endpoint = request.get("endpoint", "")

    if role in ("admin", "superadmin", "manager"):
        return 0, None

    endpoint_lower = endpoint.lower()
    for dept_path in CROSS_DEPT_ENDPOINTS:
        if endpoint_lower.startswith(dept_path.lower()):
            logger.warning("Cross-dept access by role='%s' on %s", role, endpoint)
            return 40, f"Cross-department data access by role '{role}' on {endpoint}"

    return 0, None


def check_role_escalation(request: dict) -> tuple[int, str | None]:
    """
    Rule: Request includes a 'requested_role' higher than current role.
    Risk: +70
    """
    role           = request.get("role", "").lower()
    requested_role = request.get("requested_role", "").lower()

    if not requested_role:
        return 0, None

    role_hierarchy = ["guest", "intern", "employee", "manager", "admin", "superadmin"]

    current_level   = role_hierarchy.index(role) if role in role_hierarchy else -1
    requested_level = role_hierarchy.index(requested_role) if requested_role in role_hierarchy else -1

    if requested_level > current_level:
        logger.warning("Role escalation attempt: '%s' → '%s'", role, requested_role)
        return 70, f"Role escalation attempt — '{role}' trying to act as '{requested_role}'"

    return 0, None


# ─────────────────────────────────────────────
# Main Agent Class
# ─────────────────────────────────────────────

class RBACAgent:

    def __init__(self):
        self.checks = [
            check_role_exists,
            check_admin_only_endpoints,
            check_endpoint_permission,
            check_method_permission,
            check_sensitive_action,
            check_off_hours_access,
            check_cross_department,
            check_role_escalation,
        ]
        logger.info("RBACAgent initialized with %d checks.", len(self.checks))

    def analyze(self, request: dict) -> dict:
        """
        Run all RBAC checks against a request.

        Args:
            request (dict): Expected keys:
                - user           (str)  : username
                - role           (str)  : current role
                - endpoint       (str)  : API endpoint
                - method         (str)  : HTTP method
                - requested_role (str)  : optional — if user tries to elevate role
                - hour           (int)  : optional — UTC hour (for off-hours test)

        Returns:
            dict: {
                authorized   (bool),
                risk_score   (int),
                severity     (str),
                action       (str),
                reasons      (list[str]),
                timestamp    (str),
                user         (str),
                role         (str),
                endpoint     (str)
            }
        """
        total_score = 0
        reasons     = []

        for check_fn in self.checks:
            score, reason = check_fn(request)
            if score > 0 and reason:
                total_score += score
                reasons.append(reason)

        total_score = min(total_score, 200)
        severity    = _get_severity(total_score)
        action      = _get_action(severity)
        authorized  = (action == "ALLOW")

        result = {
            "authorized" : authorized,
            "risk_score" : total_score,
            "severity"   : severity,
            "action"     : action,
            "reasons"    : reasons,
            "timestamp"  : datetime.now(timezone.utc).isoformat(),
            "user"       : request.get("user", "unknown"),
            "role"       : request.get("role", "unknown"),
            "endpoint"   : request.get("endpoint", "unknown"),
        }

        logger.info(
            "RBAC | user=%-15s | role=%-10s | endpoint=%-30s | score=%3d | %s | %s",
            result["user"], result["role"], result["endpoint"],
            result["risk_score"], result["severity"], result["action"]
        )

        return result

    def is_authorized(self, user: str, role: str, endpoint: str, method: str) -> bool:
        """
        Quick boolean check — use this in middleware/service layer.
        Returns True if access should be allowed.
        """
        result = self.analyze({
            "user": user, "role": role,
            "endpoint": endpoint, "method": method
        })
        return result["authorized"]


# ─────────────────────────────────────────────
# Self-Test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    agent = RBACAgent()

    tests = [
        {"user": "admin",    "role": "admin",    "endpoint": "/api/admin/users",   "method": "DELETE"},
        {"user": "intern_1", "role": "intern",   "endpoint": "/api/admin/logs",    "method": "GET"},
        {"user": "emp_1",    "role": "employee", "endpoint": "/api/tasks",         "method": "GET"},
        {"user": "emp_2",    "role": "employee", "endpoint": "/api/hr/salary",     "method": "GET"},
        {"user": "mgr_1",    "role": "manager",  "endpoint": "/api/reports",       "method": "POST"},
        {"user": "intern_2", "role": "intern",   "endpoint": "/api/profile/view",  "method": "GET", "hour": 23},
        {"user": "hacker",   "role": "employee", "endpoint": "/api/profile",       "method": "GET",
         "requested_role": "admin"},
    ]

    print("\n" + "="*65)
    print("  RBAC Governance Agent — Self Test")
    print("="*65)
    for t in tests:
        r = agent.analyze(t)
        print(f"\n  user={t['user']:<12} role={t['role']:<10} method={t['method']:<7} endpoint={t['endpoint']}")
        print(f"  → score={r['risk_score']:>3}  severity={r['severity']:<8}  action={r['action']:<7}  authorized={r['authorized']}")
        if r["reasons"]:
            for reason in r["reasons"]:
                print(f"    · {reason}")