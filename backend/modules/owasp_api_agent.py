"""
OWASP API Security Agent
AI Governance Platform
--------------------------
Covers all OWASP API Top 10 (2023):

  API1  — BOLA (Broken Object Level Authorization)
  API2  — Broken Authentication
  API3  — Broken Object Property Level Authorization
  API4  — Unrestricted Resource Consumption
  API5  — Broken Function Level Authorization  (reuses RBAC)
  API6  — Unrestricted Access to Sensitive Business Flows
  API7  — SSRF
  API8  — Security Misconfiguration
  API9  — Improper Inventory Management
  API10 — Unsafe Consumption of APIs
"""

import re
import logging
from datetime import datetime, timezone

# ── Phase 1 detectors ──
from modules.bola_detector            import detect as detect_bola
from modules.auth_detector            import detect as detect_auth
from modules.resource_abuse_detector  import detect as detect_resource_abuse
# ── Phase 2 detectors ──
from modules.ssrf_detector            import detect as detect_ssrf
from modules.api_inventory_detector   import detect as detect_api_inventory
from modules.jwt_threat_engine        import detect_jwt_threat
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("OWASPAgent")


# ─────────────────────────────────────────────
# OWASP Category Labels (for output)
# ─────────────────────────────────────────────
OWASP_CATEGORIES = {
    "API1":  "Broken Object Level Authorization (BOLA)",
    "API2":  "Broken Authentication",
    "API3":  "Broken Object Property Level Authorization",
    "API4":  "Unrestricted Resource Consumption",
    "API5":  "Broken Function Level Authorization",
    "API6":  "Unrestricted Access to Sensitive Business Flows",
    "API7":  "Server-Side Request Forgery (SSRF)",
    "API8":  "Security Misconfiguration",
    "API9":  "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

# ─────────────────────────────────────────────
# Severity / Action maps
# ─────────────────────────────────────────────
SEVERITY_MAP = [
    (120, "CRITICAL"),
    (80,  "HIGH"),
    (50,  "MEDIUM"),
    (20,  "LOW"),
    (0,   "SAFE"),
]

ACTION_MAP = {
    "CRITICAL": "BLOCK",
    "HIGH":     "BLOCK",
    "MEDIUM":   "FLAG",
    "LOW":      "MONITOR",
    "SAFE":     "ALLOW",
}


def _get_severity(score: int) -> str:
    for threshold, label in SEVERITY_MAP:
        if score >= threshold:
            return label
    return "SAFE"


def _get_action(severity: str) -> str:
    return ACTION_MAP.get(severity, "MONITOR")


# ─────────────────────────────────────────────
# Inline detectors for API3, API5, API8, API10
# (No separate file needed — logic is simple)
# ─────────────────────────────────────────────

# API3 — Sensitive fields that only admins can modify
ADMIN_ONLY_FIELDS = {
    "role", "permissions", "salary", "is_admin",
    "credit_limit", "account_type", "clearance_level",
    "subscription_tier", "admin_notes", "internal_flag",
}

def _detect_api3(request: dict) -> tuple[int, str | None]:
    """
    API3: Employee/intern trying to modify admin-only fields.
    Risk: +60
    """
    role        = request.get("role", "").lower()
    body_fields = request.get("body_fields", [])  # list of field names being modified

    if role in ("admin", "superadmin"):
        return 0, None

    if isinstance(body_fields, str):
        body_fields = [f.strip() for f in body_fields.split(",")]

    for field in body_fields:
        if field.lower() in ADMIN_ONLY_FIELDS:
            logger.warning(
                "API3: role='%s' attempting to modify field '%s'", role, field
            )
            return 80, f"API3 — Role '{role}' trying to modify admin-only field '{field}'"

    return 0, None


# Admin-only function endpoints (API5)
ADMIN_FUNCTION_ENDPOINTS = [
    "/api/admin", "/api/internal", "/api/superuser",
    "/api/system", "/api/config", "/api/delete_all",
]

def _detect_api5(request: dict) -> tuple[int, str | None]:
    """
    API5: Function-level authorization — non-admins calling admin functions.
    Risk: +75
    """
    role     = request.get("role", "").lower()
    endpoint = request.get("endpoint", "").lower()
    method   = request.get("method",   "").upper()

    if role in ("admin", "superadmin"):
        return 0, None

    for path in ADMIN_FUNCTION_ENDPOINTS:
        if endpoint.startswith(path):
            return 85, f"API5 — Non-admin '{role}' calling admin function {endpoint}"

    # DELETE/PUT on any endpoint by non-admin/manager
    if method in ("DELETE", "PUT") and role in ("intern", "guest"):
        return 55, f"API5 — Role '{role}' using destructive method {method}"

    return 0, None


# API8 — Security Misconfiguration signals
MISCONFIG_PATTERNS = [
    (r"debug\s*=\s*true",          "Debug mode enabled in request"),
    (r"stack.?trace",              "Stack trace exposed"),
    (r"x-powered-by:\s*(php|asp)", "Framework version exposed"),
    (r"server:\s*(apache|nginx|iis)/[\d.]+", "Server version exposed"),
    (r"default.*password|password.*default", "Default credentials detected"),
    (r"access-control-allow-origin:\s*\*",       "CORS wildcard configured"),
]

def _detect_api8(request: dict) -> tuple[int, str | None]:
    """
    API8: Security misconfiguration signals.
    Risk: +40
    """
    headers = str(request.get("headers", "") or "").lower()
    body    = str(request.get("body",    "") or "").lower()
    combined = headers + " " + body

    for pattern, description in MISCONFIG_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            logger.warning("API8: %s", description)
            return 65, f"API8 — Security misconfiguration: {description}"

    return 0, None


# API10 — Unsafe consumption (calling suspicious external URLs)
UNSAFE_EXTERNAL_PATTERNS = [
    r"http://",          # HTTP (not HTTPS)
    r"pastebin\.com",
    r"ngrok\.io",
    r"requestbin\.",
    r"hookbin\.",
    r"webhook\.site",
    r"burpcollaborator",
    r"\.onion",          # Tor
]

def _detect_api10(request: dict) -> tuple[int, str | None]:
    """
    API10: Unsafe consumption of external/untrusted APIs.
    Risk: +50
    """
    body   = str(request.get("body",   "") or "")
    params = str(request.get("params", "") or "")
    combined = body + " " + params

    # Check for external URL calls
    url_match = re.search(r"https?://([^\s\"'>/]+)", combined)
    if url_match:
        domain = url_match.group(1).lower()
        for pattern in UNSAFE_EXTERNAL_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return 65, f"API10 — Unsafe external API consumption: {domain}"

    return 0, None


# ─────────────────────────────────────────────
# Main Agent Class
# ─────────────────────────────────────────────

class OWASPSecurityAgent:

    def __init__(self):
        # Each tuple: (check_fn, owasp_category)
        self.checks = [
            (detect_bola,            "API1"),
            (detect_auth,            "API2"),
            (_detect_api3,           "API3"),
            (detect_resource_abuse,  "API4/API6"),
            (_detect_api5,           "API5"),
            (detect_ssrf,            "API7"),
            (_detect_api8,           "API8"),
            (detect_api_inventory,   "API9"),
            (_detect_api10,          "API10"),
        ]
        logger.info(
            "OWASPSecurityAgent initialized with %d checks covering API1-API10.",
            len(self.checks)
        )

    def analyze(self, request: dict) -> dict:
        """
        Run all OWASP checks against an API request.
        """

        total_score = 0
        reasons = []
        owasp_findings = []

        for check_fn, category in self.checks:
            score, reason = check_fn(request)

            if score > 0 and reason:
                total_score += score
                reasons.append(reason)

                if category not in owasp_findings:
                    owasp_findings.append(category)

        # JWT Agent Integration
        jwt_score, jwt_reason = detect_jwt_threat(request)

        if jwt_score > 0:
            total_score += jwt_score
            reasons.append(jwt_reason)

            if "JWT" not in owasp_findings:
                owasp_findings.append("JWT")

        total_score = min(total_score, 200)
        severity = _get_severity(total_score)
        action = _get_action(severity)

        result = {
            "risk_score": total_score,
            "severity": severity,
            "action": action,
            "owasp_findings": owasp_findings,
            "reasons": reasons,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": request.get("user", "unknown"),
            "endpoint": request.get("endpoint", "unknown"),
        }

        logger.info(
            "OWASP | user=%-15s | endpoint=%-30s | score=%3d | %s | %s | findings=%s",
            result["user"],
            result["endpoint"],
            result["risk_score"],
            result["severity"],
            result["action"],
            result["owasp_findings"]
        )

        return result


# ─────────────────────────────────────────────
# Self-Test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    agent = OWASPSecurityAgent()

    tests = [
        {
            "label": "API1 — BOLA: emp accessing another user's record",
            "request": {
                "user": "emp_101", "user_id": "101", "role": "employee",
                "endpoint": "/api/users/999", "method": "GET",
                "auth_token": "Bearer valid_tok",
            }
        },
        {
            "label": "API2 — Missing auth token",
            "request": {
                "user": "unknown", "role": "guest",
                "endpoint": "/api/payments", "method": "GET",
                "auth_token": "",
            }
        },
        {
            "label": "API3 — Employee modifying role field",
            "request": {
                "user": "emp_1", "role": "employee",
                "endpoint": "/api/profile", "method": "PUT",
                "auth_token": "Bearer tok",
                "body_fields": ["name", "email", "role"],
            }
        },
        {
            "label": "API4 — Rate limit abuse (600 reqs)",
            "request": {
                "user": "emp_2", "role": "employee",
                "endpoint": "/api/data", "method": "GET",
                "auth_token": "Bearer tok",
                "request_count": 600,
            }
        },
        {
            "label": "API5 — Intern calling admin function",
            "request": {
                "user": "intern_1", "role": "intern",
                "endpoint": "/api/admin/delete_user", "method": "DELETE",
                "auth_token": "Bearer tok",
            }
        },
        {
            "label": "API6 — OTP abuse (20 requests)",
            "request": {
                "user": "attacker", "role": "employee",
                "endpoint": "/api/otp/generate", "method": "POST",
                "auth_token": "Bearer tok",
                "request_count": 20,
            }
        },
        {
            "label": "API7 — SSRF payload in body",
            "request": {
                "user": "hacker", "role": "employee",
                "endpoint": "/api/fetch", "method": "POST",
                "auth_token": "Bearer tok",
                "body": '{"url": "http://169.254.169.254/latest/meta-data/"}',
            }
        },
        {
            "label": "API8 — Debug mode in headers",
            "request": {
                "user": "emp_3", "role": "employee",
                "endpoint": "/api/config", "method": "GET",
                "auth_token": "Bearer tok",
                "headers": "X-Debug: true  debug=true",
            }
        },
        {
            "label": "API9 — Zombie endpoint access",
            "request": {
                "user": "guest_1", "role": "guest",
                "endpoint": "/api/v1/users", "method": "GET",
                "auth_token": "Bearer tok",
            }
        },
        {
            "label": "API10 — Unsafe external API call",
            "request": {
                "user": "emp_4", "role": "employee",
                "endpoint": "/api/webhook", "method": "POST",
                "auth_token": "Bearer tok",
                "body": '{"callback_url": "http://requestbin.io/xyz"}',
            }
        },
        {
            "label": "CLEAN — Admin normal request",
            "request": {
                "user": "admin_1", "user_id": "999", "role": "admin",
                "endpoint": "/api/admin/users", "method": "GET",
                "auth_token": "Bearer strong_jwt_token_here_xyz",
                "request_count": 5,
            }
        },
    ]

    print("\n" + "="*70)
    print("  OWASP API Security Agent — Self Test")
    print("="*70)

    for t in tests:
        r = agent.analyze(t["request"])
        print(f"\n  ▶ {t['label']}")
        print(f"    score={r['risk_score']:>3}  severity={r['severity']:<8}  action={r['action']:<7}")
        if r["owasp_findings"]:
            print(f"    findings={r['owasp_findings']}")
        if r["reasons"]:
            for reason in r["reasons"]:
                print(f"    · {reason}")