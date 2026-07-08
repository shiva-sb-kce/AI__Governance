"""
test_api_agent.py
AI Governance Platform
-----------------------
Tests the full stack:
  Layer 1 — Schema    (input validation)
  Layer 2 — Service   (business logic)
  Layer 3 — Agent     (detection engine)

Run from backend/:
  python test_api_agent.py
"""

import sys
import os
sys.path.append(os.path.abspath(".."))

from modules.api_security_agent import APISecurityAgent
from schemas.api_security_schema import APISecurityRequest
from services.api_security_service import analyze_api_request

# ─────────────────────────────────────────────
# Color helpers for terminal output
# ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def color_severity(s):
    return {
        "CRITICAL": f"{RED}{BOLD}{s}{RESET}",
        "HIGH":     f"{RED}{s}{RESET}",
        "MEDIUM":   f"{YELLOW}{s}{RESET}",
        "LOW":      f"{CYAN}{s}{RESET}",
        "SAFE":     f"{GREEN}{s}{RESET}",
    }.get(s, s)

def color_action(a):
    return {
        "BLOCK":   f"{RED}{BOLD}{a}{RESET}",
        "FLAG":    f"{YELLOW}{a}{RESET}",
        "MONITOR": f"{CYAN}{a}{RESET}",
        "ALLOW":   f"{GREEN}{a}{RESET}",
    }.get(a, a)


# ─────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────

TEST_CASES = [

    # ── Layer 1: Schema Validation ──────────────
    {
        "group":  "LAYER 1 — Schema Validation",
        "label":  "Valid request passes schema",
        "layer":  "schema",
        "input": {
            "user": "admin", "role": "admin",
            "endpoint": "/api/admin/users", "method": "GET",
            "request_count": 5, "auth_token": "Bearer tok",
        },
        "expect_valid": True,
    },
    {
        "group":  "LAYER 1 — Schema Validation",
        "label":  "Missing required field (user) → schema rejects",
        "layer":  "schema",
        "input": {
            "role": "admin",
            "endpoint": "/api/admin/users", "method": "GET",
        },
        "expect_valid": False,
    },

    # ── Layer 2 + 3: Service + Agent ─────────────
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "Admin on admin endpoint → SAFE / ALLOW",
        "layer":  "service",
        "input": {
            "user": "admin_user", "role": "admin",
            "endpoint": "/api/admin/users", "method": "GET",
            "request_count": 5, "auth_token": "Bearer abc",
        },
        "expect_severity": "SAFE",
        "expect_action":   "ALLOW",
    },
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "Intern on admin DELETE + 500 reqs → CRITICAL / BLOCK",
        "layer":  "service",
        "input": {
            "user": "intern_1", "role": "intern",
            "endpoint": "/api/admin/logs", "method": "DELETE",
            "request_count": 500, "auth_token": "Bearer xyz",
        },
        "expect_severity": "CRITICAL",
        "expect_action":   "BLOCK",
    },
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "Employee harvesting customer records → CRITICAL / BLOCK",
        "layer":  "service",
        "input": {
            "user": "emp_2", "role": "employee",
            "endpoint": "/api/customers/452", "method": "GET",
            "request_count": 120, "auth_token": "Bearer emp",
        },
        "expect_severity": "CRITICAL",
        "expect_action":   "BLOCK",
    },
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "No auth token on /api/payments → HIGH / BLOCK",
        "layer":  "service",
        "input": {
            "user": "unknown", "role": "guest",
            "endpoint": "/api/payments", "method": "GET",
            "request_count": 3, "auth_token": "",
        },
        "expect_severity": "HIGH",
        "expect_action":   "BLOCK",
    },
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "SQL injection in params → HIGH / BLOCK",
        "layer":  "service",
        "input": {
            "user": "attacker", "role": "employee",
            "endpoint": "/api/users", "method": "GET",
            "request_count": 2, "auth_token": "Bearer tok",
            "params": "id=1 UNION SELECT * FROM users--",
        },
        "expect_severity": "HIGH",
        "expect_action":   "BLOCK",
    },
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "Large response size (150KB) → LOW / MONITOR",
        "layer":  "service",
        "input": {
            "user": "manager_1", "role": "manager",
            "endpoint": "/api/reports", "method": "GET",
            "request_count": 2, "auth_token": "Bearer mgr",
            "response_size": 150_000,
        },
        "expect_severity": "LOW",
        "expect_action":   "MONITOR",
    },
    {
        "group":  "LAYER 2+3 — Service + Agent",
        "label":  "Manager on manager endpoint → SAFE / ALLOW",
        "layer":  "service",
        "input": {
            "user": "manager_2", "role": "manager",
            "endpoint": "/api/reports", "method": "GET",
            "request_count": 3, "auth_token": "Bearer mgr2",
            "response_size": 1000,
        },
        "expect_severity": "SAFE",
        "expect_action":   "ALLOW",
    },
]


# ─────────────────────────────────────────────
# Test Runner
# ─────────────────────────────────────────────

def run_tests():
    passed = 0
    failed = 0
    current_group = ""

    for case in TEST_CASES:

        # Print group header
        if case["group"] != current_group:
            current_group = case["group"]
            print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
            print(f"{BOLD}{CYAN}  {current_group}{RESET}")
            print(f"{BOLD}{CYAN}{'─'*60}{RESET}")

        label = case["label"]

        # ── Schema Test ──────────────────────────
        if case["layer"] == "schema":
            try:
                req = APISecurityRequest(**case["input"])
                is_valid = True
            except Exception:
                is_valid = False

            expected = case["expect_valid"]
            ok = (is_valid == expected)

            status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
            print(f"\n  [{status}] {label}")
            if not ok:
                print(f"          Expected valid={expected}, got valid={is_valid}")
                failed += 1
            else:
                passed += 1
            continue

        # ── Service + Agent Test ─────────────────
        try:
            req    = APISecurityRequest(**case["input"])
            result = analyze_api_request(req)

            sev_ok = (result.severity == case["expect_severity"])
            act_ok = (result.action   == case["expect_action"])
            ok     = sev_ok and act_ok

            status_str = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
            print(f"\n  [{status_str}] {label}")
            print(f"          score={result.risk_score} | "
                  f"severity={color_severity(result.severity)} | "
                  f"action={color_action(result.action)}")

            if result.reasons:
                print(f"          reasons={result.reasons}")

            if not ok:
                if not sev_ok:
                    print(f"          {RED}Expected severity={case['expect_severity']}, got {result.severity}{RESET}")
                if not act_ok:
                    print(f"          {RED}Expected action={case['expect_action']}, got {result.action}{RESET}")
                failed += 1
            else:
                passed += 1

        except Exception as e:
            print(f"\n  [{RED}ERROR{RESET}] {label}")
            print(f"          Exception: {e}")
            failed += 1

    # ── Summary ──────────────────────────────────
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"{BOLD}  Results: {GREEN}{passed} passed{RESET}{BOLD} / "
          f"{RED}{failed} failed{RESET}{BOLD} / {total} total{RESET}")
    print(f"{'='*60}\n")

    if failed == 0:
        print(f"{GREEN}{BOLD}  ✅ All tests passed! API Security Layer is ready.{RESET}\n")
    else:
        print(f"{RED}{BOLD}  ❌ {failed} test(s) failed. Check output above.{RESET}\n")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{BOLD}{'='*60}")
    print(f"  AI Governance — API Security Full Stack Test")
    print(f"{'='*60}{RESET}")
    run_tests()