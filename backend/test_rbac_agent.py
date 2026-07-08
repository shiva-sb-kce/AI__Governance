"""
test_rbac_agent.py
AI Governance Platform
-----------------------
Tests all 3 layers:
  Layer 1 — Schema    (input validation)
  Layer 2 — Service   (business logic)
  Layer 3 — Agent     (RBAC detection engine)

Run from backend/:
  python test_rbac_agent.py
"""

import sys
import os
sys.path.append(os.path.abspath(".."))

from modules.rbac_agent import RBACAgent
from schemas.rbac_schema import RBACRequest
from services.rbac_service import check_rbac, is_authorized

# ─────────────────────────────────────────────
# Terminal colors
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

def color_bool(b):
    return f"{GREEN}ALLOWED{RESET}" if b else f"{RED}BLOCKED{RESET}"


# ─────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────

TEST_CASES = [

    # ── Layer 1: Schema Validation ─────────────
    {
        "group": "LAYER 1 — Schema validation",
        "label": "Valid request passes schema",
        "layer": "schema",
        "input": {"user": "emp_1", "role": "employee", "endpoint": "/api/tasks", "method": "GET"},
        "expect_valid": True,
    },
    {
        "group": "LAYER 1 — Schema validation",
        "label": "Missing 'role' field → schema rejects",
        "layer": "schema",
        "input": {"user": "emp_1", "endpoint": "/api/tasks", "method": "GET"},
        "expect_valid": False,
    },
    {
        "group": "LAYER 1 — Schema validation",
        "label": "hour=25 out of range → schema rejects",
        "layer": "schema",
        "input": {"user": "emp_1", "role": "employee", "endpoint": "/api/tasks", "method": "GET", "hour": 25},
        "expect_valid": False,
    },

    # ── Layer 2+3: Service + Agent ──────────────
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Admin on any endpoint → SAFE / ALLOW",
        "layer": "service",
        "input": {"user": "admin_1", "role": "admin", "endpoint": "/api/admin/users", "method": "DELETE"},
        "expect_authorized": True,
        "expect_severity":   "SAFE",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Intern on /api/admin → CRITICAL / BLOCK",
        "layer": "service",
        "input": {"user": "intern_1", "role": "intern", "endpoint": "/api/admin/logs", "method": "GET"},
        "expect_authorized": False,
        "expect_severity":   "CRITICAL",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Employee on /api/tasks (allowed) → SAFE / ALLOW",
        "layer": "service",
        "input": {"user": "emp_1", "role": "employee", "endpoint": "/api/tasks", "method": "GET"},
        "expect_authorized": True,
        "expect_severity":   "SAFE",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Employee tries DELETE → MEDIUM / FLAG",
        "layer": "service",
        "input": {"user": "emp_2", "role": "employee", "endpoint": "/api/tasks", "method": "DELETE"},
        "expect_authorized": False,
        "expect_severity":   "MEDIUM",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Employee on HR salary endpoint → MEDIUM / FLAG",
        "layer": "service",
        "input": {"user": "emp_3", "role": "employee", "endpoint": "/api/hr/salary", "method": "GET"},
        "expect_authorized": False,
        "expect_severity":   "MEDIUM",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Intern accessing off-hours (hour=23) → LOW / MONITOR",
        "layer": "service",
        "input": {"user": "intern_2", "role": "intern", "endpoint": "/api/profile/view", "method": "GET", "hour": 23},
        "expect_authorized": False,
        "expect_severity":   "LOW",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Role escalation attempt (employee → admin) → HIGH / BLOCK",
        "layer": "service",
        "input": {"user": "hacker", "role": "employee", "endpoint": "/api/profile", "method": "GET",
                  "requested_role": "admin"},
        "expect_authorized": False,
        "expect_severity":   "HIGH",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Unknown role → MEDIUM / FLAG",
        "layer": "service",
        "input": {"user": "ghost", "role": "phantom", "endpoint": "/api/profile", "method": "GET"},
        "expect_authorized": False,
        "expect_severity":   "MEDIUM",
    },
    {
        "group": "LAYER 2+3 — RBAC checks",
        "label": "Manager on /api/reports (allowed) → SAFE / ALLOW",
        "layer": "service",
        "input": {"user": "mgr_1", "role": "manager", "endpoint": "/api/reports", "method": "POST"},
        "expect_authorized": True,
        "expect_severity":   "SAFE",
    },

    # ── Quick is_authorized() check ─────────────
    {
        "group": "Quick is_authorized() helper",
        "label": "intern + GET + /api/profile/view → True",
        "layer": "quick",
        "input": {"user": "i1", "role": "intern", "endpoint": "/api/profile/view", "method": "GET"},
        "expect_authorized": True,
    },
    {
        "group": "Quick is_authorized() helper",
        "label": "intern + GET + /api/admin → False",
        "layer": "quick",
        "input": {"user": "i2", "role": "intern", "endpoint": "/api/admin/data", "method": "GET"},
        "expect_authorized": False,
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
        if case["group"] != current_group:
            current_group = case["group"]
            print(f"\n{BOLD}{CYAN}{'─'*65}{RESET}")
            print(f"{BOLD}{CYAN}  {current_group}{RESET}")
            print(f"{BOLD}{CYAN}{'─'*65}{RESET}")

        label = case["label"]

        # ── Schema test ──────────────────────────
        if case["layer"] == "schema":
            try:
                RBACRequest(**case["input"])
                is_valid = True
            except Exception:
                is_valid = False

            ok = (is_valid == case["expect_valid"])
            status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
            print(f"\n  [{status}] {label}")
            if not ok:
                print(f"          Expected valid={case['expect_valid']}, got {is_valid}")
                failed += 1
            else:
                passed += 1
            continue

        # ── Quick is_authorized() test ───────────
        if case["layer"] == "quick":
            inp = case["input"]
            result = is_authorized(inp["user"], inp["role"], inp["endpoint"], inp["method"])
            ok = (result == case["expect_authorized"])
            status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
            print(f"\n  [{status}] {label}")
            print(f"          authorized={color_bool(result)}")
            if not ok:
                print(f"          {RED}Expected {case['expect_authorized']}, got {result}{RESET}")
                failed += 1
            else:
                passed += 1
            continue

        # ── Service + Agent test ─────────────────
        try:
            req    = RBACRequest(**case["input"])
            result = check_rbac(req)

            auth_ok = (result.authorized == case["expect_authorized"])
            sev_ok  = (result.severity   == case["expect_severity"])
            ok      = auth_ok and sev_ok

            status_str = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
            print(f"\n  [{status_str}] {label}")
            print(f"          score={result.risk_score} | "
                  f"severity={color_severity(result.severity)} | "
                  f"authorized={color_bool(result.authorized)}")
            if result.reasons:
                print(f"          reasons={result.reasons}")

            if not ok:
                if not auth_ok:
                    print(f"          {RED}Expected authorized={case['expect_authorized']}, "
                          f"got {result.authorized}{RESET}")
                if not sev_ok:
                    print(f"          {RED}Expected severity={case['expect_severity']}, "
                          f"got {result.severity}{RESET}")
                failed += 1
            else:
                passed += 1

        except Exception as e:
            print(f"\n  [{RED}ERROR{RESET}] {label}")
            print(f"          Exception: {e}")
            failed += 1

    # ── Summary ──────────────────────────────────
    total = passed + failed
    print(f"\n{'='*65}")
    print(f"{BOLD}  Results: {GREEN}{passed} passed{RESET}{BOLD} / "
          f"{RED}{failed} failed{RESET}{BOLD} / {total} total{RESET}")
    print(f"{'='*65}\n")

    if failed == 0:
        print(f"{GREEN}{BOLD}  ✅ All tests passed! RBAC Layer is ready.{RESET}\n")
    else:
        print(f"{RED}{BOLD}  ❌ {failed} test(s) failed. Check output above.{RESET}\n")


if __name__ == "__main__":
    print(f"\n{BOLD}{'='*65}")
    print(f"  AI Governance — RBAC Governance Agent Full Stack Test")
    print(f"{'='*65}{RESET}")
    run_tests()