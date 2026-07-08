"""
test_unified_security_agent.py
AI Governance Platform
-----------------------
Tests Unified Security Agent

Run:
    python test_unified_security_agent.py
"""

import sys
import os

sys.path.append(os.path.abspath("."))

from modules.unified_security_agent import UnifiedSecurityAgent


RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


TEST_CASES = [

    {
        "label": "SAFE Request",
        "request": {
            "user": "employee_1",
            "endpoint": "/api/profile",

            "prompt_result": {
                "risk_score": 0,
                "severity": "SAFE",
                "reasons": []
            },

            "jwt_result": {
                "risk_score": 0,
                "severity": "SAFE",
                "reasons": []
            },

            "rbac_result": {
                "risk_score": 0,
                "severity": "SAFE",
                "reasons": []
            },

            "api_result": {
                "risk_score": 0,
                "severity": "SAFE",
                "reasons": []
            },

            "owasp_result": {
                "risk_score": 0,
                "severity": "SAFE",
                "reasons": []
            },
        }
    },

    {
        "label": "Prompt Injection + JWT Replay",
        "request": {
            "user": "attacker_1",
            "endpoint": "/api/profile",

            "prompt_result": {
                "risk_score": 90,
                "severity": "CRITICAL",
                "reasons": ["Prompt Injection"]
            },

            "jwt_result": {
                "risk_score": 70,
                "severity": "HIGH",
                "reasons": ["JWT Replay"]
            },
        }
    },

    {
        "label": "RBAC + OWASP Attack",
        "request": {
            "user": "intern_1",
            "endpoint": "/api/admin/users",

            "rbac_result": {
                "risk_score": 80,
                "severity": "HIGH",
                "reasons": ["RBAC Violation"]
            },

            "owasp_result": {
                "risk_score": 75,
                "severity": "HIGH",
                "reasons": ["BOLA"]
            },
        }
    },

    {
        "label": "Full Attack Chain",
        "request": {
            "user": "attacker_2",
            "endpoint": "/api/admin/export",

            "prompt_result": {
                "risk_score": 90,
                "severity": "CRITICAL",
                "reasons": ["Prompt Injection"]
            },

            "jwt_result": {
                "risk_score": 80,
                "severity": "HIGH",
                "reasons": ["JWT Replay"]
            },

            "rbac_result": {
                "risk_score": 85,
                "severity": "HIGH",
                "reasons": ["RBAC Violation"]
            },

            "api_result": {
                "risk_score": 70,
                "severity": "HIGH",
                "reasons": ["API Abuse"]
            },

            "owasp_result": {
                "risk_score": 80,
                "severity": "CRITICAL",
                "reasons": ["OWASP API1"]
            },
        }
    },
]


def run_tests():

    agent = UnifiedSecurityAgent()

    passed = 0
    failed = 0

    print(f"\n{BOLD}{'='*70}")
    print(" Unified Security Agent Test")
    print(f"{'='*70}{RESET}")

    for case in TEST_CASES:

        try:

            result = agent.analyze(case["request"])

            correlation = result["correlation"]

            print(f"\n{CYAN}Test:{RESET} {case['label']}")

            print(
                f"  Score={correlation['risk_score']} | "
                f"Severity={correlation['severity']} | "
                f"Action={correlation['action']}"
            )

            print(
                f"  Active Agents: "
                f"{correlation['active_agents']}"
            )

            if correlation["reasons"]:
                print(
                    f"  Reasons: "
                    f"{correlation['reasons'][:3]}"
                )

            passed += 1

        except Exception as e:

            print(
                f"\n{RED}FAILED:{RESET} "
                f"{case['label']}"
            )

            print(str(e))

            failed += 1

    total = passed + failed

    print(f"\n{'='*70}")
    print(
        f"{GREEN}{passed} Passed{RESET} | "
        f"{RED}{failed} Failed{RESET} | "
        f"{total} Total"
    )
    print(f"{'='*70}\n")


if __name__ == "__main__":
    run_tests()