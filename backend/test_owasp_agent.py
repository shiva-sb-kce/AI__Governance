"""
test_owasp_agent.py
AI Governance Platform
-----------------------
Tests all 3 layers for OWASP Agent.
Run from backend/:  python test_owasp_agent.py
"""
import sys, os
sys.path.append(os.path.abspath(".."))

from modules.owasp_api_agent  import OWASPSecurityAgent
from schemas.owasp_schema     import OWASPRequest
from services.owasp_service   import analyze_owasp

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"
def cs(s): return {"CRITICAL":f"{RED}{BOLD}{s}{RESET}","HIGH":f"{RED}{s}{RESET}","MEDIUM":f"{YELLOW}{s}{RESET}","LOW":f"{CYAN}{s}{RESET}","SAFE":f"{GREEN}{s}{RESET}"}.get(s,s)
def ca(a): return {"BLOCK":f"{RED}{BOLD}{a}{RESET}","FLAG":f"{YELLOW}{a}{RESET}","MONITOR":f"{CYAN}{a}{RESET}","ALLOW":f"{GREEN}{a}{RESET}"}.get(a,a)

# Realistic token used in all test cases (long enough to not trigger weak-token)
TOK = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"

TEST_CASES = [

  # ── Layer 1: Schema ──────────────────────────────────────────────────
  {"group":"LAYER 1 — Schema","layer":"schema",
   "label":"Valid request → schema accepts",
   "input":{"user":"u1","role":"employee","endpoint":"/api/data","method":"GET"},
   "expect_valid":True},
  {"group":"LAYER 1 — Schema","layer":"schema",
   "label":"Missing role → schema rejects",
   "input":{"user":"u1","endpoint":"/api/data","method":"GET"},
   "expect_valid":False},
  {"group":"LAYER 1 — Schema","layer":"schema",
   "label":"Missing endpoint → schema rejects",
   "input":{"user":"u1","role":"employee","method":"GET"},
   "expect_valid":False},

  # ── API1 — BOLA ──────────────────────────────────────────────────────
  {"group":"OWASP API1 — BOLA","layer":"service",
   "label":"Employee accessing another user record → MEDIUM/FLAG",
   "input":{"user":"emp_101","user_id":"101","role":"employee","endpoint":"/api/users/999","method":"GET","auth_token":TOK},
   "expect_severity":"HIGH","expect_findings":["API1"]},
  {"group":"OWASP API1 — BOLA","layer":"service",
   "label":"Admin accessing any user record → SAFE/ALLOW",
   "input":{"user":"admin","user_id":"999","role":"admin","endpoint":"/api/users/999","method":"GET","auth_token":TOK},
   "expect_severity":"SAFE","expect_findings":[]},

  # ── API2 — Auth ───────────────────────────────────────────────────────
  {"group":"OWASP API2 — Broken Auth","layer":"service",
   "label":"Missing token → CRITICAL/FLAG",
   "input":{"user":"u1","role":"employee","endpoint":"/api/data","method":"GET","auth_token":""},
   "expect_severity":"CRITICAL","expect_findings":["API2"]},
  {"group":"OWASP API2 — Broken Auth","layer":"service",
   "label":"Brute-force 15 attempts → MEDIUM/FLAG",
   "input":{"user":"u2","role":"guest","endpoint":"/api/data","method":"GET","auth_token":TOK,"login_attempts":15},
   "expect_severity":"MEDIUM","expect_findings":["API2"]},

  # ── API3 — Property auth ──────────────────────────────────────────────
  {"group":"OWASP API3 — Property Auth","layer":"service",
   "label":"Employee modifying role field → MEDIUM/FLAG",
   "input":{"user":"emp_1","role":"employee","endpoint":"/api/profile","method":"PUT","auth_token":TOK,"body_fields":["name","role"]},
   "expect_severity":"HIGH","expect_findings":["API3"]},

  # ── API4 — Resource abuse ──────────────────────────────────────────────
  {"group":"OWASP API4 — Resource Abuse","layer":"service",
   "label":"600 requests → HIGH/BLOCK",
   "input":{"user":"u3","role":"employee","endpoint":"/api/data","method":"GET","auth_token":TOK,"request_count":600},
   "expect_severity":"HIGH","expect_findings":["API4/API6"]},

  # ── API5 — Function auth ───────────────────────────────────────────────
  {"group":"OWASP API5 — Function Auth","layer":"service",
   "label":"Intern calling admin delete → CRITICAL/BLOCK",
   "input":{"user":"intern_1","role":"intern","endpoint":"/api/admin/users","method":"DELETE","auth_token":TOK},
   "expect_severity":"CRITICAL","expect_findings":["API5"]},

  # ── API6 — Business flow ───────────────────────────────────────────────
  {"group":"OWASP API6 — Business Flow","layer":"service",
   "label":"OTP abuse 20 requests → MEDIUM/FLAG",
   "input":{"user":"attacker","role":"employee","endpoint":"/api/otp/generate","method":"POST","auth_token":TOK,"request_count":20},
   "expect_severity":"MEDIUM","expect_findings":["API4/API6"]},

  # ── API7 — SSRF ────────────────────────────────────────────────────────
  {"group":"OWASP API7 — SSRF","layer":"service",
   "label":"AWS metadata SSRF → CRITICAL/BLOCK",
   "input":{"user":"hacker","role":"employee","endpoint":"/api/fetch","method":"POST","auth_token":TOK,"body":'{"url":"http://169.254.169.254/latest/meta-data/"}'},
   "expect_severity":"CRITICAL","expect_findings":["API7"]},
  {"group":"OWASP API7 — SSRF","layer":"service",
   "label":"Internal IP SSRF → CRITICAL/BLOCK",
   "input":{"user":"u4","role":"employee","endpoint":"/api/proxy","method":"POST","auth_token":TOK,"body":'{"target":"http://192.168.1.1/admin"}'},
   "expect_severity":"CRITICAL","expect_findings":["API7"]},

  # ── API8 — Misconfiguration ────────────────────────────────────────────
  {"group":"OWASP API8 — Misconfiguration","layer":"service",
   "label":"Debug mode in headers → LOW/MONITOR",
   "input":{"user":"u5","role":"employee","endpoint":"/api/data","method":"GET","auth_token":TOK,"headers":"X-Debug: true debug=true"},
   "expect_severity":"MEDIUM","expect_findings":["API8"]},

  # ── API9 — Inventory ───────────────────────────────────────────────────
  {"group":"OWASP API9 — Inventory","layer":"service",
   "label":"Old API v1 accessed → LOW/MONITOR",
   "input":{"user":"u6","role":"employee","endpoint":"/api/v1/users","method":"GET","auth_token":TOK},
   "expect_severity":"MEDIUM","expect_findings":["API9"]},
  {"group":"OWASP API9 — Inventory","layer":"service",
   "label":"Swagger docs accessed → LOW/MONITOR",
   "input":{"user":"u7","role":"guest","endpoint":"/swagger/index.html","method":"GET","auth_token":TOK},
   "expect_severity":"MEDIUM","expect_findings":["API9"]},

  # ── API10 — Unsafe consumption ─────────────────────────────────────────
  {"group":"OWASP API10 — Unsafe Consumption","layer":"service",
   "label":"Requestbin callback → MEDIUM/FLAG",
   "input":{"user":"u8","role":"employee","endpoint":"/api/webhook","method":"POST","auth_token":TOK,"body":'{"callback":"http://requestbin.io/xyz123"}'},
   "expect_severity":"MEDIUM","expect_findings":["API10"]},

  # ── CLEAN ──────────────────────────────────────────────────────────────
  {"group":"CLEAN — No threats","layer":"service",
   "label":"Admin normal GET → SAFE/ALLOW",
   "input":{"user":"admin","user_id":"1","role":"admin","endpoint":"/api/reports","method":"GET","auth_token":TOK,"request_count":3},
   "expect_severity":"SAFE","expect_findings":[]},
]


def run_tests():
    passed = failed = 0
    current_group = ""

    for case in TEST_CASES:
        if case["group"] != current_group:
            current_group = case["group"]
            print(f"\n{BOLD}{CYAN}{'─'*70}{RESET}")
            print(f"{BOLD}{CYAN}  {current_group}{RESET}")
            print(f"{BOLD}{CYAN}{'─'*70}{RESET}")

        label = case["label"]

        if case["layer"] == "schema":
            try:
                OWASPRequest(**case["input"])
                is_valid = True
            except Exception:
                is_valid = False
            ok = (is_valid == case["expect_valid"])
            print(f"\n  [{GREEN+'PASS'+RESET if ok else RED+'FAIL'+RESET}] {label}")
            if not ok:
                print(f"          Expected valid={case['expect_valid']}, got {is_valid}")
                failed += 1
            else:
                passed += 1
            continue

        try:
            req    = OWASPRequest(**case["input"])
            result = analyze_owasp(req)

            sev_ok      = (result.severity == case["expect_severity"])
            findings_ok = all(f in result.owasp_findings for f in case["expect_findings"])
            ok          = sev_ok and findings_ok

            status_str = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
            print(f"\n  [{status_str}] {label}")
            print(f"          score={result.risk_score:>3} | severity={cs(result.severity)} | action={ca(result.action)}")
            if result.owasp_findings:
                print(f"          findings={result.owasp_findings}")
            if result.reasons:
                for r in result.reasons:
                    print(f"          · {r}")

            if not ok:
                if not sev_ok:
                    print(f"          {RED}Expected severity={case['expect_severity']}, got {result.severity}{RESET}")
                if not findings_ok:
                    print(f"          {RED}Expected findings⊇{case['expect_findings']}, got {result.owasp_findings}{RESET}")
                failed += 1
            else:
                passed += 1

        except Exception as e:
            print(f"\n  [{RED}ERROR{RESET}] {label} → {e}")
            import traceback; traceback.print_exc()
            failed += 1

    total = passed + failed
    print(f"\n{'='*70}")
    print(f"{BOLD}  Results: {GREEN}{passed} passed{RESET}{BOLD} / {RED}{failed} failed{RESET}{BOLD} / {total} total{RESET}")
    print(f"{'='*70}\n")
    if failed == 0:
        print(f"{GREEN}{BOLD}  ✅ All tests passed! OWASP API1–API10 coverage ready.{RESET}\n")
    else:
        print(f"{RED}{BOLD}  ❌ {failed} test(s) failed.{RESET}\n")


if __name__ == "__main__":
    print(f"\n{BOLD}{'='*70}")
    print(f"  AI Governance — OWASP API Security Agent Full Stack Test")
    print(f"{'='*70}{RESET}")
    run_tests()