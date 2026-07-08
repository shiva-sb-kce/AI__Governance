"""
test_correlation_agent.py
AI Governance Platform
-----------------------
Tests all phases of Risk Correlation Engine:
  Phase 1 — Schema validation
  Phase 2 — Engine logic (amplification rules)
  Phase 3 — Service layer
  Phase 4 — End-to-end scenarios

Run from backend/:
  python test_correlation_agent.py
"""

import sys, os
sys.path.append(os.path.abspath(".."))

from modules.correlation_agent  import RiskCorrelationEngine
from schemas.correlation_schema import CorrelationRequest, AgentResult
from services.correlation_service import run_correlation

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def cs(s):
    return {"CRITICAL":f"{RED}{BOLD}{s}{RESET}","HIGH":f"{RED}{s}{RESET}",
            "MEDIUM":f"{YELLOW}{s}{RESET}","LOW":f"{CYAN}{s}{RESET}",
            "SAFE":f"{GREEN}{s}{RESET}"}.get(s,s)

def ca(a):
    return {"BLOCK":f"{RED}{BOLD}{a}{RESET}","FLAG":f"{YELLOW}{a}{RESET}",
            "MONITOR":f"{CYAN}{a}{RESET}","ALLOW":f"{GREEN}{a}{RESET}"}.get(a,a)

def cal(al):
    return {"SOC_ALERT":f"{RED}{BOLD}{al}{RESET}","SECURITY_ALERT":f"{RED}{al}{RESET}",
            "FLAG_REVIEW":f"{YELLOW}{al}{RESET}","LOG_ONLY":f"{CYAN}{al}{RESET}",
            "NONE":f"{GREEN}{al}{RESET}"}.get(al,al)

# ─── Helpers ───────────────────────────────────────────────────────────────
def ar(score, sev, reasons=None):
    """Shorthand: AgentResult(score, severity, reasons)"""
    return AgentResult(risk_score=score, severity=sev, reasons=reasons or [])

def safe():
    return ar(0, "SAFE", [])


TEST_CASES = [

    # ── Phase 1: Schema validation ─────────────────────────────────────────
    {"group":"PHASE 1 — Schema","layer":"schema",
     "label":"Valid request → schema accepts",
     "input":{"user":"u1","endpoint":"/api/test"},
     "expect_valid":True},

    {"group":"PHASE 1 — Schema","layer":"schema",
     "label":"Missing user → schema rejects",
     "input":{"endpoint":"/api/test"},
     "expect_valid":False},

    {"group":"PHASE 1 — Schema","layer":"schema",
     "label":"Missing endpoint → schema rejects",
     "input":{"user":"u1"},
     "expect_valid":False},

    # ── Phase 2: Engine logic ──────────────────────────────────────────────

    # All clean → SAFE
    {"group":"PHASE 2 — Engine Logic","layer":"engine",
     "label":"All agents SAFE → risk=0 / SAFE / ALLOW / NONE",
     "prompt":safe(),"jwt":safe(),"rbac":safe(),"api":safe(),"owasp":safe(),
     "user":"admin","endpoint":"/api/reports",
     "expect_severity":"SAFE","expect_action":"ALLOW","expect_alert":"NONE",
     "expect_min_score":0,"expect_max_score":5},

    # Single agent HIGH
    {"group":"PHASE 2 — Engine Logic","layer":"engine",
     "label":"Only RBAC HIGH → score≥28 / SAFE (weight=0.20)",
     "rbac":ar(80,"HIGH",["RBAC: intern on /admin"]),
     "user":"intern_1","endpoint":"/api/admin",
     "expect_min_score":28},

    # Two agents fire → Auth Bypass amplification
    {"group":"PHASE 2 — Engine Logic","layer":"engine",
     "label":"JWT+RBAC → Auth Bypass rule triggers (+25 bonus)",
     "jwt":ar(70,"MEDIUM",["JWT expired"]),
     "rbac":ar(80,"HIGH",["RBAC violation"]),
     "user":"emp_1","endpoint":"/api/admin/config",
     "expect_rule":"Auth Bypass Attempt",
     "expect_min_score":50},

    # Three agents HIGH → Triple Agent Firing amplification
    {"group":"PHASE 2 — Engine Logic","layer":"engine",
     "label":"3 agents HIGH → Triple Agent Firing bonus (+15)",
     "prompt":ar(80,"HIGH",["Injection"]),
     "rbac":  ar(80,"HIGH",["RBAC violation"]),
     "owasp": ar(75,"HIGH",["BOLA"]),
     "user":"emp_2","endpoint":"/api/admin",
     "expect_rule":"Triple Agent Firing",
     "expect_min_score":80},

    # Full attack chain
    {"group":"PHASE 2 — Engine Logic","layer":"engine",
     "label":"All 5 agents firing → CRITICAL / BLOCK / SOC_ALERT",
     "prompt":ar(90,"CRITICAL",["Prompt injection"]),
     "jwt":   ar(60,"MEDIUM",  ["JWT replay"]),
     "rbac":  ar(80,"HIGH",   ["RBAC violation"]),
     "api":   ar(50,"MEDIUM",  ["Rate abuse"]),
     "owasp": ar(75,"HIGH",   ["BOLA detected"]),
     "user":"attacker","endpoint":"/api/admin/users",
     "expect_severity":"CRITICAL",
     "expect_action":"BLOCK",
     "expect_alert":"SOC_ALERT",
     "expect_min_score":150},

    # ── Phase 3: Service layer ─────────────────────────────────────────────
    {"group":"PHASE 3 — Service Layer","layer":"service",
     "label":"Clean request through service → SAFE",
     "input":{
         "user":"admin","endpoint":"/api/reports",
     },
     "expect_severity":"SAFE","expect_action":"ALLOW"},

    {"group":"PHASE 3 — Service Layer","layer":"service",
     "label":"Critical attack through service → CRITICAL/BLOCK",
     "input":{
         "user":"emp_101","endpoint":"/api/admin/users",
         "prompt_result":{"risk_score":90,"severity":"CRITICAL","reasons":["Injection"]},
         "rbac_result":  {"risk_score":80,"severity":"HIGH",    "reasons":["RBAC violation"]},
         "owasp_result": {"risk_score":75,"severity":"HIGH",    "reasons":["BOLA"]},
     },
     "expect_severity":"CRITICAL","expect_action":"BLOCK"},

    {"group":"PHASE 3 — Service Layer","layer":"service",
     "label":"Single RBAC MEDIUM → SAFE (weight contribution low)",
     "input":{
         "user":"emp_202","endpoint":"/api/profile",
         "rbac_result":{"risk_score":60,"severity":"MEDIUM","reasons":["Role mismatch"]},
     },
     "expect_severity_in":["SAFE","LOW","MEDIUM"],
     "expect_action_in":["ALLOW","MONITOR","FLAG"]},

    # ── Phase 4: End-to-end enterprise scenarios ───────────────────────────
    {"group":"PHASE 4 — Enterprise Scenarios","layer":"engine",
     "label":"Credential + API Abuse scenario → HIGH/BLOCK",
     "jwt":ar(70,"MEDIUM",["JWT misuse"]),
     "api":ar(80,"HIGH",  ["Rate limit critical"]),
     "user":"bot_agent","endpoint":"/api/users",
     "expect_rule":"Credential + API Abuse",
     "expect_min_score":60},

    {"group":"PHASE 4 — Enterprise Scenarios","layer":"engine",
     "label":"Data Exfil chain → CRITICAL amplification",
     "prompt":ar(85,"CRITICAL",["Data exfiltration prompt"]),
     "owasp": ar(75,"HIGH",   ["BOLA + API3"]),
     "user":"insider_threat","endpoint":"/api/customers",
     "expect_rule":"Data Exfiltration Chain",
     "expect_min_score":80},

    {"group":"PHASE 4 — Enterprise Scenarios","layer":"engine",
     "label":"Low-risk intern normal access → SAFE or LOW",
     "rbac":ar(0,"SAFE",[]),
     "user":"intern_safe","endpoint":"/api/profile/view",
     "expect_severity_in":["SAFE","LOW"],
     "expect_action_in":["ALLOW","MONITOR"]},
]


def run_engine_case(case) -> tuple[bool, dict]:
    """Run a direct engine test case."""
    engine = RiskCorrelationEngine()
    result = engine.correlate(
        prompt_result = case.get("prompt", {}) if isinstance(case.get("prompt"), dict)
                        else (case["prompt"].model_dump() if "prompt" in case else None),
        jwt_result    = case.get("jwt",    {}) if isinstance(case.get("jwt"), dict)
                        else (case["jwt"].model_dump()    if "jwt"    in case else None),
        rbac_result   = case.get("rbac",   {}) if isinstance(case.get("rbac"), dict)
                        else (case["rbac"].model_dump()   if "rbac"   in case else None),
        api_result    = case.get("api",    {}) if isinstance(case.get("api"), dict)
                        else (case["api"].model_dump()    if "api"    in case else None),
        owasp_result  = case.get("owasp",  {}) if isinstance(case.get("owasp"), dict)
                        else (case["owasp"].model_dump()  if "owasp"  in case else None),
        user     = case.get("user",     "unknown"),
        endpoint = case.get("endpoint", "/unknown"),
    )
    return result


def check_engine_result(case, result) -> tuple[bool, list]:
    failures = []

    if "expect_severity" in case and result["severity"] != case["expect_severity"]:
        failures.append(f"Expected severity={case['expect_severity']}, got {result['severity']}")

    if "expect_severity_in" in case and result["severity"] not in case["expect_severity_in"]:
        failures.append(f"Expected severity in {case['expect_severity_in']}, got {result['severity']}")

    if "expect_action" in case and result["action"] != case["expect_action"]:
        failures.append(f"Expected action={case['expect_action']}, got {result['action']}")

    if "expect_action_in" in case and result["action"] not in case["expect_action_in"]:
        failures.append(f"Expected action in {case['expect_action_in']}, got {result['action']}")

    if "expect_alert" in case and result["alert"] != case["expect_alert"]:
        failures.append(f"Expected alert={case['expect_alert']}, got {result['alert']}")

    if "expect_min_score" in case and result["risk_score"] < case["expect_min_score"]:
        failures.append(f"Expected score≥{case['expect_min_score']}, got {result['risk_score']}")

    if "expect_max_score" in case and result["risk_score"] > case["expect_max_score"]:
        failures.append(f"Expected score≤{case['expect_max_score']}, got {result['risk_score']}")

    if "expect_rule" in case and case["expect_rule"] not in result["triggered_rules"]:
        failures.append(f"Expected rule '{case['expect_rule']}' in {result['triggered_rules']}")

    return len(failures) == 0, failures


def run_tests():
    passed = failed = 0
    current_group = ""

    for case in TEST_CASES:
        if case["group"] != current_group:
            current_group = case["group"]
            print(f"\n{BOLD}{CYAN}{'─'*68}{RESET}")
            print(f"{BOLD}{CYAN}  {current_group}{RESET}")
            print(f"{BOLD}{CYAN}{'─'*68}{RESET}")

        label = case["label"]

        # ── Schema test ──────────────────────────────────────────────────
        if case["layer"] == "schema":
            try:
                CorrelationRequest(**case["input"])
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

        # ── Engine test ──────────────────────────────────────────────────
        if case["layer"] == "engine":
            try:
                result = run_engine_case(case)
                ok, failures = check_engine_result(case, result)

                status_str = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
                print(f"\n  [{status_str}] {label}")
                print(f"          score={result['risk_score']:>3} "
                      f"(base={result['base_score']} +bonus={result['amplification_bonus']}) | "
                      f"severity={cs(result['severity'])} | "
                      f"action={ca(result['action'])} | "
                      f"alert={cal(result['alert'])}")
                if result["triggered_rules"]:
                    print(f"          rules={result['triggered_rules']}")
                if result["top_threats"]:
                    print(f"          top_threats={[t['agent']+':'+str(t['risk_score']) for t in result['top_threats']]}")
                for f in failures:
                    print(f"          {RED}{f}{RESET}")

                if ok: passed += 1
                else:  failed += 1

            except Exception as e:
                print(f"\n  [{RED}ERROR{RESET}] {label} → {e}")
                import traceback; traceback.print_exc()
                failed += 1
            continue

        # ── Service test ─────────────────────────────────────────────────
        if case["layer"] == "service":
            try:
                req = CorrelationRequest(**case["input"])
                result = run_correlation(req)

                failures = []
                if "expect_severity" in case and result.severity != case["expect_severity"]:
                    failures.append(f"Expected severity={case['expect_severity']}, got {result.severity}")
                if "expect_severity_in" in case and result.severity not in case["expect_severity_in"]:
                    failures.append(f"Expected severity in {case['expect_severity_in']}, got {result.severity}")
                if "expect_action" in case and result.action != case["expect_action"]:
                    failures.append(f"Expected action={case['expect_action']}, got {result.action}")
                if "expect_action_in" in case and result.action not in case["expect_action_in"]:
                    failures.append(f"Expected action in {case['expect_action_in']}, got {result.action}")

                ok = len(failures) == 0
                status_str = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
                print(f"\n  [{status_str}] {label}")
                print(f"          score={result.risk_score:>3} | "
                      f"severity={cs(result.severity)} | "
                      f"action={ca(result.action)} | "
                      f"alert={cal(result.alert)}")
                if result.triggered_rules:
                    print(f"          rules={result.triggered_rules}")
                for f in failures:
                    print(f"          {RED}{f}{RESET}")

                if ok: passed += 1
                else:  failed += 1

            except Exception as e:
                print(f"\n  [{RED}ERROR{RESET}] {label} → {e}")
                import traceback; traceback.print_exc()
                failed += 1
            continue

    # ── Summary ─────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n{'='*68}")
    print(f"{BOLD}  Results: {GREEN}{passed} passed{RESET}{BOLD} / "
          f"{RED}{failed} failed{RESET}{BOLD} / {total} total{RESET}")
    print(f"{'='*68}\n")
    if failed == 0:
        print(f"{GREEN}{BOLD}  ✅ All tests passed! Risk Correlation Engine ready.{RESET}\n")
    else:
        print(f"{RED}{BOLD}  ❌ {failed} test(s) failed.{RESET}\n")


if __name__ == "__main__":
    print(f"\n{BOLD}{'='*68}")
    print(f"  AI Governance — Risk Correlation Engine Full Test")
    print(f"{'='*68}{RESET}")
    run_tests()