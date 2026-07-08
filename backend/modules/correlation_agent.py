"""
Risk Correlation Engine
AI Governance Platform
--------------------------
Combines scores from ALL agents into one
unified enterprise risk score.

Agents covered:
  ✅ Prompt Monitor Agent
  ✅ JWT Security Agent
  ✅ RBAC Governance Agent
  ✅ API Security Agent
  ✅ OWASP API Security Agent

Output:
  {
    "risk_score":  185,
    "severity":    "CRITICAL",
    "action":      "BLOCK",
    "alert":       "SOC_ALERT",
    "components":  { each agent's contribution },
    "top_threats": [ top 3 threats ],
    "reasons":     [ all reasons combined ]
  }
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("RiskCorrelationEngine")


# ─────────────────────────────────────────────
# Weighted contribution of each agent
# (must sum to 1.0)
# ─────────────────────────────────────────────
AGENT_WEIGHTS = {
    "prompt":  0.25,   # Prompt injection / jailbreak
    "jwt":     0.15,   # JWT replay / expiry / misuse
    "rbac":    0.20,   # Role-based access violation
    "api":     0.20,   # API abuse / rate limit / harvest
    "owasp":   0.20,   # OWASP API Top 10
}

# ─────────────────────────────────────────────
# Severity → numeric value (for comparison)
# ─────────────────────────────────────────────
SEVERITY_VALUE = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "SAFE":     1,
    "UNKNOWN":  0,
}

# ─────────────────────────────────────────────
# Final risk score → severity
# ─────────────────────────────────────────────
SEVERITY_MAP = [
    (160, "CRITICAL"),
    (120, "HIGH"),
    (80,  "MEDIUM"),
    (40,  "LOW"),
    (0,   "SAFE"),
]

# ─────────────────────────────────────────────
# Action + Alert per severity
# ─────────────────────────────────────────────
ACTION_MAP = {
    "CRITICAL": "BLOCK",
    "HIGH":     "BLOCK",
    "MEDIUM":   "FLAG",
    "LOW":      "MONITOR",
    "SAFE":     "ALLOW",
}

ALERT_MAP = {
    "CRITICAL": "SOC_ALERT",       # immediate SOC notification
    "HIGH":     "SECURITY_ALERT",  # security team notification
    "MEDIUM":   "FLAG_REVIEW",     # flagged for review
    "LOW":      "LOG_ONLY",        # log only
    "SAFE":     "NONE",
}

# ─────────────────────────────────────────────
# Amplification rules
# Multiple agents firing together = amplified risk
# ─────────────────────────────────────────────
AMPLIFICATION_RULES = [
    {
        "name":       "Full Attack Chain",
        "description":"Prompt injection + RBAC violation + OWASP finding",
        "requires":   ["prompt", "rbac", "owasp"],
        "bonus":      30,
    },
    {
        "name":       "Credential + API Abuse",
        "description":"JWT issue + API rate abuse",
        "requires":   ["jwt", "api"],
        "bonus":      20,
    },
    {
        "name":       "Auth Bypass Attempt",
        "description":"JWT issue + RBAC violation",
        "requires":   ["jwt", "rbac"],
        "bonus":      25,
    },
    {
        "name":       "Data Exfiltration Chain",
        "description":"Prompt exfiltration + OWASP BOLA/API3",
        "requires":   ["prompt", "owasp"],
        "bonus":      20,
    },
    {
        "name":       "Triple Agent Firing",
        "description":"Any 3 agents with HIGH or above",
        "requires":   ["any_3_high"],
        "bonus":      15,
    },
]

MAX_SCORE = 200


def _get_severity(score: int) -> str:
    for threshold, label in SEVERITY_MAP:
        if score >= threshold:
            return label
    return "SAFE"


def _get_action(severity: str) -> str:
    return ACTION_MAP.get(severity, "MONITOR")


def _get_alert(severity: str) -> str:
    return ALERT_MAP.get(severity, "NONE")


# ─────────────────────────────────────────────
# Core Correlation Logic
# ─────────────────────────────────────────────

def _apply_amplification(
    base_score: int,
    active_agents: set,
    agent_severities: dict
) -> tuple[int, list]:
    """
    Check if multiple agents firing together
    warrants a bonus amplification score.
    Returns (bonus_score, triggered_rules).
    """
    bonus       = 0
    triggered   = []

    # Count how many agents are HIGH or above
    high_count = sum(
        1 for agent, sev in agent_severities.items()
        if SEVERITY_VALUE.get(sev, 0) >= SEVERITY_VALUE["HIGH"]
    )

    for rule in AMPLIFICATION_RULES:
        req = rule["requires"]

        if req == ["any_3_high"]:
            if high_count >= 3:
                bonus += rule["bonus"]
                triggered.append(rule["name"])
        else:
            if all(agent in active_agents for agent in req):
                bonus += rule["bonus"]
                triggered.append(rule["name"])

    return bonus, triggered


# ─────────────────────────────────────────────
# Main Engine Class
# ─────────────────────────────────────────────

class RiskCorrelationEngine:

    def __init__(self):
        logger.info(
            "RiskCorrelationEngine initialized | weights=%s",
            AGENT_WEIGHTS
        )

    def correlate(
        self,
        prompt_result: Optional[dict] = None,
        jwt_result:    Optional[dict] = None,
        rbac_result:   Optional[dict] = None,
        api_result:    Optional[dict] = None,
        owasp_result:  Optional[dict] = None,
        user:          str = "unknown",
        endpoint:      str = "unknown",
    ) -> dict:
        """
        Combines all agent results into one
        unified enterprise risk assessment.

        Args:
            prompt_result : output from PromptMonitor / prompt agent
            jwt_result    : output from JWT Security Agent
            rbac_result   : output from RBAC Governance Agent
            api_result    : output from API Security Agent
            owasp_result  : output from OWASP Security Agent
            user          : username for context
            endpoint      : API endpoint for context

        Returns:
            dict: full correlated risk result
        """
        results_map = {
            "prompt" : prompt_result,
            "jwt"    : jwt_result,
            "rbac"   : rbac_result,
            "api"    : api_result,
            "owasp"  : owasp_result,
        }

        components       = {}
        all_reasons      = []
        active_agents    = set()
        agent_severities = {}
        weighted_score   = 0.0

        # ── Step 1: Collect each agent's contribution ──
        for agent_name, result in results_map.items():
            if result is None:
                components[agent_name] = {
                    "risk_score": 0,
                    "severity":   "SAFE",
                    "weight":     AGENT_WEIGHTS[agent_name],
                    "contribution": 0,
                    "active":     False,
                }
                agent_severities[agent_name] = "SAFE"
                continue

            raw_score   = result.get("risk_score", 0)
            severity    = result.get("severity",   "SAFE")
            reasons     = result.get("reasons",    [])
            weight      = AGENT_WEIGHTS[agent_name]
            contribution = raw_score * weight

            weighted_score += contribution
            agent_severities[agent_name] = severity

            if raw_score > 0:
                active_agents.add(agent_name)
                all_reasons.extend(reasons)

            components[agent_name] = {
                "risk_score":   raw_score,
                "severity":     severity,
                "weight":       weight,
                "contribution": round(contribution, 1),
                "active":       raw_score > 0,
            }

        # ── Step 2: Base correlated score (0–200 scale) ──
        base_score = min(int(weighted_score * 2), MAX_SCORE)

        # ── Step 3: Apply amplification bonuses ──
        amplification_bonus, triggered_rules = _apply_amplification(
            base_score, active_agents, agent_severities
        )
        final_score = min(base_score + amplification_bonus, MAX_SCORE)

        # ── Step 4: Determine final severity + action ──
        severity = _get_severity(final_score)
        action   = _get_action(severity)
        alert    = _get_alert(severity)

        # ── Step 5: Top threats (top 3 by raw score) ──
        top_threats = sorted(
            [
                {
                    "agent":      agent,
                    "risk_score": components[agent]["risk_score"],
                    "severity":   components[agent]["severity"],
                }
                for agent in active_agents
            ],
            key=lambda x: x["risk_score"],
            reverse=True
        )[:3]

        result = {
            "risk_score"         : final_score,
            "base_score"         : base_score,
            "amplification_bonus": amplification_bonus,
            "severity"           : severity,
            "action"             : action,
            "alert"              : alert,
            "top_threats"        : top_threats,
            "triggered_rules"    : triggered_rules,
            "components"         : components,
            "reasons"            : all_reasons,
            "active_agents"      : list(active_agents),
            "timestamp"          : datetime.now(timezone.utc).isoformat(),
            "user"               : user,
            "endpoint"           : endpoint,
        }

        logger.info(
            "CORRELATION | user=%-15s | endpoint=%-25s | "
            "base=%3d | bonus=%2d | final=%3d | %s | %s | alert=%s",
            user, endpoint,
            base_score, amplification_bonus, final_score,
            severity, action, alert
        )

        return result

    def correlate_from_request(self, request: dict) -> dict:
        """
        Convenience method: run all agents inline
        and correlate in one call.

        Args:
            request (dict): full request context with all fields
                needed by each agent.

        Uses lazy imports to avoid circular deps.
        """
        from modules.prompt_monitor       import PromptMonitor
        from modules.rbac_agent           import RBACAgent
        from modules.api_security_agent   import APISecurityAgent
        from modules.owasp_api_agent      import OWASPSecurityAgent

        prompt_result = None
        jwt_result    = None
        rbac_result   = None
        api_result    = None
        owasp_result  = None

        # Prompt agent
        if request.get("prompt"):
            try:
                pm = PromptMonitor()
                prompt_result = pm.analyze(request["prompt"])
            except Exception as e:
                logger.warning("Prompt agent error: %s", e)

        # RBAC agent
        try:
            rbac = RBACAgent()
            rbac_result = rbac.analyze({
                "user":     request.get("user", "unknown"),
                "role":     request.get("role", "guest"),
                "endpoint": request.get("endpoint", "/"),
                "method":   request.get("method", "GET"),
                "hour":     request.get("hour", 10),
            })
        except Exception as e:
            logger.warning("RBAC agent error: %s", e)

        # API Security agent
        try:
            api = APISecurityAgent()
            api_result = api.analyze(request)
        except Exception as e:
            logger.warning("API agent error: %s", e)

        # OWASP agent
        try:
            owasp = OWASPSecurityAgent()
            owasp_result = owasp.analyze(request)
        except Exception as e:
            logger.warning("OWASP agent error: %s", e)

        return self.correlate(
            prompt_result = prompt_result,
            jwt_result    = jwt_result,
            rbac_result   = rbac_result,
            api_result    = api_result,
            owasp_result  = owasp_result,
            user          = request.get("user", "unknown"),
            endpoint      = request.get("endpoint", "unknown"),
        )


# ─────────────────────────────────────────────
# Self-Test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    engine = RiskCorrelationEngine()

    print("\n" + "="*65)
    print("  Risk Correlation Engine — Self Test")
    print("="*65)

    # Case 1: Full attack chain
    result = engine.correlate(
        prompt_result = {"risk_score": 90, "severity": "CRITICAL",
                         "reasons": ["Prompt injection detected"]},
        jwt_result    = {"risk_score": 60, "severity": "MEDIUM",
                         "reasons": ["JWT replay attempt"]},
        rbac_result   = {"risk_score": 80, "severity": "HIGH",
                         "reasons": ["RBAC violation: intern on /admin"]},
        api_result    = {"risk_score": 50, "severity": "MEDIUM",
                         "reasons": ["Rate limit warning"]},
        owasp_result  = {"risk_score": 75, "severity": "HIGH",
                         "reasons": ["BOLA: accessing other user record"]},
        user="emp_101", endpoint="/api/admin/users"
    )
    print(f"\n  Case 1 — Full Attack Chain")
    print(f"  risk_score={result['risk_score']}  severity={result['severity']}")
    print(f"  action={result['action']}  alert={result['alert']}")
    print(f"  triggered_rules={result['triggered_rules']}")
    print(f"  top_threats={[t['agent']+':'+str(t['risk_score']) for t in result['top_threats']]}")

    # Case 2: Clean request
    result2 = engine.correlate(
        prompt_result = {"risk_score": 0,  "severity": "SAFE", "reasons": []},
        jwt_result    = {"risk_score": 0,  "severity": "SAFE", "reasons": []},
        rbac_result   = {"risk_score": 0,  "severity": "SAFE", "reasons": []},
        api_result    = {"risk_score": 0,  "severity": "SAFE", "reasons": []},
        owasp_result  = {"risk_score": 0,  "severity": "SAFE", "reasons": []},
        user="admin_1", endpoint="/api/reports"
    )
    print(f"\n  Case 2 — Clean Request")
    print(f"  risk_score={result2['risk_score']}  severity={result2['severity']}")
    print(f"  action={result2['action']}  alert={result2['alert']}")

    # Case 3: JWT + RBAC only
    result3 = engine.correlate(
        jwt_result  = {"risk_score": 70, "severity": "MEDIUM",
                       "reasons": ["Expired JWT token"]},
        rbac_result = {"risk_score": 80, "severity": "HIGH",
                       "reasons": ["RBAC: employee on /api/admin"]},
        user="emp_202", endpoint="/api/admin/config"
    )
    print(f"\n  Case 3 — JWT + RBAC (Auth Bypass)")
    print(f"  risk_score={result3['risk_score']}  severity={result3['severity']}")
    print(f"  action={result3['action']}  alert={result3['alert']}")
    print(f"  triggered_rules={result3['triggered_rules']}")