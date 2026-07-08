"""
Correlation Service
AI Governance Platform
-----------------------
Business logic layer:
  - Converts Pydantic models to dicts
  - Calls RiskCorrelationEngine
  - Triggers SOC alert if CRITICAL
  - Returns CorrelationResponse
"""

import logging
from datetime import datetime, timezone

from modules.correlation_agent  import RiskCorrelationEngine
from schemas.correlation_schema import (
    CorrelationRequest,
    CorrelationResponse,
    ComponentDetail,
    TopThreat,
)

logger  = logging.getLogger("CorrelationService")
_engine = RiskCorrelationEngine()


def run_correlation(request: CorrelationRequest) -> CorrelationResponse:
    """
    Main service function.
    Converts request → dicts → engine → typed response.
    """
    logger.info(
        "Correlation request | user=%s | endpoint=%s",
        request.user, request.endpoint
    )

    def _to_dict(agent_result) -> dict | None:
        if agent_result is None:
            return None
        return {
            "risk_score": agent_result.risk_score,
            "severity":   agent_result.severity,
            "reasons":    agent_result.reasons,
        }

    result = _engine.correlate(
        prompt_result = _to_dict(request.prompt_result),
        jwt_result    = _to_dict(request.jwt_result),
        rbac_result   = _to_dict(request.rbac_result),
        api_result    = _to_dict(request.api_result),
        owasp_result  = _to_dict(request.owasp_result),
        user          = request.user,
        endpoint      = request.endpoint,
    )

    # SOC alert
    if result["severity"] == "CRITICAL":
        _trigger_soc_alert(result)
    elif result["severity"] == "HIGH":
        _trigger_security_alert(result)

    # Build typed response
    components = {
        name: ComponentDetail(**details)
        for name, details in result["components"].items()
    }

    top_threats = [TopThreat(**t) for t in result["top_threats"]]

    return CorrelationResponse(
        risk_score          = result["risk_score"],
        base_score          = result["base_score"],
        amplification_bonus = result["amplification_bonus"],
        severity            = result["severity"],
        action              = result["action"],
        alert               = result["alert"],
        top_threats         = top_threats,
        triggered_rules     = result["triggered_rules"],
        components          = components,
        reasons             = result["reasons"],
        active_agents       = result["active_agents"],
        timestamp           = result["timestamp"],
        user                = result["user"],
        endpoint            = result["endpoint"],
    )


def _trigger_soc_alert(result: dict) -> None:
    logger.critical(
        "🚨 SOC ALERT | user=%s | endpoint=%s | score=%d | threats=%s | reasons=%s",
        result["user"], result["endpoint"],
        result["risk_score"],
        result["top_threats"],
        result["reasons"][:3],
    )
    # TODO: wire to notification_service.py → Slack / email / PagerDuty


def _trigger_security_alert(result: dict) -> None:
    logger.warning(
        "⚠️  SECURITY ALERT | user=%s | endpoint=%s | score=%d",
        result["user"], result["endpoint"], result["risk_score"]
    )
    # TODO: wire to notification_service.py


def get_health() -> dict:
    return {
        "status":    "ok",
        "engine":    "RiskCorrelationEngine",
        "version":   "1.0.0",
        "agents":    ["prompt", "jwt", "rbac", "api", "owasp"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }