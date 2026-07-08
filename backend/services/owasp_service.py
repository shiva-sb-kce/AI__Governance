"""
OWASP Service
AI Governance Platform
"""
import logging
from datetime import datetime, timezone

from modules.owasp_api_agent import OWASPSecurityAgent
from schemas.owasp_schema    import OWASPRequest, OWASPResponse

logger = logging.getLogger("OWASPService")
_agent = OWASPSecurityAgent()


def analyze_owasp(request: OWASPRequest) -> OWASPResponse:
    logger.info("OWASP check | user=%s | %s %s", request.user, request.method, request.endpoint)

    req_dict = {
        "user":           request.user,
        "user_id":        request.user_id or "",
        "role":           request.role,
        "endpoint":       request.endpoint,
        "method":         request.method,
        "auth_token":     request.auth_token or "",
        "token_expired":  request.token_expired or False,
        "request_count":  request.request_count or 1,
        "payload_size":   request.payload_size  or 0,
        "body_fields":    request.body_fields   or [],
        "body":           request.body          or "",
        "params":         request.params        or "",
        "headers":        request.headers       or "",
        "login_attempts": request.login_attempts or 0,
        "url":            request.url           or "",
    }

    result = _agent.analyze(req_dict)

    if result["severity"] in ("HIGH", "CRITICAL"):
        logger.warning(
            "OWASP ALERT | severity=%s | user=%s | findings=%s",
            result["severity"], result["user"], result["owasp_findings"]
        )

    return OWASPResponse(
        risk_score     = result["risk_score"],
        severity       = result["severity"],
        action         = result["action"],
        owasp_findings = result["owasp_findings"],
        reasons        = result["reasons"],
        timestamp      = result["timestamp"],
        user           = result["user"],
        endpoint       = result["endpoint"],
    )


def get_health() -> dict:
    return {
        "status":    "ok",
        "agent":     "OWASPSecurityAgent",
        "version":   "1.0.0",
        "coverage":  "API1–API10",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }