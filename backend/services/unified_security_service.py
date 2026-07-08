"""
Unified Security Service
AI Governance Platform
-----------------------
Business logic layer for Unified Security Agent.
"""

import logging
from datetime import datetime, timezone

from modules.unified_security_agent import UnifiedSecurityAgent

from schemas.unified_security_schema import (
    UnifiedSecurityRequest,
    UnifiedSecurityResponse,
    AgentResult,
)

logger = logging.getLogger("UnifiedSecurityService")

_agent = UnifiedSecurityAgent()


def run_unified_security(
    request: UnifiedSecurityRequest
) -> UnifiedSecurityResponse:
    """
    Execute unified security analysis.
    """

    logger.info(
        "Unified Security Request | user=%s | endpoint=%s",
        request.user,
        request.endpoint,
    )

    result = _agent.analyze(
        {
            "user": request.user,
            "endpoint": request.endpoint,

            "prompt_result":
                request.prompt_result.model_dump()
                if request.prompt_result else None,

            "jwt_result":
                request.jwt_result.model_dump()
                if request.jwt_result else None,

            "rbac_result":
                request.rbac_result.model_dump()
                if request.rbac_result else None,

            "api_result":
                request.api_result.model_dump()
                if request.api_result else None,

            "owasp_result":
                request.owasp_result.model_dump()
                if request.owasp_result else None,
        }
    )

    correlation = result["correlation"]

    return UnifiedSecurityResponse(

        user=request.user,
        endpoint=request.endpoint,

        prompt_result=request.prompt_result,
        jwt_result=request.jwt_result,
        rbac_result=request.rbac_result,
        api_result=request.api_result,
        owasp_result=request.owasp_result,

        correlation=correlation,

        overall_score=correlation["risk_score"],
        overall_severity=correlation["severity"],
        overall_action=correlation["action"],

        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),
    )


def get_health() -> dict:
    """
    Health endpoint.
    """

    return {
        "status": "ok",
        "service": "UnifiedSecurityService",
        "version": "1.0.0",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }