"""
Unified Security Agent
AI Governance Platform
-----------------------
Master Orchestrator

Combines:
- Prompt Agent
- JWT Agent
- RBAC Agent
- API Security Agent
- OWASP Agent
- Risk Correlation Engine
"""

import logging

from modules.rbac_agent import RBACAgent
from modules.api_security_agent import APISecurityAgent
from modules.owasp_api_agent import OWASPSecurityAgent
from modules.correlation_agent import RiskCorrelationEngine

logger = logging.getLogger("UnifiedSecurityAgent")


class UnifiedSecurityAgent:

    def __init__(self):

        self.rbac_agent   = RBACAgent()
        self.api_agent    = APISecurityAgent()
        self.owasp_agent  = OWASPSecurityAgent()

        self.correlation_engine = RiskCorrelationEngine()

        logger.info(
            "UnifiedSecurityAgent initialized successfully."
        )

    def analyze(self, request: dict) -> dict:

        prompt_result = request.get("prompt_result")
        jwt_result    = request.get("jwt_result")
        rbac_result   = request.get("rbac_result")
        api_result    = request.get("api_result")
        owasp_result  = request.get("owasp_result")

        correlation = self.correlation_engine.correlate(
            prompt_result=prompt_result,
            jwt_result=jwt_result,
            rbac_result=rbac_result,
            api_result=api_result,
            owasp_result=owasp_result,
            user=request.get("user", "unknown"),
            endpoint=request.get("endpoint", "unknown"),
        )

        return {
            "prompt_result": prompt_result,
            "jwt_result": jwt_result,
            "rbac_result": rbac_result,
            "api_result": api_result,
            "owasp_result": owasp_result,
            "correlation": correlation,
        }