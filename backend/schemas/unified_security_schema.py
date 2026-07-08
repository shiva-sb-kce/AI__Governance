"""
Unified Security Schema
AI Governance Platform
-----------------------
Request/Response models for Unified Security Agent.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


# ============================================================
# Generic Agent Result
# ============================================================

class AgentResult(BaseModel):
    risk_score: int = Field(default=0, ge=0, example=80)
    severity: str = Field(default="SAFE", example="HIGH")
    reasons: List[str] = Field(default_factory=list)
    action: Optional[str] = None


# ============================================================
# Request
# ============================================================

class UnifiedSecurityRequest(BaseModel):
    """
    Master request passed to Unified Security Agent.
    """

    user: str = Field(..., example="emp_101")
    endpoint: str = Field(..., example="/api/admin/users")

    prompt_result: Optional[AgentResult] = None
    jwt_result: Optional[AgentResult] = None
    rbac_result: Optional[AgentResult] = None
    api_result: Optional[AgentResult] = None
    owasp_result: Optional[AgentResult] = None

    class Config:
        json_schema_extra = {
            "example": {
                "user": "emp_101",
                "endpoint": "/api/admin/users",

                "prompt_result": {
                    "risk_score": 90,
                    "severity": "CRITICAL",
                    "reasons": ["Prompt Injection"]
                },

                "jwt_result": {
                    "risk_score": 70,
                    "severity": "HIGH",
                    "reasons": ["JWT Replay Attack"]
                },

                "rbac_result": {
                    "risk_score": 80,
                    "severity": "HIGH",
                    "reasons": ["RBAC Violation"]
                },

                "api_result": {
                    "risk_score": 60,
                    "severity": "MEDIUM",
                    "reasons": ["API Abuse"]
                },

                "owasp_result": {
                    "risk_score": 75,
                    "severity": "HIGH",
                    "reasons": ["BOLA Attack"]
                }
            }
        }


# ============================================================
# Response
# ============================================================

class UnifiedSecurityResponse(BaseModel):

    user: str
    endpoint: str

    prompt_result: Optional[AgentResult] = None
    jwt_result: Optional[AgentResult] = None
    rbac_result: Optional[AgentResult] = None
    api_result: Optional[AgentResult] = None
    owasp_result: Optional[AgentResult] = None

    correlation: Dict[str, Any]

    overall_score: int
    overall_severity: str
    overall_action: str

    timestamp: str

    class Config:
        json_schema_extra = {
            "example": {
                "user": "emp_101",
                "endpoint": "/api/admin/users",

                "overall_score": 185,
                "overall_severity": "CRITICAL",
                "overall_action": "BLOCK",

                "timestamp": "2026-06-07T12:00:00Z"
            }
        }