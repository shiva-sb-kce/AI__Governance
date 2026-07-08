"""
Correlation Schema
AI Governance Platform
-----------------------
Pydantic models for Risk Correlation Engine.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


# ─────────────────────────────────────────────
# Sub-models
# ─────────────────────────────────────────────

class AgentResult(BaseModel):
    """Single agent's result — passed into the correlation engine."""
    risk_score: int       = Field(default=0,      ge=0, example=80)
    severity:   str       = Field(default="SAFE",        example="HIGH")
    reasons:    List[str] = Field(default=[])
    action:     Optional[str] = Field(default=None)


class ComponentDetail(BaseModel):
    """Per-agent breakdown in the response."""
    risk_score:   int   = Field(..., example=80)
    severity:     str   = Field(..., example="HIGH")
    weight:       float = Field(..., example=0.20)
    contribution: float = Field(..., example=16.0)
    active:       bool  = Field(..., example=True)


class TopThreat(BaseModel):
    agent:      str = Field(..., example="rbac")
    risk_score: int = Field(..., example=80)
    severity:   str = Field(..., example="HIGH")


# ─────────────────────────────────────────────
# REQUEST
# ─────────────────────────────────────────────

class CorrelationRequest(BaseModel):
    """
    Full correlation request — pass in each agent's result.
    Any agent not provided is treated as SAFE (score=0).
    """
    user:     str = Field(..., example="employee_1")
    endpoint: str = Field(..., example="/api/admin/users")

    prompt_result: Optional[AgentResult] = Field(default=None)
    jwt_result:    Optional[AgentResult] = Field(default=None)
    rbac_result:   Optional[AgentResult] = Field(default=None)
    api_result:    Optional[AgentResult] = Field(default=None)
    owasp_result:  Optional[AgentResult] = Field(default=None)

    class Config:
        json_schema_extra = {
            "example": {
                "user":     "emp_101",
                "endpoint": "/api/admin/users",
                "prompt_result": {"risk_score": 90, "severity": "CRITICAL",
                                  "reasons": ["Prompt injection detected"]},
                "rbac_result":   {"risk_score": 80, "severity": "HIGH",
                                  "reasons": ["RBAC violation"]},
                "owasp_result":  {"risk_score": 75, "severity": "HIGH",
                                  "reasons": ["BOLA detected"]},
            }
        }


# ─────────────────────────────────────────────
# RESPONSE
# ─────────────────────────────────────────────

class CorrelationResponse(BaseModel):
    """Full correlated enterprise risk result."""
    risk_score:          int                        = Field(..., example=185)
    base_score:          int                        = Field(..., example=155)
    amplification_bonus: int                        = Field(..., example=30)
    severity:            str                        = Field(..., example="CRITICAL")
    action:              str                        = Field(..., example="BLOCK")
    alert:               str                        = Field(..., example="SOC_ALERT")
    top_threats:         List[TopThreat]            = Field(default=[])
    triggered_rules:     List[str]                  = Field(default=[])
    components:          Dict[str, ComponentDetail] = Field(default={})
    reasons:             List[str]                  = Field(default=[])
    active_agents:       List[str]                  = Field(default=[])
    timestamp:           str                        = Field(..., example="2024-01-15T10:30:00+00:00")
    user:                str                        = Field(..., example="emp_101")
    endpoint:            str                        = Field(..., example="/api/admin/users")