from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List

# ─────────────────────────────────────────────
# REQUEST MODEL
# ─────────────────────────────────────────────

class APISecurityRequest(BaseModel):
    """
    Incoming API call metadata to be analyzed.
    All fields are validated automatically by FastAPI.
    """
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user": "employee_1",
                "role": "employee",
                "endpoint": "/api/admin/users",
                "method": "GET",
                "request_count": 10,
                "auth_token": "Bearer abc123",
                "response_size": 2048,
                "params": ""
            }
        }
    )

    user: str = Field(
        description="Username or user ID making the API call",
        examples=["employee_1"]
    )

    role: str = Field(
        description="Role of the user (admin, manager, employee, intern)",
        examples=["employee"]
    )

    endpoint: str = Field(
        description="The API endpoint being accessed",
        examples=["/api/admin/users"]
    )

    method: str = Field(
        description="HTTP method (GET, POST, PUT, DELETE, PATCH)",
        examples=["GET"]
    )

    request_count: int = Field(
        default=1,
        ge=0,
        description="Number of requests made in current time window",
        examples=[10]
    )

    auth_token: Optional[str] = Field(
        default=None,
        description="Authorization token (Bearer token or session token)",
        examples=["Bearer eyJhbGciOiJIUzI1NiJ9..."]
    )

    response_size: Optional[int] = Field(
        default=0,
        ge=0,
        description="Size of the API response in bytes",
        examples=[5000]
    )

    params: Optional[str] = Field(
        default="",
        description="Query parameters or request body as string (for injection detection)",
        examples=["id=1&filter=active"]
    )


# ─────────────────────────────────────────────
# RESPONSE MODEL
# ─────────────────────────────────────────────

class APISecurityResponse(BaseModel):
    """
    Output from the API Security Agent after analysis.
    """
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "risk_score": 110,
                "severity": "CRITICAL",
                "action": "BLOCK",
                "reasons": ["Unauthorized Admin Access", "API Abuse Detected"],
                "timestamp": "2026-06-06T10:30:00+00:00",
                "user": "employee_1",
                "endpoint": "/api/admin/users"
            }
        }
    )

    risk_score: int = Field(
        ge=0,
        le=200,
        description="Cumulative risk score (0 = safe, 200 = max critical)",
        examples=[110]
    )

    severity: str = Field(
        description="Severity level: SAFE | LOW | MEDIUM | HIGH | CRITICAL",
        examples=["CRITICAL"]
    )

    action: str = Field(
        description="Recommended action: ALLOW | MONITOR | FLAG | BLOCK",
        examples=["BLOCK"]
    )

    reasons: List[str] = Field(
        default_factory=list,
        description="List of detected threats/violations",
        examples=[["Unauthorized Admin Access", "API Abuse Detected"]]
    )

    timestamp: datetime = Field(
        description="UTC timestamp of the analysis",
        examples=["2026-06-06T10:30:00+00:00"]
    )

    user: str = Field(
        description="User who made the request",
        examples=["employee_1"]
    )

    endpoint: str = Field(
        description="Endpoint that was accessed",
        examples=["/api/admin/users"]
    )


# ─────────────────────────────────────────────
# HEALTH CHECK RESPONSE
# ─────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = Field(default="ok")
    agent:  str = Field(default="APISecurityAgent")
    version: str = Field(default="1.0.0")