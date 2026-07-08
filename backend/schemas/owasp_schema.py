"""
OWASP Schema
AI Governance Platform
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Union


class OWASPRequest(BaseModel):
    user:           str            = Field(..., example="employee_1")
    user_id:        Optional[str]  = Field(default=None,  example="101")
    role:           str            = Field(..., example="employee")
    endpoint:       str            = Field(..., example="/api/users/999")
    method:         str            = Field(..., example="GET")
    auth_token:     Optional[str]  = Field(default=None,  example="Bearer xyz")
    token_expired:  Optional[bool] = Field(default=False)
    request_count:  Optional[int]  = Field(default=1, ge=0)
    payload_size:   Optional[int]  = Field(default=0, ge=0)
    body_fields:    Optional[Union[List[str], str]] = Field(default=[])
    body:           Optional[str]  = Field(default="")
    params:         Optional[str]  = Field(default="")
    headers:        Optional[str]  = Field(default="")
    login_attempts: Optional[int]  = Field(default=0, ge=0)
    url:            Optional[str]  = Field(default="")

    class Config:
        json_schema_extra = {
            "example": {
                "user": "employee_1", "user_id": "101",
                "role": "employee", "endpoint": "/api/users/999",
                "method": "GET", "auth_token": "Bearer tok",
            }
        }


class OWASPResponse(BaseModel):
    risk_score:      int        = Field(..., example=80)
    severity:        str        = Field(..., example="HIGH")
    action:          str        = Field(..., example="BLOCK")
    owasp_findings:  List[str]  = Field(default=[], example=["API1", "API7"])
    reasons:         List[str]  = Field(default=[])
    timestamp:       str        = Field(..., example="2024-01-15T10:30:00+00:00")
    user:            str        = Field(..., example="employee_1")
    endpoint:        str        = Field(..., example="/api/users/999")