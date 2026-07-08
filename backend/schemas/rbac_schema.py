from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List

class RBACRequest(BaseModel):
    user: str = Field(..., examples=["employee_1"])
    role: str = Field(..., examples=["employee"])
    endpoint: str = Field(..., examples="/api/tasks")
    method: str = Field(..., examples=["GET"])
    requested_role: Optional[str] = Field(default=None, examples=["admin"])
    hour: Optional[int] = Field(default=None, ge=0, le=23, examples=[14])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user": "employee_1",
                "role": "employee",
                "endpoint": "/api/tasks",
                "method": "GET"
            }
        }
    )

class RBACResponse(BaseModel):
    authorized: bool = Field(..., examples=[False])
    risk_score: int = Field(..., examples=[80])
    severity: str = Field(..., examples=["CRITICAL"])
    action: str = Field(..., examples=["BLOCK"])
    reasons: List[str] = Field(default_factory=list)
    timestamp: str = Field(..., examples=["2026-06-06T10:30:00+00:00"])
    user: str = Field(..., examples=["employee_1"])
    role: str = Field(..., examples=["employee"])
    endpoint: str = Field(..., examples=["/api/admin/users"])

class RBACQuickCheckRequest(BaseModel):
    user: str = Field(..., examples=["employee_1"])
    role: str = Field(..., examples=["employee"])
    endpoint: str = Field(..., examples=["/api/tasks"])
    method: str = Field(..., examples=["GET"])

class RBACQuickCheckResponse(BaseModel):
    authorized: bool = Field(..., examples=[True])
    user: str = Field(..., examples=["employee_1"])
    role: str = Field(..., examples=["employee"])
    endpoint: str = Field(..., examples=["/api/tasks"])