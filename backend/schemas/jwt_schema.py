from pydantic import BaseModel, Field
from typing import List


class JWTSecurityRequest(BaseModel):
    token: str = Field(...)


class JWTSecurityResponse(BaseModel):
    valid: bool
    risk_score: int
    severity: str
    action: str
    reasons: List[str]