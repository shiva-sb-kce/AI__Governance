"""
schemas/api_anomaly_schema.py

Enterprise API Anomaly Detection - Data Models
Production Ready Version
"""

from pydantic import (
    BaseModel,
    Field,
    IPvAnyAddress,
    ConfigDict
)
from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from datetime import datetime, timezone


# ──────────────────────────────────────────
# Enums
# ──────────────────────────────────────────

class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyType(str, Enum):
    REQUEST_SPIKE = "REQUEST_SPIKE"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    GEO_ANOMALY = "GEO_ANOMALY"
    METHOD_ANOMALY = "METHOD_ANOMALY"
    PAYLOAD_ANOMALY = "PAYLOAD_ANOMALY"
    TIME_ANOMALY = "TIME_ANOMALY"
    USER_BEHAVIOR_CHANGE = "USER_BEHAVIOR_CHANGE"


# ──────────────────────────────────────────
# Incoming Request Snapshot
# ──────────────────────────────────────────

class APIRequestSnapshot(BaseModel):
    """
    Single API call captured for anomaly analysis.
    """

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    user_id: str = Field(
        ...,
        json_schema_extra={"example": "user_101"}
    )

    endpoint: str = Field(
        ...,
        json_schema_extra={"example": "/admin/export"}
    )

    method: Literal[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
        "HEAD"
    ] = Field(
        ...,
        json_schema_extra={"example": "DELETE"}
    )

    ip_address: IPvAnyAddress = Field(
        ...,
        json_schema_extra={"example": "195.12.34.56"}
    )

    country: Optional[str] = Field(
        None,
        json_schema_extra={"example": "RU"}
    )

    payload_size: int = Field(
        ...,
        ge=0,
        description="Payload size in bytes",
        json_schema_extra={"example": 5242880}
    )

    response_time: float = Field(
        ...,
        ge=0,
        description="Response time in milliseconds",
        json_schema_extra={"example": 230.5}
    )

    status_code: int = Field(
        ...,
        ge=100,
        le=599,
        json_schema_extra={"example": 200}
    )

    headers: Optional[Dict[str, str]] = None

    extra: Optional[Dict[str, Any]] = None


# ──────────────────────────────────────────
# Per-Check Result
# ──────────────────────────────────────────

class AnomalyFlag(BaseModel):

    anomaly_type: AnomalyType

    score: int = Field(
        ...,
        ge=0,
        description="Contribution to total anomaly score"
    )

    description: str

    evidence: Dict[str, Any] = Field(
        default_factory=dict
    )


# ──────────────────────────────────────────
# Baseline Profile (stored per user)
# ──────────────────────────────────────────

class UserBaseline(BaseModel):

    user_id: str

    avg_requests_per_min: float = Field(
        default=20.0,
        ge=0
    )

    known_endpoints: List[str] = Field(
        default_factory=list
    )

    known_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST"]
    )

    home_country: Optional[str] = None

    avg_payload_size: float = Field(
        default=2048.0,
        ge=0
    )

    active_hours: List[int] = Field(
        default_factory=lambda: list(range(9, 19))
    )

    last_updated: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ──────────────────────────────────────────
# Analysis Result
# ──────────────────────────────────────────

class AnomalyAnalysisResult(BaseModel):

    model_config = ConfigDict(
        use_enum_values=True
    )

    request_id: str

    user_id: str

    timestamp: datetime

    total_score: int = Field(
        ...,
        ge=0
    )

    risk_level: RiskLevel

    flags: List[AnomalyFlag]

    recommendation: str

    blocked: bool = False


# ──────────────────────────────────────────
# Risk Score Mapping
# ──────────────────────────────────────────

def score_to_risk(score: int) -> RiskLevel:

    if score <= 20:
        return RiskLevel.SAFE

    if score <= 50:
        return RiskLevel.LOW

    if score <= 80:
        return RiskLevel.MEDIUM

    if score <= 120:
        return RiskLevel.HIGH

    return RiskLevel.CRITICAL


# ──────────────────────────────────────────
# Recommendation Generator
# ──────────────────────────────────────────

def risk_recommendation(level: RiskLevel) -> str:

    return {
        RiskLevel.SAFE:
            "Request is within normal parameters. No action required.",

        RiskLevel.LOW:
            "Minor deviation detected. Monitor and log for pattern analysis.",

        RiskLevel.MEDIUM:
            "Suspicious activity detected. Apply rate limiting and alert security team.",

        RiskLevel.HIGH:
            "High-confidence attack vector detected. Block request, revoke session, and escalate immediately.",

        RiskLevel.CRITICAL:
            "CRITICAL THREAT. Immediate IP block, incident response activation, and forensic investigation required."
    }[level]