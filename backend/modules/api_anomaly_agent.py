"""
modules/api_anomaly_agent.py
Enterprise API Anomaly Detection — Rule-Based Phase 1
Each detect_* function returns an AnomalyFlag or None.
"""

from datetime import datetime
from typing import Optional

from schemas.api_anomaly_schema import (
    APIRequestSnapshot,
    UserBaseline,
    AnomalyFlag,
    AnomalyType,
)


# ─────────────────────────────────────────────────────────────
# 1. Request Spike Detection
# ─────────────────────────────────────────────────────────────

def detect_request_spike(
    snapshot: APIRequestSnapshot,
    baseline: UserBaseline,
    current_rpm: float,
) -> Optional[AnomalyFlag]:
    """
    Compare current requests-per-minute against user baseline.
    Spike thresholds:
      ≥ 10× baseline  → score 90  (brute-force / DDoS)
      ≥  5× baseline  → score 60
      ≥  3× baseline  → score 30
    """
    ratio = current_rpm / max(baseline.avg_requests_per_min, 1)

    if ratio >= 10:
        score, label = 90, "Extreme spike (≥10×)"
    elif ratio >= 5:
        score, label = 60, "High spike (≥5×)"
    elif ratio >= 3:
        score, label = 30, "Moderate spike (≥3×)"
    else:
        return None

    return AnomalyFlag(
        anomaly_type=AnomalyType.REQUEST_SPIKE,
        score=score,
        description=f"{label} – {current_rpm:.0f} req/min vs baseline {baseline.avg_requests_per_min:.0f}",
        evidence={
            "current_rpm":  current_rpm,
            "baseline_rpm": baseline.avg_requests_per_min,
            "ratio":        round(ratio, 2),
        },
    )


# ─────────────────────────────────────────────────────────────
# 2. New / Unauthorized Endpoint Access
# ─────────────────────────────────────────────────────────────

def detect_new_endpoint(
    snapshot: APIRequestSnapshot,
    baseline: UserBaseline,
) -> Optional[AnomalyFlag]:
    """
    Flags access to endpoints not in the user's known history.
    Admin/export/sensitive paths carry extra weight.
    """
    endpoint = snapshot.endpoint.lower()

    if endpoint in [ep.lower() for ep in baseline.known_endpoints]:
        return None

    # Sensitive path heuristic
    sensitive_keywords = [
        "/admin", "/export", "/delete", "/purge",
        "/config", "/internal", "/debug", "/backup",
        "/superuser", "/root",
    ]
    is_sensitive = any(kw in endpoint for kw in sensitive_keywords)
    score = 70 if is_sensitive else 40

    return AnomalyFlag(
        anomaly_type=AnomalyType.NEW_ENDPOINT,
        score=score,
        description=f"{'Sensitive' if is_sensitive else 'Unknown'} endpoint never accessed by this user",
        evidence={
            "endpoint":      snapshot.endpoint,
            "is_sensitive":  is_sensitive,
            "known_count":   len(baseline.known_endpoints),
        },
    )


# ─────────────────────────────────────────────────────────────
# 3. Geo / Impossible Travel Anomaly
# ─────────────────────────────────────────────────────────────

def detect_geo_anomaly(
    snapshot: APIRequestSnapshot,
    baseline: UserBaseline,
) -> Optional[AnomalyFlag]:
    """
    Compares current country against user's home country.
    High-risk country list amplifies the score.
    """
    if not baseline.home_country or not snapshot.country:
        return None

    if snapshot.country == baseline.home_country:
        return None

    HIGH_RISK_COUNTRIES = {
        "RU", "KP", "IR", "BY", "SY", "CU", "SD", "VE",
    }
    is_high_risk = snapshot.country in HIGH_RISK_COUNTRIES
    score = 80 if is_high_risk else 50

    return AnomalyFlag(
        anomaly_type=AnomalyType.GEO_ANOMALY,
        score=score,
        description=f"Impossible travel detected – login from {snapshot.country}, baseline {baseline.home_country}",
        evidence={
            "current_country":  snapshot.country,
            "home_country":     baseline.home_country,
            "high_risk_origin": is_high_risk,
        },
    )


# ─────────────────────────────────────────────────────────────
# 4. HTTP Method Anomaly
# ─────────────────────────────────────────────────────────────

def detect_method_anomaly(
    snapshot: APIRequestSnapshot,
    baseline: UserBaseline,
) -> Optional[AnomalyFlag]:
    """
    Flags HTTP methods outside the user's normal repertoire.
    Destructive methods (DELETE, PATCH, PUT) score higher.
    """
    method = snapshot.method.upper()

    if method in [m.upper() for m in baseline.known_methods]:
        return None

    DESTRUCTIVE = {"DELETE", "PATCH", "PUT"}
    is_destructive = method in DESTRUCTIVE
    score = 60 if is_destructive else 30

    return AnomalyFlag(
        anomaly_type=AnomalyType.METHOD_ANOMALY,
        score=score,
        description=f"{'Destructive' if is_destructive else 'Unusual'} HTTP method {method} outside user baseline",
        evidence={
            "method":         method,
            "known_methods":  baseline.known_methods,
            "is_destructive": is_destructive,
        },
    )


# ─────────────────────────────────────────────────────────────
# 5. Payload Size Anomaly
# ─────────────────────────────────────────────────────────────

def detect_payload_anomaly(
    snapshot: APIRequestSnapshot,
    baseline: UserBaseline,
) -> Optional[AnomalyFlag]:
    """
    Detects abnormally large payloads (data exfiltration / injection).
    Thresholds:
      ≥ 100× baseline → score 80
      ≥  20× baseline → score 50
      ≥   5× baseline → score 25
    """
    ratio = snapshot.payload_size / max(baseline.avg_payload_size, 1)

    if ratio >= 100:
        score, label = 80, "Extreme payload (≥100×)"
    elif ratio >= 20:
        score, label = 50, "Large payload (≥20×)"
    elif ratio >= 5:
        score, label = 25, "Elevated payload (≥5×)"
    else:
        return None

    size_kb = snapshot.payload_size / 1024
    baseline_kb = baseline.avg_payload_size / 1024

    return AnomalyFlag(
        anomaly_type=AnomalyType.PAYLOAD_ANOMALY,
        score=score,
        description=f"{label} – {size_kb:.1f} KB vs baseline {baseline_kb:.1f} KB",
        evidence={
            "payload_bytes":  snapshot.payload_size,
            "baseline_bytes": baseline.avg_payload_size,
            "ratio":          round(ratio, 2),
        },
    )


# ─────────────────────────────────────────────────────────────
# 6. Time-Based Behavioral Anomaly
# ─────────────────────────────────────────────────────────────

def detect_time_anomaly(
    snapshot: APIRequestSnapshot,
    baseline: UserBaseline,
) -> Optional[AnomalyFlag]:
    """
    Detects access outside the user's normal active hours.
    Deep-night access (0–5 AM) scores higher.
    """
    hour = snapshot.timestamp.hour

    if hour in baseline.active_hours:
        return None

    DEEP_NIGHT = set(range(0, 5))  # midnight to 5 AM
    is_deep_night = hour in DEEP_NIGHT
    score = 50 if is_deep_night else 25

    return AnomalyFlag(
        anomaly_type=AnomalyType.TIME_ANOMALY,
        score=score,
        description=f"{'Deep-night' if is_deep_night else 'Off-hours'} access at {hour:02d}:00 UTC",
        evidence={
            "access_hour":   hour,
            "active_hours":  baseline.active_hours,
            "is_deep_night": is_deep_night,
        },
    )


# ─────────────────────────────────────────────────────────────
# 7. User Behavior Change (Composite)
# ─────────────────────────────────────────────────────────────

def detect_user_behavior_change(
    active_flags: int,
    total_score: int,
) -> Optional[AnomalyFlag]:
    """
    Composite behavior detector.

    Fires when multiple anomaly signals
    occur simultaneously.
    """

    if active_flags < 3:
        return None

    score = 40

    if total_score >= 150:
        score = 70

    elif total_score >= 100:
        score = 55

    return AnomalyFlag(
        anomaly_type=AnomalyType.USER_BEHAVIOR_CHANGE,
        score=score,
        description=(
            f"Composite behavioral shift "
            f"({active_flags} concurrent anomalies)"
        ),
        evidence={
            "concurrent_anomalies": active_flags,
            "aggregate_score": total_score,
        },
    )