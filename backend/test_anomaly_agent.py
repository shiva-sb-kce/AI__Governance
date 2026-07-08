"""
test_anomaly_agent.py
Enterprise API Anomaly Detection — Comprehensive Test Suite

Run:  pytest test_anomaly_agent.py -v
"""

import pytest
from datetime import datetime, timezone
import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.dirname(__file__)
    )
)

from schemas.api_anomaly_schema import (
    APIRequestSnapshot,
    UserBaseline,
    RiskLevel,
    AnomalyType,
)
from services.api_anomaly_service import APIAnomalyService
from modules.api_anomaly_agent import (
    detect_request_spike,
    detect_new_endpoint,
    detect_geo_anomaly,
    detect_method_anomaly,
    detect_payload_anomaly,
    detect_time_anomaly,
    detect_user_behavior_change,
)


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def baseline() -> UserBaseline:
    return UserBaseline(
        user_id="user_101",
        avg_requests_per_min=20.0,
        known_endpoints=["/profile", "/tasks", "/dashboard"],
        known_methods=["GET", "POST"],
        home_country="IN",
        avg_payload_size=2048.0,
        active_hours=list(range(9, 19)),
    )


@pytest.fixture
def normal_snapshot() -> APIRequestSnapshot:
    return APIRequestSnapshot(
        user_id="user_101",
        endpoint="/profile",
        method="GET",
        ip_address="103.21.88.10",
        country="IN",
        payload_size=1500,
        response_time=120.0,
        status_code=200,
        timestamp=datetime(2025, 6, 1, 10, 30, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def service() -> APIAnomalyService:
    svc = APIAnomalyService()
    baseline = UserBaseline(
        user_id="user_101",
        avg_requests_per_min=20.0,
        known_endpoints=["/profile", "/tasks", "/dashboard"],
        known_methods=["GET", "POST"],
        home_country="IN",
        avg_payload_size=2048.0,
        active_hours=list(range(9, 19)),
    )
    svc.set_baseline(baseline)
    return svc


# ─────────────────────────────────────────────────────────────
# 1. Request Spike Tests
# ─────────────────────────────────────────────────────────────

class TestRequestSpike:

    def test_no_spike_within_3x(self, normal_snapshot, baseline):
        result = detect_request_spike(normal_snapshot, baseline, current_rpm=50.0)
        assert result is None

    def test_moderate_spike_3x(self, normal_snapshot, baseline):
        result = detect_request_spike(normal_snapshot, baseline, current_rpm=65.0)
        assert result is not None
        assert result.anomaly_type == AnomalyType.REQUEST_SPIKE
        assert result.score == 30

    def test_high_spike_5x(self, normal_snapshot, baseline):
        result = detect_request_spike(normal_snapshot, baseline, current_rpm=110.0)
        assert result is not None
        assert result.score == 60

    def test_extreme_spike_10x(self, normal_snapshot, baseline):
        result = detect_request_spike(normal_snapshot, baseline, current_rpm=500.0)
        assert result is not None
        assert result.score == 90
        assert "10×" in result.description

    def test_evidence_contains_ratio(self, normal_snapshot, baseline):
        result = detect_request_spike(normal_snapshot, baseline, current_rpm=500.0)
        assert "ratio" in result.evidence
        assert result.evidence["ratio"] == 25.0


# ─────────────────────────────────────────────────────────────
# 2. New Endpoint Tests
# ─────────────────────────────────────────────────────────────

class TestNewEndpoint:

    def test_known_endpoint_passes(self, normal_snapshot, baseline):
        result = detect_new_endpoint(normal_snapshot, baseline)
        assert result is None

    def test_unknown_endpoint_flagged(self, normal_snapshot, baseline):
        normal_snapshot.endpoint = "/payments/history"
        result = detect_new_endpoint(normal_snapshot, baseline)
        assert result is not None
        assert result.anomaly_type == AnomalyType.NEW_ENDPOINT
        assert result.score == 40

    def test_sensitive_endpoint_higher_score(self, normal_snapshot, baseline):
        normal_snapshot.endpoint = "/admin/export"
        result = detect_new_endpoint(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 70
        assert result.evidence["is_sensitive"] is True

    def test_admin_config_is_sensitive(self, normal_snapshot, baseline):
        for path in ["/admin/users", "/config/env", "/internal/debug", "/backup/restore"]:
            normal_snapshot.endpoint = path
            result = detect_new_endpoint(normal_snapshot, baseline)
            assert result is not None and result.evidence["is_sensitive"] is True


# ─────────────────────────────────────────────────────────────
# 3. Geo Anomaly Tests
# ─────────────────────────────────────────────────────────────

class TestGeoAnomaly:

    def test_same_country_no_flag(self, normal_snapshot, baseline):
        result = detect_geo_anomaly(normal_snapshot, baseline)
        assert result is None

    def test_different_non_high_risk_country(self, normal_snapshot, baseline):
        normal_snapshot.country = "DE"
        result = detect_geo_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 50
        assert result.evidence["high_risk_origin"] is False

    def test_high_risk_country_scores_higher(self, normal_snapshot, baseline):
        normal_snapshot.country = "RU"
        result = detect_geo_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 80
        assert result.evidence["high_risk_origin"] is True

    def test_no_flag_when_baseline_country_missing(self, normal_snapshot, baseline):
        baseline.home_country = None
        result = detect_geo_anomaly(normal_snapshot, baseline)
        assert result is None


# ─────────────────────────────────────────────────────────────
# 4. Method Anomaly Tests
# ─────────────────────────────────────────────────────────────

class TestMethodAnomaly:

    def test_known_method_passes(self, normal_snapshot, baseline):
        result = detect_method_anomaly(normal_snapshot, baseline)
        assert result is None

    def test_unusual_non_destructive_method(self, normal_snapshot, baseline):
        normal_snapshot.method = "OPTIONS"
        result = detect_method_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 30

    def test_destructive_method_higher_score(self, normal_snapshot, baseline):
        for method in ["DELETE", "PATCH", "PUT"]:
            normal_snapshot.method = method
            result = detect_method_anomaly(normal_snapshot, baseline)
            assert result is not None
            assert result.score == 60
            assert result.evidence["is_destructive"] is True


# ─────────────────────────────────────────────────────────────
# 5. Payload Anomaly Tests
# ─────────────────────────────────────────────────────────────

class TestPayloadAnomaly:

    def test_normal_payload_passes(self, normal_snapshot, baseline):
        result = detect_payload_anomaly(normal_snapshot, baseline)
        assert result is None

    def test_5x_payload_flagged(self, normal_snapshot, baseline):
        normal_snapshot.payload_size = 2048 * 6  # 6× baseline
        result = detect_payload_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 25

    def test_20x_payload(self, normal_snapshot, baseline):
        normal_snapshot.payload_size = 2048 * 25
        result = detect_payload_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 50

    def test_100x_payload_extreme(self, normal_snapshot, baseline):
        normal_snapshot.payload_size = 2048 * 110
        result = detect_payload_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 80

    def test_5mb_payload_detected(self, normal_snapshot, baseline):
        normal_snapshot.payload_size = 5 * 1024 * 1024  # 5 MB
        result = detect_payload_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score >= 50


# ─────────────────────────────────────────────────────────────
# 6. Time Anomaly Tests
# ─────────────────────────────────────────────────────────────

class TestTimeAnomaly:

    def test_business_hours_no_flag(self, normal_snapshot, baseline):
        normal_snapshot.timestamp = datetime(2025, 6, 1, 14, 0, 0, tzinfo=timezone.utc)
        result = detect_time_anomaly(normal_snapshot, baseline)
        assert result is None

    def test_off_hours_flagged(self, normal_snapshot, baseline):
        normal_snapshot.timestamp = datetime(2025, 6, 1, 21, 0, 0, tzinfo=timezone.utc)
        result = detect_time_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 25

    def test_deep_night_higher_score(self, normal_snapshot, baseline):
        normal_snapshot.timestamp = datetime(2025, 6, 1, 3, 0, 0, tzinfo=timezone.utc)
        result = detect_time_anomaly(normal_snapshot, baseline)
        assert result is not None
        assert result.score == 50
        assert result.evidence["is_deep_night"] is True


# ─────────────────────────────────────────────────────────────
# 7. Composite Behavior Change
# ─────────────────────────────────────────────────────────────

class TestBehaviorChange:

    def test_no_flag_below_threshold(self):

        result = detect_user_behavior_change(
            active_flags=2,
            total_score=80
        )

        assert result is None

    def test_fires_at_3_flags(self):

        result = detect_user_behavior_change(
            active_flags=3,
            total_score=120
        )

        assert result is not None
        assert result.anomaly_type == (
            AnomalyType.USER_BEHAVIOR_CHANGE
        )

    def test_high_score_behavior_change(self):

        result = detect_user_behavior_change(
            active_flags=4,
            total_score=180
        )

        assert result is not None
        assert result.score >= 40


# ─────────────────────────────────────────────────────────────
# 8. Service-Level Integration Tests
# ─────────────────────────────────────────────────────────────

class TestAnomalyService:

    def test_normal_request_is_safe(self, service, normal_snapshot):
        result = service.analyze(normal_snapshot)
        assert result.risk_level == RiskLevel.SAFE
        assert result.blocked is False
        assert len(result.flags) == 0

    def test_critical_attack_is_blocked(self, service):
        """Simulate a coordinated multi-vector attack."""
        snapshot = APIRequestSnapshot(
            user_id="user_101",
            endpoint="/admin/export",         # new sensitive endpoint
            method="DELETE",                   # destructive method
            ip_address="195.10.20.30",
            country="RU",                      # high-risk geo
            payload_size=5 * 1024 * 1024,     # 5 MB payload
            response_time=50.0,
            status_code=200,
            timestamp=datetime(2025, 6, 1, 3, 0, 0, tzinfo=timezone.utc),  # 3 AM
        )
        result = service.analyze(snapshot)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert len(result.flags) >= 4

    def test_critical_requests_are_auto_blocked(self, service):
        snapshot = APIRequestSnapshot(
            user_id="user_attacker",
            endpoint="/admin/export",
            method="DELETE",
            ip_address="1.2.3.4",
            country="KP",
            payload_size=10 * 1024 * 1024,
            response_time=10.0,
            status_code=200,
            timestamp=datetime(2025, 6, 1, 2, 0, 0, tzinfo=timezone.utc),
        )
        result = service.analyze(snapshot)
        if result.risk_level == RiskLevel.CRITICAL:
            assert result.blocked is True

    def test_baseline_learned_from_safe_requests(
        self,
        service,
        normal_snapshot
    ):
        """
        Safe requests should update baseline.
        """

        before = (
            service._baselines["user_101"]
            .avg_payload_size
        )

        service.analyze(
            normal_snapshot
        )    

        after = (
            service._baselines["user_101"]
            .avg_payload_size
        )

        assert after != before

    def test_baseline_not_updated_on_high_risk(self, service):
        """High-risk requests must not corrupt the baseline."""
        snapshot = APIRequestSnapshot(
            user_id="user_101",
            endpoint="/admin/purge",
            method="DELETE",
            ip_address="195.10.20.30",
            country="RU",
            payload_size=5 * 1024 * 1024,
            response_time=30.0,
            status_code=200,
            timestamp=datetime(2025, 6, 1, 3, 0, 0, tzinfo=timezone.utc),
        )
        before = list(service._baselines["user_101"].known_endpoints)
        service.analyze(snapshot)
        after = list(service._baselines["user_101"].known_endpoints)
        assert before == after  # baseline unchanged

    def test_request_spike_detected_via_service(self, service):
        """Rapid fire 50 requests then check RPM detection."""
        ts = datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        snapshot = APIRequestSnapshot(
            user_id="spike_user",
            endpoint="/profile",
            method="GET",
            ip_address="1.2.3.4",
            country="IN",
            payload_size=500,
            response_time=50.0,
            status_code=200,
            timestamp=ts,
        )
        service.set_baseline(UserBaseline(
            user_id="spike_user",
            avg_requests_per_min=5.0,
            known_endpoints=["/profile"],
            known_methods=["GET"],
            home_country="IN",
            avg_payload_size=500.0,
            active_hours=list(range(9, 19)),
        ))

        # Simulate 60 rapid requests
        for _ in range(60):
            service._record_and_get_rpm("spike_user", ts)

        result = service.analyze(snapshot)
        spike_flags = [f for f in result.flags if f.anomaly_type == AnomalyType.REQUEST_SPIKE]
        assert len(spike_flags) > 0

    def test_reset_baseline(self, service):
        assert service.reset_baseline("user_101") is True
        assert service.reset_baseline("nonexistent") is False


# ─────────────────────────────────────────────────────────────
# 9. Risk Score Thresholds
# ─────────────────────────────────────────────────────────────

class TestRiskScoreMapping:

    def test_score_boundaries(self):
        from schemas.api_anomaly_schema import score_to_risk
        assert score_to_risk(0)   == RiskLevel.SAFE
        assert score_to_risk(20)  == RiskLevel.SAFE
        assert score_to_risk(21)  == RiskLevel.LOW
        assert score_to_risk(50)  == RiskLevel.LOW
        assert score_to_risk(51)  == RiskLevel.MEDIUM
        assert score_to_risk(80)  == RiskLevel.MEDIUM
        assert score_to_risk(81)  == RiskLevel.HIGH
        assert score_to_risk(120) == RiskLevel.HIGH
        assert score_to_risk(121) == RiskLevel.CRITICAL
        assert score_to_risk(999) == RiskLevel.CRITICAL