"""
services/api_anomaly_service.py

Enterprise API Anomaly Detection
Production Ready Service Layer
"""

import uuid

from datetime import datetime, timezone
from typing import Dict, Optional, List
from collections import defaultdict, deque
from threading import Lock

from schemas.api_anomaly_schema import (
    APIRequestSnapshot,
    UserBaseline,
    AnomalyAnalysisResult,
    AnomalyFlag,
    RiskLevel,
    score_to_risk,
    risk_recommendation,
)

from modules.api_anomaly_agent import (
    detect_request_spike,
    detect_new_endpoint,
    detect_geo_anomaly,
    detect_method_anomaly,
    detect_payload_anomaly,
    detect_time_anomaly,
    detect_user_behavior_change,
)


class APIAnomalyService:

    def __init__(self):

        self._baselines: Dict[str, UserBaseline] = {}

        self._request_log: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        self._lock = Lock()

    # --------------------------------------------------
    # Baseline Management
    # --------------------------------------------------

    def get_or_create_baseline(
        self,
        user_id: str
    ) -> UserBaseline:

        if user_id not in self._baselines:

            self._baselines[user_id] = UserBaseline(
                user_id=user_id
            )

        return self._baselines[user_id]
    def get_baseline(
        self,
        user_id: str
    ) -> Optional[UserBaseline]:

        return self._baselines.get(
            user_id
        )

    def set_baseline(
        self,
        baseline: UserBaseline
    ) -> None:

        with self._lock:

            self._baselines[
                baseline.user_id
            ] = baseline

    def update_baseline(
        self,
        user_id: str,
        snapshot: APIRequestSnapshot
    ) -> None:

        with self._lock:

            baseline = self.get_or_create_baseline(
                user_id
            )

            alpha = 0.05

            baseline.avg_payload_size = (
                (1 - alpha)
                * baseline.avg_payload_size
                + alpha
                * snapshot.payload_size
            )

            if (
                snapshot.endpoint
                not in baseline.known_endpoints
            ):
                baseline.known_endpoints.append(
                    snapshot.endpoint
                )

            known_methods = {
                m.upper()
                for m in baseline.known_methods
            }

            method = snapshot.method.upper()

            if method not in known_methods:

                baseline.known_methods.append(
                    method
                )

            if (
                not baseline.home_country
                and snapshot.country
            ):
                baseline.home_country = (
                    snapshot.country.upper()
                )

            baseline.last_updated = (
                datetime.now(timezone.utc)
            )

    # --------------------------------------------------
    # RPM Tracking
    # --------------------------------------------------

    def _record_and_get_rpm(
        self,
        user_id: str,
        now: datetime
    ) -> float:

        log = self._request_log[user_id]

        current_ts = now.timestamp()

        log.append(current_ts)

        cutoff = current_ts - 60

        while log and log[0] < cutoff:
            log.popleft()

        return float(len(log))

    # --------------------------------------------------
    # Main Analysis Engine
    # --------------------------------------------------

    def analyze(
        self,
        snapshot: APIRequestSnapshot
    ) -> AnomalyAnalysisResult:

        user_id = snapshot.user_id

        baseline = self.get_or_create_baseline(
            user_id
        )

        now = snapshot.timestamp

        rpm = self._record_and_get_rpm(
            user_id,
            now
        )

        flags: List[AnomalyFlag] = []

        checks = [

            detect_request_spike(
                snapshot,
                baseline,
                rpm
            ),

            detect_new_endpoint(
                snapshot,
                baseline
            ),

            detect_geo_anomaly(
                snapshot,
                baseline
            ),

            detect_method_anomaly(
                snapshot,
                baseline
            ),

            detect_payload_anomaly(
                snapshot,
                baseline
            ),

            detect_time_anomaly(
                snapshot,
                baseline
            ),
        ]

        for result in checks:

            if result is not None:
                flags.append(result)

        # ------------------------------------------
        # Composite Behavior Detector
        # ------------------------------------------

        current_score = sum(
            flag.score
            for flag in flags
        )

        behavior_flag = (
            detect_user_behavior_change(
                active_flags=len(flags),
                total_score=current_score
            )
        )

        if behavior_flag:
            flags.append(
                behavior_flag
            )

        # ------------------------------------------
        # Aggregate Score
        # ------------------------------------------

        total_score = sum(
            flag.score
            for flag in flags
        )

        risk_level = score_to_risk(
            total_score
        )

        blocked = (
            risk_level
            == RiskLevel.CRITICAL
            or total_score >= 150
        )

        # ------------------------------------------
        # Learn only SAFE traffic
        # ------------------------------------------

        if risk_level == RiskLevel.SAFE:

            self.update_baseline(
                user_id,
                snapshot
            )

        return AnomalyAnalysisResult(

            request_id=str(
                uuid.uuid4()
            ),

            user_id=user_id,

            timestamp=now,

            total_score=total_score,

            risk_level=risk_level,

            flags=flags,

            recommendation=
                risk_recommendation(
                    risk_level
                ),

            blocked=blocked,
        )

    # --------------------------------------------------
    # Utilities
    # --------------------------------------------------

    def list_baselines(
        self
    ) -> List[UserBaseline]:

        return list(
            self._baselines.values()
        )

    def reset_baseline(
        self,
        user_id: str
    ) -> bool:

        with self._lock:

            if user_id in self._baselines:

                del self._baselines[
                    user_id
                ]

                return True

            return False


# ------------------------------------------------------
# Singleton Instance
# ------------------------------------------------------

_service_instance: Optional[
    APIAnomalyService
] = None


def get_anomaly_service(
) -> APIAnomalyService:

    global _service_instance

    if _service_instance is None:

        _service_instance = (
            APIAnomalyService()
        )

    return _service_instance