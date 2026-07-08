import logging
from datetime import datetime, timezone

from modules.api_security_agent import APISecurityAgent
from schemas.api_security_schema import APISecurityRequest, APISecurityResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("APISecurityService")

# Singleton Agent Instance
_agent = APISecurityAgent()


def analyze_api_request(request: APISecurityRequest) -> APISecurityResponse:
    """
    Main service function processing incoming security request structures.
    """
    logger.info(
        "Analyzing request | user=%s | role=%s | endpoint=%s | method=%s",
        request.user, request.role, request.endpoint, request.method
    )

    # Step 1: Automated clean conversion to dict using Pydantic methods
    request_dict = request.model_dump()

    # Step 2: Run agent engine calculations
    result = _agent.analyze(request_dict)

    # Step 3: Run logging execution rules
    _log_result(result)

    # Step 4: Handle conditional notifications for dangerous scores
    if result.get("severity") in ("HIGH", "CRITICAL"):
        _trigger_alert(result)

    # Step 5: Instantiated directly via dictionary unpacking
    return APISecurityResponse(**result)


def _log_result(result: dict) -> None:
    logger.info(
        "AUDIT | user=%-20s | endpoint=%-35s | score=%3d | severity=%-8s | action=%s",
        result.get("user"),
        result.get("endpoint"),
        result.get("risk_score", 0),
        result.get("severity"),
        result.get("action"),
    )


def _trigger_alert(result: dict) -> None:
    logger.warning(
        "🚨 ALERT | severity=%-8s | user=%s | endpoint=%s | reasons=%s",
        result.get("severity"),
        result.get("user"),
        result.get("endpoint"),
        result.get("reasons"),
    )


def get_health() -> dict:
    return {
        "status":    "ok",
        "agent":     "APISecurityAgent",
        "version":   "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }