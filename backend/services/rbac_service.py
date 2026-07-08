import logging
from datetime import datetime, timezone
from modules.rbac_agent import RBACAgent
from schemas.rbac_schema import RBACRequest, RBACResponse

logger = logging.getLogger("RBACService")
_agent = RBACAgent()

def check_rbac(request: RBACRequest) -> RBACResponse:
    logger.info("RBAC check incoming | user=%s | role=%s", request.user, request.role)
    
    # Fast native serialization conversion mapping
    request_dict = request.model_dump()
    if request_dict["requested_role"] is None:
        request_dict["requested_role"] = ""

    result = _agent.analyze(request_dict)

    if result["severity"] in ("HIGH", "CRITICAL"):
        _trigger_alert(result)

    return RBACResponse(**result)

def is_authorized(user: str, role: str, endpoint: str, method: str) -> bool:
    return _agent.is_authorized(user, role, endpoint, method)

def _trigger_alert(result: dict) -> None:
    logger.warning(
        "🚨 RBAC ALERT | severity=%s | user=%s | role=%s | endpoint=%s | reasons=%s",
        result["severity"], result["user"], result["role"], result["endpoint"], result["reasons"]
    )

def get_health() -> dict:
    return {
        "status": "ok",
        "agent": "RBACAgent",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }