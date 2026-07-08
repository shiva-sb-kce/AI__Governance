import logging
from fastapi import APIRouter, HTTPException, status
from schemas.rbac_schema import (
    RBACRequest,
    RBACResponse,
    RBACQuickCheckRequest,
    RBACQuickCheckResponse,
)
from services.rbac_service import check_rbac, is_authorized, get_health
from modules.rbac_agent import RBAC_MATRIX

router = APIRouter(prefix="/api/rbac", tags=["RBAC Governance Agent"])
logger = logging.getLogger("RBACRoutes")

@router.post("/check", response_model=RBACResponse, status_code=status.HTTP_200_OK)
def rbac_check(request: RBACRequest) -> RBACResponse:
    try:
        return check_rbac(request)
    except Exception as e:
        logger.error("Error in /rbac/check: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"RBAC check execution failed: {str(e)}"
        )

@router.post("/authorize", response_model=RBACQuickCheckResponse, status_code=status.HTTP_200_OK)
def rbac_authorize(request: RBACQuickCheckRequest) -> RBACQuickCheckResponse:
    try:
        authorized = is_authorized(request.user, request.role, request.endpoint, request.method)
        return RBACQuickCheckResponse(
            authorized=authorized,
            user=request.user,
            role=request.role,
            endpoint=request.endpoint
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authorization assertion failed: {str(e)}"
        )

@router.get("/matrix", status_code=status.HTTP_200_OK)
def rbac_matrix() -> dict:
    return {"rbac_matrix": RBAC_MATRIX}

@router.get("/health", status_code=status.HTTP_200_OK)
def health() -> dict:
    return get_health()