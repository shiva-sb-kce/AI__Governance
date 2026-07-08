"""
Unified Security Routes
AI Governance Platform
-----------------------
Master Security API

Endpoints:
  POST /api/unified/analyze
  POST /api/unified/batch
  GET  /api/unified/health
"""

import logging
from typing import List

from fastapi import APIRouter, HTTPException, status

from schemas.unified_security_schema import (
    UnifiedSecurityRequest,
    UnifiedSecurityResponse,
)

from services.unified_security_service import (
    run_unified_security,
    get_health,
)

router = APIRouter(
    prefix="/api/unified",
    tags=["Unified Security Agent"],
)

logger = logging.getLogger("UnifiedSecurityRoutes")


# ============================================================
# Analyze Single Request
# ============================================================

@router.post(
    "/analyze",
    response_model=UnifiedSecurityResponse,
    status_code=status.HTTP_200_OK,
    summary="Unified Enterprise Security Analysis",
)
async def analyze(
    request: UnifiedSecurityRequest
) -> UnifiedSecurityResponse:

    try:

        logger.info(
            "POST /api/unified/analyze | user=%s",
            request.user
        )

        return run_unified_security(request)

    except Exception as e:

        logger.error(
            "Unified analysis failed: %s",
            str(e)
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


# ============================================================
# Batch Analysis
# ============================================================

@router.post(
    "/batch",
    response_model=List[UnifiedSecurityResponse],
    status_code=status.HTTP_200_OK,
    summary="Batch Unified Analysis (Max 50)"
)
async def batch_analyze(
    requests: List[UnifiedSecurityRequest]
) -> List[UnifiedSecurityResponse]:

    if not requests:
        raise HTTPException(
            status_code=400,
            detail="Request list is empty."
        )

    if len(requests) > 50:
        raise HTTPException(
            status_code=400,
            detail="Batch limit is 50."
        )

    try:

        return [
            run_unified_security(req)
            for req in requests
        ]

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Batch analysis failed: {str(e)}"
        )


# ============================================================
# Health Check
# ============================================================

@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Unified Security Agent Health Check"
)
async def health():

    return get_health()