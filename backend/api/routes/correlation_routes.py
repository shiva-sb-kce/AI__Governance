"""
Correlation Routes
AI Governance Platform
-----------------------
FastAPI endpoints:
  POST /api/correlation/analyze  → full correlated risk score
  POST /api/correlation/batch    → batch analysis (up to 50)
  GET  /api/correlation/weights  → view agent weight config
  GET  /api/correlation/health   → health check
"""

import logging
from typing import List
from fastapi import APIRouter, HTTPException, status

from schemas.correlation_schema  import CorrelationRequest, CorrelationResponse
from services.correlation_service import run_correlation, get_health
from modules.correlation_agent    import AGENT_WEIGHTS, AMPLIFICATION_RULES

router = APIRouter(
    prefix="/api/correlation",
    tags=["Risk Correlation Engine"],
)
logger = logging.getLogger("CorrelationRoutes")


@router.post(
    "/analyze",
    response_model=CorrelationResponse,
    status_code=status.HTTP_200_OK,
    summary="Unified enterprise risk score from all agents",
    description="""
Combines scores from all 5 agents into one correlated risk score.

Agents:
- Prompt Monitor (weight 25%)
- JWT Security   (weight 15%)
- RBAC Agent     (weight 20%)
- API Security   (weight 20%)
- OWASP Agent    (weight 20%)

Applies amplification bonuses when multiple agents fire together.
    """,
)
async def correlate(request: CorrelationRequest) -> CorrelationResponse:
    try:
        logger.info("POST /api/correlation/analyze | user=%s", request.user)
        return run_correlation(request)
    except Exception as e:
        logger.error("Correlation error: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation failed: {str(e)}"
        )


@router.post(
    "/batch",
    response_model=List[CorrelationResponse],
    status_code=status.HTTP_200_OK,
    summary="Batch correlation — up to 50 requests",
)
async def batch_correlate(requests: List[CorrelationRequest]) -> List[CorrelationResponse]:
    if not requests:
        raise HTTPException(status_code=400, detail="Request list is empty.")
    if len(requests) > 50:
        raise HTTPException(status_code=400, detail="Batch limit is 50.")
    try:
        return [run_correlation(r) for r in requests]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch failed: {str(e)}")


@router.get(
    "/weights",
    status_code=status.HTTP_200_OK,
    summary="View agent weight configuration and amplification rules",
)
async def get_weights() -> dict:
    return {
        "agent_weights":      AGENT_WEIGHTS,
        "amplification_rules": [
            {
                "name":        r["name"],
                "description": r["description"],
                "bonus":       r["bonus"],
            }
            for r in AMPLIFICATION_RULES
        ],
    }


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Correlation engine health check",
)
async def health() -> dict:
    return get_health()