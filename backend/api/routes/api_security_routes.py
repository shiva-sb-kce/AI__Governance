import logging
from typing import List

from fastapi import APIRouter, HTTPException, status, Body
from schemas.api_security_schema import (
    APISecurityRequest,
    APISecurityResponse,
    HealthResponse,
)
from services.api_security_service import analyze_api_request, get_health

router = APIRouter(
    prefix="/api/security",
    tags=["API Security Agent"],
)
logger = logging.getLogger("APISecurityRoutes")


# Changed to standard 'def' for safe background thread allocation
@router.post(
    "/analyze",
    response_model=APISecurityResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze an API request for security threats",
)
def analyze(request: APISecurityRequest) -> APISecurityResponse:
    try:
        logger.info("POST /api/security/analyze | user=%s", request.user)
        return analyze_api_request(request)
    except Exception as e:
        logger.error("Error in /analyze: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


# Native declarative boundaries replace manual array checking logic blocks
@router.post(
    "/batch",
    response_model=List[APISecurityResponse],
    status_code=status.HTTP_200_OK,
    summary="Analyze multiple API requests at once",
)
def batch_analyze(
    requests: List[APISecurityRequest] = Body(
        ..., 
        min_length=1, 
        max_length=100, 
        description="List of 1 to 100 request schemas to batch process"
    )
) -> List[APISecurityResponse]:
    try:
        logger.info("POST /api/security/batch | count=%d", len(requests))
        return [analyze_api_request(req) for req in requests]
    except Exception as e:
        logger.error("Error in /batch: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch analysis failed: {str(e)}"
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Check API Security Agent health",
)
def health() -> HealthResponse:
    data = get_health()
    return HealthResponse(
        status=data["status"],
        agent=data["agent"],
        version=data["version"],
    )