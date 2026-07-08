"""
api/routes/api_anomaly_routes.py

Enterprise API Anomaly Detection
FastAPI Router
"""

from typing import List, Dict, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from schemas.api_anomaly_schema import (
    APIRequestSnapshot,
    AnomalyAnalysisResult,
    UserBaseline,
)

from services.api_anomaly_service import (
    APIAnomalyService,
    get_anomaly_service,
)

router = APIRouter(
    prefix="/api/v1/anomaly",
    tags=["API Anomaly Detection"],
)

# ----------------------------------------------------------
# Analyze API Request
# ----------------------------------------------------------

@router.post(
    "/analyze",
    response_model=AnomalyAnalysisResult,
    summary="Analyze API request for anomalies",
)
async def analyze_request(
    snapshot: APIRequestSnapshot,
    service: APIAnomalyService = Depends(
        get_anomaly_service
    ),
) -> AnomalyAnalysisResult:

    return service.analyze(snapshot)


# ----------------------------------------------------------
# Create / Update Baseline
# ----------------------------------------------------------

@router.post(
    "/baseline",
    response_model=UserBaseline,
    summary="Create or update user baseline",
)
async def upsert_baseline(
    baseline: UserBaseline,
    service: APIAnomalyService = Depends(
        get_anomaly_service
    ),
) -> UserBaseline:

    service.set_baseline(
        baseline
    )

    return baseline


# ----------------------------------------------------------
# Get Baseline
# ----------------------------------------------------------

@router.get(
    "/baseline/{user_id}",
    response_model=UserBaseline,
    summary="Get user baseline",
)
async def get_baseline(
    user_id: str,
    service: APIAnomalyService = Depends(
        get_anomaly_service
    ),
) -> UserBaseline:

    baseline = service.get_baseline(
        user_id
    )

    if baseline is None:

        raise HTTPException(
            status_code=404,
            detail=f"No baseline found for user '{user_id}'"
        )

    return baseline


# ----------------------------------------------------------
# List All Baselines
# ----------------------------------------------------------

@router.get(
    "/baseline",
    response_model=List[UserBaseline],
    summary="List all baselines",
)
async def list_baselines(
    service: APIAnomalyService = Depends(
        get_anomaly_service
    ),
) -> List[UserBaseline]:

    return service.list_baselines()


# ----------------------------------------------------------
# Reset Baseline
# ----------------------------------------------------------

@router.delete(
    "/baseline/{user_id}",
    summary="Delete user baseline",
)
async def reset_baseline(
    user_id: str,
    service: APIAnomalyService = Depends(
        get_anomaly_service
    ),
) -> Dict[str, str]:

    success = service.reset_baseline(
        user_id
    )

    if not success:

        raise HTTPException(
            status_code=404,
            detail=f"No baseline found for user '{user_id}'"
        )

    return {
        "status": "success",
        "message": f"Baseline reset for '{user_id}'"
    }


# ----------------------------------------------------------
# Health Check
# ----------------------------------------------------------

@router.get(
    "/health",
    summary="Health check",
)
async def health(
    service: APIAnomalyService = Depends(
        get_anomaly_service
    ),
) -> Dict[str, Any]:

    return {
        "status": "healthy",
        "module": "API Anomaly Detection",
        "phase": "Phase 1 - Rule Based",
        "tracked_users": len(
            service.list_baselines()
        ),
    }