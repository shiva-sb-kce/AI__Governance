"""
OWASP Routes
AI Governance Platform
-----------------------
Endpoints:
  POST /api/owasp/analyze    → full OWASP API1–API10 analysis
  POST /api/owasp/batch      → batch analysis (up to 100)
  GET  /api/owasp/coverage   → OWASP coverage map
  GET  /api/owasp/health     → health check
"""
import logging
from typing import List
from fastapi import APIRouter, HTTPException, status

from schemas.owasp_schema  import OWASPRequest, OWASPResponse
from services.owasp_service import analyze_owasp, get_health
from modules.owasp_api_agent import OWASP_CATEGORIES

router = APIRouter(prefix="/api/owasp", tags=["OWASP API Security Agent"])
logger = logging.getLogger("OWASPRoutes")


@router.post("/analyze", response_model=OWASPResponse, status_code=200,
    summary="Full OWASP API1–API10 analysis")
async def owasp_analyze(request: OWASPRequest) -> OWASPResponse:
    try:
        return analyze_owasp(request)
    except Exception as e:
        logger.error("OWASP analyze error: %s", str(e))
        raise HTTPException(status_code=500, detail=f"OWASP analysis failed: {str(e)}")


@router.post("/batch", response_model=List[OWASPResponse], status_code=200,
    summary="Batch OWASP analysis — up to 100 requests")
async def owasp_batch(requests: List[OWASPRequest]) -> List[OWASPResponse]:
    if not requests:
        raise HTTPException(status_code=400, detail="Request list is empty.")
    if len(requests) > 100:
        raise HTTPException(status_code=400, detail="Batch limit is 100.")
    try:
        return [analyze_owasp(r) for r in requests]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch failed: {str(e)}")


@router.get("/coverage", status_code=200,
    summary="View OWASP API Top 10 coverage map")
async def owasp_coverage() -> dict:
    return {"owasp_api_top10": OWASP_CATEGORIES, "status": "all covered"}


@router.get("/health", status_code=200, summary="Health check")
async def owasp_health() -> dict:
    return get_health()