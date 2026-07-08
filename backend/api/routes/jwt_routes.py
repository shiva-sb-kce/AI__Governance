import logging

from fastapi import (
    APIRouter,
    HTTPException,
    status
)

from schemas.jwt_schema import (
    JWTSecurityRequest,
    JWTSecurityResponse
)

from services.jwt_service import (
    analyze_jwt
)

router = APIRouter(
    prefix="/api/jwt",
    tags=["JWT Security Agent"]
)

logger = logging.getLogger(
    "JWTRoutes"
)


@router.post(
    "/analyze",
    response_model=JWTSecurityResponse,
    status_code=status.HTTP_200_OK
)
def jwt_analyze(
    request: JWTSecurityRequest
):

    try:

        return analyze_jwt(
            request
        )

    except Exception as e:

        logger.error(
            "JWT Analysis Error: %s",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )