import logging

from modules.jwt_security_agent import JWTSecurityAgent
from schemas.jwt_schema import (
    JWTSecurityRequest,
    JWTSecurityResponse
)

logger = logging.getLogger("JWTService")

agent = JWTSecurityAgent()


def analyze_jwt(
    request: JWTSecurityRequest
) -> JWTSecurityResponse:

    logger.info(
        "JWT analysis requested"
    )

    result = agent.analyze(
        request.token
    )

    return JWTSecurityResponse(
        **result
    )