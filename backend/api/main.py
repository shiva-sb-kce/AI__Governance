import sys
import os


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi import FastAPI

from api.routes.api_security_routes import router as api_security_router
from api.routes.rbac_routes import router as rbac_router
from api.routes.jwt_routes import router as jwt_router
from api.routes.owasp_routes import router as owasp_router
from api.routes.correlation_routes import router as correlation_router
from api.routes.unified_security_routes import router as unified_router

app = FastAPI(
    title="AI Governance Platform",
    description="Enterprise AI Governance & Security Platform",
    version="1.0.0"
)

# Register Routers
app.include_router(api_security_router)
app.include_router(rbac_router)
app.include_router(jwt_router)
app.include_router(owasp_router)
app.include_router(correlation_router)
app.include_router(unified_router)


@app.get("/")
def root():
    return {
        "status": "running",
        "platform": "AI Governance",
        "version": "1.0.0"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "services": [
            "API Security Agent",
            "RBAC Governance Agent",
            "JWT Security Agent"
        ]
    }