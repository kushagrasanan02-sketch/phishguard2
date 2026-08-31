import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from app.core.config import settings
from app.database.session import engine, Base
# Import all models to ensure they are registered on Base.metadata
from app.models.user import User
from app.models.scan import Scan, URLFeatures, RiskFactor, EmailScan, ModelVersion
from app.models.audit import AuditLog
from app.models.apikey import APIKey
from app.models.webhook import WebhookSubscription

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.scans import router as scans_router
from app.api.v1.email import router as email_router
from app.api.v1.admin import router as admin_router
from app.api.v1.websocket import router as ws_router
from app.api.v1.apikeys import router as apikeys_router
from app.api.v1.diagnostics import router as diagnostics_router
from app.api.v1.webhooks import router as webhooks_router
from app.api.v1.threats import router as threats_router
from app.api.v1.chat import router as chat_router
from app.api.v1.soar import router as soar_router

# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-grade AI Phishing Detection and URL/Email Risk Analysis Platform.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Process time & security headers middleware
@app.middleware("http")
async def add_security_headers_and_process_time(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Include API Routers
app.include_router(health_router, prefix=f"{settings.API_V1_STR}/health", tags=["Health"])
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])
app.include_router(apikeys_router, prefix=f"{settings.API_V1_STR}/auth/api-keys", tags=["API Keys"])
app.include_router(scans_router, prefix=f"{settings.API_V1_STR}/scans", tags=["Scans & Telemetry"])
app.include_router(email_router, prefix=f"{settings.API_V1_STR}/scans/email", tags=["Email Security"])
app.include_router(admin_router, prefix=f"{settings.API_V1_STR}/admin", tags=["Admin & System"])
app.include_router(diagnostics_router, prefix=f"{settings.API_V1_STR}/admin", tags=["System Diagnostics"])
app.include_router(webhooks_router, prefix=f"{settings.API_V1_STR}/webhooks", tags=["Webhooks & Threat Alerts"])
app.include_router(threats_router, prefix=f"{settings.API_V1_STR}/threats", tags=["Threat Intelligence Feed"])
app.include_router(chat_router, prefix=f"{settings.API_V1_STR}/chat", tags=["GuardAI SOC Assistant"])
app.include_router(soar_router, prefix=f"{settings.API_V1_STR}/soar", tags=["SOAR Automation Engine"])
app.include_router(ws_router, prefix=f"{settings.API_V1_STR}", tags=["WebSockets"])

@app.get("/")
def root():
    return {
        "title": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "docs": "/docs"
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
