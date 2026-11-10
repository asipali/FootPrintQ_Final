"""
FootprintIQ - Enterprise FastAPI Application Entry Point
Integrates OSINT reconnaissance, Nmap network scanning, NSE vulnerability scripts,
Greenbone/OpenVAS, Nessus, SQL Server 2022 Express, and SeaweedFS object storage.
"""

import os
import sys
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.api.routers import (
    auth, investigations, targets, scans, findings, evidence, reports, health, ui
)
from src.db.session import init_engine
from src.db.repository import FootprintIQRepository
from src.services.auth_service import AuthService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("FootprintIQ")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup & shutdown lifecycle handler.
    Initializes DB engine, default admin, initial investigation, and authorized target.
    """
    logger.info("Initializing FootprintIQ platform...")
    init_engine()

    repo = FootprintIQRepository()
    # Initialize default admin
    AuthService(repo=repo)

    # Initialize default investigation & authorized Metasploitable2 target if none exist
    invs = repo.list_investigations()
    if not invs:
        inv = repo.create_investigation(
            title="Metasploitable2 Baseline Reconnaissance & Vulnerability Audit",
            description="Automated digital footprint reconnaissance and multi-scanner vulnerability assessment of local lab VM."
        )
        inv_id = inv["investigation_id"]
        repo.add_authorized_target(
            investigation_id=inv_id,
            target="192.168.56.111",
            name="Metasploitable2 (Local VirtualBox Lab VM)",
            scope="192.168.56.111 (Host-Only Network 192.168.56.0/24)",
            permitted_profiles="lab-basic,lab-safe-minimal",
            allowed_ports="1-65535",
            authorized_by="asip_ali"
        )
        logger.info(f"Initialized default investigation {inv_id} with authorized target 192.168.56.111")

    yield
    logger.info("FootprintIQ platform shutdown complete.")


# Initialize FastAPI app
app = FastAPI(
    title="FootprintIQ API",
    description="Digital Footprint Investigation, OSINT Reconnaissance & Vulnerability Assessment Platform",
    version="2.0-Enterprise",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Trusted Localhost & Enterprise Origins
TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

# Static files mount
static_dir = os.path.join(PROJECT_ROOT, "src", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Server"] = "FootprintIQ-Engine"
    return response

# Include all API routers
app.include_router(auth.router)
app.include_router(investigations.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(evidence.router)
app.include_router(reports.router)
app.include_router(health.router)

# Include UI Dashboard router
app.include_router(ui.router)

