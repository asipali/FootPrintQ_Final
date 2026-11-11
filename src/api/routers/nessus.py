"""
FootprintIQ - Tenable Nessus Scanner Management Router
Endpoints:
- GET  /api/v1/scanners/nessus/status     (Scanner availability & version)
- POST /api/v1/scanners/nessus/test       (Administrator live connection test)
- GET  /api/v1/scanners/nessus/templates  (Discovered scan templates)
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel

from src.collectors.nessus_collector import NessusCollector
from src.api.dependencies import get_current_user, require_admin

router = APIRouter(prefix="/api/v1/scanners/nessus", tags=["Tenable Nessus Scanner"])


@router.get("/status")
def get_nessus_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns sanitized status of the Tenable Nessus vulnerability scanner.
    Never exposes internal credentials or raw API tokens.
    """
    collector = NessusCollector()
    res = collector.check_status()
    res.pop("server_url", None)
    return res


@router.post("/test")
def test_nessus_connection(current_user: Dict[str, Any] = Depends(require_admin)):
    """
    Administrator-only endpoint to test live connectivity and authentication with Nessus API.
    """
    collector = NessusCollector()
    result = collector.test_connection()
    return result


@router.get("/templates")
def list_nessus_templates(
    refresh: bool = Query(False, description="Force refresh template cache from Nessus API"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Discovers and returns available scan templates from the Nessus installation.
    Filters out subscription-restricted templates that are unusable by the current license.
    """
    collector = NessusCollector()
    templates = collector.get_scan_templates(refresh=refresh)
    return {
        "count": len(templates),
        "available_count": sum(1 for t in templates if t.get("is_available")),
        "templates": templates
    }

