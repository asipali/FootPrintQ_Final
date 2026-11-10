"""
FootprintIQ - System & Scanner Health Router
Endpoint:
- GET /api/v1/health (Comprehensive health status across DB, SeaweedFS, and all scanners)
"""

import os
import shutil
from fastapi import APIRouter
from src.db.session import check_db_health
from src.storage.seaweedfs_client import SeaweedFSClient
from src.collectors.nessus_collector import NessusCollector
from src.collectors.greenbone_collector import GreenboneCollector

router = APIRouter(prefix="/api/v1/health", tags=["Health & Diagnostics"])


def _detect_nmap_binary() -> str:
    """Cross-platform binary resolution for Nmap."""
    env_path = os.getenv("NMAP_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    
    which_path = shutil.which("nmap") or shutil.which("nmap.exe")
    if which_path:
        return which_path

    # Common Windows install locations
    if os.name == "nt":
        for win_path in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]:
            if os.path.isfile(win_path):
                return win_path

    # Linux default
    if os.path.isfile("/usr/bin/nmap"):
        return "/usr/bin/nmap"

    return ""


@router.get("")
def get_system_health():
    # 1. Database Health
    db_status = check_db_health()

    # 2. SeaweedFS Health
    storage = SeaweedFSClient()
    seaweed_status = storage.check_health()

    # 3. Nmap / NSE Health
    nmap_path = _detect_nmap_binary()
    nmap_status = {
        "status": "ONLINE" if nmap_path else "MISSING",
        "binary_path": nmap_path or None,
        "capabilities": ["SYN", "TCP", "UDP", "NSE", "Service Detection", "OS Detection"]
    }

    # 4. Greenbone / OpenVAS Health (Probe socket & GMP readiness)
    gvmd_sock = "/run/gvmd/gvmd.sock"
    ospd_sock = "/run/ospd/ospd-openvas.sock"
    socket_exists = os.path.exists(gvmd_sock)
    
    gb_status_label = "UNAVAILABLE"
    gb_details = {}
    if socket_exists:
        try:
            gb_col = GreenboneCollector()
            is_ready, details = gb_col.check_readiness()
            gb_details = details
            if is_ready:
                gb_status_label = "ONLINE"
            elif details.get("connected"):
                gb_status_label = "FEED_SYNCING"
            else:
                gb_status_label = "INITIALIZING"
        except Exception:
            gb_status_label = "INITIALIZING"

    greenbone_status = {
        "status": gb_status_label,
        "gvmd_socket": gvmd_sock,
        "gvmd_active": socket_exists,
        "ospd_socket": ospd_sock,
        "ospd_active": os.path.exists(ospd_sock),
        "details": gb_details,
        "gsad_ui": "https://127.0.0.1:9392"
    }

    # 5. Nessus Scanner Health
    nessus_collector = NessusCollector()
    nessus_status = nessus_collector.check_status()

    # Overall system state
    all_ready = (
        seaweed_status.get("status") == "ONLINE" and
        nmap_status.get("status") == "ONLINE"
    )

    return {
        "platform": "FootprintIQ",
        "version": "2.0-Enterprise",
        "system_status": "OPERATIONAL" if all_ready else "DEGRADED",
        "database": db_status,
        "object_storage": seaweed_status,
        "network_scanner": nmap_status,
        "vulnerability_scanners": {
            "greenbone_openvas": greenbone_status,
            "nessus": nessus_status
        }
    }

