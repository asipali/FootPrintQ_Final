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

router = APIRouter(prefix="/api/v1/health", tags=["Health & Diagnostics"])


@router.get("")
def get_system_health():
    # 1. Database Health
    db_status = check_db_health()

    # 2. SeaweedFS Health
    storage = SeaweedFSClient()
    seaweed_status = storage.check_health()

    # 3. Nmap / NSE Health
    nmap_path = shutil.which("nmap")
    nmap_status = {
        "status": "ONLINE" if nmap_path else "MISSING",
        "binary_path": nmap_path,
        "capabilities": ["SYN", "TCP", "UDP", "NSE", "Service Detection", "OS Detection"]
    }

    # 4. Greenbone / OpenVAS Health
    gvmd_sock = "/run/gvmd/gvmd.sock"
    ospd_sock = "/run/ospd/ospd-openvas.sock"
    greenbone_status = {
        "status": "ONLINE" if os.path.exists(gvmd_sock) else "INITIALIZING",
        "gvmd_socket": gvmd_sock,
        "gvmd_active": os.path.exists(gvmd_sock),
        "ospd_socket": ospd_sock,
        "ospd_active": os.path.exists(ospd_sock),
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

