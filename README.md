# FootprintIQ: Digital Footprint Investigation & Vulnerability Assessment Platform

## 1. Project Overview

**FootprintIQ** is an enterprise-grade digital footprint investigation, OSINT reconnaissance, network discovery, multi-scanner vulnerability assessment, evidence correlation, and security reporting platform.

Developed as the production evolution of the OSINT-RECON Digital Footprint Investigator, FootprintIQ unifies passive OSINT intelligence, active network reconnaissance, policy-controlled Nmap Scripting Engine (NSE) scripts, Greenbone/OpenVAS vulnerability assessments, and Tenable Nessus integration into a single web dashboard and REST API.

### Engineering Team
- **Asip Ali**
- **Mohan Prasad**

---

## 2. Technology Architecture

| Component | Technology | Implementation Detail |
|---|---|---|
| **Backend Framework** | Python 3.13 + FastAPI | REST API & Jinja2 Web Dashboard (`src/api/`) |
| **Application Database** | Microsoft SQL Server 2022 Express | Pure MSSQL dialect (`mssql+pymssql`), SQLAlchemy ORM (`src/db/`) |
| **Database Migrations** | Alembic | Reversible T-SQL migrations targeting SQL Server 2022 (`alembic/`) |
| **Evidence Storage** | SeaweedFS (weed v3.64) | Distributed object storage with SHA-256 integrity checks (`src/storage/`) |
| **Passive OSINT** | WHOIS, RDAP, DNS, theHarvester | Domain, IP, entity, and sub-domain intelligence (`src/collectors/`) |
| **Active Network Recon** | Nmap (v7.95) | Fast/full port discovery, service detection, OS detection (`src/collectors/nmap_collector.py`) |
| **Script Vulnerability Checks** | Nmap NSE | Safe, policy-enforced vulnerability script execution (`src/collectors/nse_collector.py`) |
| **Vulnerability Scanner** | Greenbone / OpenVAS | GMP socket protocol, active SCAP/VT feed integration (`src/collectors/greenbone_collector.py`) |
| **Secondary Scanner** | Tenable Nessus | Independent REST API adapter with offline simulation fallback (`src/collectors/nessus_collector.py`) |
| **Exposure Engine** | FootprintIQ Risk Scoring | Asymptotic exposure score (0 - 100), multi-scanner corroboration boost |
| **Reporting Engine** | ReportLab | Executive PDF generation with cryptographic evidence catalog (`src/reporting/`) |

---

## 3. Laboratory Environment

- **Host Operating System:** Windows
- **Hypervisor:** Oracle VirtualBox
- **Guest Operating System:** Kali Linux 2025.4 (Rolling)
- **Virtual Network Adapters:**
  - `eth0`: NAT (`10.0.2.15/24`) — Internet connectivity & OSINT sources.
  - `eth1`: Host-Only (`192.168.56.106/24`) — Isolated lab network.
- **Authorized Target VM:** Metasploitable2 (`192.168.56.111`)
- **SeaweedFS Object Storage:** Master port `9333`, Volume port `8080`.
- **Greenbone Services:** GVMD socket `/run/gvmd/gvmd.sock`, OSPD socket `/run/ospd/ospd-openvas.sock`, GSAD Web UI `https://127.0.0.1:9392`.

---

## 4. Platform Directory Structure

```text
OSINT-RECON/
├── alembic/                    # Alembic SQL Server 2022 migration environment
│   ├── env.py                  # MSSQL migration runner
│   └── versions/               # T-SQL reversible migrations
│       └── 001_initial_sql_server_schema.py
├── config/
│   ├── target_authorization.json # Fail-closed target authorization whitelist
│   ├── correlation_config.json
│   └── recon_schema.json       # Draft 2020-12 JSON schemas
├── data/
│   ├── evidence_cache/         # SeaweedFS local cache
│   ├── raw/nse/                # Nmap NSE XML outputs
│   └── processed/              # Normalized JSON scans
├── reports/                    # Executive PDF reports
├── src/
│   ├── api/                    # FastAPI application & routers
│   │   ├── app.py              # Main FastAPI application entry point
│   │   ├── dependencies.py     # JWT & RBAC security dependencies
│   │   └── routers/            # auth, investigations, targets, scans, findings, evidence, reports, health, ui
│   ├── authorization/          # Strict fail-closed target authorizer
│   ├── collectors/             # whois, dns, theharvester, nmap, nse, greenbone, nessus, rdap
│   ├── db/                     # SQL Server session, SQLAlchemy models, repository
│   ├── orchestration/          # Unified orchestrator (all 7 scan modes)
│   ├── processors/             # Normalizers & cross-scanner correlators
│   ├── reporting/              # Unified PDF report generator
│   ├── services/               # AuthService, NSEPolicyService, ExposureScoringEngine
│   ├── storage/                # SeaweedFS client with SHA-256 verification
│   └── templates/              # Modern Jinja2 Web Dashboard templates
├── tests/                      # 147 unit and integration tests
├── main.py                     # CLI & Web Server entry point
└── requirements.txt            # Pinned dependencies
```

---

## 5. Quickstart & Usage

### A. Run Platform Health Diagnostics
```bash
python main.py --health
```

### B. Launch the Web Application & UI Dashboard
```bash
python main.py --server --host 0.0.0.0 --port 8000
```
- Web Dashboard: `http://localhost:8000/`
- Interactive OpenAPI / Swagger Docs: `http://localhost:8000/docs`

### C. Execute Unified CLI Scans
```bash
# Combined Multi-Scanner Assessment against authorized Metasploitable2:
python main.py --unified-scan combined --target 192.168.56.111

# Policy-Controlled Nmap NSE Vulnerability Check:
python main.py --unified-scan nmap_nse --target 192.168.56.111

# Passive OSINT Reconnaissance:
python main.py --unified-scan passive --target example.com
```

### D. Run Database Migrations (SQL Server 2022)
```bash
# Preview generated T-SQL:
alembic upgrade head --sql

# Run live migration against configured SQL Server:
alembic upgrade head
```

### E. Run Test Suite
```bash
python -m unittest discover tests
```
*Current test coverage: 147 passing tests across all modules.*
