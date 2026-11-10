"""
FootprintIQ - Microsoft SQL Server 2022 Express Database Session Management
Strict Architecture Requirement: Microsoft SQL Server 2022 Express ONLY.
No SQLite. No PostgreSQL. No secondary database.
"""

import os
import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.pool import QueuePool

logger = logging.getLogger("FootprintIQ.DB")

# Base class for SQLAlchemy ORM models
Base = declarative_base()

def get_database_url() -> str:
    """
    Constructs or retrieves the SQL Server 2022 connection string.
    Supported dialects:
    - mssql+pymssql (pure Python FreeTDS, cross-platform)
    - mssql+pyodbc (ODBC Driver 17/18 for SQL Server)
    """
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url

    host = os.getenv("SQL_SERVER_HOST", "127.0.0.1")
    port = os.getenv("SQL_SERVER_PORT", "1433")
    user = os.getenv("SQL_SERVER_USER", "sa")
    password = os.getenv("SQL_SERVER_PASSWORD", "FootprintIQ2026!")
    database = os.getenv("SQL_SERVER_DATABASE", "FootprintIQ")
    driver = os.getenv("SQL_SERVER_DRIVER", "pymssql")

    if driver == "pyodbc":
        odbc_driver = os.getenv("ODBC_DRIVER", "ODBC Driver 18 for SQL Server")
        return f"mssql+pyodbc://{user}:{password}@{host}:{port}/{database}?driver={odbc_driver}&TrustServerCertificate=yes"
    else:
        return f"mssql+pymssql://{user}:{password}@{host}:{port}/{database}?charset=utf8"

# Default MSSQL engine
DATABASE_URL = get_database_url()

engine = None
SessionLocal = None

def init_engine(db_url: str = None):
    global engine, SessionLocal
    url = db_url or get_database_url()
    try:
        engine = create_engine(
            url,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True,
            echo=False
        )
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        logger.info(f"Initialized SQLAlchemy Engine for SQL Server: {url.split('@')[-1] if '@' in url else url}")
        return engine
    except Exception as e:
        logger.warning(f"Could not connect to SQL Server at {url}: {e}")
        # Retain SessionLocal factory bound to engine if created
        return None

# Attempt initialization
try:
    init_engine(DATABASE_URL)
except Exception:
    pass

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session.
    """
    if SessionLocal is None:
        init_engine(DATABASE_URL)
    
    if SessionLocal is None:
        raise ConnectionError("SQL Server 2022 database engine is not initialized.")
        
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def check_db_health() -> dict:
    """
    Checks the connectivity and status of Microsoft SQL Server 2022.
    """
    if engine is None:
        try:
            init_engine(DATABASE_URL)
        except Exception as e:
            return {
                "status": "UNREACHABLE",
                "database": "Microsoft SQL Server 2022 Express",
                "url": DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL,
                "error": str(e)
            }
            
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT @@VERSION AS [version], DB_NAME() AS [database]"))
            row = result.fetchone()
            return {
                "status": "ONLINE",
                "database_product": "Microsoft SQL Server",
                "version": row[0] if row else "Unknown",
                "database_name": row[1] if row else "FootprintIQ",
                "dialect": engine.dialect.name
            }
    except Exception as e:
        return {
            "status": "OFFLINE",
            "database_product": "Microsoft SQL Server 2022 Express",
            "error": str(e),
            "target": DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL
        }

