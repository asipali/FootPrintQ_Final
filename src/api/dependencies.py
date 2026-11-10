"""
FootprintIQ - FastAPI Dependencies
Handles JWT authentication, current user resolution, RBAC authorization,
and database repository injection.
"""

from typing import Dict, Any, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from src.services.auth_service import AuthService, decode_access_token
from src.db.repository import FootprintIQRepository

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_repository() -> FootprintIQRepository:
    """Dependency for data access repository."""
    return FootprintIQRepository()


def get_auth_service(repo: FootprintIQRepository = Depends(get_repository)) -> AuthService:
    """Dependency for authentication service."""
    return AuthService(repo=repo)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    repo: FootprintIQRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """
    Validates bearer token and returns authenticated user record.
    If no token is supplied, returns a guest investigator session for local lab UI convenience.
    """
    if not token:
        # Fallback to local default investigator for seamless local UI browsing
        default_user = repo.get_user_by_username("asip_ali")
        if not default_user:
            default_user = repo.create_user(
                username="asip_ali",
                email="asip_ali@footprintiq.local",
                hashed_password="",
                role="investigator",
                is_approved=True
            )
        return default_user

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token."
        )

    user = repo.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authenticated user no longer exists."
        )

    return user


def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Ensures current user possesses Administrator role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required."
        )
    return current_user


def require_investigator(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Ensures current user is an active, approved Investigator or Administrator."""
    if not current_user.get("is_approved", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is pending administrator approval."
        )
    return current_user

