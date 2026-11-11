"""
FootprintIQ - Authentication and User Management Router
Endpoints:
- POST /api/v1/auth/register (Investigator self-registration, strictly role='investigator', pending approval)
- POST /api/v1/auth/login (JWT + cookie + bound CSRF issuance)
- POST /api/v1/auth/logout (Cookie revocation & audit)
- GET  /api/v1/auth/me (Current user profile & effective permissions)
- GET  /api/v1/auth/users (Admin user listing)
- POST /api/v1/auth/approve/{username} (Admin approval)
- POST /api/v1/auth/reject/{username} (Admin rejection)
- PATCH /api/v1/auth/users/{username}/status (Admin suspend / reactivate)
- PATCH /api/v1/auth/users/{username}/role (Admin role assignment, protected against self-lockout)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from typing import Dict, Any, Optional
from src.services.auth_service import AuthService
from src.services.rbac_service import record_security_audit
from src.api.dependencies import (
    get_auth_service,
    get_current_user,
    get_optional_current_user,
    require_admin,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "investigator"


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    csrf_token: str
    username: str
    role: str
    user_id: int


class UserStatusUpdateRequest(BaseModel):
    is_active: bool


class UserRoleUpdateRequest(BaseModel):
    role: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(
    req: RegisterRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        user = auth_service.register(
            username=req.username,
            email=req.email,
            password=req.password,
            role=req.role,
            request=request,
        )
        return {
            "message": "User registered successfully and is pending administrator approval.",
            "username": user["username"],
            "role": user["role"],
            "is_approved": user["is_approved"],
            "requires_approval": not user["is_approved"],
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/login", response_model=TokenResponse)
def login_user(
    req: LoginRequest,
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        token_data = auth_service.authenticate(
            username=req.username,
            password=req.password,
            request=request,
        )
        if not token_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token_data["access_token"],
            httponly=True,
            samesite="lax",
            max_age=28800,
        )
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token_data["csrf_token"],
            httponly=False,
            samesite="lax",
            max_age=28800,
        )
        return token_data
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post("/logout")
def logout_user(
    request: Request,
    response: Response,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    if current_user:
        record_security_audit(
            auth_service.repo,
            user=current_user,
            action="LOGOUT",
            target_resource=current_user.get("username"),
            outcome="SUCCESS",
            request=request,
        )
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    response.delete_cookie(key=CSRF_COOKIE_NAME)
    return {"message": "Signed out cleanly."}


@router.get("/me")
def get_current_user_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "user_id": current_user.get("id"),
        "username": current_user.get("username"),
        "email": current_user.get("email"),
        "role": current_user.get("role"),
        "is_active": current_user.get("is_active"),
        "is_approved": current_user.get("is_approved"),
    }


@router.get("/users")
def list_users(
    _admin: Dict[str, Any] = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
):
    return auth_service.repo.list_users()


@router.post("/approve/{username}")
def approve_user(
    username: str,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
):
    success = auth_service.approve_investigator(admin, username, request=request)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found.")
    return {"message": f"User '{username}' approved successfully."}


@router.post("/reject/{username}")
def reject_user(
    username: str,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        success = auth_service.reject_investigator(admin, username, request=request)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found.")
    return {"message": f"User '{username}' registration rejected and deactivated."}


@router.patch("/users/{username}/status")
def update_user_status(
    username: str,
    req: UserStatusUpdateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        updated = auth_service.update_user_status(admin, username, req.is_active, request=request)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found.")
    return {"message": f"User '{username}' status updated.", "user": updated}


@router.patch("/users/{username}/role")
def update_user_role(
    username: str,
    req: UserRoleUpdateRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        updated = auth_service.assign_user_role(admin, username, req.role, request=request)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found.")
    return {"message": f"User '{username}' role updated to '{updated['role']}'.", "user": updated}
