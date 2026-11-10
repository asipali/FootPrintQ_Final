"""
FootprintIQ - Authentication Router
Endpoints:
- POST /api/v1/auth/register (Investigator self-registration)
- POST /api/v1/auth/login (JWT token issuance)
- GET  /api/v1/auth/me (Current user profile)
- POST /api/v1/auth/approve/{username} (Admin approval of pending investigators)
- GET  /api/v1/auth/users (Admin user listing)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any, List
from src.services.auth_service import AuthService
from src.api.dependencies import get_auth_service, get_current_user, require_admin

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
    username: str
    role: str
    user_id: int


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest, auth_service: AuthService = Depends(get_auth_service)):
    try:
        user = auth_service.register(
            username=req.username,
            email=req.email,
            password=req.password,
            role=req.role
        )
        return {
            "message": "User registered successfully.",
            "username": user["username"],
            "role": user["role"],
            "is_approved": user["is_approved"],
            "requires_approval": not user["is_approved"]
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/login", response_model=TokenResponse)
def login_user(req: LoginRequest, auth_service: AuthService = Depends(get_auth_service)):
    try:
        token_data = auth_service.authenticate(username=req.username, password=req.password)
        if not token_data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
        return token_data
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get("/me")
def get_current_user_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "user_id": current_user.get("id"),
        "username": current_user.get("username"),
        "email": current_user.get("email"),
        "role": current_user.get("role"),
        "is_active": current_user.get("is_active"),
        "is_approved": current_user.get("is_approved")
    }


@router.get("/users", dependencies=[Depends(require_admin)])
def list_users(auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.repo.list_users()


@router.post("/approve/{username}", dependencies=[Depends(require_admin)])
def approve_user(
    username: str,
    admin: Dict[str, Any] = Depends(require_admin),
    auth_service: AuthService = Depends(get_auth_service)
):
    success = auth_service.approve_investigator(admin, username)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found.")
    return {"message": f"User '{username}' approved successfully."}
