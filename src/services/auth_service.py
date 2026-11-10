"""
FootprintIQ - Authentication and Role-Based Access Control (RBAC) Service
Provides bcrypt password hashing, JWT session token generation and verification,
and strict server-side role enforcement (admin vs investigator).
"""

import os
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from src.db.repository import FootprintIQRepository

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "FootprintIQ-SuperSecretKey-2026-ProductionSafe")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT session token with expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


class AuthService:
    def __init__(self, repo: Optional[FootprintIQRepository] = None):
        self.repo = repo or FootprintIQRepository()
        self._ensure_default_admin()

    def _ensure_default_admin(self):
        """Initializes default admin user if absent."""
        admin = self.repo.get_user_by_username("admin")
        if not admin:
            self.repo.create_user(
                username="admin",
                email="admin@footprintiq.internal",
                hashed_password=hash_password("AdminPass2026!"),
                role="admin",
                is_approved=True
            )

    def register(self, username: str, email: str, password: str, role: str = "investigator") -> Dict[str, Any]:
        """Registers a new user. Investigators require admin approval."""
        existing = self.repo.get_user_by_username(username)
        if existing:
            raise ValueError(f"Username '{username}' is already registered.")

        # Require admin approval for newly registered investigators
        is_approved = True if role == "admin" else False
        user = self.repo.create_user(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=role,
            is_approved=is_approved
        )
        self.repo.log_audit(
            user_id=user["id"],
            action="USER_REGISTERED",
            target_resource=username,
            details_json=f'{{"role": "{role}", "is_approved": {str(is_approved).lower()}}}'
        )
        return user

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticates a user and returns a session JWT token."""
        user = self.repo.get_user_by_username(username)
        if not user:
            return None

        if not verify_password(password, user["hashed_password"]):
            self.repo.log_audit(
                user_id=user["id"],
                action="LOGIN_FAILED",
                target_resource=username
            )
            return None

        if not user.get("is_active", True):
            raise PermissionError("Account is inactive.")

        if not user.get("is_approved", True):
            raise PermissionError("Account registration is pending administrator approval.")

        token = create_access_token({
            "sub": user["username"],
            "user_id": user["id"],
            "role": user["role"]
        })

        self.repo.log_audit(
            user_id=user["id"],
            action="LOGIN_SUCCESS",
            target_resource=username
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "username": user["username"],
            "role": user["role"],
            "user_id": user["id"]
        }

    def approve_investigator(self, admin_user: Dict[str, Any], target_username: str) -> bool:
        """Approves a pending investigator registration."""
        if admin_user.get("role") != "admin":
            raise PermissionError("Only administrators can approve registrations.")

        success = self.repo.approve_user(target_username)
        if success:
            self.repo.log_audit(
                user_id=admin_user.get("user_id"),
                action="USER_APPROVED",
                target_resource=target_username
            )
        return success

