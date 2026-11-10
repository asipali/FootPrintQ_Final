"""
OSINT-RECON Greenbone Authentication & Configuration Module
Retrieves GVM connection and authentication parameters securely from environment
variables or explicit configuration. Strictly prohibits hardcoded passwords.
"""

import os
from typing import Optional, Dict, Any, Tuple
from dotenv import load_dotenv

# Load local .env if present
load_dotenv()

DEFAULT_UNIX_SOCKETS = [
    "/run/gvmd/gvmd.sock",
    "/run/gvm/gvmd.sock",
    "/var/run/gvmd.sock"
]


class GreenboneAuthConfig:
    """
    Manages Greenbone connection parameters and authentication credentials.
    Hides sensitive credentials from string representations.
    """

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        socket_path: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[int] = None
    ):
        self.username = username or os.getenv("GVM_USER") or os.getenv("GREENBONE_USER") or "admin"
        self._password = password or os.getenv("GVM_PASSWORD") or os.getenv("GREENBONE_PASSWORD")
        self.host = host or os.getenv("GVM_HOST")
        self.port = port if port is not None else (int(os.getenv("GVM_PORT", "9390")) if os.getenv("GVM_PORT") else None)
        self.timeout = timeout or int(os.getenv("GVM_TIMEOUT", "60"))

        # Resolve socket path
        env_sock = os.getenv("GVM_SOCKET_PATH") or os.getenv("GREENBONE_SOCKET")
        if socket_path:
            self.socket_path = socket_path
        elif env_sock:
            self.socket_path = env_sock
        else:
            # Pick first existing socket, or default to standard Debian/Kali path
            found_sock = next((s for s in DEFAULT_UNIX_SOCKETS if os.path.exists(s)), DEFAULT_UNIX_SOCKETS[0])
            self.socket_path = found_sock

    @property
    def password(self) -> Optional[str]:
        """Provides access to raw password."""
        return self._password

    def validate_credentials(self) -> Tuple[bool, str]:
        """
        Validates presence of required authentication credentials.
        Returns: (is_valid, message)
        """
        if not self.username:
            return False, "GVM username is not configured (set GVM_USER environment variable)."
        if not self._password:
            return False, "GVM password is not configured (set GVM_PASSWORD environment variable)."
        return True, "Credentials specified."

    def validate_connection_target(self) -> Tuple[bool, str]:
        """
        Validates whether the Unix socket or TLS endpoint is reachable.
        """
        if self.host:
            return True, f"Configured for remote TLS connection to {self.host}:{self.port or 9390}"

        if os.path.exists(self.socket_path):
            return True, f"Found local GVM Unix socket at {self.socket_path}"

        return False, (
            f"GVM Unix socket not found at '{self.socket_path}'. "
            "Please verify that gvmd service is active ('systemctl status gvmd')."
        )

    def to_dict(self) -> Dict[str, Any]:
        """Returns safe dictionary with masked credentials."""
        return {
            "username": self.username,
            "password_configured": bool(self._password),
            "socket_path": self.socket_path,
            "host": self.host,
            "port": self.port,
            "timeout": self.timeout
        }

    def __repr__(self) -> str:
        masked = "***" if self._password else "None"
        return (
            f"GreenboneAuthConfig(user='{self.username}', password={masked}, "
            f"socket='{self.socket_path}', host={self.host})"
        )
