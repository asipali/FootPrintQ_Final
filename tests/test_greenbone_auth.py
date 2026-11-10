"""
Unit tests for Greenbone authentication and configuration management (W5).
Verifies secure credential extraction, masking, environment handling, and validation.
"""

import os
import unittest
from unittest.mock import patch

from src.integrations.greenbone_auth import GreenboneAuthConfig


class TestGreenboneAuth(unittest.TestCase):
    """Tests GreenboneAuthConfig validation, environment variable extraction, and masking."""

    def setUp(self):
        # Save env
        self._env_backup = dict(os.environ)
        # Clear GVM related env vars for deterministic tests
        for key in ["GVM_USER", "GREENBONE_USER", "GVM_PASSWORD", "GREENBONE_PASSWORD",
                    "GVM_SOCKET_PATH", "GREENBONE_SOCKET", "GVM_HOST", "GVM_PORT", "GVM_TIMEOUT"]:
            if key in os.environ:
                del os.environ[key]

    def tearDown(self):
        # Restore env
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_default_initialization(self):
        """Test default values without environment variables."""
        cfg = GreenboneAuthConfig()
        self.assertEqual(cfg.username, "admin")
        self.assertIsNone(cfg.password)
        self.assertIsNone(cfg.host)
        self.assertIsNone(cfg.port)
        self.assertEqual(cfg.timeout, 60)
        self.assertIn("/run/gvmd/gvmd.sock", cfg.socket_path)

    def test_environment_variable_loading(self):
        """Test loading parameters from environment variables."""
        os.environ["GVM_USER"] = "secops_user"
        os.environ["GVM_PASSWORD"] = "SecretPass123!"
        os.environ["GVM_SOCKET_PATH"] = "/tmp/test_gvmd.sock"
        os.environ["GVM_HOST"] = "127.0.0.1"
        os.environ["GVM_PORT"] = "9390"
        os.environ["GVM_TIMEOUT"] = "120"

        cfg = GreenboneAuthConfig()
        self.assertEqual(cfg.username, "secops_user")
        self.assertEqual(cfg.password, "SecretPass123!")
        self.assertEqual(cfg.socket_path, "/tmp/test_gvmd.sock")
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 9390)
        self.assertEqual(cfg.timeout, 120)

    def test_explicit_arguments_override_environment(self):
        """Test explicit constructor arguments take precedence over environment variables."""
        os.environ["GVM_USER"] = "env_user"
        os.environ["GVM_PASSWORD"] = "env_pass"

        cfg = GreenboneAuthConfig(
            username="explicit_user",
            password="explicit_pass",
            socket_path="/custom/sock.path",
            host="192.168.1.100",
            port=9391,
            timeout=300
        )
        self.assertEqual(cfg.username, "explicit_user")
        self.assertEqual(cfg.password, "explicit_pass")
        self.assertEqual(cfg.socket_path, "/custom/sock.path")
        self.assertEqual(cfg.host, "192.168.1.100")
        self.assertEqual(cfg.port, 9391)
        self.assertEqual(cfg.timeout, 300)

    def test_credential_masking(self):
        """Test password is never exposed in repr or dict representations."""
        cfg = GreenboneAuthConfig(username="admin", password="SuperSensitivePassword99!")

        repr_str = repr(cfg)
        self.assertNotIn("SuperSensitivePassword99!", repr_str)
        self.assertIn("***", repr_str)

        info_dict = cfg.to_dict()
        self.assertNotIn("SuperSensitivePassword99!", str(info_dict))
        self.assertTrue(info_dict["password_configured"])
        self.assertNotIn("password", info_dict)

    def test_validate_credentials(self):
        """Test validate_credentials returns expected booleans and messages."""
        cfg_no_pass = GreenboneAuthConfig(username="admin", password=None)
        valid, msg = cfg_no_pass.validate_credentials()
        self.assertFalse(valid)
        self.assertIn("GVM password is not configured", msg)

        cfg_valid = GreenboneAuthConfig(username="admin", password="validpassword")
        valid, msg = cfg_valid.validate_credentials()
        self.assertTrue(valid)
        self.assertIn("Credentials specified", msg)

    def test_validate_connection_target_socket(self):
        """Test socket existence check."""
        with patch("os.path.exists", return_value=True):
            cfg = GreenboneAuthConfig(socket_path="/run/gvmd/gvmd.sock")
            valid, msg = cfg.validate_connection_target()
            self.assertTrue(valid)
            self.assertIn("Found local GVM Unix socket", msg)

        with patch("os.path.exists", return_value=False):
            cfg = GreenboneAuthConfig(socket_path="/nonexistent/gvmd.sock")
            valid, msg = cfg.validate_connection_target()
            self.assertFalse(valid)
            self.assertIn("Unix socket not found", msg)

    def test_validate_connection_target_tls(self):
        """Test TLS host connection check."""
        cfg = GreenboneAuthConfig(host="gvm.internal.lab", port=9390)
        valid, msg = cfg.validate_connection_target()
        self.assertTrue(valid)
        self.assertIn("Configured for remote TLS connection", msg)


if __name__ == "__main__":
    unittest.main()

